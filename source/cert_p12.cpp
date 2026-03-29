/*
 * cert_p12.cpp – PKCS12 truststore builder (RFC 7292)
 *
 * Structure built from scratch using mbedTLS ASN.1 + crypto primitives:
 *
 *   PFX SEQUENCE {
 *     version INTEGER 3
 *     authSafe ContentInfo (id-data) {
 *       OCTET STRING( AuthenticatedSafe SEQUENCE {
 *         ContentInfo (id-data) {
 *           OCTET STRING( SafeContents SEQUENCE OF SafeBag(CertBag) )
 *         }
 *       })
 *     }
 *     macData SEQUENCE {
 *       DigestInfo { AlgorithmIdentifier(SHA-256), HMAC-SHA256(macKey, authSafe) }
 *       macSalt OCTET STRING (16 bytes)
 *       iterations INTEGER 10000
 *     }
 *   }
 *
 *  macKey  = PKCS12_KDF(SHA-256, "changeit" UTF-16BE, salt, iterations=10000, id=3)
 *
 *  Each CertBag carries:
 *    - friendlyName  (BMPString, e.g. "cert-1")
 *    - trustedKeyUsage (Oracle OID 2.16.840.1.113894.746875.1.1)
 *      value: SET { OID anyExtendedKeyUsage (2.5.29.37.0) }
 *  The trustedKeyUsage attribute is required for Java's KeyStore to expose
 *  certificate bags as TrustedCertificateEntry objects.
 */
#include "cert_p12.h"
#include "cert_export.h"   // for ensureOutDir()

#include <mbedtls/pkcs12.h>
#include <mbedtls/md.h>

#include <3ds.h>           // for svcGetSystemTick()

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <dirent.h>

static const char* OUT_DIR    = "sdmc:/3ds/crip";
static const char* CERT_STORE = "sdmc:/3ds/crip/certs";

// ============================================================
//  Minimal forward-writing DER builder
// ============================================================
struct DerBuf {
    std::vector<uint8_t> v;

    void u8(uint8_t x) { v.push_back(x); }

    void encLen(size_t n) {
        if      (n < 0x80)    { u8((uint8_t)n); }
        else if (n < 0x100)   { u8(0x81); u8((uint8_t)n); }
        else if (n < 0x10000) { u8(0x82); u8((uint8_t)(n>>8)); u8((uint8_t)n); }
        else { u8(0x83); u8((uint8_t)(n>>16)); u8((uint8_t)(n>>8)); u8((uint8_t)n); }
    }

    void tlv(uint8_t tag, const uint8_t* val, size_t len) {
        u8(tag); encLen(len); v.insert(v.end(), val, val + len);
    }
};

// ---- TLV factory helpers ----------------------------------------
static std::vector<uint8_t> p12Seq(const std::vector<uint8_t>& in)  { DerBuf b; b.tlv(0x30, in.data(), in.size()); return b.v; }
static std::vector<uint8_t> p12Oct(const uint8_t* d, size_t n)      { DerBuf b; b.tlv(0x04, d, n); return b.v; }
static std::vector<uint8_t> p12OID(const uint8_t* d, size_t n)      { DerBuf b; b.tlv(0x06, d, n); return b.v; }
static std::vector<uint8_t> p12Null()                                { return {0x05, 0x00}; }

// DER INTEGER encoding for any non-negative integer value.
static std::vector<uint8_t> p12Int(int v) {
    std::vector<uint8_t> bytes;
    unsigned uv = (unsigned)v;
    do {
        bytes.insert(bytes.begin(), (uint8_t)(uv & 0xFF));
        uv >>= 8;
    } while (uv);
    if (bytes[0] >= 0x80) bytes.insert(bytes.begin(), 0x00);
    std::vector<uint8_t> result = {0x02, (uint8_t)bytes.size()};
    result.insert(result.end(), bytes.begin(), bytes.end());
    return result;
}

static std::vector<uint8_t> p12Expl(uint8_t tag, const std::vector<uint8_t>& in) {
    DerBuf b; b.tlv((uint8_t)(0xA0 | tag), in.data(), in.size()); return b.v;
}

static std::vector<uint8_t> p12BMP(const char* s) {
    std::vector<uint8_t> bmp;
    for (const char* c = s; *c; ++c) { bmp.push_back(0x00); bmp.push_back((uint8_t)*c); }
    DerBuf b; b.tlv(0x1E, bmp.data(), bmp.size()); return b.v;
}

// Append src into dst
static void p12Cat(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

// ============================================================
//  PKCS12 builder
// ============================================================
static std::vector<uint8_t> buildP12(const std::vector<CertInfo>& certs) {
    // Pre-encoded OIDs
    static const uint8_t OID_DATA[]    = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01};           // 1.2.840.113549.1.7.1
    static const uint8_t OID_CERTBAG[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x03}; // 1.2.840.113549.1.12.10.1.3
    static const uint8_t OID_X509[]    = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x16,0x01};      // 1.2.840.113549.1.9.22.1
    static const uint8_t OID_FNAME[]   = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x14};           // 1.2.840.113549.1.9.20 (friendlyName)
    static const uint8_t OID_SHA256[]  = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};           // 2.16.840.1.101.3.4.2.1
    // Oracle-specific trustedKeyUsage: 2.16.840.1.113894.746875.1.1
    static const uint8_t OID_TKU[]     = {0x60,0x86,0x48,0x01,0x86,0xF9,0x66,0xAD,0xCA,0x7B,0x01,0x01};
    // anyExtendedKeyUsage: 2.5.29.37.0
    static const uint8_t OID_ANY_EKU[] = {0x55,0x1D,0x25,0x00};

    // Password: "changeit" as UTF-16BE with null terminator
    std::vector<uint8_t> pwd;
    for (const char* c = "changeit"; *c; ++c) { pwd.push_back(0x00); pwd.push_back((uint8_t)*c); }
    pwd.push_back(0x00); pwd.push_back(0x00);

    // 16-byte salt from system tick
    uint8_t salt[16];
    { u64 t1 = svcGetSystemTick(); u64 t2 = t1 ^ 0xDEADBEEFCAFEBABEULL;
      memcpy(salt, &t1, 8); memcpy(salt + 8, &t2, 8); }

    // ---- SafeContents: SEQUENCE OF SafeBag(CertBag) ----
    std::vector<uint8_t> safeBody;

    for (int i = 0; i < (int)certs.size(); ++i) {
        // CertBag = SEQUENCE { OID_X509, [0] OCTET_STRING(DER) }
        auto oidX   = p12OID(OID_X509, sizeof(OID_X509));
        auto derOct = p12Oct(certs[i].der.data(), certs[i].der.size());
        auto derE0  = p12Expl(0, derOct);
        std::vector<uint8_t> cbBody; p12Cat(cbBody, oidX); p12Cat(cbBody, derE0);
        auto certBag = p12Seq(cbBody);

        // ---- Attribute 1: friendlyName ----
        char alias[24]; snprintf(alias, sizeof(alias), "cert-%d", i + 1);
        auto bmp  = p12BMP(alias);
        DerBuf setFN; setFN.tlv(0x31, bmp.data(), bmp.size());
        auto oidF = p12OID(OID_FNAME, sizeof(OID_FNAME));
        std::vector<uint8_t> fnBody; p12Cat(fnBody, oidF); p12Cat(fnBody, setFN.v);
        auto fnAttr = p12Seq(fnBody);

        // ---- Attribute 2: trustedKeyUsage = SET { OID anyExtendedKeyUsage } ----
        // Required by Java's KeyStore to expose the bag as a TrustedCertificateEntry.
        auto oidAnyEKU = p12OID(OID_ANY_EKU, sizeof(OID_ANY_EKU));
        DerBuf setTKU; setTKU.tlv(0x31, oidAnyEKU.data(), oidAnyEKU.size());
        auto oidTKU = p12OID(OID_TKU, sizeof(OID_TKU));
        std::vector<uint8_t> tkuBody; p12Cat(tkuBody, oidTKU); p12Cat(tkuBody, setTKU.v);
        auto tkuAttr = p12Seq(tkuBody);

        // bagAttributes = SET { friendlyName, trustedKeyUsage }
        std::vector<uint8_t> allAttrs; p12Cat(allAttrs, fnAttr); p12Cat(allAttrs, tkuAttr);
        DerBuf bagA; bagA.tlv(0x31, allAttrs.data(), allAttrs.size());

        // SafeBag = SEQUENCE { OID_CERTBAG, [0] CertBag, bagAttributes }
        auto oidC = p12OID(OID_CERTBAG, sizeof(OID_CERTBAG));
        auto bval = p12Expl(0, certBag);
        std::vector<uint8_t> sbBody; p12Cat(sbBody, oidC); p12Cat(sbBody, bval); p12Cat(sbBody, bagA.v);
        p12Cat(safeBody, p12Seq(sbBody));
    }

    auto safeContents = p12Seq(safeBody);

    // ---- Inner ContentInfo: SEQUENCE { OID_DATA, [0] OCTET_STRING(safeContents) } ----
    auto oidD1 = p12OID(OID_DATA, sizeof(OID_DATA));
    auto scOct = p12Oct(safeContents.data(), safeContents.size());
    auto scE0  = p12Expl(0, scOct);
    std::vector<uint8_t> iciBody; p12Cat(iciBody, oidD1); p12Cat(iciBody, scE0);
    auto innerCI = p12Seq(iciBody);

    // ---- AuthenticatedSafe = SEQUENCE { innerContentInfo } ----
    // MAC is computed over the DER encoding of this value.
    auto authSafe = p12Seq(innerCI);

    // ---- Outer ContentInfo: SEQUENCE { OID_DATA, [0] OCTET_STRING(authSafe) } ----
    auto oidD2 = p12OID(OID_DATA, sizeof(OID_DATA));
    auto asOct = p12Oct(authSafe.data(), authSafe.size());
    auto asE0  = p12Expl(0, asOct);
    std::vector<uint8_t> ociBody; p12Cat(ociBody, oidD2); p12Cat(ociBody, asE0);
    auto outerCI = p12Seq(ociBody);

    // ---- MAC: PKCS12-KDF(SHA-256, id=3, 10000 iters) → HMAC-SHA256 ----
    static constexpr int MAC_ITERS = 10000;
    uint8_t macKey[32]{};
    if (mbedtls_pkcs12_derivation(macKey, sizeof(macKey),
                                   pwd.data(), pwd.size(),
                                   salt, sizeof(salt),
                                   MBEDTLS_MD_SHA256, 3, MAC_ITERS) != 0)
        return {};

    uint8_t macVal[32]{};
    const mbedtls_md_info_t* sha256Info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!sha256Info) return {};
    if (mbedtls_md_hmac(sha256Info, macKey, sizeof(macKey),
                         authSafe.data(), authSafe.size(), macVal) != 0)
        return {};

    // ---- MacData = SEQUENCE { DigestInfo(SHA-256), macSalt, iterations } ----
    auto sha256Oid = p12OID(OID_SHA256, sizeof(OID_SHA256));
    auto nullEnc   = p12Null();
    std::vector<uint8_t> algBody; p12Cat(algBody, sha256Oid); p12Cat(algBody, nullEnc);
    auto algId = p12Seq(algBody);
    auto macOct = p12Oct(macVal, sizeof(macVal));
    std::vector<uint8_t> diBody; p12Cat(diBody, algId); p12Cat(diBody, macOct);
    auto digestInfo = p12Seq(diBody);
    auto saltOct = p12Oct(salt, sizeof(salt));
    auto iterInt = p12Int(MAC_ITERS);
    std::vector<uint8_t> mdBody; p12Cat(mdBody, digestInfo); p12Cat(mdBody, saltOct); p12Cat(mdBody, iterInt);
    auto macData = p12Seq(mdBody);

    // ---- PFX = SEQUENCE { version=3, outerCI, macData } ----
    auto ver = p12Int(3);
    std::vector<uint8_t> pfxBody; p12Cat(pfxBody, ver); p12Cat(pfxBody, outerCI); p12Cat(pfxBody, macData);
    return p12Seq(pfxBody);
}

// ============================================================
//  Cert store (one DER file per unique cert, keyed by SHA-256 fingerprint)
// ============================================================

// Returns true if the cert was new and successfully stored.
static bool storeAddCert(const CertInfo& cert) {
    ensureOutDir();
    mkdir(CERT_STORE, 0777);

    // Filename = 64 hex chars (fingerprint without colons)
    std::string fname;
    for (char c : cert.fingerprint) if (c != ':') fname += c;

    char path[300];
    snprintf(path, sizeof(path), "%s/%s.der", CERT_STORE, fname.c_str());

    FILE* chk = fopen(path, "rb");
    if (chk) { fclose(chk); return false; }   // already present

    FILE* f = fopen(path, "wb");
    if (!f) return false;
    fwrite(cert.der.data(), 1, cert.der.size(), f);
    fclose(f);
    return true;
}

// Returns all certs in the store (der field only – sufficient for buildP12).
static std::vector<CertInfo> storeReadAll() {
    std::vector<CertInfo> out;
    DIR* dir = opendir(CERT_STORE);
    if (!dir) return out;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.size() < 5 || name.substr(name.size() - 4) != ".der") continue;

        char path[300];
        snprintf(path, sizeof(path), "%s/%s", CERT_STORE, name.c_str());

        FILE* f = fopen(path, "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        if (sz <= 0 || sz > 65536) { fclose(f); continue; }

        CertInfo ci;
        ci.der.resize((size_t)sz);
        fread(ci.der.data(), 1, (size_t)sz, f);
        fclose(f);
        out.push_back(std::move(ci));
    }
    closedir(dir);
    return out;
}

// ============================================================
//  Public API
// ============================================================
int saveP12(const std::vector<CertInfo>& newCerts) {
    int added = 0;
    for (const CertInfo& c : newCerts)
        if (storeAddCert(c)) ++added;

    std::vector<CertInfo> allCerts = storeReadAll();
    if (allCerts.empty()) return -1;

    auto p12 = buildP12(allCerts);
    if (p12.empty()) return -1;

    ensureOutDir();
    char path[256];
    snprintf(path, sizeof(path), "%s/truststore.p12", OUT_DIR);

    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(p12.data(), 1, p12.size(), f);
    fclose(f);
    return added;
}
