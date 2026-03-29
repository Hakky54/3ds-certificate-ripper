/*
 * cert_export.cpp – PEM and DER certificate export to SD card
 */
#include "cert_export.h"

#include <mbedtls/base64.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>

static const char* OUT_DIR = "sdmc:/3ds/crip";

// ---- Internal helper ------------------------------------------------

static std::string derToPEM(const uint8_t* der, size_t derLen) {
    size_t b64Len = 0;
    mbedtls_base64_encode(nullptr, 0, &b64Len, der, derLen);

    std::vector<unsigned char> b64(b64Len + 1, 0);
    mbedtls_base64_encode(b64.data(), b64Len, &b64Len, der, derLen);

    std::string pem = "-----BEGIN CERTIFICATE-----\n";
    for (size_t i = 0; i < b64Len; i += 64) {
        size_t lineLen = std::min((size_t)64, b64Len - i);
        pem.append(reinterpret_cast<char*>(b64.data()) + i, lineLen);
        pem += '\n';
    }
    pem += "-----END CERTIFICATE-----\n";
    return pem;
}

static std::string safeHostname(const std::string& host) {
    std::string s = host;
    for (char& c : s) if (c == ':' || c == '/' || c == '\\') c = '_';
    return s;
}

// ---- Public API -----------------------------------------------------

void ensureOutDir() {
    mkdir("sdmc:/3ds", 0777);
    mkdir(OUT_DIR,     0777);
}

bool savePEM(const CertInfo& cert, const std::string& host, int idx) {
    ensureOutDir();
    char path[256];
    snprintf(path, sizeof(path), "%s/%s_%d.pem",
             OUT_DIR, safeHostname(host).c_str(), idx + 1);

    std::string pem = derToPEM(cert.der.data(), cert.der.size());
    FILE* f = fopen(path, "w");
    if (!f) return false;
    fwrite(pem.c_str(), 1, pem.size(), f);
    fclose(f);
    return true;
}

bool saveDER(const CertInfo& cert, const std::string& host, int idx) {
    ensureOutDir();
    char path[256];
    snprintf(path, sizeof(path), "%s/%s_%d.der",
             OUT_DIR, safeHostname(host).c_str(), idx + 1);

    FILE* f = fopen(path, "wb");
    if (!f) return false;
    fwrite(cert.der.data(), 1, cert.der.size(), f);
    fclose(f);
    return true;
}

int saveChainPEM(const std::vector<CertInfo>& certs, const std::string& host) {
    int saved = 0;
    for (int i = 0; i < (int)certs.size(); ++i)
        if (savePEM(certs[i], host, i)) ++saved;
    return saved;
}
