/*
 * Certificate Ripper
 * A Nintendo 3DS homebrew that extracts TLS server certificates,
 * inspired by https://github.com/Hakky54/certificate-ripper
 *
 * Features
 * --------
 *   - Connects to any HTTPS/TLS host and extracts the full certificate chain
 *   - Displays all certificate fields: Subject, Issuer, Validity, Key, Serial,
 *     SHA-256 fingerprint
 *   - Saves individual certificates as PEM or DER to the SD card
 *   - Saves the entire chain at once
 *
 * Controls
 * --------
 *   A            – Enter host URL (software keyboard)
 *   Up / Down    – Scroll certificate fields
 *   L / R        – Previous / next certificate in chain
 *   B            – Save current certificate as PEM  (sdmc:/3ds/crip/)
 *   X            – Save ALL chain certificates as PEM
 *   Y            – Save current certificate as DER (binary)
 *   START        – Exit
 *
 * Build requirements: devkitARM, libctru, citro2d, citro3d, mbedtls
 *   (all available via devkitPro pacman)
 */

#include "cert_types.h"
#include "cert_export.h"
#include "cert_p12.h"

#include <3ds.h>
#include <citro2d.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>   // for MBEDTLS_ERR_NET_* error codes only

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <malloc.h>
#include <string>
#include <vector>

// ============================================================
//  Screen / layout constants
// ============================================================
static constexpr int   TOP_W         = 400;
static constexpr int   BOT_W         = 320;
static constexpr int   SCREEN_H      = 240;
static constexpr int   TEXTBUF_GLYPHS = 4096;
static constexpr int   URL_BAR_H     = 26;
static constexpr int   STATUS_BAR_H  = 26;
static constexpr float LINE_H        = 13.5f;
static constexpr float CONTENT_SCALE = 0.48f;
static constexpr float UI_SCALE      = 0.42f;
static constexpr int   CONTENT_W     = 50;   // chars per wrapped line
static constexpr int   VIS_LINES     = (int)((SCREEN_H - 8) / LINE_H);  // ≈17

// ============================================================
//  Colours
// ============================================================
static const u32 CLR_BG      = C2D_Color32(0x0D, 0x14, 0x24, 0xFF);
static const u32 CLR_BAR     = C2D_Color32(0x1A, 0x26, 0x3A, 0xFF);
static const u32 CLR_TEXT    = C2D_Color32(0xE8, 0xF0, 0xFF, 0xFF);
static const u32 CLR_LABEL   = C2D_Color32(0x60, 0xC0, 0xFF, 0xFF);
static const u32 CLR_GOOD    = C2D_Color32(0x40, 0xE0, 0x80, 0xFF);
static const u32 CLR_ERR     = C2D_Color32(0xFF, 0x50, 0x50, 0xFF);
static const u32 CLR_GRAY    = C2D_Color32(0x70, 0x80, 0xA0, 0xFF);
static const u32 CLR_ACCENT  = C2D_Color32(0x40, 0xA0, 0xE0, 0xFF);
static const u32 CLR_DIVIDER = C2D_Color32(0x28, 0x3C, 0x5A, 0xFF);

// ============================================================
//  Application state
// ============================================================
enum class State { Idle, Connecting, ShowCerts, Error };

struct App {
    std::string             url;
    std::string             host;
    uint16_t                port      = 443;
    std::string             statusMsg = "Press [A] to enter a host";
    State                   state     = State::Idle;
    std::vector<CertInfo>   certs;
    // Lines pre-rendered for each cert (scrollable)
    std::vector<std::vector<std::string>> certLines;
    int                     certIdx   = 0;   // which cert in chain
    int                     scrollY   = 0;   // scroll offset in current cert
    int                     holdTimer = 0;
};

// ============================================================
//  Utility
// ============================================================
static std::string strLower(const std::string& s) {
    std::string o(s.size(), ' ');
    std::transform(s.begin(), s.end(), o.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return o;
}

// Word-wrap at space/comma boundaries; prefix each continuation line with indent
static void appendWrapped(std::vector<std::string>& out,
                          const std::string& text,
                          int maxW,
                          const std::string& indent = "  ") {
    std::string s = text;
    while ((int)s.size() > maxW) {
        // Try to break at the last space or comma before maxW
        int cut = maxW;
        for (int k = maxW - 1; k > maxW / 2; --k) {
            if (s[k] == ' ' || s[k] == ',') { cut = k + 1; break; }
        }
        out.push_back(s.substr(0, cut));
        s = indent + s.substr(cut);
    }
    out.push_back(s);
}

// ============================================================
// ============================================================
//  URL parser: accepts https:// only; rejects all other schemes.
//  Returns false if a non-HTTPS scheme is present.
// ============================================================
static bool parseURL(const std::string& raw, std::string& host, uint16_t& port) {
    std::string u = raw;
    port = 443;

    // Check/strip scheme
    size_t sep = u.find("://");
    if (sep != std::string::npos) {
        std::string scheme = strLower(u.substr(0, sep));
        if (scheme != "https") return false;
        u = u.substr(sep + 3);
    }

    // Strip path, query, fragment
    for (char stop : {'/', '?', '#'}) {
        size_t p = u.find(stop);
        if (p != std::string::npos) u = u.substr(0, p);
    }

    // Extract port if present (handle IPv6 like [::1]:443)
    bool ipv6 = (!u.empty() && u[0] == '[');
    size_t colon = ipv6 ? u.rfind("]:") : u.rfind(':');
    if (colon != std::string::npos && (!ipv6 || colon != std::string::npos)) {
        size_t portStart = ipv6 ? colon + 2 : colon + 1;
        std::string portStr = u.substr(portStart);
        bool allDigit = !portStr.empty();
        for (char c : portStr) if (c < '0' || c > '9') allDigit = false;
        if (allDigit) {
            int p = atoi(portStr.c_str());
            if (p > 0 && p < 65536) port = (uint16_t)p;
        }
        u = u.substr(0, colon);
    }

    // Strip surrounding brackets from IPv6
    if (!u.empty() && u.front() == '[' && u.back() == ']')
        u = u.substr(1, u.size() - 2);

    host = u;
    return true;
}

// ============================================================
//  Socket read/write callbacks for mbedTLS
// ============================================================
static int tlsSend(void* ctx, const unsigned char* buf, size_t len) {
    int fd  = *static_cast<int*>(ctx);
    int ret = (int)send(fd, buf, len, 0);
    if (ret < 0) return MBEDTLS_ERR_NET_SEND_FAILED;
    return ret;
}

static int tlsRecv(void* ctx, unsigned char* buf, size_t len) {
    int fd  = *static_cast<int*>(ctx);
    int ret = (int)recv(fd, buf, len, 0);
    if (ret < 0) return MBEDTLS_ERR_NET_RECV_FAILED;
    if (ret == 0) return MBEDTLS_ERR_NET_CONN_RESET;
    return ret;
}

// ============================================================
//  Connect to host and extract certificate chain via mbedTLS
// ============================================================
static std::vector<CertInfo> extractCerts(const std::string& host,
                                          uint16_t           port,
                                          std::string&       errOut) {
    std::vector<CertInfo> result;

    // --- Open TCP socket ---
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

    if (getaddrinfo(host.c_str(), portStr, &hints, &res) != 0 || !res) {
        errOut = "DNS lookup failed for: " + host;
        return result;
    }

    int sockfd = socket(res->ai_family, res->ai_socktype, 0);
    if (sockfd < 0) {
        freeaddrinfo(res);
        errOut = "socket() failed";
        return result;
    }

    // 10-second socket timeout (SO_RCVTIMEO / SO_SNDTIMEO are not available
    // on the 3DS socket layer; rely on mbedTLS handshake timeout instead)
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close(sockfd);
        errOut = "connect() failed to " + host + ":" + portStr;
        return result;
    }
    freeaddrinfo(res);

    // --- mbedTLS setup ---
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    int ret;
    const char* seed = "3ds-cert-ripper";

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char*)seed, strlen(seed));
    if (ret != 0) {
        errOut = "RNG seed failed";
        goto cleanup;
    }

    ret = mbedtls_ssl_config_defaults(&conf,
                                       MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { errOut = "SSL config failed"; goto cleanup; }

    // We purposely skip peer verification so we can extract even
    // self-signed / expired / untrusted certificates.
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) { errOut = "SSL setup failed"; goto cleanup; }

    ret = mbedtls_ssl_set_hostname(&ssl, host.c_str());  // SNI
    if (ret != 0) { errOut = "SNI failed"; goto cleanup; }

    mbedtls_ssl_set_bio(&ssl, &sockfd, tlsSend, tlsRecv, nullptr);

    // Perform TLS handshake
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0) {
        char mbedErr[128];
        mbedtls_strerror(ret, mbedErr, sizeof(mbedErr));
        errOut = "Handshake failed: ";
        errOut += mbedErr;
        goto cleanup;
    }

    // --- Walk the certificate chain ---
    {
        const mbedtls_x509_crt* cert = mbedtls_ssl_get_peer_cert(&ssl);
        if (!cert) {
            errOut = "No certificate returned by server";
            goto cleanup;
        }

        while (cert) {
            CertInfo ci;
            char buf[1024];

            // Subject & Issuer
            if (mbedtls_x509_dn_gets(buf, sizeof(buf), &cert->subject) > 0)
                ci.subject = buf;
            else
                ci.subject = "(empty)";

            if (mbedtls_x509_dn_gets(buf, sizeof(buf), &cert->issuer) > 0)
                ci.issuer = buf;
            else
                ci.issuer = "(empty)";

            // Validity dates
            snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                     cert->valid_from.year, cert->valid_from.mon,
                     cert->valid_from.day,  cert->valid_from.hour,
                     cert->valid_from.min,  cert->valid_from.sec);
            ci.validFrom = buf;

            snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                     cert->valid_to.year, cert->valid_to.mon,
                     cert->valid_to.day,  cert->valid_to.hour,
                     cert->valid_to.min,  cert->valid_to.sec);
            ci.validTo = buf;

            // Serial number (hex, colon-separated)
            {
                std::string serial;
                for (size_t j = 0; j < cert->serial.len; ++j) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02X", cert->serial.p[j]);
                    if (!serial.empty()) serial += ':';
                    serial += hex;
                }
                ci.serialHex = serial.empty() ? "(none)" : serial;
            }

            // SHA-256 fingerprint
            {
                unsigned char sha[32];
                mbedtls_sha256(cert->raw.p, cert->raw.len, sha, 0);
                std::string fp;
                for (int j = 0; j < 32; ++j) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02X", sha[j]);
                    if (!fp.empty()) fp += ':';
                    fp += hex;
                }
                ci.fingerprint = fp;
            }

            // Public key description
            {
                int bits = (int)mbedtls_pk_get_bitlen(&cert->pk);
                const char* typeName = mbedtls_pk_get_name(&cert->pk);
                snprintf(buf, sizeof(buf), "%s %d bits",
                         typeName ? typeName : "Unknown", bits);
                ci.keyDesc = buf;
            }

            // Raw DER copy
            ci.der.assign(cert->raw.p, cert->raw.p + cert->raw.len);

            result.push_back(ci);
            cert = cert->next;
        }
    }

    mbedtls_ssl_close_notify(&ssl);

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    close(sockfd);

    return result;
}

// ============================================================
//  Build display lines for one certificate
// ============================================================
static std::vector<std::string> buildCertLines(const CertInfo& c,
                                               int certIdx, int total,
                                               const std::string& host) {
    std::vector<std::string> lines;

    // Header
    {
        char hdr[64];
        snprintf(hdr, sizeof(hdr), "=== Certificate %d / %d  [%s] ===",
                 certIdx + 1, total, host.c_str());
        appendWrapped(lines, hdr, CONTENT_W);
        lines.emplace_back("");
    }

    // Subject
    lines.emplace_back("SUBJECT");
    appendWrapped(lines, "  " + c.subject, CONTENT_W);
    lines.emplace_back("");

    // Issuer
    lines.emplace_back("ISSUER");
    appendWrapped(lines, "  " + c.issuer, CONTENT_W);
    lines.emplace_back("");

    // Validity
    lines.emplace_back("VALIDITY");
    lines.push_back("  From: " + c.validFrom);
    lines.push_back("  To:   " + c.validTo);
    lines.emplace_back("");

    // Public key
    lines.emplace_back("PUBLIC KEY");
    lines.push_back("  " + c.keyDesc);
    lines.emplace_back("");

    // Serial
    lines.emplace_back("SERIAL NUMBER");
    appendWrapped(lines, "  " + c.serialHex, CONTENT_W);
    lines.emplace_back("");

    // SHA-256 fingerprint (split into two ~47-char halves at a ':' boundary)
    lines.emplace_back("SHA-256 FINGERPRINT");
    {
        const std::string& fp = c.fingerprint;
        // Try to break at a ':' near the midpoint (byte 16 = char pos 47-48)
        size_t mid = fp.rfind(':', 47);
        if (mid != std::string::npos && mid > 0) {
            lines.push_back("  " + fp.substr(0, mid));
            lines.push_back("  " + fp.substr(mid + 1));
        } else {
            appendWrapped(lines, "  " + fp, CONTENT_W);
        }
    }
    lines.emplace_back("");

    // Size
    {
        char sz[64];
        snprintf(sz, sizeof(sz), "DER size: %u bytes", (unsigned)c.der.size());
        lines.push_back(sz);
    }
    lines.emplace_back("");

    // Controls reminder
    lines.emplace_back("[B] Save PEM  [Y] Save DER  [X] Save chain as PEM");
    lines.emplace_back("[L/R] Prev/next cert  [A] New host");

    return lines;
}

// ============================================================
//  Text rendering helpers (citro2d system font)
// ============================================================
static C2D_TextBuf s_textBuf;

static void drawText(const char* str, float x, float y, float depth,
                     float scale, u32 color, u32 extraFlags = 0) {
    if (!str || !str[0]) return;
    C2D_Text t;
    C2D_TextParse(&t, s_textBuf, str);
    C2D_TextOptimize(&t);
    C2D_DrawText(&t, C2D_WithColor | extraFlags, x, y, depth, scale, scale, color);
}

static void drawTextC(const char* str, float cx, float y, float depth,
                      float scale, u32 color) {
    drawText(str, cx, y, depth, scale, color, C2D_AlignCenter);
}

// ============================================================
//  Main
// ============================================================
int main() {
    // --- Core services ---
    gfxInitDefault();
    C3D_Init(C3D_DEFAULT_CMDBUF_SIZE);
    C2D_Init(C2D_DEFAULT_MAX_OBJECTS);
    C2D_Prepare();

    acInit();

    // Socket service (required for all networking on 3DS homebrew)
    u32* socBuf = static_cast<u32*>(memalign(0x1000, 0x100000));
    if (socBuf) socInit(socBuf, 0x100000);

    osSetSpeedupEnable(true);  // New 3DS CPU boost

    // --- Render targets ---
    C3D_RenderTarget* topScreen = C2D_CreateScreenTarget(GFX_TOP,    GFX_LEFT);
    C3D_RenderTarget* botScreen = C2D_CreateScreenTarget(GFX_BOTTOM, GFX_LEFT);

    s_textBuf = C2D_TextBufNew(TEXTBUF_GLYPHS);

    App app;

    while (aptMainLoop()) {
        hidScanInput();
        u32 kDown = hidKeysDown();
        u32 kHeld = hidKeysHeld();

        if (kDown & KEY_START) break;

        // ---- Open keyboard to enter a host ----
        if (kDown & KEY_A) {
            SwkbdState kbd;
            swkbdInit(&kbd, SWKBD_TYPE_NORMAL, 2, 512);
            swkbdSetHintText(&kbd, "Enter host  (e.g. github.com or https://github.com)");
            std::string initText = app.url.empty() ? "https://" : app.url;
            swkbdSetInitialText(&kbd, initText.c_str());
            swkbdSetValidation(&kbd, SWKBD_NOTEMPTY_NOTBLANK, 0, 0);

            char urlBuf[513] = {};
            SwkbdButton btn = swkbdInputText(&kbd, urlBuf, sizeof(urlBuf) - 1);

            if (btn == SWKBD_BUTTON_CONFIRM && urlBuf[0] != '\0') {
                app.url = urlBuf;
                if (app.url.find("://") == std::string::npos)
                    app.url = "https://" + app.url;

                if (!parseURL(app.url, app.host, app.port)) {
                    app.state     = State::Error;
                    app.certLines = {{ "Unsupported scheme.", "",
                                       "Only https:// is supported.",
                                       "", "Press [A] to try again." }};
                    app.statusMsg = "Only https:// is supported";
                } else {
                    app.state     = State::Connecting;
                    app.statusMsg = "Connecting...";
                    app.certs.clear();
                    app.certLines.clear();
                    app.certIdx = 0;
                    app.scrollY = 0;
                }
            }
        }

        // ---- Save controls (only in ShowCerts state) ----
        if (app.state == State::ShowCerts && !app.certs.empty()) {
            int ci = app.certIdx;

            if (kDown & KEY_B) {
                bool ok = savePEM(app.certs[ci], app.host, ci);
                app.statusMsg = ok
                    ? "Saved PEM to sdmc:/3ds/crip/"
                    : "ERROR: Could not write to SD card";
            }
            if (kDown & KEY_Y) {
                bool ok = saveDER(app.certs[ci], app.host, ci);
                app.statusMsg = ok
                    ? "Saved DER to sdmc:/3ds/crip/"
                    : "ERROR: Could not write to SD card";
            }
            if (kDown & KEY_X) {
                int n = saveChainPEM(app.certs, app.host);
                char tmp[64];
                snprintf(tmp, sizeof(tmp), "Saved %d PEM file(s) to sdmc:/3ds/crip/", n);
                app.statusMsg = tmp;
            }
            if (kDown & KEY_SELECT) {
                int n = saveP12(app.certs);
                if (n < 0)
                    app.statusMsg = "ERROR: P12 build/write failed";
                else {
                    char tmp[72];
                    snprintf(tmp, sizeof(tmp),
                             "truststore.p12 updated  (+%d new)", n);
                    app.statusMsg = tmp;
                }
            }

            // Navigate between certificates in the chain
            if (kDown & KEY_L) {
                if (app.certIdx > 0) { --app.certIdx; app.scrollY = 0; }
            }
            if (kDown & KEY_R) {
                if (app.certIdx < (int)app.certs.size() - 1) {
                    ++app.certIdx; app.scrollY = 0;
                }
            }

            // Scroll within the current cert's lines
            auto scrollBy = [&](int delta) {
                const auto& lines = app.certLines[app.certIdx];
                int maxScroll = std::max(0, (int)lines.size() - VIS_LINES);
                app.scrollY   = std::max(0, std::min(maxScroll, app.scrollY + delta));
            };

            if (kDown & KEY_UP)   { scrollBy(-1); app.holdTimer = 0; }
            if (kDown & KEY_DOWN) { scrollBy(+1); app.holdTimer = 0; }
            if ((kHeld & KEY_UP) || (kHeld & KEY_DOWN)) {
                ++app.holdTimer;
                if (app.holdTimer > 20 && (app.holdTimer % 3) == 0)
                    scrollBy((kHeld & KEY_DOWN) ? +1 : -1);
            } else if (!(kDown & (KEY_UP | KEY_DOWN))) {
                app.holdTimer = 0;
            }
        }

        // ================================================================
        //  Certificate extraction (blocking; renders a "Connecting" frame first)
        // ================================================================
        if (app.state == State::Connecting) {
            // Draw "connecting" frame
            C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
            C2D_TargetClear(topScreen, CLR_BG);
            C2D_TargetClear(botScreen, CLR_BG);
            C2D_TextBufClear(s_textBuf);

            C2D_SceneBegin(topScreen);
            drawTextC("Certificate Ripper",
                      TOP_W / 2.f, 80.f, 0.5f, 0.6f, CLR_ACCENT);
            {
                char msg[128];
                snprintf(msg, sizeof(msg), "Connecting to %s:%u ...",
                         app.host.c_str(), (unsigned)app.port);
                drawTextC(msg, TOP_W / 2.f, 108.f, 0.5f, CONTENT_SCALE, CLR_TEXT);
            }
            C3D_FrameEnd(0);

            // Extract certificates
            std::string err;
            app.certs = extractCerts(app.host, app.port, err);

            if (!app.certs.empty()) {
                // Pre-build display lines for each certificate
                app.certLines.clear();
                for (int i = 0; i < (int)app.certs.size(); ++i)
                    app.certLines.push_back(
                        buildCertLines(app.certs[i], i,
                                       (int)app.certs.size(), app.host));

                app.state = State::ShowCerts;

                char tmp[64];
                snprintf(tmp, sizeof(tmp),
                         "Found %d certificate(s)  |  L/R to navigate",
                         (int)app.certs.size());
                app.statusMsg = tmp;
            } else {
                app.state     = State::Error;
                app.certLines = {{ "Connection failed.", "", err,
                                   "", "Press [A] to try again." }};
                app.statusMsg = err.empty() ? "Unknown error" : err;
            }

            app.certIdx = 0;
            app.scrollY = 0;
            continue;
        }

        // ================================================================
        //  Draw
        // ================================================================
        C3D_FrameBegin(C3D_FRAME_SYNCDRAW);
        C2D_TargetClear(topScreen, CLR_BG);
        C2D_TargetClear(botScreen, CLR_BG);
        C2D_TextBufClear(s_textBuf);

        // ---- TOP SCREEN: certificate content ----
        C2D_SceneBegin(topScreen);

        if (app.state == State::Idle) {
            // Welcome screen
            drawTextC("Certificate Ripper",
                      TOP_W / 2.f, 60.f, 0.5f, 0.65f, CLR_ACCENT);
            drawTextC("by Hakan Altindag",
                      TOP_W / 2.f, 82.f, 0.5f, UI_SCALE, CLR_TEXT);
            drawTextC("Inspired by github.com/Hakky54/certificate-ripper",
                      TOP_W / 2.f, 98.f, 0.5f, UI_SCALE, CLR_GRAY);
            drawTextC("Press [A] on the bottom screen to enter a host",
                      TOP_W / 2.f, 122.f, 0.5f, UI_SCALE, CLR_TEXT);
            drawTextC("Certificates are saved to  sdmc:/3ds/crip/",
                      TOP_W / 2.f, 140.f, 0.5f, UI_SCALE, CLR_GRAY);

        } else if ((app.state == State::ShowCerts ||
                    app.state == State::Error) &&
                   !app.certLines.empty()) {

            int ci = std::min(app.certIdx, (int)app.certLines.size() - 1);
            const auto& lines = app.certLines[ci];

            // Render visible lines
            for (int i = 0; i < VIS_LINES; ++i) {
                int idx = app.scrollY + i;
                if (idx >= (int)lines.size()) break;
                const std::string& ln = lines[idx];
                if (ln.empty()) continue;

                // Colour section labels differently
                bool isLabel = !ln.empty() && ln[0] != ' ' && ln[0] != '[' &&
                               ln[0] != '=' && ln.find(':') == std::string::npos;
                u32 col = isLabel ? CLR_LABEL : CLR_TEXT;
                // Header line (starts with '=') gets accent colour
                if (!ln.empty() && ln[0] == '=') col = CLR_ACCENT;

                drawText(ln.c_str(), 4.f,
                         4.f + i * LINE_H, 0.5f,
                         CONTENT_SCALE, col);
            }

            // Scrollbar
            if ((int)lines.size() > VIS_LINES) {
                float total = (float)lines.size();
                float barH  = SCREEN_H * ((float)VIS_LINES / total);
                float barY  = SCREEN_H * ((float)app.scrollY / total);
                barH = std::max(barH, 6.f);
                barY = std::min(barY, (float)SCREEN_H - barH);
                C2D_DrawRectSolid(396.f, 0.f,  0.5f, 4.f, SCREEN_H, CLR_DIVIDER);
                C2D_DrawRectSolid(396.f, barY, 0.5f, 4.f, barH,     CLR_ACCENT);
            }
        }

        // ---- BOTTOM SCREEN: controls / URL bar / status ----
        C2D_SceneBegin(botScreen);

        // URL bar
        C2D_DrawRectSolid(0, 0, 0.5f, BOT_W, URL_BAR_H, CLR_BAR);
        drawText("[A]:", 4.f, 6.f, 0.5f, UI_SCALE, CLR_GRAY);
        {
            std::string du = app.host.empty() ? "(press A to enter a host)" : app.url;
            if (du.size() > 40) du = du.substr(0, 37) + "...";
            drawText(du.c_str(), 34.f, 6.f, 0.5f, UI_SCALE, CLR_TEXT);
        }

        // Cert navigation indicator
        if (app.state == State::ShowCerts && !app.certs.empty()) {
            char nav[48];
            snprintf(nav, sizeof(nav), "[L] Cert %d/%d [R]",
                     app.certIdx + 1, (int)app.certs.size());
            drawTextC(nav, BOT_W / 2.f, 34.f, 0.5f, UI_SCALE, CLR_ACCENT);
        }

        // Control hints
        static const char* const HINTS[] = {
            "[A] Enter host",
            "[B] Save PEM   [Y] Save DER",
            "[X] Save chain as PEM  [SEL] Save P12",
            "[L/R] Prev/Next  [START] Exit",
            nullptr
        };
        float hy = 52.f;
        for (int i = 0; HINTS[i]; ++i, hy += 17.f)
            drawTextC(HINTS[i], BOT_W / 2.f, hy, 0.5f, UI_SCALE, CLR_GRAY);

        // Scroll indicator
        if ((app.state == State::ShowCerts || app.state == State::Error) &&
            !app.certLines.empty()) {
            int ci = std::min(app.certIdx, (int)app.certLines.size() - 1);
            const auto& lines = app.certLines[ci];
            if (!lines.empty()) {
                char pos[32];
                snprintf(pos, sizeof(pos), "Line %d/%d",
                         app.scrollY + 1, (int)lines.size());
                drawTextC(pos, BOT_W / 2.f, 128.f, 0.5f, UI_SCALE, CLR_GRAY);
            }
        }

        // Status bar
        C2D_DrawRectSolid(0, SCREEN_H - STATUS_BAR_H, 0.5f,
                          BOT_W, STATUS_BAR_H, CLR_BAR);
        u32 sc = (app.state == State::Error) ? CLR_ERR   :
                 (app.state == State::ShowCerts) ? CLR_GOOD : CLR_GRAY;
        {
            std::string ds = app.statusMsg;
            if (ds.size() > 46) ds = ds.substr(0, 43) + "...";
            drawText(ds.c_str(), 4.f,
                     SCREEN_H - STATUS_BAR_H + 7.f, 0.5f,
                     UI_SCALE, sc);
        }

        C3D_FrameEnd(0);
    }

    // ---- Cleanup ----
    C2D_TextBufDelete(s_textBuf);
    if (socBuf) { socExit(); free(socBuf); }
    C2D_Fini();
    C3D_Fini();
    acExit();
    gfxExit();
    return 0;
}
