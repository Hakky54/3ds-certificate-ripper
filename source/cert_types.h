/*
 * cert_types.h – shared data types for 3DS Certificate Ripper
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct CertInfo {
    std::string          subject;
    std::string          issuer;
    std::string          validFrom;
    std::string          validTo;
    std::string          serialHex;
    std::string          fingerprint;  // SHA-256, colon-separated hex
    std::string          keyDesc;      // e.g. "RSA 2048" or "EC P-256 (256)"
    std::vector<uint8_t> der;          // raw DER bytes
};
