/*
 * cert_p12.h – PKCS12 truststore export
 *
 * Builds a certificate-only PKCS12 (RFC 7292) truststore named
 * "truststore.p12" on the SD card, accumulating certificates across
 * multiple calls.  Password: "changeit" (Java KeyStore default).
 */
#pragma once

#include "cert_types.h"
#include <vector>

// Add newCerts to the on-SD cert store and rebuild truststore.p12 from
// the full store.  Returns the number of newly added certificates, or
// -1 on build/write failure.
int saveP12(const std::vector<CertInfo>& newCerts);
