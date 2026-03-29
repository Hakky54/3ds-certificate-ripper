/*
 * cert_export.h – PEM and DER certificate export to SD card
 */
#pragma once

#include "cert_types.h"
#include <string>
#include <vector>

// Ensure the output directory (sdmc:/3ds/crip) exists.
void ensureOutDir();

// Save one certificate as PEM.  File: sdmc:/3ds/crip/<host>_<idx+1>.pem
bool savePEM(const CertInfo& cert, const std::string& host, int idx);

// Save one certificate as DER.  File: sdmc:/3ds/crip/<host>_<idx+1>.der
bool saveDER(const CertInfo& cert, const std::string& host, int idx);

// Save every certificate in the chain as PEM.
// Returns the number of files successfully written.
int saveChainPEM(const std::vector<CertInfo>& certs, const std::string& host);
