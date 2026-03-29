# 🔒 Certificate Ripper

A Nintendo 3DS homebrew application that extracts TLS server certificates directly
from your 3DS device. Inspired by [Hakky54/certificate-ripper](https://github.com/Hakky54/certificate-ripper).

---

## Features

- Connect to any HTTPS host and extract its full certificate chain
- Display subject, issuer, validity dates, public key, serial number and SHA-256 fingerprint
- Export certificates in multiple formats:
  - **PEM** – single certificate (`.pem`)
  - **DER** – single certificate (`.der`)
  - **Chain PEM** – all certificates in the chain as individual `.pem` files
  - **PKCS12 / truststore** – all certificates accumulated into a single `truststore.p12` (password: `changeit`)
- The `truststore.p12` is a cumulative store: each save adds new certificates and deduplicates by SHA-256 fingerprint
- Only `https://` scheme is supported

---

## Installation

1. Copy `3ds-certificate-ripper.3dsx` to your SD card:

   ```
   SD:/3ds/3ds-certificate-ripper/3ds-certificate-ripper.3dsx
   ```

2. Launch via the **Homebrew Launcher** on your 3DS.

---

## Usage

| Button | Action |
|--------|--------|
| **A** | Enter a host (keyboard opens pre-filled with `https://`) |
| **B** | Save current certificate as PEM |
| **Y** | Save current certificate as DER |
| **X** | Save full chain as PEM files |
| **SELECT** | Save all certs to `truststore.p12` |
| **L / R** | Navigate previous / next certificate in the chain |
| **↑ / ↓** | Scroll certificate details |
| **START** | Exit |

### Output location

All files are saved to `sdmc:/3ds/crip/`:

```
SD:/3ds/crip/
├── <host>_1.pem          # single cert PEM
├── <host>_1.der          # single cert DER
├── truststore.p12        # cumulative PKCS12 truststore
└── certs/                # internal cert store (one .der per unique cert)
```

### Using truststore.p12 with Java

```bash
keytool -list -keystore truststore.p12 -storetype PKCS12 -storepass changeit
```

---

## Building from source

### Prerequisites

- [devkitPro](https://devkitpro.org/wiki/Getting_Started) with **devkitARM**
- 3DS libraries: `3ds-mbedtls`, `3ds-citro2d`, `3ds-libctru`

Install via pacman:

```bash
dkp-pacman -S 3ds-dev 3ds-mbedtls 3ds-citro2d
```

### Build

```bash
make
```

The build produces:

```
3ds-certificate-ripper.3dsx   # homebrew executable
3ds-certificate-ripper.smdh   # icon + metadata
3ds-certificate-ripper.elf    # debug ELF
```

### Clean

```bash
make clean      # remove build artefacts
```

---

## Technical details

- **TLS**: raw POSIX sockets + [mbedTLS](https://github.com/Mbed-TLS/mbedtls) (verification disabled so even self-signed/expired certs are captured)
- **PKCS12**: hand-built RFC 7292 PFX using mbedTLS ASN.1 primitives, SHA-256 MAC, 10 000 iterations
- **UI**: [citro2d](https://github.com/devkitPro/citro2d) with the system font
- **Platform**: ARMv6K, tested on Nintendo 3DS / New 3DS

---

## License

Apache 2.0
