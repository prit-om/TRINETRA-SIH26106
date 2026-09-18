# Section 63 Bharatiya Sakshya Adhiniyam, 2023 (BSA) Compliance Guide

## Background & Statutory Mandate
On July 1, 2024, India replaced the Indian Evidence Act, 1872 with the **Bharatiya Sakshya Adhiniyam, 2023 (BSA)**.
Section 63 of the BSA sets out the statutory requirements for the **admissibility of electronic records** in judicial proceedings, serving as the modernized successor to Section 65B of the legacy Act.

## TRINETRA Forensic Compliance Architecture

### 1. Cryptographic Evidence Sealing (Sub-section 2 & 4)
- **Immediate SHA-256 Hashing**: The exact byte stream of raw RFC 5322 MIME email data is cryptographically hashed at the microsecond of ingestion before any parsing or processing takes place.
- **Dynamic Tamper Re-verification**: On demand, the system recomputes the SHA-256 hash of the stored raw artifact and matches it against the sealed record in the database. Any modification of a single bit triggers a `TAMPER DETECTED` warning.

### 2. Zero-Leak PII Redaction
- To ensure compliance with the **Digital Personal Data Protection Act, 2023 (DPDP Act)**, sensitive personal identifiers:
  - Indian 12-digit Aadhaar numbers
  - Permanent Account Numbers (PAN cards)
  - Mobile numbers & bank account strings
  are masked in analyst-facing UI cards while the original evidence remains sealed in an isolated vault.

### 3. Court-Admissible Electronic Certificate
Under Section 63(4) of the BSA 2023, an electronic record must be accompanied by a certificate signed by a person occupying a responsible official position. TRINETRA's ReportLab PDF engine automatically generates a structured **Section 63 BSA 2023 Certificate of Electronic Evidence** containing:
1. **Device Identification**: Hostname, local operating system, and system timestamp.
2. **Cryptographic Hashes**: SHA-256 evidence seal, Byte length, and MIME integrity hash.
3. **Forensic Examiner Declaration**: Standard statutory wording affirming lawful custody and uncompromised operating condition.
4. **Relay Hop Evidence Table**: Step-by-step RFC 5322 received headers with timestamps and IP addresses.
