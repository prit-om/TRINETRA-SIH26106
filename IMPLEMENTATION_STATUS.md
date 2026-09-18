# Trinetra implementation status

This repository is an incremental update of the supplied Trinetra project; existing parser, forensic, Track-B, dashboard and reporting modules were retained and extended.

## Implemented in this update
- SHA-256 sealing before sanitization, evidence metadata and chain-of-custody event.
- Analyst PII masking with investigator/LEA raw-content access path.
- `.eml`, `.txt`, raw MIME and `.msg` ingestion (MSG via `extract-msg`).
- RFC 5322/MIME parsing and chronological Received-chain reconstruction.
- Relay anomaly and timestamp-drift diagnostics.
- SPF, DKIM, DMARC result + policy/alignment telemetry.
- GeoIP + ASN and optional Team Cymru BGP enrichment.
- URL redirect, VirusTotal URL reputation, lookalike and URL-shortener checks.
- Domain DNS/MX/NS intelligence and punycode detection.
- Optional local transformer scoring hook (`TRINETRA_NLP_MODEL`) with offline fallback.
- Real Track-B processing wired into the existing integration adapter (the former demo stub is removed).
- Local IOC/campaign correlation plus optional Neo4j persistence.
- Case persistence, case history, high-risk alerts and SHA-256 verification endpoint.
- IMAP unseen-message monitoring with automatic case creation and high-risk quarantine copy.
- Existing React UI extended with Live Monitor, relay trace, graph intelligence and evidence-integrity views.

## Production configuration
Set `ANALYST_API_KEY` and `INVESTIGATOR_API_KEY`; configure PostgreSQL/Neo4j in a production deployment and terminate TLS 1.3 at the reverse proxy. The included SQLite store is a zero-setup development fallback.

## Local transformer
To use a local DeBERTa-family classifier, point `TRINETRA_NLP_MODEL` to a locally available Hugging Face sequence-classification model. Keep `TRINETRA_NLP_LOCAL_ONLY=true` for offline operation. The classifier is optional; the deterministic fallback remains available.
