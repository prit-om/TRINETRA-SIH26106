# TRINETRA REST API Reference

The backend exposes a high-performance RESTful API built on **FastAPI**.
Interactive Swagger documentation is available at `http://127.0.0.1:8000/docs`.

---

## Endpoints

### 1. Ingestion & Analysis
- **`POST /analyze`**
  - **Payload**: `multipart/form-data` with either:
    - `file`: Uploaded `.eml`, `.msg`, or `.txt` file
    - `raw_text`: Direct RFC 5322 MIME string
  - **Response**: Full normalized forensic intelligence report containing:
    - `case_id`: Unique forensic case identifier (UUID)
    - `risk_score`: Calibrated 0–100 threat score
    - `classification`: `SAFE` | `LOW RISK` | `SUSPICIOUS` | `CRITICAL`
    - `header_analysis`: SPF, DKIM, DMARC validation
    - `relay_forensics`: Hop-0 origin IP, intermediate hops, time drift
    - `geolocation`: MaxMind GeoLite2 coordinates, ASN, country, city
    - `nlp_analysis`: 6-vector behavioral threat scoring & model reasoning
    - `evidence_package`: 3-layer scores (Deterministic, Intelligence, AI)
    - `graph`: IOC nodes and relationship edges for Neo4j / Cytoscape

### 2. Case Management
- **`GET /cases`**
  - Returns list of all stored historical cases with timestamps, sender, subject, and scores.
- **`GET /cases/{case_id}`**
  - Retrieves the full cached evidence and analysis envelope for a given case.
- **`GET /cases/{case_id}/verify`**
  - Recomputes the SHA-256 seal against stored raw bytes to prove evidence integrity.
- **`GET /cases/{case_id}/report`**
  - Streams a binary PDF containing the court-admissible Section 63 BSA 2023 Forensic Dossier.

### 3. Live Mailbox Monitoring
- **`POST /monitor/start`**: Starts background IMAP polling worker.
- **`POST /monitor/stop`**: Stops the running IMAP monitor.
- **`GET /monitor/status`**: Returns current polling status and processed count.
- **`GET /alerts`**: Returns recent high-risk cases flagged by the live monitor.
