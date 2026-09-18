# Trinetra AI — Database

AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform (SIH26106)

## File

Single file: `trinetra_database_complete.sql`

This is the ONLY database file for this project. It replaces all earlier
versions (schema.sql, seed.sql, queries.sql, the SQLite .db file, and the
separate evidence_package migration) — do not use any of those alongside
this one.

**Engine:** PostgreSQL 16+
**Contains:**
- Full schema — 8 tables total: `cases`, `header_analysis`, `nlp_analysis`,
  `url_findings`, `attachment_findings`, `geolocation`, `evidence_package`,
  `case_correlation`
- One convenience view: `case_full_view` (joins everything for a case into
  one row — use this for the dashboard/report endpoints instead of writing
  the join yourself)
- 3 verified demo/seed cases spanning the full risk spectrum: **Safe**,
  **Suspicious**, **Critical**

## Why one file

Two database files in the repo is how someone loads the stale one on demo
day. If you need to change the schema, edit this file directly and note
the change at the bottom of this README — don't create a second file.

## Setup

```bash
# 1. Create the database (only needed once per machine)
createdb trinetra_ai

# 2. Load the schema + seed data
psql -d trinetra_ai -f trinetra_database_complete.sql
```

If you need to start over from a clean slate:

```bash
dropdb trinetra_ai
createdb trinetra_ai
psql -d trinetra_ai -f trinetra_database_complete.sql
```

## Connecting from the app

The backend does NOT read this `.sql` file directly at runtime — it connects
to the running PostgreSQL database via a connection string. Every teammate
should use the same database name (`trinetra_ai`) locally, and set this in
their own `.env` file (never commit `.env`):

```
DATABASE_URL=postgresql://username:password@localhost:5432/trinetra_ai
```

## Schema overview

| Table | Purpose | Relationship to `cases` |
|---|---|---|
| `cases` | Central record — one row per analyzed email | — |
| `header_analysis` | Layer 1: SPF/DKIM/DMARC, sender/reply-to anomalies | one-to-one |
| `nlp_analysis` | Initial content-pass NLP scores | one-to-one |
| `url_findings` | URL reputation results | many-to-one |
| `attachment_findings` | Attachment hash/reputation results | many-to-one |
| `geolocation` | Origin IP, country/city, VPN/TOR flags | one-to-one |
| `evidence_package` | Layer 1 + Layer 2 + Layer 3 breakdown (the Trinetra 3-layer engine's final reasoning) | one-to-one |
| `case_correlation` | Links cases sharing an indicator (campaign/attribution view) | many-to-many (self-referencing) |

## Demo seed cases

| Case | Subject | risk_score | classification | Notes |
|---|---|---|---|---|
| `11111111-...` | Class schedule update | 0 | Safe | Clean auth, no flagged signals |
| `22222222-...` | Urgent account verification required | 92 | Critical | Failed SPF/DKIM/DMARC, malicious+lookalike URL, VPN origin, flagged attachment |
| `33333333-...` | Payment request | 48 | Suspicious | SPF fail + Reply-To anomaly, moderately elevated content, lookalike URL |

All `risk_score`/`classification`/`evidence_package` values for these three
cases were verified by actually running their header/NLP/URL/geo data
through the real pipeline code (`compute_layer1_score`, `compute_layer2_score`,
`synthesize_forensic_reasoning`, `fuse_risk`) — they are not hand-picked
numbers, so they'll match what the live system produces for equivalent input.

`case_correlation` links Case 2 and Case 3 via a shared domain, to
demonstrate the campaign-attribution view.

## Useful queries

Full breakdown for a case:
```sql
SELECT * FROM case_full_view WHERE case_id = '22222222-2222-2222-2222-222222222222';
```

All cases above a risk threshold:
```sql
SELECT subject, risk_score, classification FROM cases WHERE risk_score >= 70 ORDER BY risk_score DESC;
```

Cases linked to a given case (campaign view):
```sql
SELECT ca.subject, cb.subject, cor.shared_indicator_type, cor.shared_indicator_value
FROM case_correlation cor
JOIN cases ca ON ca.case_id = cor.case_id_a
JOIN cases cb ON cb.case_id = cor.case_id_b
WHERE cor.case_id_a = '22222222-2222-2222-2222-222222222222'
   OR cor.case_id_b = '22222222-2222-2222-2222-222222222222';
```

## Known-good test coverage

This file has been loaded into a fresh PostgreSQL 16 instance and verified to:
- Load with zero errors (all tables, constraints, indexes, seed inserts)
- Correctly reject invalid data via CHECK constraints (out-of-range scores,
  invalid classification/enum values)
- Correctly CASCADE delete dependent rows (header_analysis, nlp_analysis,
  url_findings, attachment_findings, geolocation, evidence_package) when a
  case is deleted
- Correctly enforce UNIQUE(case_id) on all one-to-one tables

## Change log

- Consolidated schema.sql + seed.sql + queries.sql + evidence_package
  migration into this single file
- Added `evidence_package` table and `case_full_view` for the Trinetra
  3-layer risk engine
- Fixed seed data for Case 3 so its stored `risk_score`/`classification`
  match what the real pipeline code computes from its own header/NLP/URL
  data (previously an illustrative/hand-picked value)
