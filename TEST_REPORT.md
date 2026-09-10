# ULPF - Test Report

## Universal Log Pre-processing Framework (ULPF)

**SIH Problem Statement:** SIH26156
**Sponsor:** NTRO
**Theme:** Blockchain & Cybersecurity
**Track:** Software

---

# 1. Test Objective

The objective of testing is to verify that ULPF can:

- Accept heterogeneous security logs
- Automatically detect supported log formats
- Parse logs using the parser registry
- Extract common security fields
- Normalize heterogeneous logs into a universal schema
- Preserve the original raw log
- Maintain event traceability
- Validate important fields
- Safely preserve malformed or unknown logs
- Provide offline AI-assisted analysis for unknown logs
- Export normalized events for downstream systems
- Handle batch processing and larger workloads
- Maintain security controls against oversized or malformed input

---

# 2. Test Environment

| Component | Value |
|---|---|
| Operating System | Windows |
| Runtime | Node.js v24.20.0 |
| Package Manager | npm 11.19.0 |
| Backend | Node.js + Express |
| Storage | In-memory |
| Deployment Mode | Local / Air-gapped ready |
| Server | http://localhost:3000 |
| Parser Registry | Enabled |
| Built-in Parsers | 5 |
| AI Assistance | Offline heuristic analyzer |

---

# 3. Parser Registry Testing

ULPF uses a plug-and-play parser registry architecture.

### Registered Parsers

| Parser | Format | Status |
|---|---|---|
| `json-parser` | JSON | PASS |
| `cef-parser` | CEF | PASS |
| `syslog-parser` | Syslog | PASS |
| `keyvalue-parser` | Key=Value | PASS |
| `csv-parser` | CSV | PASS |

### Parser Registry API

Endpoint:

`GET /api/parsers`

Verified result:

- Parser registry enabled
- Parser count: 5
- All five built-in parsers registered successfully

**Result: PASS**

---

# 4. Functional Testing

## 4.1 JSON Log

Tested automatic format detection and normalization.

**Result:**

- Parser: `json-parser`
- Detected format: `JSON`
- Normalization: `normalized`

**Result: PASS**

---

## 4.2 Common Event Format (CEF)

Tested CEF security log processing.

**Result:**

- Parser: `cef-parser`
- Detected format: `CEF`
- Vendor extracted
- Product extracted
- Severity extracted
- Source IP extracted
- Protocol extracted
- Normalization: `normalized`

**Result: PASS**

---

## 4.3 Syslog

Tested RFC5424-style Syslog processing.

**Result:**

- Parser: `syslog-parser`
- Detected format: `SYSLOG`
- Hostname extracted
- Timestamp extracted
- Severity derived from Syslog priority
- Message preserved
- Normalization: `normalized`

**Result: PASS**

---

## 4.4 Key=Value Log

Tested structured key-value security logs.

Example pattern:

`src=10.10.10.7 dst=192.168.1.22 action=DENY severity=5 protocol=TCP`

**Result:**

- Parser: `keyvalue-parser`
- Detected format: `KEYVALUE`
- Source IP extracted
- Action extracted
- Severity extracted
- Protocol extracted
- Normalization: `normalized`

**Result: PASS**

---

## 4.5 CSV Log

Tested CSV header and data-row processing.

**Result:**

- Parser: `csv-parser`
- Detected format: `CSV`
- Timestamp extracted
- Source IP extracted
- Destination IP extracted
- Action extracted
- Severity extracted
- Protocol extracted
- Normalization: `normalized`

**Result: PASS**

---

# 5. Five-Format Automatic Detection Regression Test

A final regression test processed five different formats in a single request using:

`sourceType = auto`

### Verified Output

| Parser | Detected Format | Normalization Status |
|---|---|---|
| `json-parser` | JSON | normalized |
| `cef-parser` | CEF | normalized |
| `syslog-parser` | SYSLOG | normalized |
| `keyvalue-parser` | KEYVALUE | normalized |
| `csv-parser` | CSV | normalized |

**Overall Result: PASS**

---

# 6. Raw Log Preservation

ULPF preserves the original input through the:

`raw_log`

field.

This allows downstream systems and investigators to retain the original evidence even after normalization.

**Result: PASS**

---

# 7. Traceability Testing

Each processed event receives a unique:

`event_id`

and:

`trace_id`

The normalized event also records:

- Parser used
- Detected format
- Processing timestamp
- Normalization status

This provides processing traceability from the original log to the normalized representation.

**Result: PASS**

---

# 8. Universal Schema Testing

Normalized events contain common fields including:

- event_id
- timestamp
- source_type
- vendor
- product
- event_type
- severity
- action
- source_ip
- source_port
- destination_ip
- destination_port
- protocol
- username
- hostname
- message
- raw_log
- parser
- detected_format
- normalization_status
- processing_timestamp
- trace_id
- ai_assistance
- additional_fields

**Result: PASS**

---

# 9. Validation and Security Testing

ULPF performs defensive validation and input protection.

### Tested / Implemented Controls

| Test | Result |
|---|---|
| Invalid source IP validation | PASS |
| Invalid destination IP validation | PASS |
| Invalid port validation | PASS |
| Invalid timestamp validation | PASS |
| Unexpected fields preservation | PASS |
| Empty input handling | PASS |
| Malformed JSON preservation | PASS |
| Oversized log protection | PASS |
| Request payload size protection | PASS |
| Maximum logs per request | PASS |
| Total request log size limit | PASS |

### Input Limits

- Maximum request size: 5 MB
- Maximum individual log size: 512 KB
- Maximum logs per request: 1000
- Maximum total log size per request: 5 MB

Oversized inputs are rejected or safely preserved according to the processing path.

**Result: PASS**

---

# 10. Unknown Log Handling

Unknown formats are not discarded.

ULPF uses:

`fallback-raw-preservation`

when no supported parser is detected.

The original log is preserved and the event is marked:

`unknown-preserved`

This provides safe handling for previously unseen log formats.

**Result: PASS**

---

# 11. Offline AI-Assisted Unknown Log Analysis

ULPF includes an offline heuristic AI-assisted analyzer for unknown logs.

The analyzer can provide:

- Suggested format
- Suggested event type
- Detected fields
- Suggested fields
- Confidence score
- Interpretation
- Evidence
- Raw-log preservation confirmation

### Verified AI Response

Tested with an unknown security-alert style log.

The system successfully returned:

- `assisted: true`
- `engine: ULPF Offline AI-Assisted Analyzer`
- Confidence score
- Suggested format
- Suggested event type
- Detected fields
- Evidence
- `raw_preserved: true`

The implementation is intentionally offline and does not require an external cloud AI service.

**Result: PASS**

---

# 12. API Verification

## Health API

Endpoint:

`GET /api/health`

Verified response:

```json
{
  "status": "ok",
  "service": "ULPF",
  "version": "1.0.0"
}
