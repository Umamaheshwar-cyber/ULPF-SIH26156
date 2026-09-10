# ULPF – Test Report

## 1. Project

**Project:** Universal Log Pre-processing Framework  
**Problem Statement:** SIH26156  
**Sponsor:** NTRO  
**Track:** Software  
**Theme:** Blockchain & Cybersecurity  

---

## 2. Testing Objective

The objective of testing is to verify that ULPF can safely ingest heterogeneous logs, automatically detect their formats, parse and normalize them into a common event schema, preserve the original raw log, and maintain traceability.

---

## 3. Functional Testing

| Test Case | Expected Result | Status |
|---|---|---|
| JSON log processing | JSON detected and normalized | PASS |
| CEF log processing | CEF detected and normalized | PASS |
| Syslog processing | Syslog detected and normalized | PASS |
| Key-Value processing | Key-Value detected and normalized | PASS |
| Unknown format | Raw log preserved using fallback parser | PASS |
| Malformed JSON | Request does not crash; raw log preserved | PASS |
| File upload | Log file successfully ingested | PASS |
| Multiple log processing | Multiple events processed in one request | PASS |
| Search and filtering | Events can be searched and filtered | PASS |
| JSON export | Filtered events exported as JSON | PASS |
| CSV export | Events exported as CSV | PASS |
| Raw preservation | Original raw log retained | PASS |
| Traceability | Trace ID connects processed event to raw log | PASS |
| Dashboard statistics | Format and severity statistics displayed | PASS |

---

## 4. Security and Validation Testing

| Test Case | Expected Result | Status |
|---|---|---|
| Invalid source type | Request rejected safely | PASS |
| Empty log array | Request rejected safely | PASS |
| Oversized request | Request rejected with size limit | PASS |
| More than 1000 logs | Request rejected safely | PASS |
| Unknown log format | Raw content preserved without crash | PASS |
| Malformed JSON | Parser failure handled safely | PASS |
| Large individual log | Size protection implemented | IMPLEMENTED |
| Unexpected fields | Preserved through additional fields | PASS |

---

## 5. API Verification

### Health API

`GET /api/health`

Result:

```json
{
  "status": "ok",
  "service": "ULPF",
  "version": "1.0.0"
}