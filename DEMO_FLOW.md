# ULPF — SIH26156 Demo Flow

## 1. Project Overview

ULPF (Universal Log Pre-processing Framework) is a cybersecurity log pre-processing framework designed to handle heterogeneous logs from different sources and convert them into a common normalized event structure.

The framework focuses on:

- Log ingestion
- Automatic format detection
- Source-specific parsing
- Field extraction
- Normalization
- Raw-log preservation
- Traceability
- Search and filtering
- JSON/CSV export
- Basic analytics

---

## 2. End-to-End Processing Flow

```text
Heterogeneous Logs
        |
        v
     Ingestion
        |
        v
 Automatic Format Detection
        |
        +-----------------------------+
        |             |               |
        v             v               v
       JSON          CEF          Syslog
        |             |               |
        +-------------+---------------+
                      |
                      v
                Parser Engine
                      |
                      v
                Field Extraction
                      |
                      v
              Normalization Engine
                      |
                      v
             Universal Event Schema
                      |
             +--------+--------+
             |                 |
             v                 v
       Raw Log Store       Traceability
             |                 |
             +--------+--------+
                      |
                      v
              Dashboard / Search
                      |
             +--------+--------+
             |                 |
             v                 v
          JSON Export       CSV Export