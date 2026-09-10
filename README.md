# ULPF — Universal Log Pre-processing Framework

**SIH26156 | Universal Log Pre-processing Framework**

ULPF is a cybersecurity log pre-processing framework designed to ingest heterogeneous logs, automatically detect their formats, parse them, normalize them into a common schema, preserve the original raw logs, and maintain traceability between raw and normalized events.

It is designed as a **pre-processing layer** that can prepare security logs for downstream SIEM, data-lake, analytics, and AI/ML systems.

---

## 1. Problem Statement

Modern enterprises generate security logs from many different sources such as:

- Firewalls
- Servers
- Network devices
- Applications
- Authentication systems
- Security appliances
- Cloud and infrastructure components

These logs commonly use different formats and field names.

ULPF addresses this problem by providing a unified processing pipeline:

```text
Heterogeneous Logs
        ↓
     Ingest
        ↓
Format Detection
        ↓
      Parse
        ↓
Field Extraction
        ↓
Normalization
        ↓
Universal Event Schema
        ↓
Raw Log Preservation
        ↓
Traceability
        ↓
Search / Export / Analytics