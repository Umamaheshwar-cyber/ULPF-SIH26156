# ULPF — System Architecture

## 1. Overview

ULPF (Universal Log Pre-processing Framework) is a cybersecurity log pre-processing framework designed to convert heterogeneous security logs into a common normalized event structure.

The framework focuses on log ingestion, automatic format detection, parsing, field extraction, normalization, raw-log preservation, traceability, validation, search, analytics, and export.

ULPF is a pre-processing layer and is not intended to replace a SIEM.

---

## 2. Architecture Flow

```text
                HETEROGENEOUS LOG SOURCES
                         |
                         v
                  +-------------+
                  | Log Ingest  |
                  +-------------+
                         |
                         v
                  +-------------+
                  |   Format    |
                  |  Detection  |
                  +-------------+
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       JSON             CEF          Syslog
          |              |              |
          +--------------+--------------+
                         |
                         v
                  +-------------+
                  |   Parser    |
                  |   Engine    |
                  +-------------+
                         |
                         v
                  +-------------+
                  |    Field    |
                  |  Extraction |
                  +-------------+
                         |
                         v
                  +-------------+
                  |Normalization|
                  +-------------+
                         |
                         v
              +-----------------------+
              | Universal Event Schema|
              +-----------------------+
                    /            \
                   /              \
                  v                v
        +----------------+  +----------------+
        | Raw Log Store  |  | Traceability   |
        +----------------+  +----------------+
                  \                /
                   \              /
                    v            v
                 +------------------+
                 | Dashboard/Search |
                 | Export/Analytics |
                 +------------------+