/*
=========================================================
ULPF AI-ASSISTED UNKNOWN LOG ANALYZER
Offline / Air-Gapped Parser Suggestion Engine
=========================================================

Purpose:
- Assist with unknown/custom log formats
- Suggest likely field mappings
- Never modifies the original raw log
- Does not replace deterministic parsers
- Works without cloud APIs or internet
=========================================================
*/

function analyzeUnknownLog(rawLog) {
  const raw = String(rawLog ?? "").trim();

  const suggestions = {};
  const detectedFields = [];
  const evidence = [];

  if (!raw) {
    return {
      assisted: false,
      confidence: 0,
      interpretation: "Empty log",
      suggested_format: "Unknown",
      suggested_fields: {},
      evidence: []
    };
  }

  /*
  =======================================================
  FIELD DETECTION RULES
  =======================================================
  */

  const fieldPatterns = [
    {
      field: "timestamp",
      patterns: [
        /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/,
        /\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\b/,
        /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/i
      ]
    },
    {
      field: "source_ip",
      patterns: [
        /\b(?:src(?:_ip|ip|addr)?|source(?:_ip|ip|addr)?)\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})\b/i
      ]
    },
    {
      field: "destination_ip",
      patterns: [
        /\b(?:dst(?:_ip|ip|addr)?|destination(?:_ip|ip|addr)?)\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})\b/i
      ]
    },
    {
      field: "source_port",
      patterns: [
        /\b(?:srcport|src_port|source_port|spt)\s*[=:]\s*(\d+)\b/i
      ]
    },
    {
      field: "destination_port",
      patterns: [
        /\b(?:dstport|dst_port|destination_port|dpt)\s*[=:]\s*(\d+)\b/i
      ]
    },
    {
      field: "username",
      patterns: [
        /\b(?:user|username|account)\s*[=:]\s*["']?([A-Za-z0-9._@-]+)["']?/i
      ]
    },
    {
      field: "hostname",
      patterns: [
        /\b(?:host|hostname)\s*[=:]\s*["']?([A-Za-z0-9._-]+)["']?/i
      ]
    },
    {
      field: "protocol",
      patterns: [
        /\b(?:protocol|proto)\s*[=:]\s*(tcp|udp|icmp|http|https|ssh|dns|ftp)\b/i
      ]
    },
    {
      field: "severity",
      patterns: [
        /\b(?:severity|sev|level)\s*[=:]\s*([A-Za-z0-9_-]+)\b/i
      ]
    },
    {
      field: "action",
      patterns: [
        /\b(?:action|act)\s*[=:]\s*([A-Za-z0-9_-]+)\b/i
      ]
    }
  ];

  /*
  =======================================================
  EXTRACT FIELD EVIDENCE
  =======================================================
  */

  for (const rule of fieldPatterns) {
    for (const pattern of rule.patterns) {
      const match = raw.match(pattern);

      if (match) {
        detectedFields.push(rule.field);

        suggestions[rule.field] =
          match[1] || match[0];

        evidence.push(
          `${rule.field} detected from log pattern`
        );

        break;
      }
    }
  }

  /*
  =======================================================
  EVENT TYPE INFERENCE
  =======================================================
  */

  let eventType = "generic";

  if (
    /\b(failed|failure|denied|blocked|invalid|unauthorized)\b/i.test(raw)
  ) {
    eventType = "security_failure";

    evidence.push(
      "Security failure indicators detected"
    );
  } else if (
    /\b(success|successful|accepted|allow|allowed|login_success)\b/i.test(raw)
  ) {
    eventType = "security_success";

    evidence.push(
      "Successful security action indicators detected"
    );
  } else if (
    /\b(login|authentication|auth)\b/i.test(raw)
  ) {
    eventType = "authentication_event";

    evidence.push(
      "Authentication-related indicators detected"
    );
  } else if (
    /\b(connection|connect|network|packet|traffic)\b/i.test(raw)
  ) {
    eventType = "network_event";

    evidence.push(
      "Network activity indicators detected"
    );
  }

  suggestions.event_type = eventType;

  /*
  =======================================================
  FORMAT SUGGESTION
  =======================================================
  */

  let suggestedFormat = "Custom / Unknown";

  if (
    /\b[A-Za-z_][A-Za-z0-9_.-]*=(?:"[^"]*"|'[^']*'|[^\s]+)/.test(raw)
  ) {
    suggestedFormat = "Key-Value-like";
    evidence.push(
      "Key-value field pattern detected"
    );
  } else if (
    raw.includes(",") &&
    raw.includes("\n")
  ) {
    suggestedFormat = "CSV-like";
    evidence.push(
      "Comma-separated multi-line structure detected"
    );
  } else if (
    /^\S+\s+\S+\s+.+/.test(raw)
  ) {
    suggestedFormat = "Structured text";
    evidence.push(
      "Structured token-based log pattern detected"
    );
  }

  /*
  =======================================================
  CONFIDENCE
  =======================================================
  */

  let confidence = 25;

  confidence +=
    Math.min(detectedFields.length * 8, 48);

  if (eventType !== "generic") {
    confidence += 12;
  }

  if (suggestedFormat !== "Custom / Unknown") {
    confidence += 10;
  }

  confidence = Math.min(confidence, 95);

  /*
  =======================================================
  INTERPRETATION
  =======================================================
  */

  let interpretation =
    "Custom log detected. AI-assisted field mapping is suggested.";

  if (eventType === "security_failure") {
    interpretation =
      "Possible security failure or denied activity detected.";
  } else if (eventType === "security_success") {
    interpretation =
      "Possible successful security activity detected.";
  } else if (eventType === "authentication_event") {
    interpretation =
      "Possible authentication-related activity detected.";
  } else if (eventType === "network_event") {
    interpretation =
      "Possible network activity detected.";
  }

  /*
  =======================================================
  RETURN AI-ASSISTED RESULT
  =======================================================
  */

  return {
    assisted: true,
    engine: "ULPF Offline AI-Assisted Analyzer",
    confidence,
    interpretation,
    suggested_format: suggestedFormat,
    suggested_event_type: eventType,
    suggested_fields: suggestions,
    detected_fields: detectedFields,
    evidence,
    raw_preserved: true
  };
}

module.exports = {
  analyzeUnknownLog
};