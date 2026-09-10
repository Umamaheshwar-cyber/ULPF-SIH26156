const express = require("express");
const path = require("path");

const { analyzeUnknownLog } = require("./ai-assist");

const {
  registerParser,
  getParser,
  findParser,
  listParsers,
  parserCount
} = require("./parsers/parser-registry");

require("./parsers/builtin-parsers");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================================================
// SECURITY / INPUT LIMITS
// =========================================================

const MAX_REQUEST_SIZE = "5mb";
const MAX_LOG_SIZE = 512 * 1024;
const MAX_LOGS_PER_REQUEST = 1000;
const MAX_TOTAL_LOG_SIZE = 5 * 1024 * 1024;

const ALLOWED_SOURCE_TYPES = [
  "auto",
  "json",
  "cef",
  "keyvalue",
  "syslog",
  "csv"
];

// =========================================================
// MIDDLEWARE
// =========================================================

app.use(express.json({ limit: MAX_REQUEST_SIZE }));
app.use(express.urlencoded({ extended: false, limit: MAX_REQUEST_SIZE }));

app.use(express.static(path.join(__dirname, "public")));

// =========================================================
// IN-MEMORY EVENT STORE
// =========================================================

const events = [];

// =========================================================
// UTILITY FUNCTIONS
// =========================================================

function isoNow() {
  return new Date().toISOString();
}

function generateEventId() {
  return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function generateTraceId() {
  return `trace-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

// =========================================================
// VALIDATION
// =========================================================

function isValidIPv4(value) {
  if (!value) return true;

  const parts = String(value).split(".");

  if (parts.length !== 4) return false;

  return parts.every(part => {
    if (!/^\d+$/.test(part)) return false;

    const num = Number(part);

    return num >= 0 && num <= 255;
  });
}

function isValidPort(value) {
  if (value === undefined || value === null || value === "") {
    return true;
  }

  const num = Number(value);

  return Number.isInteger(num) && num >= 1 && num <= 65535;
}

function isValidTimestamp(value) {
  if (!value) return true;

  return !Number.isNaN(Date.parse(String(value)));
}

// =========================================================
// NORMALIZATION HELPERS
// =========================================================

function normalizeSeverity(value) {
  if (value === undefined || value === null || value === "") {
    return "unknown";
  }

  const text = String(value).toLowerCase().trim();

  const severityMap = {
    "0": "low",
    "1": "low",
    "2": "low",
    "3": "medium",
    "4": "medium",
    "5": "medium",
    "6": "high",
    "7": "high",
    "8": "critical",
    "9": "critical",
    "10": "critical",

    "info": "informational",
    "informational": "informational",
    "notice": "low",

    "warning": "medium",
    "warn": "medium",

    "error": "high",
    "err": "high",

    "critical": "critical",
    "crit": "critical",

    "fatal": "critical",

    "debug": "low"
  };

  return severityMap[text] || text;
}

function cleanValue(value) {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();

    return trimmed === "" ? null : trimmed;
  }

  return value;
}

function firstValue(data, keys) {
  if (!data || typeof data !== "object") {
    return null;
  }

  for (const key of keys) {
    if (
      Object.prototype.hasOwnProperty.call(data, key) &&
      data[key] !== undefined &&
      data[key] !== null &&
      data[key] !== ""
    ) {
      return cleanValue(data[key]);
    }
  }

  return null;
}

// =========================================================
// PARSER REGISTRY INTEGRATION
// =========================================================

const SOURCE_TO_PARSER = {
  json: "json-parser",
  cef: "cef-parser",
  csv: "csv-parser",
  syslog: "syslog-parser",
  keyvalue: "keyvalue-parser"
};

function selectParser(rawText, sourceType) {
  if (sourceType !== "auto") {
    const parserName = SOURCE_TO_PARSER[sourceType];

    if (!parserName) {
      return null;
    }

    return getParser(parserName);
  }

  return findParser(rawText);
}

function parserResultToData(parserResult) {
  if (parserResult === null || parserResult === undefined) {
    return {};
  }

  if (typeof parserResult === "object") {
    return parserResult;
  }

  return {
    message: String(parserResult)
  };
}

// =========================================================
// AI UNKNOWN LOG ANALYSIS
// =========================================================

function safeAIAnalysis(rawText) {
  try {
    return analyzeUnknownLog(rawText);
  } catch (error) {
    return {
      assisted: false,
      engine: "ULPF Offline AI-Assisted Analyzer",
      confidence: 0,
      interpretation: "AI-assisted analysis unavailable.",
      suggested_format: "Unknown",
      suggested_event_type: "unknown",
      suggested_fields: {},
      detected_fields: [],
      evidence: ["AI analyzer failed safely."],
      raw_preserved: true
    };
  }
}

// =========================================================
// CORE NORMALIZATION ENGINE
// =========================================================

function normalize(rawLog, sourceType = "auto") {
  const rawText = String(rawLog ?? "");

  const processingTimestamp = isoNow();
  const traceId = generateTraceId();

  let parser = null;
  let parsed = {};
  let detectedFormat = "Unknown";
  let parseError = null;
  let aiAssistance = null;

  // -------------------------------------------------------
  // Select parser through registry
  // -------------------------------------------------------

  try {
    parser = selectParser(rawText, sourceType);

    if (parser) {
      detectedFormat = parser.name
        .replace("-parser", "")
        .toUpperCase();

      try {
        parsed = parserResultToData(parser.parse(rawText));
      } catch (error) {
        parseError = error.message || "Parser error";
        parsed = {};
      }
    }
  } catch (error) {
    parseError = error.message || "Parser selection error";
    parser = null;
  }

  // -------------------------------------------------------
  // Unknown / failed parser fallback
  // -------------------------------------------------------

  if (!parser) {
    detectedFormat = "Unknown";

    parsed = {
      message: rawText
    };

    aiAssistance = safeAIAnalysis(rawText);
  } else if (parseError) {
    if (detectedFormat === "JSON" || detectedFormat === "UNKNOWN") {
      aiAssistance = safeAIAnalysis(rawText);
    }
  }

  // -------------------------------------------------------
  // Extract common fields
  // -------------------------------------------------------

  const timestamp =
    firstValue(parsed, [
      "timestamp",
      "@timestamp",
      "time",
      "datetime",
      "date"
    ]) || null;

  const vendor =
    firstValue(parsed, [
      "vendor",
      "device_vendor",
      "deviceVendor"
    ]) || null;

  const product =
    firstValue(parsed, [
      "product",
      "device_product",
      "deviceProduct"
    ]) || null;

  const eventType =
    firstValue(parsed, [
      "event_type",
      "eventType",
      "type",
      "event_name",
      "eventName",
      "name"
    ]) || "generic_event";

  const severity = normalizeSeverity(
    firstValue(parsed, [
      "severity",
      "level",
      "priority",
      "loglevel",
      "log_level"
    ])
  );

  const action =
    firstValue(parsed, [
      "action",
      "activity",
      "operation",
      "verb"
    ]) || null;

  const sourceIP =
    firstValue(parsed, [
      "source_ip",
      "sourceIP",
      "src_ip",
      "src",
      "source"
    ]) || null;

  const sourcePort =
    firstValue(parsed, [
      "source_port",
      "sourcePort",
      "src_port",
      "srcPort"
    ]) || null;

  const destinationIP =
    firstValue(parsed, [
      "destination_ip",
      "destinationIP",
      "dest_ip",
      "dst_ip",
      "destination",
      "dest"
    ]) || null;

  const destinationPort =
    firstValue(parsed, [
      "destination_port",
      "destinationPort",
      "dest_port",
      "dst_port",
      "destPort"
    ]) || null;

  const protocol =
    firstValue(parsed, [
      "protocol",
      "proto"
    ]) || null;

  const username =
    firstValue(parsed, [
      "username",
      "user",
      "user_name",
      "account"
    ]) || null;

  const hostname =
    firstValue(parsed, [
      "hostname",
      "host",
      "device",
      "computer"
    ]) || null;

  const message =
    firstValue(parsed, [
      "message",
      "msg",
      "description",
      "event_message"
    ]) || rawText;

  // -------------------------------------------------------
  // Source type
  // -------------------------------------------------------

  let normalizedSourceType =
    firstValue(parsed, [
      "source_type",
      "sourceType",
      "category",
      "device_type"
    ]);

  if (!normalizedSourceType) {
    if (detectedFormat === "SYSLOG") {
      normalizedSourceType = "system/server";
    } else if (detectedFormat === "CEF") {
      normalizedSourceType = "security/perimeter";
    } else {
      normalizedSourceType = "network/perimeter";
    }
  }

  // -------------------------------------------------------
  // Validation warnings
  // -------------------------------------------------------

  const validationWarnings = [];

  if (sourceIP && !isValidIPv4(sourceIP)) {
    validationWarnings.push("Invalid source IP address.");
  }

  if (destinationIP && !isValidIPv4(destinationIP)) {
    validationWarnings.push("Invalid destination IP address.");
  }

  if (!isValidPort(sourcePort)) {
    validationWarnings.push("Invalid source port.");
  }

  if (!isValidPort(destinationPort)) {
    validationWarnings.push("Invalid destination port.");
  }

  if (timestamp && !isValidTimestamp(timestamp)) {
    validationWarnings.push("Invalid timestamp.");
  }

  // -------------------------------------------------------
  // Normalization status
  // -------------------------------------------------------

  let normalizationStatus = "normalized";

  if (parseError) {
    normalizationStatus = "malformed-preserved";
  } else if (detectedFormat === "Unknown") {
    normalizationStatus = "unknown-preserved";
  } else if (validationWarnings.length > 0) {
    normalizationStatus = "normalized-with-validation-warnings";
  }

  // -------------------------------------------------------
  // Additional fields
  // -------------------------------------------------------

  const knownKeys = new Set([
    "timestamp",
    "@timestamp",
    "time",
    "datetime",
    "date",

    "vendor",
    "device_vendor",
    "deviceVendor",

    "product",
    "device_product",
    "deviceProduct",

    "event_type",
    "eventType",
    "type",
    "event_name",
    "eventName",
    "name",

    "severity",
    "level",
    "priority",
    "loglevel",
    "log_level",

    "action",
    "activity",
    "operation",
    "verb",

    "source_ip",
    "sourceIP",
    "src_ip",
    "src",
    "source",

    "source_port",
    "sourcePort",
    "src_port",
    "srcPort",

    "destination_ip",
    "destinationIP",
    "dest_ip",
    "dst_ip",
    "destination",
    "dest",

    "destination_port",
    "destinationPort",
    "dest_port",
    "dst_port",
    "destPort",

    "protocol",
    "proto",

    "username",
    "user",
    "user_name",
    "account",

    "hostname",
    "host",
    "device",
    "computer",

    "message",
    "msg",
    "description",
    "event_message",

    "source_type",
    "sourceType",
    "category",
    "device_type"
  ]);

  const additionalParsedFields = {};

  if (parsed && typeof parsed === "object") {
    for (const [key, value] of Object.entries(parsed)) {
      if (!knownKeys.has(key)) {
        additionalParsedFields[key] = value;
      }
    }
  }

  const additionalFields = {
    parsed: additionalParsedFields,
    parse_error: parseError,
    validation_warnings: validationWarnings
  };

  // -------------------------------------------------------
  // Universal normalized event
  // -------------------------------------------------------

  return {
    event_id: generateEventId(),

    timestamp:
      timestamp && isValidTimestamp(timestamp)
        ? new Date(timestamp).toISOString()
        : timestamp || processingTimestamp,

    source_type: normalizedSourceType,

    vendor,
    product,

    event_type: eventType,
    severity,

    action,

    source_ip: sourceIP,
    source_port: sourcePort,

    destination_ip: destinationIP,
    destination_port: destinationPort,

    protocol,
    username,
    hostname,

    message,

    // Original log ALWAYS preserved.
    raw_log: rawText,

    // Registry-selected parser.
    parser: parser ? parser.name : "fallback-raw-preservation",

    detected_format: detectedFormat,

    normalization_status: normalizationStatus,

    processing_timestamp: processingTimestamp,

    trace_id: traceId,

    ai_assistance: aiAssistance,

    additional_fields: additionalFields
  };
}

// =========================================================
// HEALTH API
// =========================================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ULPF",
    version: "1.0.0",

    parser_registry: {
      enabled: true,
      parser_count: parserCount()
    },

    ai_assisted_unknown_parsing: "offline-enabled",

    storage: "in-memory",

    uptime_seconds: Math.floor(process.uptime()),

    timestamp: isoNow()
  });
});

// =========================================================
// PARSER REGISTRY API
// =========================================================

app.get("/api/parsers", (req, res) => {
  res.json({
    count: parserCount(),
    parsers: listParsers()
  });
});

// =========================================================
// EVENTS API
// =========================================================

app.get("/api/events", (req, res) => {
  res.json({
    count: events.length,
    events: [...events].reverse()
  });
});

// =========================================================
// PROCESS API
// =========================================================

app.post("/api/process", (req, res) => {
  try {
    const body = req.body || {};

    const sourceType = String(
      body.sourceType || "auto"
    ).toLowerCase();

    if (!ALLOWED_SOURCE_TYPES.includes(sourceType)) {
      return res.status(400).json({
        error: "Invalid sourceType.",
        allowed_source_types: ALLOWED_SOURCE_TYPES
      });
    }

    let logs = [];

    if (Array.isArray(body.logs)) {
      logs = body.logs;
    } else if (typeof body.log === "string") {
      logs = [body.log];
    } else if (typeof body.logs === "string") {
      logs = [body.logs];
    } else {
      return res.status(400).json({
        error: "Provide log or logs."
      });
    }

    if (logs.length > MAX_LOGS_PER_REQUEST) {
      return res.status(413).json({
        error:
          `Maximum ${MAX_LOGS_PER_REQUEST} logs allowed per request.`
      });
    }

    let totalSize = 0;

    const processedEvents = [];

    for (const inputLog of logs) {
      if (typeof inputLog !== "string") {
        continue;
      }

      const rawLog = inputLog;

      if (!rawLog.trim()) {
        continue;
      }

      const logSize = Buffer.byteLength(
        rawLog,
        "utf8"
      );

      if (logSize > MAX_LOG_SIZE) {
        processedEvents.push({
          event_id: generateEventId(),
          timestamp: isoNow(),
          source_type: "unknown",
          vendor: null,
          product: null,
          event_type: "input_rejected",
          severity: "high",
          action: "rejected",

          source_ip: null,
          source_port: null,

          destination_ip: null,
          destination_port: null,

          protocol: null,
          username: null,
          hostname: null,

          message:
            "Log exceeded maximum allowed size.",

          raw_log: rawLog.slice(0, 4096),

          parser: "security-input-limit",
          detected_format: "Rejected",

          normalization_status:
            "input-rejected",

          processing_timestamp: isoNow(),

          trace_id: generateTraceId(),

          ai_assistance: null,

          additional_fields: {
            parse_error:
              "Maximum log size exceeded.",
            validation_warnings: []
          }
        });

        continue;
      }

      totalSize += logSize;

      if (totalSize > MAX_TOTAL_LOG_SIZE) {
        return res.status(413).json({
          error:
            `Total request log size cannot exceed ${MAX_TOTAL_LOG_SIZE} bytes.`
        });
      }

      let event;

      try {
        event = normalize(
          rawLog,
          sourceType
        );
      } catch (error) {
        event = {
          event_id: generateEventId(),

          timestamp: isoNow(),

          source_type: "unknown",

          vendor: null,
          product: null,

          event_type: "processing_error",

          severity: "high",

          action: null,

          source_ip: null,
          source_port: null,

          destination_ip: null,
          destination_port: null,

          protocol: null,

          username: null,
          hostname: null,

          message: rawLog,

          raw_log: rawLog,

          parser:
            "fallback-error-preservation",

          detected_format: "Unknown",

          normalization_status:
            "processing-error-preserved",

          processing_timestamp: isoNow(),

          trace_id: generateTraceId(),

          ai_assistance:
            safeAIAnalysis(rawLog),

          additional_fields: {
            parse_error:
              error.message ||
              "Unknown processing error",

            validation_warnings: []
          }
        };
      }

      events.push(event);
      processedEvents.push(event);
    }

    return res.json({
      success: true,
      processed: processedEvents.length,
      total_events: events.length,
      source_type: sourceType,
      events: processedEvents
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to process logs.",
      message: error.message
    });
  }
});

// =========================================================
// CLEAR EVENTS
// =========================================================

app.delete("/api/events", (req, res) => {
  const previousCount = events.length;

  events.length = 0;

  res.json({
    success: true,
    cleared: previousCount,
    message: "All processed events cleared."
  });
});

// =========================================================
// INTEGRATION-READY EXPORT API
// =========================================================

app.get("/api/export", (req, res) => {
  const format = String(
    req.query.format || "ndjson"
  ).toLowerCase();

  if (!["ndjson", "json"].includes(format)) {
    return res.status(400).json({
      error: "Unsupported export format.",
      supported_formats: [
        "ndjson",
        "json"
      ]
    });
  }

  // Standard JSON export.
  if (format === "json") {
    res.setHeader(
      "Content-Type",
      "application/json"
    );

    res.setHeader(
      "Content-Disposition",
      'attachment; filename="ulpf-events.json"'
    );

    return res.send(
      JSON.stringify(events, null, 2)
    );
  }

  // NDJSON export:
  // One normalized event per line.
  // Suitable for streaming pipelines,
  // SIEM ingestion and data-lake workflows.
  res.setHeader(
    "Content-Type",
    "application/x-ndjson"
  );

  res.setHeader(
    "Content-Disposition",
    'attachment; filename="ulpf-events.ndjson"'
  );

  const ndjson = events
    .map(event => JSON.stringify(event))
    .join("\n");

  return res.send(ndjson);
});

// =========================================================
// STATISTICS API
// =========================================================

app.get("/api/stats", (req, res) => {
  const byFormat = {};
  const bySeverity = {};
  const byParser = {};
  const byNormalizationStatus = {};

  for (const event of events) {
    const format =
      event.detected_format || "Unknown";

    const severity =
      event.severity || "unknown";

    const parser =
      event.parser || "unknown";

    const status =
      event.normalization_status ||
      "unknown";

    byFormat[format] =
      (byFormat[format] || 0) + 1;

    bySeverity[severity] =
      (bySeverity[severity] || 0) + 1;

    byParser[parser] =
      (byParser[parser] || 0) + 1;

    byNormalizationStatus[status] =
      (byNormalizationStatus[status] || 0) + 1;
  }

  res.json({
    total: events.length,

    byFormat,
    bySeverity,
    byParser,
    byNormalizationStatus,

    parser_registry: {
      count: parserCount(),
      parsers: listParsers()
    }
  });
});

// =========================================================
// ROOT ROUTE
// =========================================================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// =========================================================
// ERROR HANDLER
// =========================================================

app.use((error, req, res, next) => {
  if (
    error instanceof SyntaxError &&
    error.status === 400
  ) {
    return res.status(400).json({
      error: "Malformed JSON request."
    });
  }

  if (
    error.type === "entity.too.large" ||
    error.status === 413
  ) {
    return res.status(413).json({
      error: "Request payload is too large."
    });
  }

  console.error(
    "Unhandled server error:",
    error
  );

  return res.status(500).json({
    error: "Internal server error."
  });
});

// =========================================================
// START SERVER
// =========================================================

app.listen(PORT, () => {
  console.log(
    `ULPF running at http://localhost:${PORT}`
  );

  console.log(
    `Parser Registry: ${parserCount()} parsers loaded`
  );
});