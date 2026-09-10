const express = require("express");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

/*
=========================================================
ULPF SECURITY / RESOURCE LIMITS
=========================================================
*/

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

/*
=========================================================
MIDDLEWARE
=========================================================
*/

app.use(
  express.json({
    limit: MAX_REQUEST_SIZE
  })
);

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/*
=========================================================
IN-MEMORY EVENT STORE
=========================================================
*/

const events = [];

/*
=========================================================
UTILITY
=========================================================
*/

function isoNow() {
  return new Date().toISOString();
}

function generateEventId() {
  return `ULPF-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
}

function generateTraceId() {
  return `TRACE-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

/*
=========================================================
VALIDATION HELPERS
=========================================================
*/

function isValidIPv4(value) {
  if (!value) return true;

  const parts = String(value).trim().split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }

    const number = Number(part);

    return number >= 0 && number <= 255;
  });
}

function isValidPort(value) {
  if (value === undefined || value === null || value === "") {
    return true;
  }

  const text = String(value).trim();

  if (!/^\d+$/.test(text)) {
    return false;
  }

  const port = Number(text);

  return port >= 0 && port <= 65535;
}

function isValidTimestamp(value) {
  if (!value) return true;

  const text = String(value).trim();

  if (!text) {
    return true;
  }

  /*
  ISO-8601 timestamps
  */
  if (
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(text)
  ) {
    return !Number.isNaN(Date.parse(text));
  }

  /*
  Common date/time formats
  */
  if (
    /^\d{4}-\d{2}-\d{2}(?:\s+|\T)\d{2}:\d{2}:\d{2}$/.test(text)
  ) {
    return !Number.isNaN(Date.parse(text));
  }

  /*
  Syslog timestamp:
  Sep 10 10:30:00
  */
  if (
    /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$/.test(text)
  ) {
    return true;
  }

  return false;
}

/*
=========================================================
KEY-VALUE PARSER
=========================================================
*/

function parseKeyValue(text) {
  const out = {};

  const re =
    /([A-Za-z_][A-Za-z0-9_.-]*)=(?:"([^"]*)"|'([^']*)'|([^\s]+))/g;

  let match;

  while ((match = re.exec(text)) !== null) {
    out[match[1]] =
      match[2] ??
      match[3] ??
      match[4];
  }

  return out;
}

/*
=========================================================
SEVERITY NORMALIZATION
=========================================================
*/

function normalizeSeverity(value) {
  const raw =
    String(value ?? "")
      .trim()
      .toLowerCase();

  const severityMap = {
    "0": "critical",
    "1": "high",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "low",
    "6": "info",
    "7": "debug"
  };

  return (
    severityMap[raw] ||
    raw ||
    "info"
  );
}

/*
=========================================================
NORMALIZER
=========================================================
*/

function normalize(raw, sourceType = "auto") {

  const rawText =
    String(raw ?? "").trim();

  let format = "Unknown";
  let parsed = {};
  let parser = "unknown";

  let parseError = "";

  /*
  =======================================================
  JSON
  =======================================================
  */

  if (
    (sourceType === "auto" ||
      sourceType === "json") &&
    rawText.startsWith("{")
  ) {

    try {

      const jsonData =
        JSON.parse(rawText);

      if (
        jsonData &&
        typeof jsonData === "object" &&
        !Array.isArray(jsonData)
      ) {

        parsed = jsonData;
        format = "JSON";
        parser = "json-parser";
      }

    } catch (error) {

      parseError = "Malformed JSON";
      parsed = {};
    }
  }

  /*
  =======================================================
  CEF
  =======================================================
  */

  if (
    !Object.keys(parsed).length &&
    (sourceType === "auto" ||
      sourceType === "cef") &&
    rawText.startsWith("CEF:")
  ) {

    const parts =
      rawText.split("|");

    parsed = {

      device_vendor:
        parts[1] || "",

      device_product:
        parts[2] || "",

      device_version:
        parts[3] || "",

      event_id:
        parts[4] || "",

      event_name:
        parts[5] || "",

      severity:
        parts[6] || ""
    };

    /*
    CEF extension fields
    */

    const extension =
      parts
        .slice(7)
        .join("|");

    Object.assign(
      parsed,
      parseKeyValue(extension)
    );

    format = "CEF";
    parser = "cef-parser";
  }

  /*
  =======================================================
  CSV
  =======================================================
  */

  if (
    !Object.keys(parsed).length &&
    (sourceType === "auto" ||
      sourceType === "csv") &&
    rawText.includes(",") &&
    /\r?\n/.test(rawText)
  ) {

    const lines =
      rawText
        .trim()
        .split(/\r?\n/);

    if (lines.length >= 2) {

      const headers =
        lines[0]
          .split(",")
          .map(
            x => x.trim()
          );

      const values =
        lines[1]
          .split(",")
          .map(
            x => x.trim()
          );

      parsed =
        Object.fromEntries(
          headers.map(
            (header, index) => [
              header,
              values[index] ?? ""
            ]
          )
        );

      format = "CSV";
      parser = "csv-parser";
    }
  }

  /*
  =======================================================
  SYSLOG
  IMPORTANT:
  SYSLOG IS CHECKED BEFORE KEY-VALUE.
  =======================================================
  */

  if (
    !Object.keys(parsed).length &&
    (sourceType === "auto" ||
      sourceType === "syslog")
  ) {

    const match =
      rawText.match(
        /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(\S+)\s+(.*)$/
      );

    if (match) {

      const syslogTime =
        match[1];

      const hostname =
        match[2];

      const message =
        match[3];

      parsed = {

        syslog_time:
          syslogTime,

        hostname:
          hostname,

        message:
          message
      };

      /*
      SSH authentication failure
      */

      if (
        /failed password/i.test(
          message
        )
      ) {

        parsed.event_type =
          "authentication_failure";

        parsed.action =
          "failed_login";

        const userMatch =
          message.match(
            /for\s+(?:invalid user\s+)?(\S+)/i
          );

        if (userMatch) {

          parsed.username =
            userMatch[1];
        }

        parsed.severity =
          "high";
      }

      /*
      SSH authentication success
      */

      else if (
        /accepted password/i.test(
          message
        )
      ) {

        parsed.event_type =
          "authentication_success";

        parsed.action =
          "login_success";

        const userMatch =
          message.match(
            /for\s+(\S+)/i
          );

        if (userMatch) {

          parsed.username =
            userMatch[1];
        }

        parsed.severity =
          "info";
      }

      /*
      Generic Syslog
      */

      else {

        parsed.event_type =
          "system_event";
      }

      format = "Syslog";
      parser = "syslog-parser";
    }
  }

  /*
  =======================================================
  KEY-VALUE
  =======================================================
  */

  if (
    !Object.keys(parsed).length &&
    (sourceType === "auto" ||
      sourceType === "keyvalue")
  ) {

    const kv =
      parseKeyValue(rawText);

    if (
      Object.keys(kv).length
    ) {

      parsed = kv;

      format = "Key-Value";
      parser = "keyvalue-parser";
    }
  }

  /*
  =======================================================
  UNKNOWN / RAW PRESERVATION
  =======================================================
  */

  if (
    !Object.keys(parsed).length
  ) {

    parsed = {
      message: rawText
    };

    format = "Unknown";
    parser =
      "fallback-raw-preservation";
  }

  /*
  =======================================================
  FIELD GETTER
  =======================================================
  */

  const get = (...keys) => {

    for (const key of keys) {

      if (
        parsed[key] !== undefined &&
        parsed[key] !== null &&
        parsed[key] !== ""
      ) {

        return parsed[key];
      }
    }

    return "";
  };

  /*
  =======================================================
  SEVERITY
  =======================================================
  */

  const severity =
    normalizeSeverity(
      get(
        "severity",
        "sev",
        "level"
      )
    );

  /*
  =======================================================
  EVENT TYPE
  =======================================================
  */

  const eventType =
    get(
      "event_type",
      "eventType",
      "eventName",
      "event_name",
      "action"
    ) || "generic";

  /*
  =======================================================
  SOURCE TYPE
  =======================================================
  */

  let sourceTypeValue =
    get(
      "source_type",
      "device_type",
      "type"
    );

  if (!sourceTypeValue) {

    if (format === "Syslog") {

      sourceTypeValue =
        "system/server";

    } else {

      sourceTypeValue =
        "network/perimeter";
    }
  }

  /*
  =======================================================
  VALIDATION
  =======================================================
  */

  const sourceIp =
    get(
      "source_ip",
      "src_ip",
      "src",
      "srcaddr",
      "srcip"
    ) || "";

  const sourcePort =
    get(
      "source_port",
      "src_port",
      "srcport",
      "spt"
    ) || "";

  const destinationIp =
    get(
      "destination_ip",
      "dst_ip",
      "dst",
      "dstaddr",
      "dstip"
    ) || "";

  const destinationPort =
    get(
      "destination_port",
      "dst_port",
      "dstport",
      "dpt"
    ) || "";

  const timestamp =
    get(
      "timestamp",
      "time",
      "date",
      "syslog_time"
    ) || "";

  const validationWarnings = [];

  if (
    sourceIp &&
    !isValidIPv4(sourceIp)
  ) {
    validationWarnings.push(
      "Invalid source IP address"
    );
  }

  if (
    destinationIp &&
    !isValidIPv4(destinationIp)
  ) {
    validationWarnings.push(
      "Invalid destination IP address"
    );
  }

  if (
    sourcePort &&
    !isValidPort(sourcePort)
  ) {
    validationWarnings.push(
      "Invalid source port"
    );
  }

  if (
    destinationPort &&
    !isValidPort(destinationPort)
  ) {
    validationWarnings.push(
      "Invalid destination port"
    );
  }

  if (
    timestamp &&
    !isValidTimestamp(timestamp)
  ) {
    validationWarnings.push(
      "Invalid timestamp format"
    );
  }

  /*
  =======================================================
  NORMALIZATION STATUS
  =======================================================
  */

  let normalizationStatus =
    "normalized";

  if (
    format === "Unknown" &&
    parseError
  ) {

    normalizationStatus =
      "malformed-preserved";

  } else if (
    format === "Unknown"
  ) {

    normalizationStatus =
      "unknown-preserved";

  } else if (
    validationWarnings.length
  ) {

    normalizationStatus =
      "normalized-with-validation-warnings";
  }

  /*
  =======================================================
  ADDITIONAL FIELDS
  =======================================================
  */

  const additionalFields = {
    ...parsed
  };

  if (parseError) {

    additionalFields.parse_error =
      parseError;
  }

  if (
    validationWarnings.length
  ) {

    additionalFields.validation_warnings =
      validationWarnings;
  }

  /*
  =======================================================
  UNIVERSAL EVENT
  =======================================================
  */

  const event = {

    event_id:
      generateEventId(),

    timestamp:
      timestamp || isoNow(),

    source_type:
      sourceTypeValue,

    vendor:
      get(
        "vendor",
        "device_vendor",
        "manufacturer"
      ) || "Unknown",

    product:
      get(
        "product",
        "device_product",
        "device"
      ) || "Unknown",

    event_type:
      eventType,

    severity:
      severity,

    action:
      get(
        "action",
        "act",
        "event_action"
      ) || "",

    source_ip:
      sourceIp,

    source_port:
      sourcePort,

    destination_ip:
      destinationIp,

    destination_port:
      destinationPort,

    protocol:
      get(
        "protocol",
        "proto"
      ) || "",

    username:
      get(
        "username",
        "user",
        "account"
      ) || "",

    hostname:
      get(
        "hostname",
        "host"
      ) || "",

    message:
      get(
        "message",
        "msg"
      ) || rawText,

    /*
    Original raw log is ALWAYS preserved.
    */

    raw_log:
      rawText,

    parser:
      parser,

    detected_format:
      format,

    normalization_status:
      normalizationStatus,

    processing_timestamp:
      isoNow(),

    trace_id:
      generateTraceId(),

    additional_fields:
      additionalFields
  };

  return event;
}

/*
=========================================================
HEALTH API
=========================================================
*/

app.get(
  "/api/health",
  (_, res) => {

    res.json({

      status: "ok",

      service: "ULPF",

      version: "1.0.0",

      uptime:
        Math.floor(
          process.uptime()
        )
    });
  }
);

/*
=========================================================
EVENTS API
=========================================================
*/

app.get(
  "/api/events",
  (_, res) => {

    res.json({

      count:
        events.length,

      events:
        events
          .slice()
          .reverse()
    });
  }
);

/*
=========================================================
PROCESS API
=========================================================
*/

app.post(
  "/api/process",
  (req, res) => {

    /*
    Validate request body
    */

    if (
      !req.body ||
      typeof req.body !== "object" ||
      Array.isArray(req.body)
    ) {

      return res.status(400).json({

        error:
          "Request body must be a JSON object."
      });
    }

    /*
    Source type
    */

    const sourceType =
      req.body.sourceType ||
      "auto";

    if (
      !ALLOWED_SOURCE_TYPES.includes(
        sourceType
      )
    ) {

      return res.status(400).json({

        error:
          "Invalid sourceType.",

        allowed:
          ALLOWED_SOURCE_TYPES
      });
    }

    /*
    Accept either:
      { "log": "..." }

    or:
      { "logs": ["...", "..."] }
    */

    let logs;

    if (
      Array.isArray(
        req.body.logs
      )
    ) {

      logs =
        req.body.logs;

    } else if (
      typeof req.body.log ===
      "string"
    ) {

      logs = [
        req.body.log
      ];

    } else {

      return res.status(400).json({

        error:
          "Provide a log string or logs array."
      });
    }

    /*
    Maximum number of logs
    */

    if (
      logs.length >
      MAX_LOGS_PER_REQUEST
    ) {

      return res.status(400).json({

        error:
          `Too many logs. Maximum allowed is ${MAX_LOGS_PER_REQUEST}.`
      });
    }

    /*
    Validate individual logs
    */

    let totalSize = 0;

    const clean = [];

    for (
      const log of logs
    ) {

      if (
        typeof log !==
        "string"
      ) {

        return res.status(400).json({

          error:
            "Every log must be a string."
        });
      }

      const trimmed =
        log.trim();

      /*
      Ignore empty logs
      */

      if (!trimmed) {
        continue;
      }

      const size =
        Buffer.byteLength(
          trimmed,
          "utf8"
        );

      /*
      Individual size limit
      */

      if (
        size >
        MAX_LOG_SIZE
      ) {

        return res.status(413).json({

          error:
            "A log exceeds the 512 KB maximum size."
        });
      }

      totalSize += size;

      /*
      Total request log limit
      */

      if (
        totalSize >
        MAX_TOTAL_LOG_SIZE
      ) {

        return res.status(413).json({

          error:
            "Total log size exceeds the 5 MB limit."
        });
      }

      clean.push(
        trimmed
      );
    }

    /*
    No usable logs
    */

    if (
      clean.length === 0
    ) {

      return res.status(400).json({

        error:
          "No non-empty logs were provided."
      });
    }

    /*
    Process independently.
    One unexpected parser failure should not
    terminate the complete request.
    */

    const processed = [];

    for (
      const raw of clean
    ) {

      try {

        const event =
          normalize(
            raw,
            sourceType
          );

        events.push(
          event
        );

        processed.push(
          event
        );

      } catch (error) {

        /*
        Defensive fallback.
        Original raw log is still preserved.
        */

        const fallbackEvent = {

          event_id:
            generateEventId(),

          timestamp:
            isoNow(),

          source_type:
            "network/perimeter",

          vendor:
            "Unknown",

          product:
            "Unknown",

          event_type:
            "processing_error",

          severity:
            "info",

          action:
            "",

          source_ip:
            "",

          source_port:
            "",

          destination_ip:
            "",

          destination_port:
            "",

          protocol:
            "",

          username:
            "",

          hostname:
            "",

          message:
            raw,

          raw_log:
            raw,

          parser:
            "processing-error-preserved",

          detected_format:
            "Unknown",

          normalization_status:
            "processing-error-preserved",

          processing_timestamp:
            isoNow(),

          trace_id:
            generateTraceId(),

          additional_fields: {

            error:
              "Parser processing failed."
          }
        };

        events.push(
          fallbackEvent
        );

        processed.push(
          fallbackEvent
        );
      }
    }

    /*
    Response
    */

    res.json({

      count:
        processed.length,

      events:
        processed
    });
  }
);

/*
=========================================================
CLEAR EVENTS
=========================================================
*/

app.delete(
  "/api/events",
  (_, res) => {

    events.length = 0;

    res.json({

      status:
        "cleared"
    });
  }
);

/*
=========================================================
STATISTICS
=========================================================
*/

app.get(
  "/api/stats",
  (_, res) => {

    const byFormat = {};
    const bySeverity = {};

    for (
      const event of events
    ) {

      const format =
        event.detected_format ||
        "Unknown";

      const severity =
        event.severity ||
        "info";

      byFormat[format] =
        (byFormat[format] || 0) +
        1;

      bySeverity[severity] =
        (bySeverity[severity] || 0) +
        1;
    }

    res.json({

      total:
        events.length,

      byFormat:
        byFormat,

      bySeverity:
        bySeverity
    });
  }
);

/*
=========================================================
ERROR HANDLING
=========================================================
*/

/*
Malformed JSON request
*/

app.use(
  (err, req, res, next) => {

    if (
      err &&
      err.type ===
      "entity.parse.failed"
    ) {

      return res.status(400).json({

        error:
          "Malformed JSON request body."
      });
    }

    /*
    Request too large
    */

    if (
      err &&
      err.type ===
      "entity.too.large"
    ) {

      return res.status(413).json({

        error:
          "Request body exceeds the 5 MB limit."
      });
    }

    /*
    Other errors
    */

    if (err) {

      console.error(
        "Request error:",
        err.message
      );

      return res.status(500).json({

        error:
          "Internal server error."
      });
    }

    next();
  }
);

/*
=========================================================
START SERVER
=========================================================
*/

app.listen(
  PORT,
  () => {

    console.log(
      `ULPF running at http://localhost:${PORT}`
    );
  }
);