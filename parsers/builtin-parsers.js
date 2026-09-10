const { registerParser } = require("./parser-registry");

// ---------------------------------------------------------
// JSON PARSER
// ---------------------------------------------------------
registerParser({
  name: "json-parser",
  description: "Parses structured JSON security logs.",
  version: "1.0.0",

  detect(rawLog) {
    const text = String(rawLog || "").trim();
    return text.startsWith("{") || text.startsWith("[");
  },

  parse(rawLog) {
    const parsed = JSON.parse(String(rawLog).trim());

    if (Array.isArray(parsed)) {
      return {
        message: JSON.stringify(parsed)
      };
    }

    return parsed;
  }
});

// ---------------------------------------------------------
// CEF PARSER
// ---------------------------------------------------------
registerParser({
  name: "cef-parser",
  description: "Parses Common Event Format security logs.",
  version: "1.0.0",

  detect(rawLog) {
    return /^CEF:\d+\|/i.test(String(rawLog || "").trim());
  },

  parse(rawLog) {
    const text = String(rawLog).trim();
    const parts = text.split("|");

    if (parts.length < 7) {
      throw new Error("Malformed CEF log.");
    }

    const extension = parts.slice(7).join("|");

    const result = {
      cef_version: parts[0].replace(/^CEF:/i, ""),
      vendor: parts[1],
      product: parts[2],
      device_version: parts[3],
      signature_id: parts[4],
      event_name: parts[5],
      severity: parts[6]
    };

    const extensionRegex = /([A-Za-z0-9_.-]+)=("[^"]*"|\S+)/g;
    let match;

    while ((match = extensionRegex.exec(extension)) !== null) {
      result[match[1]] = match[2].replace(/^"|"$/g, "");
    }

    return result;
  }
});

// ---------------------------------------------------------
// CSV PARSER
// ---------------------------------------------------------
registerParser({
  name: "csv-parser",
  description: "Parses comma-separated security log records.",
  version: "1.0.0",

  detect(rawLog) {
    const text = String(rawLog || "").trim();

    if (!text.includes(",")) {
      return false;
    }

    const lines = text.split(/\r?\n/).filter(Boolean);

    if (lines.length < 2) {
      return false;
    }

    const header = lines[0].split(",").map(value => value.trim());

    return header.some(field =>
      [
        "timestamp",
        "time",
        "source_ip",
        "src_ip",
        "destination_ip",
        "dst_ip",
        "action",
        "severity",
        "protocol"
      ].includes(field.toLowerCase())
    );
  },

  parse(rawLog) {
    const lines = String(rawLog)
      .trim()
      .split(/\r?\n/)
      .filter(Boolean);

    if (lines.length < 2) {
      throw new Error("CSV requires a header and at least one data row.");
    }

    const headers = lines[0]
      .split(",")
      .map(value => value.trim());

    const values = lines[1]
      .split(",")
      .map(value => value.trim());

    const result = {};

    headers.forEach((header, index) => {
      result[header] = values[index] ?? "";
    });

    return result;
  }
});

// ---------------------------------------------------------
// SYSLOG PARSER
// Supports RFC3164 and RFC5424-style messages
// ---------------------------------------------------------
registerParser({
  name: "syslog-parser",
  description: "Parses RFC3164/RFC5424-style Syslog security logs.",
  version: "1.1.0",

  detect(rawLog) {
    const text = String(rawLog || "").trim();

    // RFC5424:
    // <34>1 2026-09-10T10:30:00Z server sshd - - - message
    if (/^<\d+>\d+\s+\S+\s+\S+\s+\S+/i.test(text)) {
      return true;
    }

    // RFC3164:
    // <34>Sep 10 10:30:00 server sshd: message
    if (/^<\d+>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+/i.test(text)) {
      return true;
    }

    return false;
  },

  parse(rawLog) {
    const text = String(rawLog).trim();

    // -----------------------------
    // RFC5424
    // -----------------------------
    const rfc5424 =
      /^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/i;

    const match5424 = text.match(rfc5424);

    if (match5424) {
      const priority = Number(match5424[1]);
      const facility = Math.floor(priority / 8);
      const severity = priority % 8;

      return {
        priority,
        facility,
        severity,
        syslog_version: match5424[2],
        timestamp: match5424[3],
        hostname: match5424[4],
        app_name: match5424[5],
        process_id: match5424[6],
        message_id: match5424[7],
        message: match5424[8]
      };
    }

    // -----------------------------
    // RFC3164
    // -----------------------------
    const rfc3164 =
      /^<(\d+)>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?::)?\s*(.*)$/i;

    const match3164 = text.match(rfc3164);

    if (match3164) {
      const priority = Number(match3164[1]);
      const facility = Math.floor(priority / 8);
      const severity = priority % 8;

      return {
        priority,
        facility,
        severity,
        timestamp: match3164[2],
        hostname: match3164[3],
        app_name: match3164[4],
        message: match3164[5]
      };
    }

    throw new Error("Malformed Syslog log.");
  }
});

// ---------------------------------------------------------
// KEY=VALUE PARSER
// ---------------------------------------------------------
registerParser({
  name: "keyvalue-parser",
  description: "Parses key=value structured security logs.",
  version: "1.0.0",

  detect(rawLog) {
    const text = String(rawLog || "").trim();

    const matches = text.match(
      /\b[A-Za-z_][A-Za-z0-9_.-]*=(?:"[^"]*"|'[^']*'|\S+)/g
    );

    return Boolean(matches && matches.length >= 2);
  },

  parse(rawLog) {
    const text = String(rawLog).trim();

    const result = {};

    const regex =
      /\b([A-Za-z_][A-Za-z0-9_.-]*)=(?:"([^"]*)"|'([^']*)'|(\S+))/g;

    let match;

    while ((match = regex.exec(text)) !== null) {
      result[match[1]] =
        match[2] ??
        match[3] ??
        match[4] ??
        "";
    }

    if (Object.keys(result).length === 0) {
      throw new Error("No key=value fields detected.");
    }

    return result;
  }
});

console.log("Built-in parser registry initialized with 5 parsers.");