/*
=========================================================
ULPF PARSER REGISTRY
=========================================================

Purpose:
- Register available log parsers
- Find a parser by name
- List registered parsers
- Support plug-and-play parser onboarding

The core engine should not need to be rewritten
when a new parser is added.
=========================================================
*/

const parserRegistry = new Map();

/*
=========================================================
REGISTER PARSER
=========================================================
*/
function registerParser(parser) {
  if (!parser || typeof parser !== "object") {
    throw new Error("Parser must be an object.");
  }

  if (!parser.name) {
    throw new Error("Parser name is required.");
  }

  if (typeof parser.detect !== "function") {
    throw new Error(`Parser "${parser.name}" must provide detect().`);
  }

  if (typeof parser.parse !== "function") {
    throw new Error(`Parser "${parser.name}" must provide parse().`);
  }

  parserRegistry.set(parser.name, parser);

  return parser;
}

/*
=========================================================
GET PARSER
=========================================================
*/
function getParser(name) {
  return parserRegistry.get(name) || null;
}

/*
=========================================================
FIND PARSER
=========================================================
Finds the first parser that detects the log.
=========================================================
*/
function findParser(rawLog) {
  for (const parser of parserRegistry.values()) {
    try {
      if (parser.detect(rawLog)) {
        return parser;
      }
    } catch (error) {
      // Ignore parser detection errors and continue.
    }
  }

  return null;
}

/*
=========================================================
LIST PARSERS
=========================================================
*/
function listParsers() {
  return Array.from(parserRegistry.values()).map(parser => ({
    name: parser.name,
    description: parser.description || "",
    version: parser.version || "1.0.0"
  }));
}

/*
=========================================================
REGISTRY SIZE
=========================================================
*/
function parserCount() {
  return parserRegistry.size;
}

module.exports = {
  registerParser,
  getParser,
  findParser,
  listParsers,
  parserCount
};