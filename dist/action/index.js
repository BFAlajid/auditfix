var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/semver/internal/constants.js
var require_constants = __commonJS({
  "node_modules/semver/internal/constants.js"(exports, module) {
    "use strict";
    var SEMVER_SPEC_VERSION = "2.0.0";
    var MAX_LENGTH = 256;
    var MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER || /* istanbul ignore next */
    9007199254740991;
    var MAX_SAFE_COMPONENT_LENGTH = 16;
    var MAX_SAFE_BUILD_LENGTH = MAX_LENGTH - 6;
    var RELEASE_TYPES = [
      "major",
      "premajor",
      "minor",
      "preminor",
      "patch",
      "prepatch",
      "prerelease"
    ];
    module.exports = {
      MAX_LENGTH,
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_SAFE_INTEGER,
      RELEASE_TYPES,
      SEMVER_SPEC_VERSION,
      FLAG_INCLUDE_PRERELEASE: 1,
      FLAG_LOOSE: 2
    };
  }
});

// node_modules/semver/internal/debug.js
var require_debug = __commonJS({
  "node_modules/semver/internal/debug.js"(exports, module) {
    "use strict";
    var debug2 = typeof process === "object" && process.env && process.env.NODE_DEBUG && /\bsemver\b/i.test(process.env.NODE_DEBUG) ? (...args) => console.error("SEMVER", ...args) : () => {
    };
    module.exports = debug2;
  }
});

// node_modules/semver/internal/re.js
var require_re = __commonJS({
  "node_modules/semver/internal/re.js"(exports, module) {
    "use strict";
    var {
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_LENGTH
    } = require_constants();
    var debug2 = require_debug();
    exports = module.exports = {};
    var re = exports.re = [];
    var safeRe = exports.safeRe = [];
    var src = exports.src = [];
    var safeSrc = exports.safeSrc = [];
    var t = exports.t = {};
    var R = 0;
    var LETTERDASHNUMBER = "[a-zA-Z0-9-]";
    var safeRegexReplacements = [
      ["\\s", 1],
      ["\\d", MAX_LENGTH],
      [LETTERDASHNUMBER, MAX_SAFE_BUILD_LENGTH]
    ];
    var makeSafeRegex = (value) => {
      for (const [token, max] of safeRegexReplacements) {
        value = value.split(`${token}*`).join(`${token}{0,${max}}`).split(`${token}+`).join(`${token}{1,${max}}`);
      }
      return value;
    };
    var createToken = (name, value, isGlobal) => {
      const safe = makeSafeRegex(value);
      const index = R++;
      debug2(name, index, value);
      t[name] = index;
      src[index] = value;
      safeSrc[index] = safe;
      re[index] = new RegExp(value, isGlobal ? "g" : void 0);
      safeRe[index] = new RegExp(safe, isGlobal ? "g" : void 0);
    };
    createToken("NUMERICIDENTIFIER", "0|[1-9]\\d*");
    createToken("NUMERICIDENTIFIERLOOSE", "\\d+");
    createToken("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${LETTERDASHNUMBER}*`);
    createToken("MAINVERSION", `(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})`);
    createToken("MAINVERSIONLOOSE", `(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASEIDENTIFIER", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIER]})`);
    createToken("PRERELEASEIDENTIFIERLOOSE", `(?:${src[t.NONNUMERICIDENTIFIER]}|${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASE", `(?:-(${src[t.PRERELEASEIDENTIFIER]}(?:\\.${src[t.PRERELEASEIDENTIFIER]})*))`);
    createToken("PRERELEASELOOSE", `(?:-?(${src[t.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${src[t.PRERELEASEIDENTIFIERLOOSE]})*))`);
    createToken("BUILDIDENTIFIER", `${LETTERDASHNUMBER}+`);
    createToken("BUILD", `(?:\\+(${src[t.BUILDIDENTIFIER]}(?:\\.${src[t.BUILDIDENTIFIER]})*))`);
    createToken("FULLPLAIN", `v?${src[t.MAINVERSION]}${src[t.PRERELEASE]}?${src[t.BUILD]}?`);
    createToken("FULL", `^${src[t.FULLPLAIN]}$`);
    createToken("LOOSEPLAIN", `[v=\\s]*${src[t.MAINVERSIONLOOSE]}${src[t.PRERELEASELOOSE]}?${src[t.BUILD]}?`);
    createToken("LOOSE", `^${src[t.LOOSEPLAIN]}$`);
    createToken("GTLT", "((?:<|>)?=?)");
    createToken("XRANGEIDENTIFIERLOOSE", `${src[t.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);
    createToken("XRANGEIDENTIFIER", `${src[t.NUMERICIDENTIFIER]}|x|X|\\*`);
    createToken("XRANGEPLAIN", `[v=\\s]*(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:${src[t.PRERELEASE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGEPLAINLOOSE", `[v=\\s]*(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:${src[t.PRERELEASELOOSE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAIN]}$`);
    createToken("XRANGELOOSE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COERCEPLAIN", `${"(^|[^\\d])(\\d{1,"}${MAX_SAFE_COMPONENT_LENGTH}})(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?`);
    createToken("COERCE", `${src[t.COERCEPLAIN]}(?:$|[^\\d])`);
    createToken("COERCEFULL", src[t.COERCEPLAIN] + `(?:${src[t.PRERELEASE]})?(?:${src[t.BUILD]})?(?:$|[^\\d])`);
    createToken("COERCERTL", src[t.COERCE], true);
    createToken("COERCERTLFULL", src[t.COERCEFULL], true);
    createToken("LONETILDE", "(?:~>?)");
    createToken("TILDETRIM", `(\\s*)${src[t.LONETILDE]}\\s+`, true);
    exports.tildeTrimReplace = "$1~";
    createToken("TILDE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAIN]}$`);
    createToken("TILDELOOSE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("LONECARET", "(?:\\^)");
    createToken("CARETTRIM", `(\\s*)${src[t.LONECARET]}\\s+`, true);
    exports.caretTrimReplace = "$1^";
    createToken("CARET", `^${src[t.LONECARET]}${src[t.XRANGEPLAIN]}$`);
    createToken("CARETLOOSE", `^${src[t.LONECARET]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COMPARATORLOOSE", `^${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]})$|^$`);
    createToken("COMPARATOR", `^${src[t.GTLT]}\\s*(${src[t.FULLPLAIN]})$|^$`);
    createToken("COMPARATORTRIM", `(\\s*)${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]}|${src[t.XRANGEPLAIN]})`, true);
    exports.comparatorTrimReplace = "$1$2$3";
    createToken("HYPHENRANGE", `^\\s*(${src[t.XRANGEPLAIN]})\\s+-\\s+(${src[t.XRANGEPLAIN]})\\s*$`);
    createToken("HYPHENRANGELOOSE", `^\\s*(${src[t.XRANGEPLAINLOOSE]})\\s+-\\s+(${src[t.XRANGEPLAINLOOSE]})\\s*$`);
    createToken("STAR", "(<|>)?=?\\s*\\*");
    createToken("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$");
    createToken("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$");
  }
});

// node_modules/semver/internal/parse-options.js
var require_parse_options = __commonJS({
  "node_modules/semver/internal/parse-options.js"(exports, module) {
    "use strict";
    var looseOption = Object.freeze({ loose: true });
    var emptyOpts = Object.freeze({});
    var parseOptions = (options) => {
      if (!options) {
        return emptyOpts;
      }
      if (typeof options !== "object") {
        return looseOption;
      }
      return options;
    };
    module.exports = parseOptions;
  }
});

// node_modules/semver/internal/identifiers.js
var require_identifiers = __commonJS({
  "node_modules/semver/internal/identifiers.js"(exports, module) {
    "use strict";
    var numeric = /^[0-9]+$/;
    var compareIdentifiers = (a, b) => {
      if (typeof a === "number" && typeof b === "number") {
        return a === b ? 0 : a < b ? -1 : 1;
      }
      const anum = numeric.test(a);
      const bnum = numeric.test(b);
      if (anum && bnum) {
        a = +a;
        b = +b;
      }
      return a === b ? 0 : anum && !bnum ? -1 : bnum && !anum ? 1 : a < b ? -1 : 1;
    };
    var rcompareIdentifiers = (a, b) => compareIdentifiers(b, a);
    module.exports = {
      compareIdentifiers,
      rcompareIdentifiers
    };
  }
});

// node_modules/semver/classes/semver.js
var require_semver = __commonJS({
  "node_modules/semver/classes/semver.js"(exports, module) {
    "use strict";
    var debug2 = require_debug();
    var { MAX_LENGTH, MAX_SAFE_INTEGER } = require_constants();
    var { safeRe: re, t } = require_re();
    var parseOptions = require_parse_options();
    var { compareIdentifiers } = require_identifiers();
    var SemVer = class _SemVer {
      constructor(version, options) {
        options = parseOptions(options);
        if (version instanceof _SemVer) {
          if (version.loose === !!options.loose && version.includePrerelease === !!options.includePrerelease) {
            return version;
          } else {
            version = version.version;
          }
        } else if (typeof version !== "string") {
          throw new TypeError(`Invalid version. Must be a string. Got type "${typeof version}".`);
        }
        if (version.length > MAX_LENGTH) {
          throw new TypeError(
            `version is longer than ${MAX_LENGTH} characters`
          );
        }
        debug2("SemVer", version, options);
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        const m = version.trim().match(options.loose ? re[t.LOOSE] : re[t.FULL]);
        if (!m) {
          throw new TypeError(`Invalid Version: ${version}`);
        }
        this.raw = version;
        this.major = +m[1];
        this.minor = +m[2];
        this.patch = +m[3];
        if (this.major > MAX_SAFE_INTEGER || this.major < 0) {
          throw new TypeError("Invalid major version");
        }
        if (this.minor > MAX_SAFE_INTEGER || this.minor < 0) {
          throw new TypeError("Invalid minor version");
        }
        if (this.patch > MAX_SAFE_INTEGER || this.patch < 0) {
          throw new TypeError("Invalid patch version");
        }
        if (!m[4]) {
          this.prerelease = [];
        } else {
          this.prerelease = m[4].split(".").map((id) => {
            if (/^[0-9]+$/.test(id)) {
              const num = +id;
              if (num >= 0 && num < MAX_SAFE_INTEGER) {
                return num;
              }
            }
            return id;
          });
        }
        this.build = m[5] ? m[5].split(".") : [];
        this.format();
      }
      format() {
        this.version = `${this.major}.${this.minor}.${this.patch}`;
        if (this.prerelease.length) {
          this.version += `-${this.prerelease.join(".")}`;
        }
        return this.version;
      }
      toString() {
        return this.version;
      }
      compare(other) {
        debug2("SemVer.compare", this.version, this.options, other);
        if (!(other instanceof _SemVer)) {
          if (typeof other === "string" && other === this.version) {
            return 0;
          }
          other = new _SemVer(other, this.options);
        }
        if (other.version === this.version) {
          return 0;
        }
        return this.compareMain(other) || this.comparePre(other);
      }
      compareMain(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.major < other.major) {
          return -1;
        }
        if (this.major > other.major) {
          return 1;
        }
        if (this.minor < other.minor) {
          return -1;
        }
        if (this.minor > other.minor) {
          return 1;
        }
        if (this.patch < other.patch) {
          return -1;
        }
        if (this.patch > other.patch) {
          return 1;
        }
        return 0;
      }
      comparePre(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.prerelease.length && !other.prerelease.length) {
          return -1;
        } else if (!this.prerelease.length && other.prerelease.length) {
          return 1;
        } else if (!this.prerelease.length && !other.prerelease.length) {
          return 0;
        }
        let i = 0;
        do {
          const a = this.prerelease[i];
          const b = other.prerelease[i];
          debug2("prerelease compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      compareBuild(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        let i = 0;
        do {
          const a = this.build[i];
          const b = other.build[i];
          debug2("build compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      // preminor will bump the version up to the next minor release, and immediately
      // down to pre-release. premajor and prepatch work the same way.
      inc(release, identifier, identifierBase) {
        if (release.startsWith("pre")) {
          if (!identifier && identifierBase === false) {
            throw new Error("invalid increment argument: identifier is empty");
          }
          if (identifier) {
            const match = `-${identifier}`.match(this.options.loose ? re[t.PRERELEASELOOSE] : re[t.PRERELEASE]);
            if (!match || match[1] !== identifier) {
              throw new Error(`invalid identifier: ${identifier}`);
            }
          }
        }
        switch (release) {
          case "premajor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor = 0;
            this.major++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "preminor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "prepatch":
            this.prerelease.length = 0;
            this.inc("patch", identifier, identifierBase);
            this.inc("pre", identifier, identifierBase);
            break;
          // If the input is a non-prerelease version, this acts the same as
          // prepatch.
          case "prerelease":
            if (this.prerelease.length === 0) {
              this.inc("patch", identifier, identifierBase);
            }
            this.inc("pre", identifier, identifierBase);
            break;
          case "release":
            if (this.prerelease.length === 0) {
              throw new Error(`version ${this.raw} is not a prerelease`);
            }
            this.prerelease.length = 0;
            break;
          case "major":
            if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0) {
              this.major++;
            }
            this.minor = 0;
            this.patch = 0;
            this.prerelease = [];
            break;
          case "minor":
            if (this.patch !== 0 || this.prerelease.length === 0) {
              this.minor++;
            }
            this.patch = 0;
            this.prerelease = [];
            break;
          case "patch":
            if (this.prerelease.length === 0) {
              this.patch++;
            }
            this.prerelease = [];
            break;
          // This probably shouldn't be used publicly.
          // 1.0.0 'pre' would become 1.0.0-0 which is the wrong direction.
          case "pre": {
            const base = Number(identifierBase) ? 1 : 0;
            if (this.prerelease.length === 0) {
              this.prerelease = [base];
            } else {
              let i = this.prerelease.length;
              while (--i >= 0) {
                if (typeof this.prerelease[i] === "number") {
                  this.prerelease[i]++;
                  i = -2;
                }
              }
              if (i === -1) {
                if (identifier === this.prerelease.join(".") && identifierBase === false) {
                  throw new Error("invalid increment argument: identifier already exists");
                }
                this.prerelease.push(base);
              }
            }
            if (identifier) {
              let prerelease = [identifier, base];
              if (identifierBase === false) {
                prerelease = [identifier];
              }
              if (compareIdentifiers(this.prerelease[0], identifier) === 0) {
                if (isNaN(this.prerelease[1])) {
                  this.prerelease = prerelease;
                }
              } else {
                this.prerelease = prerelease;
              }
            }
            break;
          }
          default:
            throw new Error(`invalid increment argument: ${release}`);
        }
        this.raw = this.format();
        if (this.build.length) {
          this.raw += `+${this.build.join(".")}`;
        }
        return this;
      }
    };
    module.exports = SemVer;
  }
});

// node_modules/semver/functions/parse.js
var require_parse = __commonJS({
  "node_modules/semver/functions/parse.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var parse = (version, options, throwErrors = false) => {
      if (version instanceof SemVer) {
        return version;
      }
      try {
        return new SemVer(version, options);
      } catch (er) {
        if (!throwErrors) {
          return null;
        }
        throw er;
      }
    };
    module.exports = parse;
  }
});

// node_modules/semver/functions/valid.js
var require_valid = __commonJS({
  "node_modules/semver/functions/valid.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var valid = (version, options) => {
      const v = parse(version, options);
      return v ? v.version : null;
    };
    module.exports = valid;
  }
});

// node_modules/semver/functions/clean.js
var require_clean = __commonJS({
  "node_modules/semver/functions/clean.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var clean = (version, options) => {
      const s = parse(version.trim().replace(/^[=v]+/, ""), options);
      return s ? s.version : null;
    };
    module.exports = clean;
  }
});

// node_modules/semver/functions/inc.js
var require_inc = __commonJS({
  "node_modules/semver/functions/inc.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var inc = (version, release, options, identifier, identifierBase) => {
      if (typeof options === "string") {
        identifierBase = identifier;
        identifier = options;
        options = void 0;
      }
      try {
        return new SemVer(
          version instanceof SemVer ? version.version : version,
          options
        ).inc(release, identifier, identifierBase).version;
      } catch (er) {
        return null;
      }
    };
    module.exports = inc;
  }
});

// node_modules/semver/functions/diff.js
var require_diff = __commonJS({
  "node_modules/semver/functions/diff.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var diff = (version1, version2) => {
      const v1 = parse(version1, null, true);
      const v2 = parse(version2, null, true);
      const comparison = v1.compare(v2);
      if (comparison === 0) {
        return null;
      }
      const v1Higher = comparison > 0;
      const highVersion = v1Higher ? v1 : v2;
      const lowVersion = v1Higher ? v2 : v1;
      const highHasPre = !!highVersion.prerelease.length;
      const lowHasPre = !!lowVersion.prerelease.length;
      if (lowHasPre && !highHasPre) {
        if (!lowVersion.patch && !lowVersion.minor) {
          return "major";
        }
        if (lowVersion.compareMain(highVersion) === 0) {
          if (lowVersion.minor && !lowVersion.patch) {
            return "minor";
          }
          return "patch";
        }
      }
      const prefix = highHasPre ? "pre" : "";
      if (v1.major !== v2.major) {
        return prefix + "major";
      }
      if (v1.minor !== v2.minor) {
        return prefix + "minor";
      }
      if (v1.patch !== v2.patch) {
        return prefix + "patch";
      }
      return "prerelease";
    };
    module.exports = diff;
  }
});

// node_modules/semver/functions/major.js
var require_major = __commonJS({
  "node_modules/semver/functions/major.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var major = (a, loose) => new SemVer(a, loose).major;
    module.exports = major;
  }
});

// node_modules/semver/functions/minor.js
var require_minor = __commonJS({
  "node_modules/semver/functions/minor.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var minor = (a, loose) => new SemVer(a, loose).minor;
    module.exports = minor;
  }
});

// node_modules/semver/functions/patch.js
var require_patch = __commonJS({
  "node_modules/semver/functions/patch.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var patch = (a, loose) => new SemVer(a, loose).patch;
    module.exports = patch;
  }
});

// node_modules/semver/functions/prerelease.js
var require_prerelease = __commonJS({
  "node_modules/semver/functions/prerelease.js"(exports, module) {
    "use strict";
    var parse = require_parse();
    var prerelease = (version, options) => {
      const parsed = parse(version, options);
      return parsed && parsed.prerelease.length ? parsed.prerelease : null;
    };
    module.exports = prerelease;
  }
});

// node_modules/semver/functions/compare.js
var require_compare = __commonJS({
  "node_modules/semver/functions/compare.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var compare = (a, b, loose) => new SemVer(a, loose).compare(new SemVer(b, loose));
    module.exports = compare;
  }
});

// node_modules/semver/functions/rcompare.js
var require_rcompare = __commonJS({
  "node_modules/semver/functions/rcompare.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var rcompare = (a, b, loose) => compare(b, a, loose);
    module.exports = rcompare;
  }
});

// node_modules/semver/functions/compare-loose.js
var require_compare_loose = __commonJS({
  "node_modules/semver/functions/compare-loose.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var compareLoose = (a, b) => compare(a, b, true);
    module.exports = compareLoose;
  }
});

// node_modules/semver/functions/compare-build.js
var require_compare_build = __commonJS({
  "node_modules/semver/functions/compare-build.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var compareBuild = (a, b, loose) => {
      const versionA = new SemVer(a, loose);
      const versionB = new SemVer(b, loose);
      return versionA.compare(versionB) || versionA.compareBuild(versionB);
    };
    module.exports = compareBuild;
  }
});

// node_modules/semver/functions/sort.js
var require_sort = __commonJS({
  "node_modules/semver/functions/sort.js"(exports, module) {
    "use strict";
    var compareBuild = require_compare_build();
    var sort = (list, loose) => list.sort((a, b) => compareBuild(a, b, loose));
    module.exports = sort;
  }
});

// node_modules/semver/functions/rsort.js
var require_rsort = __commonJS({
  "node_modules/semver/functions/rsort.js"(exports, module) {
    "use strict";
    var compareBuild = require_compare_build();
    var rsort = (list, loose) => list.sort((a, b) => compareBuild(b, a, loose));
    module.exports = rsort;
  }
});

// node_modules/semver/functions/gt.js
var require_gt = __commonJS({
  "node_modules/semver/functions/gt.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var gt = (a, b, loose) => compare(a, b, loose) > 0;
    module.exports = gt;
  }
});

// node_modules/semver/functions/lt.js
var require_lt = __commonJS({
  "node_modules/semver/functions/lt.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var lt = (a, b, loose) => compare(a, b, loose) < 0;
    module.exports = lt;
  }
});

// node_modules/semver/functions/eq.js
var require_eq = __commonJS({
  "node_modules/semver/functions/eq.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var eq = (a, b, loose) => compare(a, b, loose) === 0;
    module.exports = eq;
  }
});

// node_modules/semver/functions/neq.js
var require_neq = __commonJS({
  "node_modules/semver/functions/neq.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var neq = (a, b, loose) => compare(a, b, loose) !== 0;
    module.exports = neq;
  }
});

// node_modules/semver/functions/gte.js
var require_gte = __commonJS({
  "node_modules/semver/functions/gte.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var gte = (a, b, loose) => compare(a, b, loose) >= 0;
    module.exports = gte;
  }
});

// node_modules/semver/functions/lte.js
var require_lte = __commonJS({
  "node_modules/semver/functions/lte.js"(exports, module) {
    "use strict";
    var compare = require_compare();
    var lte = (a, b, loose) => compare(a, b, loose) <= 0;
    module.exports = lte;
  }
});

// node_modules/semver/functions/cmp.js
var require_cmp = __commonJS({
  "node_modules/semver/functions/cmp.js"(exports, module) {
    "use strict";
    var eq = require_eq();
    var neq = require_neq();
    var gt = require_gt();
    var gte = require_gte();
    var lt = require_lt();
    var lte = require_lte();
    var cmp = (a, op, b, loose) => {
      switch (op) {
        case "===":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a === b;
        case "!==":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a !== b;
        case "":
        case "=":
        case "==":
          return eq(a, b, loose);
        case "!=":
          return neq(a, b, loose);
        case ">":
          return gt(a, b, loose);
        case ">=":
          return gte(a, b, loose);
        case "<":
          return lt(a, b, loose);
        case "<=":
          return lte(a, b, loose);
        default:
          throw new TypeError(`Invalid operator: ${op}`);
      }
    };
    module.exports = cmp;
  }
});

// node_modules/semver/functions/coerce.js
var require_coerce = __commonJS({
  "node_modules/semver/functions/coerce.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var parse = require_parse();
    var { safeRe: re, t } = require_re();
    var coerce = (version, options) => {
      if (version instanceof SemVer) {
        return version;
      }
      if (typeof version === "number") {
        version = String(version);
      }
      if (typeof version !== "string") {
        return null;
      }
      options = options || {};
      let match = null;
      if (!options.rtl) {
        match = version.match(options.includePrerelease ? re[t.COERCEFULL] : re[t.COERCE]);
      } else {
        const coerceRtlRegex = options.includePrerelease ? re[t.COERCERTLFULL] : re[t.COERCERTL];
        let next;
        while ((next = coerceRtlRegex.exec(version)) && (!match || match.index + match[0].length !== version.length)) {
          if (!match || next.index + next[0].length !== match.index + match[0].length) {
            match = next;
          }
          coerceRtlRegex.lastIndex = next.index + next[1].length + next[2].length;
        }
        coerceRtlRegex.lastIndex = -1;
      }
      if (match === null) {
        return null;
      }
      const major = match[2];
      const minor = match[3] || "0";
      const patch = match[4] || "0";
      const prerelease = options.includePrerelease && match[5] ? `-${match[5]}` : "";
      const build = options.includePrerelease && match[6] ? `+${match[6]}` : "";
      return parse(`${major}.${minor}.${patch}${prerelease}${build}`, options);
    };
    module.exports = coerce;
  }
});

// node_modules/semver/internal/lrucache.js
var require_lrucache = __commonJS({
  "node_modules/semver/internal/lrucache.js"(exports, module) {
    "use strict";
    var LRUCache = class {
      constructor() {
        this.max = 1e3;
        this.map = /* @__PURE__ */ new Map();
      }
      get(key) {
        const value = this.map.get(key);
        if (value === void 0) {
          return void 0;
        } else {
          this.map.delete(key);
          this.map.set(key, value);
          return value;
        }
      }
      delete(key) {
        return this.map.delete(key);
      }
      set(key, value) {
        const deleted = this.delete(key);
        if (!deleted && value !== void 0) {
          if (this.map.size >= this.max) {
            const firstKey = this.map.keys().next().value;
            this.delete(firstKey);
          }
          this.map.set(key, value);
        }
        return this;
      }
    };
    module.exports = LRUCache;
  }
});

// node_modules/semver/classes/range.js
var require_range = __commonJS({
  "node_modules/semver/classes/range.js"(exports, module) {
    "use strict";
    var SPACE_CHARACTERS = /\s+/g;
    var Range = class _Range {
      constructor(range, options) {
        options = parseOptions(options);
        if (range instanceof _Range) {
          if (range.loose === !!options.loose && range.includePrerelease === !!options.includePrerelease) {
            return range;
          } else {
            return new _Range(range.raw, options);
          }
        }
        if (range instanceof Comparator) {
          this.raw = range.value;
          this.set = [[range]];
          this.formatted = void 0;
          return this;
        }
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        this.raw = range.trim().replace(SPACE_CHARACTERS, " ");
        this.set = this.raw.split("||").map((r) => this.parseRange(r.trim())).filter((c) => c.length);
        if (!this.set.length) {
          throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
        }
        if (this.set.length > 1) {
          const first = this.set[0];
          this.set = this.set.filter((c) => !isNullSet(c[0]));
          if (this.set.length === 0) {
            this.set = [first];
          } else if (this.set.length > 1) {
            for (const c of this.set) {
              if (c.length === 1 && isAny(c[0])) {
                this.set = [c];
                break;
              }
            }
          }
        }
        this.formatted = void 0;
      }
      get range() {
        if (this.formatted === void 0) {
          this.formatted = "";
          for (let i = 0; i < this.set.length; i++) {
            if (i > 0) {
              this.formatted += "||";
            }
            const comps = this.set[i];
            for (let k = 0; k < comps.length; k++) {
              if (k > 0) {
                this.formatted += " ";
              }
              this.formatted += comps[k].toString().trim();
            }
          }
        }
        return this.formatted;
      }
      format() {
        return this.range;
      }
      toString() {
        return this.range;
      }
      parseRange(range) {
        const memoOpts = (this.options.includePrerelease && FLAG_INCLUDE_PRERELEASE) | (this.options.loose && FLAG_LOOSE);
        const memoKey = memoOpts + ":" + range;
        const cached = cache.get(memoKey);
        if (cached) {
          return cached;
        }
        const loose = this.options.loose;
        const hr = loose ? re[t.HYPHENRANGELOOSE] : re[t.HYPHENRANGE];
        range = range.replace(hr, hyphenReplace(this.options.includePrerelease));
        debug2("hyphen replace", range);
        range = range.replace(re[t.COMPARATORTRIM], comparatorTrimReplace);
        debug2("comparator trim", range);
        range = range.replace(re[t.TILDETRIM], tildeTrimReplace);
        debug2("tilde trim", range);
        range = range.replace(re[t.CARETTRIM], caretTrimReplace);
        debug2("caret trim", range);
        let rangeList = range.split(" ").map((comp) => parseComparator(comp, this.options)).join(" ").split(/\s+/).map((comp) => replaceGTE0(comp, this.options));
        if (loose) {
          rangeList = rangeList.filter((comp) => {
            debug2("loose invalid filter", comp, this.options);
            return !!comp.match(re[t.COMPARATORLOOSE]);
          });
        }
        debug2("range list", rangeList);
        const rangeMap = /* @__PURE__ */ new Map();
        const comparators = rangeList.map((comp) => new Comparator(comp, this.options));
        for (const comp of comparators) {
          if (isNullSet(comp)) {
            return [comp];
          }
          rangeMap.set(comp.value, comp);
        }
        if (rangeMap.size > 1 && rangeMap.has("")) {
          rangeMap.delete("");
        }
        const result = [...rangeMap.values()];
        cache.set(memoKey, result);
        return result;
      }
      intersects(range, options) {
        if (!(range instanceof _Range)) {
          throw new TypeError("a Range is required");
        }
        return this.set.some((thisComparators) => {
          return isSatisfiable(thisComparators, options) && range.set.some((rangeComparators) => {
            return isSatisfiable(rangeComparators, options) && thisComparators.every((thisComparator) => {
              return rangeComparators.every((rangeComparator) => {
                return thisComparator.intersects(rangeComparator, options);
              });
            });
          });
        });
      }
      // if ANY of the sets match ALL of its comparators, then pass
      test(version) {
        if (!version) {
          return false;
        }
        if (typeof version === "string") {
          try {
            version = new SemVer(version, this.options);
          } catch (er) {
            return false;
          }
        }
        for (let i = 0; i < this.set.length; i++) {
          if (testSet(this.set[i], version, this.options)) {
            return true;
          }
        }
        return false;
      }
    };
    module.exports = Range;
    var LRU = require_lrucache();
    var cache = new LRU();
    var parseOptions = require_parse_options();
    var Comparator = require_comparator();
    var debug2 = require_debug();
    var SemVer = require_semver();
    var {
      safeRe: re,
      t,
      comparatorTrimReplace,
      tildeTrimReplace,
      caretTrimReplace
    } = require_re();
    var { FLAG_INCLUDE_PRERELEASE, FLAG_LOOSE } = require_constants();
    var isNullSet = (c) => c.value === "<0.0.0-0";
    var isAny = (c) => c.value === "";
    var isSatisfiable = (comparators, options) => {
      let result = true;
      const remainingComparators = comparators.slice();
      let testComparator = remainingComparators.pop();
      while (result && remainingComparators.length) {
        result = remainingComparators.every((otherComparator) => {
          return testComparator.intersects(otherComparator, options);
        });
        testComparator = remainingComparators.pop();
      }
      return result;
    };
    var parseComparator = (comp, options) => {
      comp = comp.replace(re[t.BUILD], "");
      debug2("comp", comp, options);
      comp = replaceCarets(comp, options);
      debug2("caret", comp);
      comp = replaceTildes(comp, options);
      debug2("tildes", comp);
      comp = replaceXRanges(comp, options);
      debug2("xrange", comp);
      comp = replaceStars(comp, options);
      debug2("stars", comp);
      return comp;
    };
    var isX = (id) => !id || id.toLowerCase() === "x" || id === "*";
    var replaceTildes = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options)).join(" ");
    };
    var replaceTilde = (comp, options) => {
      const r = options.loose ? re[t.TILDELOOSE] : re[t.TILDE];
      return comp.replace(r, (_, M, m, p, pr) => {
        debug2("tilde", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0 <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          ret = `>=${M}.${m}.0 <${M}.${+m + 1}.0-0`;
        } else if (pr) {
          debug2("replaceTilde pr", pr);
          ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
        } else {
          ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
        }
        debug2("tilde return", ret);
        return ret;
      });
    };
    var replaceCarets = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceCaret(c, options)).join(" ");
    };
    var replaceCaret = (comp, options) => {
      debug2("caret", comp, options);
      const r = options.loose ? re[t.CARETLOOSE] : re[t.CARET];
      const z = options.includePrerelease ? "-0" : "";
      return comp.replace(r, (_, M, m, p, pr) => {
        debug2("caret", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          if (M === "0") {
            ret = `>=${M}.${m}.0${z} <${M}.${+m + 1}.0-0`;
          } else {
            ret = `>=${M}.${m}.0${z} <${+M + 1}.0.0-0`;
          }
        } else if (pr) {
          debug2("replaceCaret pr", pr);
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p}-${pr} <${+M + 1}.0.0-0`;
          }
        } else {
          debug2("no pr");
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}${z} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}${z} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p} <${+M + 1}.0.0-0`;
          }
        }
        debug2("caret return", ret);
        return ret;
      });
    };
    var replaceXRanges = (comp, options) => {
      debug2("replaceXRanges", comp, options);
      return comp.split(/\s+/).map((c) => replaceXRange(c, options)).join(" ");
    };
    var replaceXRange = (comp, options) => {
      comp = comp.trim();
      const r = options.loose ? re[t.XRANGELOOSE] : re[t.XRANGE];
      return comp.replace(r, (ret, gtlt, M, m, p, pr) => {
        debug2("xRange", comp, ret, gtlt, M, m, p, pr);
        const xM = isX(M);
        const xm = xM || isX(m);
        const xp = xm || isX(p);
        const anyX = xp;
        if (gtlt === "=" && anyX) {
          gtlt = "";
        }
        pr = options.includePrerelease ? "-0" : "";
        if (xM) {
          if (gtlt === ">" || gtlt === "<") {
            ret = "<0.0.0-0";
          } else {
            ret = "*";
          }
        } else if (gtlt && anyX) {
          if (xm) {
            m = 0;
          }
          p = 0;
          if (gtlt === ">") {
            gtlt = ">=";
            if (xm) {
              M = +M + 1;
              m = 0;
              p = 0;
            } else {
              m = +m + 1;
              p = 0;
            }
          } else if (gtlt === "<=") {
            gtlt = "<";
            if (xm) {
              M = +M + 1;
            } else {
              m = +m + 1;
            }
          }
          if (gtlt === "<") {
            pr = "-0";
          }
          ret = `${gtlt + M}.${m}.${p}${pr}`;
        } else if (xm) {
          ret = `>=${M}.0.0${pr} <${+M + 1}.0.0-0`;
        } else if (xp) {
          ret = `>=${M}.${m}.0${pr} <${M}.${+m + 1}.0-0`;
        }
        debug2("xRange return", ret);
        return ret;
      });
    };
    var replaceStars = (comp, options) => {
      debug2("replaceStars", comp, options);
      return comp.trim().replace(re[t.STAR], "");
    };
    var replaceGTE0 = (comp, options) => {
      debug2("replaceGTE0", comp, options);
      return comp.trim().replace(re[options.includePrerelease ? t.GTE0PRE : t.GTE0], "");
    };
    var hyphenReplace = (incPr) => ($0, from, fM, fm, fp, fpr, fb, to, tM, tm, tp, tpr) => {
      if (isX(fM)) {
        from = "";
      } else if (isX(fm)) {
        from = `>=${fM}.0.0${incPr ? "-0" : ""}`;
      } else if (isX(fp)) {
        from = `>=${fM}.${fm}.0${incPr ? "-0" : ""}`;
      } else if (fpr) {
        from = `>=${from}`;
      } else {
        from = `>=${from}${incPr ? "-0" : ""}`;
      }
      if (isX(tM)) {
        to = "";
      } else if (isX(tm)) {
        to = `<${+tM + 1}.0.0-0`;
      } else if (isX(tp)) {
        to = `<${tM}.${+tm + 1}.0-0`;
      } else if (tpr) {
        to = `<=${tM}.${tm}.${tp}-${tpr}`;
      } else if (incPr) {
        to = `<${tM}.${tm}.${+tp + 1}-0`;
      } else {
        to = `<=${to}`;
      }
      return `${from} ${to}`.trim();
    };
    var testSet = (set2, version, options) => {
      for (let i = 0; i < set2.length; i++) {
        if (!set2[i].test(version)) {
          return false;
        }
      }
      if (version.prerelease.length && !options.includePrerelease) {
        for (let i = 0; i < set2.length; i++) {
          debug2(set2[i].semver);
          if (set2[i].semver === Comparator.ANY) {
            continue;
          }
          if (set2[i].semver.prerelease.length > 0) {
            const allowed = set2[i].semver;
            if (allowed.major === version.major && allowed.minor === version.minor && allowed.patch === version.patch) {
              return true;
            }
          }
        }
        return false;
      }
      return true;
    };
  }
});

// node_modules/semver/classes/comparator.js
var require_comparator = __commonJS({
  "node_modules/semver/classes/comparator.js"(exports, module) {
    "use strict";
    var ANY = /* @__PURE__ */ Symbol("SemVer ANY");
    var Comparator = class _Comparator {
      static get ANY() {
        return ANY;
      }
      constructor(comp, options) {
        options = parseOptions(options);
        if (comp instanceof _Comparator) {
          if (comp.loose === !!options.loose) {
            return comp;
          } else {
            comp = comp.value;
          }
        }
        comp = comp.trim().split(/\s+/).join(" ");
        debug2("comparator", comp, options);
        this.options = options;
        this.loose = !!options.loose;
        this.parse(comp);
        if (this.semver === ANY) {
          this.value = "";
        } else {
          this.value = this.operator + this.semver.version;
        }
        debug2("comp", this);
      }
      parse(comp) {
        const r = this.options.loose ? re[t.COMPARATORLOOSE] : re[t.COMPARATOR];
        const m = comp.match(r);
        if (!m) {
          throw new TypeError(`Invalid comparator: ${comp}`);
        }
        this.operator = m[1] !== void 0 ? m[1] : "";
        if (this.operator === "=") {
          this.operator = "";
        }
        if (!m[2]) {
          this.semver = ANY;
        } else {
          this.semver = new SemVer(m[2], this.options.loose);
        }
      }
      toString() {
        return this.value;
      }
      test(version) {
        debug2("Comparator.test", version, this.options.loose);
        if (this.semver === ANY || version === ANY) {
          return true;
        }
        if (typeof version === "string") {
          try {
            version = new SemVer(version, this.options);
          } catch (er) {
            return false;
          }
        }
        return cmp(version, this.operator, this.semver, this.options);
      }
      intersects(comp, options) {
        if (!(comp instanceof _Comparator)) {
          throw new TypeError("a Comparator is required");
        }
        if (this.operator === "") {
          if (this.value === "") {
            return true;
          }
          return new Range(comp.value, options).test(this.value);
        } else if (comp.operator === "") {
          if (comp.value === "") {
            return true;
          }
          return new Range(this.value, options).test(comp.semver);
        }
        options = parseOptions(options);
        if (options.includePrerelease && (this.value === "<0.0.0-0" || comp.value === "<0.0.0-0")) {
          return false;
        }
        if (!options.includePrerelease && (this.value.startsWith("<0.0.0") || comp.value.startsWith("<0.0.0"))) {
          return false;
        }
        if (this.operator.startsWith(">") && comp.operator.startsWith(">")) {
          return true;
        }
        if (this.operator.startsWith("<") && comp.operator.startsWith("<")) {
          return true;
        }
        if (this.semver.version === comp.semver.version && this.operator.includes("=") && comp.operator.includes("=")) {
          return true;
        }
        if (cmp(this.semver, "<", comp.semver, options) && this.operator.startsWith(">") && comp.operator.startsWith("<")) {
          return true;
        }
        if (cmp(this.semver, ">", comp.semver, options) && this.operator.startsWith("<") && comp.operator.startsWith(">")) {
          return true;
        }
        return false;
      }
    };
    module.exports = Comparator;
    var parseOptions = require_parse_options();
    var { safeRe: re, t } = require_re();
    var cmp = require_cmp();
    var debug2 = require_debug();
    var SemVer = require_semver();
    var Range = require_range();
  }
});

// node_modules/semver/functions/satisfies.js
var require_satisfies = __commonJS({
  "node_modules/semver/functions/satisfies.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var satisfies2 = (version, range, options) => {
      try {
        range = new Range(range, options);
      } catch (er) {
        return false;
      }
      return range.test(version);
    };
    module.exports = satisfies2;
  }
});

// node_modules/semver/ranges/to-comparators.js
var require_to_comparators = __commonJS({
  "node_modules/semver/ranges/to-comparators.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var toComparators = (range, options) => new Range(range, options).set.map((comp) => comp.map((c) => c.value).join(" ").trim().split(" "));
    module.exports = toComparators;
  }
});

// node_modules/semver/ranges/max-satisfying.js
var require_max_satisfying = __commonJS({
  "node_modules/semver/ranges/max-satisfying.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Range = require_range();
    var maxSatisfying = (versions, range, options) => {
      let max = null;
      let maxSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!max || maxSV.compare(v) === -1) {
            max = v;
            maxSV = new SemVer(max, options);
          }
        }
      });
      return max;
    };
    module.exports = maxSatisfying;
  }
});

// node_modules/semver/ranges/min-satisfying.js
var require_min_satisfying = __commonJS({
  "node_modules/semver/ranges/min-satisfying.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Range = require_range();
    var minSatisfying = (versions, range, options) => {
      let min = null;
      let minSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!min || minSV.compare(v) === 1) {
            min = v;
            minSV = new SemVer(min, options);
          }
        }
      });
      return min;
    };
    module.exports = minSatisfying;
  }
});

// node_modules/semver/ranges/min-version.js
var require_min_version = __commonJS({
  "node_modules/semver/ranges/min-version.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Range = require_range();
    var gt = require_gt();
    var minVersion = (range, loose) => {
      range = new Range(range, loose);
      let minver = new SemVer("0.0.0");
      if (range.test(minver)) {
        return minver;
      }
      minver = new SemVer("0.0.0-0");
      if (range.test(minver)) {
        return minver;
      }
      minver = null;
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let setMin = null;
        comparators.forEach((comparator) => {
          const compver = new SemVer(comparator.semver.version);
          switch (comparator.operator) {
            case ">":
              if (compver.prerelease.length === 0) {
                compver.patch++;
              } else {
                compver.prerelease.push(0);
              }
              compver.raw = compver.format();
            /* fallthrough */
            case "":
            case ">=":
              if (!setMin || gt(compver, setMin)) {
                setMin = compver;
              }
              break;
            case "<":
            case "<=":
              break;
            /* istanbul ignore next */
            default:
              throw new Error(`Unexpected operation: ${comparator.operator}`);
          }
        });
        if (setMin && (!minver || gt(minver, setMin))) {
          minver = setMin;
        }
      }
      if (minver && range.test(minver)) {
        return minver;
      }
      return null;
    };
    module.exports = minVersion;
  }
});

// node_modules/semver/ranges/valid.js
var require_valid2 = __commonJS({
  "node_modules/semver/ranges/valid.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var validRange = (range, options) => {
      try {
        return new Range(range, options).range || "*";
      } catch (er) {
        return null;
      }
    };
    module.exports = validRange;
  }
});

// node_modules/semver/ranges/outside.js
var require_outside = __commonJS({
  "node_modules/semver/ranges/outside.js"(exports, module) {
    "use strict";
    var SemVer = require_semver();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var Range = require_range();
    var satisfies2 = require_satisfies();
    var gt = require_gt();
    var lt = require_lt();
    var lte = require_lte();
    var gte = require_gte();
    var outside = (version, range, hilo, options) => {
      version = new SemVer(version, options);
      range = new Range(range, options);
      let gtfn, ltefn, ltfn, comp, ecomp;
      switch (hilo) {
        case ">":
          gtfn = gt;
          ltefn = lte;
          ltfn = lt;
          comp = ">";
          ecomp = ">=";
          break;
        case "<":
          gtfn = lt;
          ltefn = gte;
          ltfn = gt;
          comp = "<";
          ecomp = "<=";
          break;
        default:
          throw new TypeError('Must provide a hilo val of "<" or ">"');
      }
      if (satisfies2(version, range, options)) {
        return false;
      }
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let high = null;
        let low = null;
        comparators.forEach((comparator) => {
          if (comparator.semver === ANY) {
            comparator = new Comparator(">=0.0.0");
          }
          high = high || comparator;
          low = low || comparator;
          if (gtfn(comparator.semver, high.semver, options)) {
            high = comparator;
          } else if (ltfn(comparator.semver, low.semver, options)) {
            low = comparator;
          }
        });
        if (high.operator === comp || high.operator === ecomp) {
          return false;
        }
        if ((!low.operator || low.operator === comp) && ltefn(version, low.semver)) {
          return false;
        } else if (low.operator === ecomp && ltfn(version, low.semver)) {
          return false;
        }
      }
      return true;
    };
    module.exports = outside;
  }
});

// node_modules/semver/ranges/gtr.js
var require_gtr = __commonJS({
  "node_modules/semver/ranges/gtr.js"(exports, module) {
    "use strict";
    var outside = require_outside();
    var gtr = (version, range, options) => outside(version, range, ">", options);
    module.exports = gtr;
  }
});

// node_modules/semver/ranges/ltr.js
var require_ltr = __commonJS({
  "node_modules/semver/ranges/ltr.js"(exports, module) {
    "use strict";
    var outside = require_outside();
    var ltr = (version, range, options) => outside(version, range, "<", options);
    module.exports = ltr;
  }
});

// node_modules/semver/ranges/intersects.js
var require_intersects = __commonJS({
  "node_modules/semver/ranges/intersects.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var intersects = (r1, r2, options) => {
      r1 = new Range(r1, options);
      r2 = new Range(r2, options);
      return r1.intersects(r2, options);
    };
    module.exports = intersects;
  }
});

// node_modules/semver/ranges/simplify.js
var require_simplify = __commonJS({
  "node_modules/semver/ranges/simplify.js"(exports, module) {
    "use strict";
    var satisfies2 = require_satisfies();
    var compare = require_compare();
    module.exports = (versions, range, options) => {
      const set2 = [];
      let first = null;
      let prev = null;
      const v = versions.sort((a, b) => compare(a, b, options));
      for (const version of v) {
        const included = satisfies2(version, range, options);
        if (included) {
          prev = version;
          if (!first) {
            first = version;
          }
        } else {
          if (prev) {
            set2.push([first, prev]);
          }
          prev = null;
          first = null;
        }
      }
      if (first) {
        set2.push([first, null]);
      }
      const ranges = [];
      for (const [min, max] of set2) {
        if (min === max) {
          ranges.push(min);
        } else if (!max && min === v[0]) {
          ranges.push("*");
        } else if (!max) {
          ranges.push(`>=${min}`);
        } else if (min === v[0]) {
          ranges.push(`<=${max}`);
        } else {
          ranges.push(`${min} - ${max}`);
        }
      }
      const simplified = ranges.join(" || ");
      const original = typeof range.raw === "string" ? range.raw : String(range);
      return simplified.length < original.length ? simplified : range;
    };
  }
});

// node_modules/semver/ranges/subset.js
var require_subset = __commonJS({
  "node_modules/semver/ranges/subset.js"(exports, module) {
    "use strict";
    var Range = require_range();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var satisfies2 = require_satisfies();
    var compare = require_compare();
    var subset = (sub, dom, options = {}) => {
      if (sub === dom) {
        return true;
      }
      sub = new Range(sub, options);
      dom = new Range(dom, options);
      let sawNonNull = false;
      OUTER: for (const simpleSub of sub.set) {
        for (const simpleDom of dom.set) {
          const isSub = simpleSubset(simpleSub, simpleDom, options);
          sawNonNull = sawNonNull || isSub !== null;
          if (isSub) {
            continue OUTER;
          }
        }
        if (sawNonNull) {
          return false;
        }
      }
      return true;
    };
    var minimumVersionWithPreRelease = [new Comparator(">=0.0.0-0")];
    var minimumVersion = [new Comparator(">=0.0.0")];
    var simpleSubset = (sub, dom, options) => {
      if (sub === dom) {
        return true;
      }
      if (sub.length === 1 && sub[0].semver === ANY) {
        if (dom.length === 1 && dom[0].semver === ANY) {
          return true;
        } else if (options.includePrerelease) {
          sub = minimumVersionWithPreRelease;
        } else {
          sub = minimumVersion;
        }
      }
      if (dom.length === 1 && dom[0].semver === ANY) {
        if (options.includePrerelease) {
          return true;
        } else {
          dom = minimumVersion;
        }
      }
      const eqSet = /* @__PURE__ */ new Set();
      let gt, lt;
      for (const c of sub) {
        if (c.operator === ">" || c.operator === ">=") {
          gt = higherGT(gt, c, options);
        } else if (c.operator === "<" || c.operator === "<=") {
          lt = lowerLT(lt, c, options);
        } else {
          eqSet.add(c.semver);
        }
      }
      if (eqSet.size > 1) {
        return null;
      }
      let gtltComp;
      if (gt && lt) {
        gtltComp = compare(gt.semver, lt.semver, options);
        if (gtltComp > 0) {
          return null;
        } else if (gtltComp === 0 && (gt.operator !== ">=" || lt.operator !== "<=")) {
          return null;
        }
      }
      for (const eq of eqSet) {
        if (gt && !satisfies2(eq, String(gt), options)) {
          return null;
        }
        if (lt && !satisfies2(eq, String(lt), options)) {
          return null;
        }
        for (const c of dom) {
          if (!satisfies2(eq, String(c), options)) {
            return false;
          }
        }
        return true;
      }
      let higher, lower;
      let hasDomLT, hasDomGT;
      let needDomLTPre = lt && !options.includePrerelease && lt.semver.prerelease.length ? lt.semver : false;
      let needDomGTPre = gt && !options.includePrerelease && gt.semver.prerelease.length ? gt.semver : false;
      if (needDomLTPre && needDomLTPre.prerelease.length === 1 && lt.operator === "<" && needDomLTPre.prerelease[0] === 0) {
        needDomLTPre = false;
      }
      for (const c of dom) {
        hasDomGT = hasDomGT || c.operator === ">" || c.operator === ">=";
        hasDomLT = hasDomLT || c.operator === "<" || c.operator === "<=";
        if (gt) {
          if (needDomGTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomGTPre.major && c.semver.minor === needDomGTPre.minor && c.semver.patch === needDomGTPre.patch) {
              needDomGTPre = false;
            }
          }
          if (c.operator === ">" || c.operator === ">=") {
            higher = higherGT(gt, c, options);
            if (higher === c && higher !== gt) {
              return false;
            }
          } else if (gt.operator === ">=" && !satisfies2(gt.semver, String(c), options)) {
            return false;
          }
        }
        if (lt) {
          if (needDomLTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomLTPre.major && c.semver.minor === needDomLTPre.minor && c.semver.patch === needDomLTPre.patch) {
              needDomLTPre = false;
            }
          }
          if (c.operator === "<" || c.operator === "<=") {
            lower = lowerLT(lt, c, options);
            if (lower === c && lower !== lt) {
              return false;
            }
          } else if (lt.operator === "<=" && !satisfies2(lt.semver, String(c), options)) {
            return false;
          }
        }
        if (!c.operator && (lt || gt) && gtltComp !== 0) {
          return false;
        }
      }
      if (gt && hasDomLT && !lt && gtltComp !== 0) {
        return false;
      }
      if (lt && hasDomGT && !gt && gtltComp !== 0) {
        return false;
      }
      if (needDomGTPre || needDomLTPre) {
        return false;
      }
      return true;
    };
    var higherGT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp > 0 ? a : comp < 0 ? b : b.operator === ">" && a.operator === ">=" ? b : a;
    };
    var lowerLT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp < 0 ? a : comp > 0 ? b : b.operator === "<" && a.operator === "<=" ? b : a;
    };
    module.exports = subset;
  }
});

// node_modules/semver/index.js
var require_semver2 = __commonJS({
  "node_modules/semver/index.js"(exports, module) {
    "use strict";
    var internalRe = require_re();
    var constants = require_constants();
    var SemVer = require_semver();
    var identifiers = require_identifiers();
    var parse = require_parse();
    var valid = require_valid();
    var clean = require_clean();
    var inc = require_inc();
    var diff = require_diff();
    var major = require_major();
    var minor = require_minor();
    var patch = require_patch();
    var prerelease = require_prerelease();
    var compare = require_compare();
    var rcompare = require_rcompare();
    var compareLoose = require_compare_loose();
    var compareBuild = require_compare_build();
    var sort = require_sort();
    var rsort = require_rsort();
    var gt = require_gt();
    var lt = require_lt();
    var eq = require_eq();
    var neq = require_neq();
    var gte = require_gte();
    var lte = require_lte();
    var cmp = require_cmp();
    var coerce = require_coerce();
    var Comparator = require_comparator();
    var Range = require_range();
    var satisfies2 = require_satisfies();
    var toComparators = require_to_comparators();
    var maxSatisfying = require_max_satisfying();
    var minSatisfying = require_min_satisfying();
    var minVersion = require_min_version();
    var validRange = require_valid2();
    var outside = require_outside();
    var gtr = require_gtr();
    var ltr = require_ltr();
    var intersects = require_intersects();
    var simplifyRange = require_simplify();
    var subset = require_subset();
    module.exports = {
      parse,
      valid,
      clean,
      inc,
      diff,
      major,
      minor,
      patch,
      prerelease,
      compare,
      rcompare,
      compareLoose,
      compareBuild,
      sort,
      rsort,
      gt,
      lt,
      eq,
      neq,
      gte,
      lte,
      cmp,
      coerce,
      Comparator,
      Range,
      satisfies: satisfies2,
      toComparators,
      maxSatisfying,
      minSatisfying,
      minVersion,
      validRange,
      outside,
      gtr,
      ltr,
      intersects,
      simplifyRange,
      subset,
      SemVer,
      re: internalRe.re,
      src: internalRe.src,
      tokens: internalRe.t,
      SEMVER_SPEC_VERSION: constants.SEMVER_SPEC_VERSION,
      RELEASE_TYPES: constants.RELEASE_TYPES,
      compareIdentifiers: identifiers.compareIdentifiers,
      rcompareIdentifiers: identifiers.rcompareIdentifiers
    };
  }
});

// action/index.ts
import { appendFileSync, writeFileSync as writeFileSync3 } from "fs";
import { resolve as resolve4 } from "path";
import { gzipSync } from "zlib";

// src/core/lockfile/parser.ts
import { readFileSync, existsSync } from "fs";
import { join } from "path";

// node_modules/js-yaml/dist/js-yaml.mjs
function isNothing(subject) {
  return typeof subject === "undefined" || subject === null;
}
function isObject(subject) {
  return typeof subject === "object" && subject !== null;
}
function toArray(sequence) {
  if (Array.isArray(sequence)) return sequence;
  else if (isNothing(sequence)) return [];
  return [sequence];
}
function extend(target, source) {
  var index, length, key, sourceKeys;
  if (source) {
    sourceKeys = Object.keys(source);
    for (index = 0, length = sourceKeys.length; index < length; index += 1) {
      key = sourceKeys[index];
      target[key] = source[key];
    }
  }
  return target;
}
function repeat(string, count) {
  var result = "", cycle;
  for (cycle = 0; cycle < count; cycle += 1) {
    result += string;
  }
  return result;
}
function isNegativeZero(number) {
  return number === 0 && Number.NEGATIVE_INFINITY === 1 / number;
}
var isNothing_1 = isNothing;
var isObject_1 = isObject;
var toArray_1 = toArray;
var repeat_1 = repeat;
var isNegativeZero_1 = isNegativeZero;
var extend_1 = extend;
var common = {
  isNothing: isNothing_1,
  isObject: isObject_1,
  toArray: toArray_1,
  repeat: repeat_1,
  isNegativeZero: isNegativeZero_1,
  extend: extend_1
};
function formatError(exception2, compact) {
  var where = "", message = exception2.reason || "(unknown reason)";
  if (!exception2.mark) return message;
  if (exception2.mark.name) {
    where += 'in "' + exception2.mark.name + '" ';
  }
  where += "(" + (exception2.mark.line + 1) + ":" + (exception2.mark.column + 1) + ")";
  if (!compact && exception2.mark.snippet) {
    where += "\n\n" + exception2.mark.snippet;
  }
  return message + " " + where;
}
function YAMLException$1(reason, mark) {
  Error.call(this);
  this.name = "YAMLException";
  this.reason = reason;
  this.mark = mark;
  this.message = formatError(this, false);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  } else {
    this.stack = new Error().stack || "";
  }
}
YAMLException$1.prototype = Object.create(Error.prototype);
YAMLException$1.prototype.constructor = YAMLException$1;
YAMLException$1.prototype.toString = function toString(compact) {
  return this.name + ": " + formatError(this, compact);
};
var exception = YAMLException$1;
function getLine(buffer, lineStart, lineEnd, position, maxLineLength) {
  var head = "";
  var tail = "";
  var maxHalfLength = Math.floor(maxLineLength / 2) - 1;
  if (position - lineStart > maxHalfLength) {
    head = " ... ";
    lineStart = position - maxHalfLength + head.length;
  }
  if (lineEnd - position > maxHalfLength) {
    tail = " ...";
    lineEnd = position + maxHalfLength - tail.length;
  }
  return {
    str: head + buffer.slice(lineStart, lineEnd).replace(/\t/g, "\u2192") + tail,
    pos: position - lineStart + head.length
    // relative position
  };
}
function padStart(string, max) {
  return common.repeat(" ", max - string.length) + string;
}
function makeSnippet(mark, options) {
  options = Object.create(options || null);
  if (!mark.buffer) return null;
  if (!options.maxLength) options.maxLength = 79;
  if (typeof options.indent !== "number") options.indent = 1;
  if (typeof options.linesBefore !== "number") options.linesBefore = 3;
  if (typeof options.linesAfter !== "number") options.linesAfter = 2;
  var re = /\r?\n|\r|\0/g;
  var lineStarts = [0];
  var lineEnds = [];
  var match;
  var foundLineNo = -1;
  while (match = re.exec(mark.buffer)) {
    lineEnds.push(match.index);
    lineStarts.push(match.index + match[0].length);
    if (mark.position <= match.index && foundLineNo < 0) {
      foundLineNo = lineStarts.length - 2;
    }
  }
  if (foundLineNo < 0) foundLineNo = lineStarts.length - 1;
  var result = "", i, line;
  var lineNoLength = Math.min(mark.line + options.linesAfter, lineEnds.length).toString().length;
  var maxLineLength = options.maxLength - (options.indent + lineNoLength + 3);
  for (i = 1; i <= options.linesBefore; i++) {
    if (foundLineNo - i < 0) break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo - i],
      lineEnds[foundLineNo - i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo - i]),
      maxLineLength
    );
    result = common.repeat(" ", options.indent) + padStart((mark.line - i + 1).toString(), lineNoLength) + " | " + line.str + "\n" + result;
  }
  line = getLine(mark.buffer, lineStarts[foundLineNo], lineEnds[foundLineNo], mark.position, maxLineLength);
  result += common.repeat(" ", options.indent) + padStart((mark.line + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  result += common.repeat("-", options.indent + lineNoLength + 3 + line.pos) + "^\n";
  for (i = 1; i <= options.linesAfter; i++) {
    if (foundLineNo + i >= lineEnds.length) break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo + i],
      lineEnds[foundLineNo + i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo + i]),
      maxLineLength
    );
    result += common.repeat(" ", options.indent) + padStart((mark.line + i + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  }
  return result.replace(/\n$/, "");
}
var snippet = makeSnippet;
var TYPE_CONSTRUCTOR_OPTIONS = [
  "kind",
  "multi",
  "resolve",
  "construct",
  "instanceOf",
  "predicate",
  "represent",
  "representName",
  "defaultStyle",
  "styleAliases"
];
var YAML_NODE_KINDS = [
  "scalar",
  "sequence",
  "mapping"
];
function compileStyleAliases(map2) {
  var result = {};
  if (map2 !== null) {
    Object.keys(map2).forEach(function(style) {
      map2[style].forEach(function(alias) {
        result[String(alias)] = style;
      });
    });
  }
  return result;
}
function Type$1(tag, options) {
  options = options || {};
  Object.keys(options).forEach(function(name) {
    if (TYPE_CONSTRUCTOR_OPTIONS.indexOf(name) === -1) {
      throw new exception('Unknown option "' + name + '" is met in definition of "' + tag + '" YAML type.');
    }
  });
  this.options = options;
  this.tag = tag;
  this.kind = options["kind"] || null;
  this.resolve = options["resolve"] || function() {
    return true;
  };
  this.construct = options["construct"] || function(data) {
    return data;
  };
  this.instanceOf = options["instanceOf"] || null;
  this.predicate = options["predicate"] || null;
  this.represent = options["represent"] || null;
  this.representName = options["representName"] || null;
  this.defaultStyle = options["defaultStyle"] || null;
  this.multi = options["multi"] || false;
  this.styleAliases = compileStyleAliases(options["styleAliases"] || null);
  if (YAML_NODE_KINDS.indexOf(this.kind) === -1) {
    throw new exception('Unknown kind "' + this.kind + '" is specified for "' + tag + '" YAML type.');
  }
}
var type = Type$1;
function compileList(schema2, name) {
  var result = [];
  schema2[name].forEach(function(currentType) {
    var newIndex = result.length;
    result.forEach(function(previousType, previousIndex) {
      if (previousType.tag === currentType.tag && previousType.kind === currentType.kind && previousType.multi === currentType.multi) {
        newIndex = previousIndex;
      }
    });
    result[newIndex] = currentType;
  });
  return result;
}
function compileMap() {
  var result = {
    scalar: {},
    sequence: {},
    mapping: {},
    fallback: {},
    multi: {
      scalar: [],
      sequence: [],
      mapping: [],
      fallback: []
    }
  }, index, length;
  function collectType(type2) {
    if (type2.multi) {
      result.multi[type2.kind].push(type2);
      result.multi["fallback"].push(type2);
    } else {
      result[type2.kind][type2.tag] = result["fallback"][type2.tag] = type2;
    }
  }
  for (index = 0, length = arguments.length; index < length; index += 1) {
    arguments[index].forEach(collectType);
  }
  return result;
}
function Schema$1(definition) {
  return this.extend(definition);
}
Schema$1.prototype.extend = function extend2(definition) {
  var implicit = [];
  var explicit = [];
  if (definition instanceof type) {
    explicit.push(definition);
  } else if (Array.isArray(definition)) {
    explicit = explicit.concat(definition);
  } else if (definition && (Array.isArray(definition.implicit) || Array.isArray(definition.explicit))) {
    if (definition.implicit) implicit = implicit.concat(definition.implicit);
    if (definition.explicit) explicit = explicit.concat(definition.explicit);
  } else {
    throw new exception("Schema.extend argument should be a Type, [ Type ], or a schema definition ({ implicit: [...], explicit: [...] })");
  }
  implicit.forEach(function(type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
    }
    if (type$1.loadKind && type$1.loadKind !== "scalar") {
      throw new exception("There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.");
    }
    if (type$1.multi) {
      throw new exception("There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.");
    }
  });
  explicit.forEach(function(type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
    }
  });
  var result = Object.create(Schema$1.prototype);
  result.implicit = (this.implicit || []).concat(implicit);
  result.explicit = (this.explicit || []).concat(explicit);
  result.compiledImplicit = compileList(result, "implicit");
  result.compiledExplicit = compileList(result, "explicit");
  result.compiledTypeMap = compileMap(result.compiledImplicit, result.compiledExplicit);
  return result;
};
var schema = Schema$1;
var str = new type("tag:yaml.org,2002:str", {
  kind: "scalar",
  construct: function(data) {
    return data !== null ? data : "";
  }
});
var seq = new type("tag:yaml.org,2002:seq", {
  kind: "sequence",
  construct: function(data) {
    return data !== null ? data : [];
  }
});
var map = new type("tag:yaml.org,2002:map", {
  kind: "mapping",
  construct: function(data) {
    return data !== null ? data : {};
  }
});
var failsafe = new schema({
  explicit: [
    str,
    seq,
    map
  ]
});
function resolveYamlNull(data) {
  if (data === null) return true;
  var max = data.length;
  return max === 1 && data === "~" || max === 4 && (data === "null" || data === "Null" || data === "NULL");
}
function constructYamlNull() {
  return null;
}
function isNull(object) {
  return object === null;
}
var _null = new type("tag:yaml.org,2002:null", {
  kind: "scalar",
  resolve: resolveYamlNull,
  construct: constructYamlNull,
  predicate: isNull,
  represent: {
    canonical: function() {
      return "~";
    },
    lowercase: function() {
      return "null";
    },
    uppercase: function() {
      return "NULL";
    },
    camelcase: function() {
      return "Null";
    },
    empty: function() {
      return "";
    }
  },
  defaultStyle: "lowercase"
});
function resolveYamlBoolean(data) {
  if (data === null) return false;
  var max = data.length;
  return max === 4 && (data === "true" || data === "True" || data === "TRUE") || max === 5 && (data === "false" || data === "False" || data === "FALSE");
}
function constructYamlBoolean(data) {
  return data === "true" || data === "True" || data === "TRUE";
}
function isBoolean(object) {
  return Object.prototype.toString.call(object) === "[object Boolean]";
}
var bool = new type("tag:yaml.org,2002:bool", {
  kind: "scalar",
  resolve: resolveYamlBoolean,
  construct: constructYamlBoolean,
  predicate: isBoolean,
  represent: {
    lowercase: function(object) {
      return object ? "true" : "false";
    },
    uppercase: function(object) {
      return object ? "TRUE" : "FALSE";
    },
    camelcase: function(object) {
      return object ? "True" : "False";
    }
  },
  defaultStyle: "lowercase"
});
function isHexCode(c) {
  return 48 <= c && c <= 57 || 65 <= c && c <= 70 || 97 <= c && c <= 102;
}
function isOctCode(c) {
  return 48 <= c && c <= 55;
}
function isDecCode(c) {
  return 48 <= c && c <= 57;
}
function resolveYamlInteger(data) {
  if (data === null) return false;
  var max = data.length, index = 0, hasDigits = false, ch;
  if (!max) return false;
  ch = data[index];
  if (ch === "-" || ch === "+") {
    ch = data[++index];
  }
  if (ch === "0") {
    if (index + 1 === max) return true;
    ch = data[++index];
    if (ch === "b") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_") continue;
        if (ch !== "0" && ch !== "1") return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "x") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_") continue;
        if (!isHexCode(data.charCodeAt(index))) return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "o") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_") continue;
        if (!isOctCode(data.charCodeAt(index))) return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
  }
  if (ch === "_") return false;
  for (; index < max; index++) {
    ch = data[index];
    if (ch === "_") continue;
    if (!isDecCode(data.charCodeAt(index))) {
      return false;
    }
    hasDigits = true;
  }
  if (!hasDigits || ch === "_") return false;
  return true;
}
function constructYamlInteger(data) {
  var value = data, sign = 1, ch;
  if (value.indexOf("_") !== -1) {
    value = value.replace(/_/g, "");
  }
  ch = value[0];
  if (ch === "-" || ch === "+") {
    if (ch === "-") sign = -1;
    value = value.slice(1);
    ch = value[0];
  }
  if (value === "0") return 0;
  if (ch === "0") {
    if (value[1] === "b") return sign * parseInt(value.slice(2), 2);
    if (value[1] === "x") return sign * parseInt(value.slice(2), 16);
    if (value[1] === "o") return sign * parseInt(value.slice(2), 8);
  }
  return sign * parseInt(value, 10);
}
function isInteger(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 === 0 && !common.isNegativeZero(object));
}
var int = new type("tag:yaml.org,2002:int", {
  kind: "scalar",
  resolve: resolveYamlInteger,
  construct: constructYamlInteger,
  predicate: isInteger,
  represent: {
    binary: function(obj) {
      return obj >= 0 ? "0b" + obj.toString(2) : "-0b" + obj.toString(2).slice(1);
    },
    octal: function(obj) {
      return obj >= 0 ? "0o" + obj.toString(8) : "-0o" + obj.toString(8).slice(1);
    },
    decimal: function(obj) {
      return obj.toString(10);
    },
    /* eslint-disable max-len */
    hexadecimal: function(obj) {
      return obj >= 0 ? "0x" + obj.toString(16).toUpperCase() : "-0x" + obj.toString(16).toUpperCase().slice(1);
    }
  },
  defaultStyle: "decimal",
  styleAliases: {
    binary: [2, "bin"],
    octal: [8, "oct"],
    decimal: [10, "dec"],
    hexadecimal: [16, "hex"]
  }
});
var YAML_FLOAT_PATTERN = new RegExp(
  // 2.5e4, 2.5 and integers
  "^(?:[-+]?(?:[0-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN))$"
);
function resolveYamlFloat(data) {
  if (data === null) return false;
  if (!YAML_FLOAT_PATTERN.test(data) || // Quick hack to not allow integers end with `_`
  // Probably should update regexp & check speed
  data[data.length - 1] === "_") {
    return false;
  }
  return true;
}
function constructYamlFloat(data) {
  var value, sign;
  value = data.replace(/_/g, "").toLowerCase();
  sign = value[0] === "-" ? -1 : 1;
  if ("+-".indexOf(value[0]) >= 0) {
    value = value.slice(1);
  }
  if (value === ".inf") {
    return sign === 1 ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
  } else if (value === ".nan") {
    return NaN;
  }
  return sign * parseFloat(value, 10);
}
var SCIENTIFIC_WITHOUT_DOT = /^[-+]?[0-9]+e/;
function representYamlFloat(object, style) {
  var res;
  if (isNaN(object)) {
    switch (style) {
      case "lowercase":
        return ".nan";
      case "uppercase":
        return ".NAN";
      case "camelcase":
        return ".NaN";
    }
  } else if (Number.POSITIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return ".inf";
      case "uppercase":
        return ".INF";
      case "camelcase":
        return ".Inf";
    }
  } else if (Number.NEGATIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return "-.inf";
      case "uppercase":
        return "-.INF";
      case "camelcase":
        return "-.Inf";
    }
  } else if (common.isNegativeZero(object)) {
    return "-0.0";
  }
  res = object.toString(10);
  return SCIENTIFIC_WITHOUT_DOT.test(res) ? res.replace("e", ".e") : res;
}
function isFloat(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 !== 0 || common.isNegativeZero(object));
}
var float = new type("tag:yaml.org,2002:float", {
  kind: "scalar",
  resolve: resolveYamlFloat,
  construct: constructYamlFloat,
  predicate: isFloat,
  represent: representYamlFloat,
  defaultStyle: "lowercase"
});
var json = failsafe.extend({
  implicit: [
    _null,
    bool,
    int,
    float
  ]
});
var core = json;
var YAML_DATE_REGEXP = new RegExp(
  "^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$"
);
var YAML_TIMESTAMP_REGEXP = new RegExp(
  "^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:[Tt]|[ \\t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\\.([0-9]*))?(?:[ \\t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?$"
);
function resolveYamlTimestamp(data) {
  if (data === null) return false;
  if (YAML_DATE_REGEXP.exec(data) !== null) return true;
  if (YAML_TIMESTAMP_REGEXP.exec(data) !== null) return true;
  return false;
}
function constructYamlTimestamp(data) {
  var match, year, month, day, hour, minute, second, fraction = 0, delta = null, tz_hour, tz_minute, date;
  match = YAML_DATE_REGEXP.exec(data);
  if (match === null) match = YAML_TIMESTAMP_REGEXP.exec(data);
  if (match === null) throw new Error("Date resolve error");
  year = +match[1];
  month = +match[2] - 1;
  day = +match[3];
  if (!match[4]) {
    return new Date(Date.UTC(year, month, day));
  }
  hour = +match[4];
  minute = +match[5];
  second = +match[6];
  if (match[7]) {
    fraction = match[7].slice(0, 3);
    while (fraction.length < 3) {
      fraction += "0";
    }
    fraction = +fraction;
  }
  if (match[9]) {
    tz_hour = +match[10];
    tz_minute = +(match[11] || 0);
    delta = (tz_hour * 60 + tz_minute) * 6e4;
    if (match[9] === "-") delta = -delta;
  }
  date = new Date(Date.UTC(year, month, day, hour, minute, second, fraction));
  if (delta) date.setTime(date.getTime() - delta);
  return date;
}
function representYamlTimestamp(object) {
  return object.toISOString();
}
var timestamp = new type("tag:yaml.org,2002:timestamp", {
  kind: "scalar",
  resolve: resolveYamlTimestamp,
  construct: constructYamlTimestamp,
  instanceOf: Date,
  represent: representYamlTimestamp
});
function resolveYamlMerge(data) {
  return data === "<<" || data === null;
}
var merge = new type("tag:yaml.org,2002:merge", {
  kind: "scalar",
  resolve: resolveYamlMerge
});
var BASE64_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r";
function resolveYamlBinary(data) {
  if (data === null) return false;
  var code, idx, bitlen = 0, max = data.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    code = map2.indexOf(data.charAt(idx));
    if (code > 64) continue;
    if (code < 0) return false;
    bitlen += 6;
  }
  return bitlen % 8 === 0;
}
function constructYamlBinary(data) {
  var idx, tailbits, input = data.replace(/[\r\n=]/g, ""), max = input.length, map2 = BASE64_MAP, bits = 0, result = [];
  for (idx = 0; idx < max; idx++) {
    if (idx % 4 === 0 && idx) {
      result.push(bits >> 16 & 255);
      result.push(bits >> 8 & 255);
      result.push(bits & 255);
    }
    bits = bits << 6 | map2.indexOf(input.charAt(idx));
  }
  tailbits = max % 4 * 6;
  if (tailbits === 0) {
    result.push(bits >> 16 & 255);
    result.push(bits >> 8 & 255);
    result.push(bits & 255);
  } else if (tailbits === 18) {
    result.push(bits >> 10 & 255);
    result.push(bits >> 2 & 255);
  } else if (tailbits === 12) {
    result.push(bits >> 4 & 255);
  }
  return new Uint8Array(result);
}
function representYamlBinary(object) {
  var result = "", bits = 0, idx, tail, max = object.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    if (idx % 3 === 0 && idx) {
      result += map2[bits >> 18 & 63];
      result += map2[bits >> 12 & 63];
      result += map2[bits >> 6 & 63];
      result += map2[bits & 63];
    }
    bits = (bits << 8) + object[idx];
  }
  tail = max % 3;
  if (tail === 0) {
    result += map2[bits >> 18 & 63];
    result += map2[bits >> 12 & 63];
    result += map2[bits >> 6 & 63];
    result += map2[bits & 63];
  } else if (tail === 2) {
    result += map2[bits >> 10 & 63];
    result += map2[bits >> 4 & 63];
    result += map2[bits << 2 & 63];
    result += map2[64];
  } else if (tail === 1) {
    result += map2[bits >> 2 & 63];
    result += map2[bits << 4 & 63];
    result += map2[64];
    result += map2[64];
  }
  return result;
}
function isBinary(obj) {
  return Object.prototype.toString.call(obj) === "[object Uint8Array]";
}
var binary = new type("tag:yaml.org,2002:binary", {
  kind: "scalar",
  resolve: resolveYamlBinary,
  construct: constructYamlBinary,
  predicate: isBinary,
  represent: representYamlBinary
});
var _hasOwnProperty$3 = Object.prototype.hasOwnProperty;
var _toString$2 = Object.prototype.toString;
function resolveYamlOmap(data) {
  if (data === null) return true;
  var objectKeys = [], index, length, pair, pairKey, pairHasKey, object = data;
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    pairHasKey = false;
    if (_toString$2.call(pair) !== "[object Object]") return false;
    for (pairKey in pair) {
      if (_hasOwnProperty$3.call(pair, pairKey)) {
        if (!pairHasKey) pairHasKey = true;
        else return false;
      }
    }
    if (!pairHasKey) return false;
    if (objectKeys.indexOf(pairKey) === -1) objectKeys.push(pairKey);
    else return false;
  }
  return true;
}
function constructYamlOmap(data) {
  return data !== null ? data : [];
}
var omap = new type("tag:yaml.org,2002:omap", {
  kind: "sequence",
  resolve: resolveYamlOmap,
  construct: constructYamlOmap
});
var _toString$1 = Object.prototype.toString;
function resolveYamlPairs(data) {
  if (data === null) return true;
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    if (_toString$1.call(pair) !== "[object Object]") return false;
    keys = Object.keys(pair);
    if (keys.length !== 1) return false;
    result[index] = [keys[0], pair[keys[0]]];
  }
  return true;
}
function constructYamlPairs(data) {
  if (data === null) return [];
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    keys = Object.keys(pair);
    result[index] = [keys[0], pair[keys[0]]];
  }
  return result;
}
var pairs = new type("tag:yaml.org,2002:pairs", {
  kind: "sequence",
  resolve: resolveYamlPairs,
  construct: constructYamlPairs
});
var _hasOwnProperty$2 = Object.prototype.hasOwnProperty;
function resolveYamlSet(data) {
  if (data === null) return true;
  var key, object = data;
  for (key in object) {
    if (_hasOwnProperty$2.call(object, key)) {
      if (object[key] !== null) return false;
    }
  }
  return true;
}
function constructYamlSet(data) {
  return data !== null ? data : {};
}
var set = new type("tag:yaml.org,2002:set", {
  kind: "mapping",
  resolve: resolveYamlSet,
  construct: constructYamlSet
});
var _default = core.extend({
  implicit: [
    timestamp,
    merge
  ],
  explicit: [
    binary,
    omap,
    pairs,
    set
  ]
});
var _hasOwnProperty$1 = Object.prototype.hasOwnProperty;
var CONTEXT_FLOW_IN = 1;
var CONTEXT_FLOW_OUT = 2;
var CONTEXT_BLOCK_IN = 3;
var CONTEXT_BLOCK_OUT = 4;
var CHOMPING_CLIP = 1;
var CHOMPING_STRIP = 2;
var CHOMPING_KEEP = 3;
var PATTERN_NON_PRINTABLE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
var PATTERN_NON_ASCII_LINE_BREAKS = /[\x85\u2028\u2029]/;
var PATTERN_FLOW_INDICATORS = /[,\[\]\{\}]/;
var PATTERN_TAG_HANDLE = /^(?:!|!!|![a-z\-]+!)$/i;
var PATTERN_TAG_URI = /^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;
function _class(obj) {
  return Object.prototype.toString.call(obj);
}
function is_EOL(c) {
  return c === 10 || c === 13;
}
function is_WHITE_SPACE(c) {
  return c === 9 || c === 32;
}
function is_WS_OR_EOL(c) {
  return c === 9 || c === 32 || c === 10 || c === 13;
}
function is_FLOW_INDICATOR(c) {
  return c === 44 || c === 91 || c === 93 || c === 123 || c === 125;
}
function fromHexCode(c) {
  var lc;
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  lc = c | 32;
  if (97 <= lc && lc <= 102) {
    return lc - 97 + 10;
  }
  return -1;
}
function escapedHexLen(c) {
  if (c === 120) {
    return 2;
  }
  if (c === 117) {
    return 4;
  }
  if (c === 85) {
    return 8;
  }
  return 0;
}
function fromDecimalCode(c) {
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  return -1;
}
function simpleEscapeSequence(c) {
  return c === 48 ? "\0" : c === 97 ? "\x07" : c === 98 ? "\b" : c === 116 ? "	" : c === 9 ? "	" : c === 110 ? "\n" : c === 118 ? "\v" : c === 102 ? "\f" : c === 114 ? "\r" : c === 101 ? "\x1B" : c === 32 ? " " : c === 34 ? '"' : c === 47 ? "/" : c === 92 ? "\\" : c === 78 ? "\x85" : c === 95 ? "\xA0" : c === 76 ? "\u2028" : c === 80 ? "\u2029" : "";
}
function charFromCodepoint(c) {
  if (c <= 65535) {
    return String.fromCharCode(c);
  }
  return String.fromCharCode(
    (c - 65536 >> 10) + 55296,
    (c - 65536 & 1023) + 56320
  );
}
function setProperty(object, key, value) {
  if (key === "__proto__") {
    Object.defineProperty(object, key, {
      configurable: true,
      enumerable: true,
      writable: true,
      value
    });
  } else {
    object[key] = value;
  }
}
var simpleEscapeCheck = new Array(256);
var simpleEscapeMap = new Array(256);
for (i = 0; i < 256; i++) {
  simpleEscapeCheck[i] = simpleEscapeSequence(i) ? 1 : 0;
  simpleEscapeMap[i] = simpleEscapeSequence(i);
}
var i;
function State$1(input, options) {
  this.input = input;
  this.filename = options["filename"] || null;
  this.schema = options["schema"] || _default;
  this.onWarning = options["onWarning"] || null;
  this.legacy = options["legacy"] || false;
  this.json = options["json"] || false;
  this.listener = options["listener"] || null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.typeMap = this.schema.compiledTypeMap;
  this.length = input.length;
  this.position = 0;
  this.line = 0;
  this.lineStart = 0;
  this.lineIndent = 0;
  this.firstTabInLine = -1;
  this.documents = [];
}
function generateError(state, message) {
  var mark = {
    name: state.filename,
    buffer: state.input.slice(0, -1),
    // omit trailing \0
    position: state.position,
    line: state.line,
    column: state.position - state.lineStart
  };
  mark.snippet = snippet(mark);
  return new exception(message, mark);
}
function throwError(state, message) {
  throw generateError(state, message);
}
function throwWarning(state, message) {
  if (state.onWarning) {
    state.onWarning.call(null, generateError(state, message));
  }
}
var directiveHandlers = {
  YAML: function handleYamlDirective(state, name, args) {
    var match, major, minor;
    if (state.version !== null) {
      throwError(state, "duplication of %YAML directive");
    }
    if (args.length !== 1) {
      throwError(state, "YAML directive accepts exactly one argument");
    }
    match = /^([0-9]+)\.([0-9]+)$/.exec(args[0]);
    if (match === null) {
      throwError(state, "ill-formed argument of the YAML directive");
    }
    major = parseInt(match[1], 10);
    minor = parseInt(match[2], 10);
    if (major !== 1) {
      throwError(state, "unacceptable YAML version of the document");
    }
    state.version = args[0];
    state.checkLineBreaks = minor < 2;
    if (minor !== 1 && minor !== 2) {
      throwWarning(state, "unsupported YAML version of the document");
    }
  },
  TAG: function handleTagDirective(state, name, args) {
    var handle, prefix;
    if (args.length !== 2) {
      throwError(state, "TAG directive accepts exactly two arguments");
    }
    handle = args[0];
    prefix = args[1];
    if (!PATTERN_TAG_HANDLE.test(handle)) {
      throwError(state, "ill-formed tag handle (first argument) of the TAG directive");
    }
    if (_hasOwnProperty$1.call(state.tagMap, handle)) {
      throwError(state, 'there is a previously declared suffix for "' + handle + '" tag handle');
    }
    if (!PATTERN_TAG_URI.test(prefix)) {
      throwError(state, "ill-formed tag prefix (second argument) of the TAG directive");
    }
    try {
      prefix = decodeURIComponent(prefix);
    } catch (err) {
      throwError(state, "tag prefix is malformed: " + prefix);
    }
    state.tagMap[handle] = prefix;
  }
};
function captureSegment(state, start, end, checkJson) {
  var _position, _length, _character, _result;
  if (start < end) {
    _result = state.input.slice(start, end);
    if (checkJson) {
      for (_position = 0, _length = _result.length; _position < _length; _position += 1) {
        _character = _result.charCodeAt(_position);
        if (!(_character === 9 || 32 <= _character && _character <= 1114111)) {
          throwError(state, "expected valid JSON character");
        }
      }
    } else if (PATTERN_NON_PRINTABLE.test(_result)) {
      throwError(state, "the stream contains non-printable characters");
    }
    state.result += _result;
  }
}
function mergeMappings(state, destination, source, overridableKeys) {
  var sourceKeys, key, index, quantity;
  if (!common.isObject(source)) {
    throwError(state, "cannot merge mappings; the provided source object is unacceptable");
  }
  sourceKeys = Object.keys(source);
  for (index = 0, quantity = sourceKeys.length; index < quantity; index += 1) {
    key = sourceKeys[index];
    if (!_hasOwnProperty$1.call(destination, key)) {
      setProperty(destination, key, source[key]);
      overridableKeys[key] = true;
    }
  }
}
function storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, startLine, startLineStart, startPos) {
  var index, quantity;
  if (Array.isArray(keyNode)) {
    keyNode = Array.prototype.slice.call(keyNode);
    for (index = 0, quantity = keyNode.length; index < quantity; index += 1) {
      if (Array.isArray(keyNode[index])) {
        throwError(state, "nested arrays are not supported inside keys");
      }
      if (typeof keyNode === "object" && _class(keyNode[index]) === "[object Object]") {
        keyNode[index] = "[object Object]";
      }
    }
  }
  if (typeof keyNode === "object" && _class(keyNode) === "[object Object]") {
    keyNode = "[object Object]";
  }
  keyNode = String(keyNode);
  if (_result === null) {
    _result = {};
  }
  if (keyTag === "tag:yaml.org,2002:merge") {
    if (Array.isArray(valueNode)) {
      for (index = 0, quantity = valueNode.length; index < quantity; index += 1) {
        mergeMappings(state, _result, valueNode[index], overridableKeys);
      }
    } else {
      mergeMappings(state, _result, valueNode, overridableKeys);
    }
  } else {
    if (!state.json && !_hasOwnProperty$1.call(overridableKeys, keyNode) && _hasOwnProperty$1.call(_result, keyNode)) {
      state.line = startLine || state.line;
      state.lineStart = startLineStart || state.lineStart;
      state.position = startPos || state.position;
      throwError(state, "duplicated mapping key");
    }
    setProperty(_result, keyNode, valueNode);
    delete overridableKeys[keyNode];
  }
  return _result;
}
function readLineBreak(state) {
  var ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 10) {
    state.position++;
  } else if (ch === 13) {
    state.position++;
    if (state.input.charCodeAt(state.position) === 10) {
      state.position++;
    }
  } else {
    throwError(state, "a line break is expected");
  }
  state.line += 1;
  state.lineStart = state.position;
  state.firstTabInLine = -1;
}
function skipSeparationSpace(state, allowComments, checkIndent) {
  var lineBreaks = 0, ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    while (is_WHITE_SPACE(ch)) {
      if (ch === 9 && state.firstTabInLine === -1) {
        state.firstTabInLine = state.position;
      }
      ch = state.input.charCodeAt(++state.position);
    }
    if (allowComments && ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (ch !== 10 && ch !== 13 && ch !== 0);
    }
    if (is_EOL(ch)) {
      readLineBreak(state);
      ch = state.input.charCodeAt(state.position);
      lineBreaks++;
      state.lineIndent = 0;
      while (ch === 32) {
        state.lineIndent++;
        ch = state.input.charCodeAt(++state.position);
      }
    } else {
      break;
    }
  }
  if (checkIndent !== -1 && lineBreaks !== 0 && state.lineIndent < checkIndent) {
    throwWarning(state, "deficient indentation");
  }
  return lineBreaks;
}
function testDocumentSeparator(state) {
  var _position = state.position, ch;
  ch = state.input.charCodeAt(_position);
  if ((ch === 45 || ch === 46) && ch === state.input.charCodeAt(_position + 1) && ch === state.input.charCodeAt(_position + 2)) {
    _position += 3;
    ch = state.input.charCodeAt(_position);
    if (ch === 0 || is_WS_OR_EOL(ch)) {
      return true;
    }
  }
  return false;
}
function writeFoldedLines(state, count) {
  if (count === 1) {
    state.result += " ";
  } else if (count > 1) {
    state.result += common.repeat("\n", count - 1);
  }
}
function readPlainScalar(state, nodeIndent, withinFlowCollection) {
  var preceding, following, captureStart, captureEnd, hasPendingContent, _line, _lineStart, _lineIndent, _kind = state.kind, _result = state.result, ch;
  ch = state.input.charCodeAt(state.position);
  if (is_WS_OR_EOL(ch) || is_FLOW_INDICATOR(ch) || ch === 35 || ch === 38 || ch === 42 || ch === 33 || ch === 124 || ch === 62 || ch === 39 || ch === 34 || ch === 37 || ch === 64 || ch === 96) {
    return false;
  }
  if (ch === 63 || ch === 45) {
    following = state.input.charCodeAt(state.position + 1);
    if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
      return false;
    }
  }
  state.kind = "scalar";
  state.result = "";
  captureStart = captureEnd = state.position;
  hasPendingContent = false;
  while (ch !== 0) {
    if (ch === 58) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
        break;
      }
    } else if (ch === 35) {
      preceding = state.input.charCodeAt(state.position - 1);
      if (is_WS_OR_EOL(preceding)) {
        break;
      }
    } else if (state.position === state.lineStart && testDocumentSeparator(state) || withinFlowCollection && is_FLOW_INDICATOR(ch)) {
      break;
    } else if (is_EOL(ch)) {
      _line = state.line;
      _lineStart = state.lineStart;
      _lineIndent = state.lineIndent;
      skipSeparationSpace(state, false, -1);
      if (state.lineIndent >= nodeIndent) {
        hasPendingContent = true;
        ch = state.input.charCodeAt(state.position);
        continue;
      } else {
        state.position = captureEnd;
        state.line = _line;
        state.lineStart = _lineStart;
        state.lineIndent = _lineIndent;
        break;
      }
    }
    if (hasPendingContent) {
      captureSegment(state, captureStart, captureEnd, false);
      writeFoldedLines(state, state.line - _line);
      captureStart = captureEnd = state.position;
      hasPendingContent = false;
    }
    if (!is_WHITE_SPACE(ch)) {
      captureEnd = state.position + 1;
    }
    ch = state.input.charCodeAt(++state.position);
  }
  captureSegment(state, captureStart, captureEnd, false);
  if (state.result) {
    return true;
  }
  state.kind = _kind;
  state.result = _result;
  return false;
}
function readSingleQuotedScalar(state, nodeIndent) {
  var ch, captureStart, captureEnd;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 39) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 39) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (ch === 39) {
        captureStart = state.position;
        state.position++;
        captureEnd = state.position;
      } else {
        return true;
      }
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a single quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a single quoted scalar");
}
function readDoubleQuotedScalar(state, nodeIndent) {
  var captureStart, captureEnd, hexLength, hexResult, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 34) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 34) {
      captureSegment(state, captureStart, state.position, true);
      state.position++;
      return true;
    } else if (ch === 92) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (is_EOL(ch)) {
        skipSeparationSpace(state, false, nodeIndent);
      } else if (ch < 256 && simpleEscapeCheck[ch]) {
        state.result += simpleEscapeMap[ch];
        state.position++;
      } else if ((tmp = escapedHexLen(ch)) > 0) {
        hexLength = tmp;
        hexResult = 0;
        for (; hexLength > 0; hexLength--) {
          ch = state.input.charCodeAt(++state.position);
          if ((tmp = fromHexCode(ch)) >= 0) {
            hexResult = (hexResult << 4) + tmp;
          } else {
            throwError(state, "expected hexadecimal character");
          }
        }
        state.result += charFromCodepoint(hexResult);
        state.position++;
      } else {
        throwError(state, "unknown escape sequence");
      }
      captureStart = captureEnd = state.position;
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a double quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a double quoted scalar");
}
function readFlowCollection(state, nodeIndent) {
  var readNext = true, _line, _lineStart, _pos, _tag = state.tag, _result, _anchor = state.anchor, following, terminator, isPair, isExplicitPair, isMapping, overridableKeys = /* @__PURE__ */ Object.create(null), keyNode, keyTag, valueNode, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 91) {
    terminator = 93;
    isMapping = false;
    _result = [];
  } else if (ch === 123) {
    terminator = 125;
    isMapping = true;
    _result = {};
  } else {
    return false;
  }
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(++state.position);
  while (ch !== 0) {
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === terminator) {
      state.position++;
      state.tag = _tag;
      state.anchor = _anchor;
      state.kind = isMapping ? "mapping" : "sequence";
      state.result = _result;
      return true;
    } else if (!readNext) {
      throwError(state, "missed comma between flow collection entries");
    } else if (ch === 44) {
      throwError(state, "expected the node content, but found ','");
    }
    keyTag = keyNode = valueNode = null;
    isPair = isExplicitPair = false;
    if (ch === 63) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following)) {
        isPair = isExplicitPair = true;
        state.position++;
        skipSeparationSpace(state, true, nodeIndent);
      }
    }
    _line = state.line;
    _lineStart = state.lineStart;
    _pos = state.position;
    composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
    keyTag = state.tag;
    keyNode = state.result;
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if ((isExplicitPair || state.line === _line) && ch === 58) {
      isPair = true;
      ch = state.input.charCodeAt(++state.position);
      skipSeparationSpace(state, true, nodeIndent);
      composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
      valueNode = state.result;
    }
    if (isMapping) {
      storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos);
    } else if (isPair) {
      _result.push(storeMappingPair(state, null, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos));
    } else {
      _result.push(keyNode);
    }
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === 44) {
      readNext = true;
      ch = state.input.charCodeAt(++state.position);
    } else {
      readNext = false;
    }
  }
  throwError(state, "unexpected end of the stream within a flow collection");
}
function readBlockScalar(state, nodeIndent) {
  var captureStart, folding, chomping = CHOMPING_CLIP, didReadContent = false, detectedIndent = false, textIndent = nodeIndent, emptyLines = 0, atMoreIndented = false, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 124) {
    folding = false;
  } else if (ch === 62) {
    folding = true;
  } else {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  while (ch !== 0) {
    ch = state.input.charCodeAt(++state.position);
    if (ch === 43 || ch === 45) {
      if (CHOMPING_CLIP === chomping) {
        chomping = ch === 43 ? CHOMPING_KEEP : CHOMPING_STRIP;
      } else {
        throwError(state, "repeat of a chomping mode identifier");
      }
    } else if ((tmp = fromDecimalCode(ch)) >= 0) {
      if (tmp === 0) {
        throwError(state, "bad explicit indentation width of a block scalar; it cannot be less than one");
      } else if (!detectedIndent) {
        textIndent = nodeIndent + tmp - 1;
        detectedIndent = true;
      } else {
        throwError(state, "repeat of an indentation width identifier");
      }
    } else {
      break;
    }
  }
  if (is_WHITE_SPACE(ch)) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (is_WHITE_SPACE(ch));
    if (ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (!is_EOL(ch) && ch !== 0);
    }
  }
  while (ch !== 0) {
    readLineBreak(state);
    state.lineIndent = 0;
    ch = state.input.charCodeAt(state.position);
    while ((!detectedIndent || state.lineIndent < textIndent) && ch === 32) {
      state.lineIndent++;
      ch = state.input.charCodeAt(++state.position);
    }
    if (!detectedIndent && state.lineIndent > textIndent) {
      textIndent = state.lineIndent;
    }
    if (is_EOL(ch)) {
      emptyLines++;
      continue;
    }
    if (state.lineIndent < textIndent) {
      if (chomping === CHOMPING_KEEP) {
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (chomping === CHOMPING_CLIP) {
        if (didReadContent) {
          state.result += "\n";
        }
      }
      break;
    }
    if (folding) {
      if (is_WHITE_SPACE(ch)) {
        atMoreIndented = true;
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (atMoreIndented) {
        atMoreIndented = false;
        state.result += common.repeat("\n", emptyLines + 1);
      } else if (emptyLines === 0) {
        if (didReadContent) {
          state.result += " ";
        }
      } else {
        state.result += common.repeat("\n", emptyLines);
      }
    } else {
      state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
    }
    didReadContent = true;
    detectedIndent = true;
    emptyLines = 0;
    captureStart = state.position;
    while (!is_EOL(ch) && ch !== 0) {
      ch = state.input.charCodeAt(++state.position);
    }
    captureSegment(state, captureStart, state.position, false);
  }
  return true;
}
function readBlockSequence(state, nodeIndent) {
  var _line, _tag = state.tag, _anchor = state.anchor, _result = [], following, detected = false, ch;
  if (state.firstTabInLine !== -1) return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    if (ch !== 45) {
      break;
    }
    following = state.input.charCodeAt(state.position + 1);
    if (!is_WS_OR_EOL(following)) {
      break;
    }
    detected = true;
    state.position++;
    if (skipSeparationSpace(state, true, -1)) {
      if (state.lineIndent <= nodeIndent) {
        _result.push(null);
        ch = state.input.charCodeAt(state.position);
        continue;
      }
    }
    _line = state.line;
    composeNode(state, nodeIndent, CONTEXT_BLOCK_IN, false, true);
    _result.push(state.result);
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a sequence entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "sequence";
    state.result = _result;
    return true;
  }
  return false;
}
function readBlockMapping(state, nodeIndent, flowIndent) {
  var following, allowCompact, _line, _keyLine, _keyLineStart, _keyPos, _tag = state.tag, _anchor = state.anchor, _result = {}, overridableKeys = /* @__PURE__ */ Object.create(null), keyTag = null, keyNode = null, valueNode = null, atExplicitKey = false, detected = false, ch;
  if (state.firstTabInLine !== -1) return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (!atExplicitKey && state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    following = state.input.charCodeAt(state.position + 1);
    _line = state.line;
    if ((ch === 63 || ch === 58) && is_WS_OR_EOL(following)) {
      if (ch === 63) {
        if (atExplicitKey) {
          storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
          keyTag = keyNode = valueNode = null;
        }
        detected = true;
        atExplicitKey = true;
        allowCompact = true;
      } else if (atExplicitKey) {
        atExplicitKey = false;
        allowCompact = true;
      } else {
        throwError(state, "incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line");
      }
      state.position += 1;
      ch = following;
    } else {
      _keyLine = state.line;
      _keyLineStart = state.lineStart;
      _keyPos = state.position;
      if (!composeNode(state, flowIndent, CONTEXT_FLOW_OUT, false, true)) {
        break;
      }
      if (state.line === _line) {
        ch = state.input.charCodeAt(state.position);
        while (is_WHITE_SPACE(ch)) {
          ch = state.input.charCodeAt(++state.position);
        }
        if (ch === 58) {
          ch = state.input.charCodeAt(++state.position);
          if (!is_WS_OR_EOL(ch)) {
            throwError(state, "a whitespace character is expected after the key-value separator within a block mapping");
          }
          if (atExplicitKey) {
            storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
            keyTag = keyNode = valueNode = null;
          }
          detected = true;
          atExplicitKey = false;
          allowCompact = false;
          keyTag = state.tag;
          keyNode = state.result;
        } else if (detected) {
          throwError(state, "can not read an implicit mapping pair; a colon is missed");
        } else {
          state.tag = _tag;
          state.anchor = _anchor;
          return true;
        }
      } else if (detected) {
        throwError(state, "can not read a block mapping entry; a multiline key may not be an implicit key");
      } else {
        state.tag = _tag;
        state.anchor = _anchor;
        return true;
      }
    }
    if (state.line === _line || state.lineIndent > nodeIndent) {
      if (atExplicitKey) {
        _keyLine = state.line;
        _keyLineStart = state.lineStart;
        _keyPos = state.position;
      }
      if (composeNode(state, nodeIndent, CONTEXT_BLOCK_OUT, true, allowCompact)) {
        if (atExplicitKey) {
          keyNode = state.result;
        } else {
          valueNode = state.result;
        }
      }
      if (!atExplicitKey) {
        storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _keyLine, _keyLineStart, _keyPos);
        keyTag = keyNode = valueNode = null;
      }
      skipSeparationSpace(state, true, -1);
      ch = state.input.charCodeAt(state.position);
    }
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a mapping entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (atExplicitKey) {
    storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "mapping";
    state.result = _result;
  }
  return detected;
}
function readTagProperty(state) {
  var _position, isVerbatim = false, isNamed = false, tagHandle, tagName, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 33) return false;
  if (state.tag !== null) {
    throwError(state, "duplication of a tag property");
  }
  ch = state.input.charCodeAt(++state.position);
  if (ch === 60) {
    isVerbatim = true;
    ch = state.input.charCodeAt(++state.position);
  } else if (ch === 33) {
    isNamed = true;
    tagHandle = "!!";
    ch = state.input.charCodeAt(++state.position);
  } else {
    tagHandle = "!";
  }
  _position = state.position;
  if (isVerbatim) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (ch !== 0 && ch !== 62);
    if (state.position < state.length) {
      tagName = state.input.slice(_position, state.position);
      ch = state.input.charCodeAt(++state.position);
    } else {
      throwError(state, "unexpected end of the stream within a verbatim tag");
    }
  } else {
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      if (ch === 33) {
        if (!isNamed) {
          tagHandle = state.input.slice(_position - 1, state.position + 1);
          if (!PATTERN_TAG_HANDLE.test(tagHandle)) {
            throwError(state, "named tag handle cannot contain such characters");
          }
          isNamed = true;
          _position = state.position + 1;
        } else {
          throwError(state, "tag suffix cannot contain exclamation marks");
        }
      }
      ch = state.input.charCodeAt(++state.position);
    }
    tagName = state.input.slice(_position, state.position);
    if (PATTERN_FLOW_INDICATORS.test(tagName)) {
      throwError(state, "tag suffix cannot contain flow indicator characters");
    }
  }
  if (tagName && !PATTERN_TAG_URI.test(tagName)) {
    throwError(state, "tag name cannot contain such characters: " + tagName);
  }
  try {
    tagName = decodeURIComponent(tagName);
  } catch (err) {
    throwError(state, "tag name is malformed: " + tagName);
  }
  if (isVerbatim) {
    state.tag = tagName;
  } else if (_hasOwnProperty$1.call(state.tagMap, tagHandle)) {
    state.tag = state.tagMap[tagHandle] + tagName;
  } else if (tagHandle === "!") {
    state.tag = "!" + tagName;
  } else if (tagHandle === "!!") {
    state.tag = "tag:yaml.org,2002:" + tagName;
  } else {
    throwError(state, 'undeclared tag handle "' + tagHandle + '"');
  }
  return true;
}
function readAnchorProperty(state) {
  var _position, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 38) return false;
  if (state.anchor !== null) {
    throwError(state, "duplication of an anchor property");
  }
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an anchor node must contain at least one character");
  }
  state.anchor = state.input.slice(_position, state.position);
  return true;
}
function readAlias(state) {
  var _position, alias, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 42) return false;
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an alias node must contain at least one character");
  }
  alias = state.input.slice(_position, state.position);
  if (!_hasOwnProperty$1.call(state.anchorMap, alias)) {
    throwError(state, 'unidentified alias "' + alias + '"');
  }
  state.result = state.anchorMap[alias];
  skipSeparationSpace(state, true, -1);
  return true;
}
function composeNode(state, parentIndent, nodeContext, allowToSeek, allowCompact) {
  var allowBlockStyles, allowBlockScalars, allowBlockCollections, indentStatus = 1, atNewLine = false, hasContent = false, typeIndex, typeQuantity, typeList, type2, flowIndent, blockIndent;
  if (state.listener !== null) {
    state.listener("open", state);
  }
  state.tag = null;
  state.anchor = null;
  state.kind = null;
  state.result = null;
  allowBlockStyles = allowBlockScalars = allowBlockCollections = CONTEXT_BLOCK_OUT === nodeContext || CONTEXT_BLOCK_IN === nodeContext;
  if (allowToSeek) {
    if (skipSeparationSpace(state, true, -1)) {
      atNewLine = true;
      if (state.lineIndent > parentIndent) {
        indentStatus = 1;
      } else if (state.lineIndent === parentIndent) {
        indentStatus = 0;
      } else if (state.lineIndent < parentIndent) {
        indentStatus = -1;
      }
    }
  }
  if (indentStatus === 1) {
    while (readTagProperty(state) || readAnchorProperty(state)) {
      if (skipSeparationSpace(state, true, -1)) {
        atNewLine = true;
        allowBlockCollections = allowBlockStyles;
        if (state.lineIndent > parentIndent) {
          indentStatus = 1;
        } else if (state.lineIndent === parentIndent) {
          indentStatus = 0;
        } else if (state.lineIndent < parentIndent) {
          indentStatus = -1;
        }
      } else {
        allowBlockCollections = false;
      }
    }
  }
  if (allowBlockCollections) {
    allowBlockCollections = atNewLine || allowCompact;
  }
  if (indentStatus === 1 || CONTEXT_BLOCK_OUT === nodeContext) {
    if (CONTEXT_FLOW_IN === nodeContext || CONTEXT_FLOW_OUT === nodeContext) {
      flowIndent = parentIndent;
    } else {
      flowIndent = parentIndent + 1;
    }
    blockIndent = state.position - state.lineStart;
    if (indentStatus === 1) {
      if (allowBlockCollections && (readBlockSequence(state, blockIndent) || readBlockMapping(state, blockIndent, flowIndent)) || readFlowCollection(state, flowIndent)) {
        hasContent = true;
      } else {
        if (allowBlockScalars && readBlockScalar(state, flowIndent) || readSingleQuotedScalar(state, flowIndent) || readDoubleQuotedScalar(state, flowIndent)) {
          hasContent = true;
        } else if (readAlias(state)) {
          hasContent = true;
          if (state.tag !== null || state.anchor !== null) {
            throwError(state, "alias node should not have any properties");
          }
        } else if (readPlainScalar(state, flowIndent, CONTEXT_FLOW_IN === nodeContext)) {
          hasContent = true;
          if (state.tag === null) {
            state.tag = "?";
          }
        }
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
      }
    } else if (indentStatus === 0) {
      hasContent = allowBlockCollections && readBlockSequence(state, blockIndent);
    }
  }
  if (state.tag === null) {
    if (state.anchor !== null) {
      state.anchorMap[state.anchor] = state.result;
    }
  } else if (state.tag === "?") {
    if (state.result !== null && state.kind !== "scalar") {
      throwError(state, 'unacceptable node kind for !<?> tag; it should be "scalar", not "' + state.kind + '"');
    }
    for (typeIndex = 0, typeQuantity = state.implicitTypes.length; typeIndex < typeQuantity; typeIndex += 1) {
      type2 = state.implicitTypes[typeIndex];
      if (type2.resolve(state.result)) {
        state.result = type2.construct(state.result);
        state.tag = type2.tag;
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
        break;
      }
    }
  } else if (state.tag !== "!") {
    if (_hasOwnProperty$1.call(state.typeMap[state.kind || "fallback"], state.tag)) {
      type2 = state.typeMap[state.kind || "fallback"][state.tag];
    } else {
      type2 = null;
      typeList = state.typeMap.multi[state.kind || "fallback"];
      for (typeIndex = 0, typeQuantity = typeList.length; typeIndex < typeQuantity; typeIndex += 1) {
        if (state.tag.slice(0, typeList[typeIndex].tag.length) === typeList[typeIndex].tag) {
          type2 = typeList[typeIndex];
          break;
        }
      }
    }
    if (!type2) {
      throwError(state, "unknown tag !<" + state.tag + ">");
    }
    if (state.result !== null && type2.kind !== state.kind) {
      throwError(state, "unacceptable node kind for !<" + state.tag + '> tag; it should be "' + type2.kind + '", not "' + state.kind + '"');
    }
    if (!type2.resolve(state.result, state.tag)) {
      throwError(state, "cannot resolve a node with !<" + state.tag + "> explicit tag");
    } else {
      state.result = type2.construct(state.result, state.tag);
      if (state.anchor !== null) {
        state.anchorMap[state.anchor] = state.result;
      }
    }
  }
  if (state.listener !== null) {
    state.listener("close", state);
  }
  return state.tag !== null || state.anchor !== null || hasContent;
}
function readDocument(state) {
  var documentStart = state.position, _position, directiveName, directiveArgs, hasDirectives = false, ch;
  state.version = null;
  state.checkLineBreaks = state.legacy;
  state.tagMap = /* @__PURE__ */ Object.create(null);
  state.anchorMap = /* @__PURE__ */ Object.create(null);
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if (state.lineIndent > 0 || ch !== 37) {
      break;
    }
    hasDirectives = true;
    ch = state.input.charCodeAt(++state.position);
    _position = state.position;
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      ch = state.input.charCodeAt(++state.position);
    }
    directiveName = state.input.slice(_position, state.position);
    directiveArgs = [];
    if (directiveName.length < 1) {
      throwError(state, "directive name must not be less than one character in length");
    }
    while (ch !== 0) {
      while (is_WHITE_SPACE(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      if (ch === 35) {
        do {
          ch = state.input.charCodeAt(++state.position);
        } while (ch !== 0 && !is_EOL(ch));
        break;
      }
      if (is_EOL(ch)) break;
      _position = state.position;
      while (ch !== 0 && !is_WS_OR_EOL(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      directiveArgs.push(state.input.slice(_position, state.position));
    }
    if (ch !== 0) readLineBreak(state);
    if (_hasOwnProperty$1.call(directiveHandlers, directiveName)) {
      directiveHandlers[directiveName](state, directiveName, directiveArgs);
    } else {
      throwWarning(state, 'unknown document directive "' + directiveName + '"');
    }
  }
  skipSeparationSpace(state, true, -1);
  if (state.lineIndent === 0 && state.input.charCodeAt(state.position) === 45 && state.input.charCodeAt(state.position + 1) === 45 && state.input.charCodeAt(state.position + 2) === 45) {
    state.position += 3;
    skipSeparationSpace(state, true, -1);
  } else if (hasDirectives) {
    throwError(state, "directives end mark is expected");
  }
  composeNode(state, state.lineIndent - 1, CONTEXT_BLOCK_OUT, false, true);
  skipSeparationSpace(state, true, -1);
  if (state.checkLineBreaks && PATTERN_NON_ASCII_LINE_BREAKS.test(state.input.slice(documentStart, state.position))) {
    throwWarning(state, "non-ASCII line breaks are interpreted as content");
  }
  state.documents.push(state.result);
  if (state.position === state.lineStart && testDocumentSeparator(state)) {
    if (state.input.charCodeAt(state.position) === 46) {
      state.position += 3;
      skipSeparationSpace(state, true, -1);
    }
    return;
  }
  if (state.position < state.length - 1) {
    throwError(state, "end of the stream or a document separator is expected");
  } else {
    return;
  }
}
function loadDocuments(input, options) {
  input = String(input);
  options = options || {};
  if (input.length !== 0) {
    if (input.charCodeAt(input.length - 1) !== 10 && input.charCodeAt(input.length - 1) !== 13) {
      input += "\n";
    }
    if (input.charCodeAt(0) === 65279) {
      input = input.slice(1);
    }
  }
  var state = new State$1(input, options);
  var nullpos = input.indexOf("\0");
  if (nullpos !== -1) {
    state.position = nullpos;
    throwError(state, "null byte is not allowed in input");
  }
  state.input += "\0";
  while (state.input.charCodeAt(state.position) === 32) {
    state.lineIndent += 1;
    state.position += 1;
  }
  while (state.position < state.length - 1) {
    readDocument(state);
  }
  return state.documents;
}
function loadAll$1(input, iterator, options) {
  if (iterator !== null && typeof iterator === "object" && typeof options === "undefined") {
    options = iterator;
    iterator = null;
  }
  var documents = loadDocuments(input, options);
  if (typeof iterator !== "function") {
    return documents;
  }
  for (var index = 0, length = documents.length; index < length; index += 1) {
    iterator(documents[index]);
  }
}
function load$1(input, options) {
  var documents = loadDocuments(input, options);
  if (documents.length === 0) {
    return void 0;
  } else if (documents.length === 1) {
    return documents[0];
  }
  throw new exception("expected a single document in the stream, but found more");
}
var loadAll_1 = loadAll$1;
var load_1 = load$1;
var loader = {
  loadAll: loadAll_1,
  load: load_1
};
var _toString = Object.prototype.toString;
var _hasOwnProperty = Object.prototype.hasOwnProperty;
var CHAR_BOM = 65279;
var CHAR_TAB = 9;
var CHAR_LINE_FEED = 10;
var CHAR_CARRIAGE_RETURN = 13;
var CHAR_SPACE = 32;
var CHAR_EXCLAMATION = 33;
var CHAR_DOUBLE_QUOTE = 34;
var CHAR_SHARP = 35;
var CHAR_PERCENT = 37;
var CHAR_AMPERSAND = 38;
var CHAR_SINGLE_QUOTE = 39;
var CHAR_ASTERISK = 42;
var CHAR_COMMA = 44;
var CHAR_MINUS = 45;
var CHAR_COLON = 58;
var CHAR_EQUALS = 61;
var CHAR_GREATER_THAN = 62;
var CHAR_QUESTION = 63;
var CHAR_COMMERCIAL_AT = 64;
var CHAR_LEFT_SQUARE_BRACKET = 91;
var CHAR_RIGHT_SQUARE_BRACKET = 93;
var CHAR_GRAVE_ACCENT = 96;
var CHAR_LEFT_CURLY_BRACKET = 123;
var CHAR_VERTICAL_LINE = 124;
var CHAR_RIGHT_CURLY_BRACKET = 125;
var ESCAPE_SEQUENCES = {};
ESCAPE_SEQUENCES[0] = "\\0";
ESCAPE_SEQUENCES[7] = "\\a";
ESCAPE_SEQUENCES[8] = "\\b";
ESCAPE_SEQUENCES[9] = "\\t";
ESCAPE_SEQUENCES[10] = "\\n";
ESCAPE_SEQUENCES[11] = "\\v";
ESCAPE_SEQUENCES[12] = "\\f";
ESCAPE_SEQUENCES[13] = "\\r";
ESCAPE_SEQUENCES[27] = "\\e";
ESCAPE_SEQUENCES[34] = '\\"';
ESCAPE_SEQUENCES[92] = "\\\\";
ESCAPE_SEQUENCES[133] = "\\N";
ESCAPE_SEQUENCES[160] = "\\_";
ESCAPE_SEQUENCES[8232] = "\\L";
ESCAPE_SEQUENCES[8233] = "\\P";
var DEPRECATED_BOOLEANS_SYNTAX = [
  "y",
  "Y",
  "yes",
  "Yes",
  "YES",
  "on",
  "On",
  "ON",
  "n",
  "N",
  "no",
  "No",
  "NO",
  "off",
  "Off",
  "OFF"
];
var DEPRECATED_BASE60_SYNTAX = /^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/;
function compileStyleMap(schema2, map2) {
  var result, keys, index, length, tag, style, type2;
  if (map2 === null) return {};
  result = {};
  keys = Object.keys(map2);
  for (index = 0, length = keys.length; index < length; index += 1) {
    tag = keys[index];
    style = String(map2[tag]);
    if (tag.slice(0, 2) === "!!") {
      tag = "tag:yaml.org,2002:" + tag.slice(2);
    }
    type2 = schema2.compiledTypeMap["fallback"][tag];
    if (type2 && _hasOwnProperty.call(type2.styleAliases, style)) {
      style = type2.styleAliases[style];
    }
    result[tag] = style;
  }
  return result;
}
function encodeHex(character) {
  var string, handle, length;
  string = character.toString(16).toUpperCase();
  if (character <= 255) {
    handle = "x";
    length = 2;
  } else if (character <= 65535) {
    handle = "u";
    length = 4;
  } else if (character <= 4294967295) {
    handle = "U";
    length = 8;
  } else {
    throw new exception("code point within a string may not be greater than 0xFFFFFFFF");
  }
  return "\\" + handle + common.repeat("0", length - string.length) + string;
}
var QUOTING_TYPE_SINGLE = 1;
var QUOTING_TYPE_DOUBLE = 2;
function State(options) {
  this.schema = options["schema"] || _default;
  this.indent = Math.max(1, options["indent"] || 2);
  this.noArrayIndent = options["noArrayIndent"] || false;
  this.skipInvalid = options["skipInvalid"] || false;
  this.flowLevel = common.isNothing(options["flowLevel"]) ? -1 : options["flowLevel"];
  this.styleMap = compileStyleMap(this.schema, options["styles"] || null);
  this.sortKeys = options["sortKeys"] || false;
  this.lineWidth = options["lineWidth"] || 80;
  this.noRefs = options["noRefs"] || false;
  this.noCompatMode = options["noCompatMode"] || false;
  this.condenseFlow = options["condenseFlow"] || false;
  this.quotingType = options["quotingType"] === '"' ? QUOTING_TYPE_DOUBLE : QUOTING_TYPE_SINGLE;
  this.forceQuotes = options["forceQuotes"] || false;
  this.replacer = typeof options["replacer"] === "function" ? options["replacer"] : null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.explicitTypes = this.schema.compiledExplicit;
  this.tag = null;
  this.result = "";
  this.duplicates = [];
  this.usedDuplicates = null;
}
function indentString(string, spaces) {
  var ind = common.repeat(" ", spaces), position = 0, next = -1, result = "", line, length = string.length;
  while (position < length) {
    next = string.indexOf("\n", position);
    if (next === -1) {
      line = string.slice(position);
      position = length;
    } else {
      line = string.slice(position, next + 1);
      position = next + 1;
    }
    if (line.length && line !== "\n") result += ind;
    result += line;
  }
  return result;
}
function generateNextLine(state, level) {
  return "\n" + common.repeat(" ", state.indent * level);
}
function testImplicitResolving(state, str2) {
  var index, length, type2;
  for (index = 0, length = state.implicitTypes.length; index < length; index += 1) {
    type2 = state.implicitTypes[index];
    if (type2.resolve(str2)) {
      return true;
    }
  }
  return false;
}
function isWhitespace(c) {
  return c === CHAR_SPACE || c === CHAR_TAB;
}
function isPrintable(c) {
  return 32 <= c && c <= 126 || 161 <= c && c <= 55295 && c !== 8232 && c !== 8233 || 57344 <= c && c <= 65533 && c !== CHAR_BOM || 65536 <= c && c <= 1114111;
}
function isNsCharOrWhitespace(c) {
  return isPrintable(c) && c !== CHAR_BOM && c !== CHAR_CARRIAGE_RETURN && c !== CHAR_LINE_FEED;
}
function isPlainSafe(c, prev, inblock) {
  var cIsNsCharOrWhitespace = isNsCharOrWhitespace(c);
  var cIsNsChar = cIsNsCharOrWhitespace && !isWhitespace(c);
  return (
    // ns-plain-safe
    (inblock ? (
      // c = flow-in
      cIsNsCharOrWhitespace
    ) : cIsNsCharOrWhitespace && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET) && c !== CHAR_SHARP && !(prev === CHAR_COLON && !cIsNsChar) || isNsCharOrWhitespace(prev) && !isWhitespace(prev) && c === CHAR_SHARP || prev === CHAR_COLON && cIsNsChar
  );
}
function isPlainSafeFirst(c) {
  return isPrintable(c) && c !== CHAR_BOM && !isWhitespace(c) && c !== CHAR_MINUS && c !== CHAR_QUESTION && c !== CHAR_COLON && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET && c !== CHAR_SHARP && c !== CHAR_AMPERSAND && c !== CHAR_ASTERISK && c !== CHAR_EXCLAMATION && c !== CHAR_VERTICAL_LINE && c !== CHAR_EQUALS && c !== CHAR_GREATER_THAN && c !== CHAR_SINGLE_QUOTE && c !== CHAR_DOUBLE_QUOTE && c !== CHAR_PERCENT && c !== CHAR_COMMERCIAL_AT && c !== CHAR_GRAVE_ACCENT;
}
function isPlainSafeLast(c) {
  return !isWhitespace(c) && c !== CHAR_COLON;
}
function codePointAt(string, pos) {
  var first = string.charCodeAt(pos), second;
  if (first >= 55296 && first <= 56319 && pos + 1 < string.length) {
    second = string.charCodeAt(pos + 1);
    if (second >= 56320 && second <= 57343) {
      return (first - 55296) * 1024 + second - 56320 + 65536;
    }
  }
  return first;
}
function needIndentIndicator(string) {
  var leadingSpaceRe = /^\n* /;
  return leadingSpaceRe.test(string);
}
var STYLE_PLAIN = 1;
var STYLE_SINGLE = 2;
var STYLE_LITERAL = 3;
var STYLE_FOLDED = 4;
var STYLE_DOUBLE = 5;
function chooseScalarStyle(string, singleLineOnly, indentPerLevel, lineWidth, testAmbiguousType, quotingType, forceQuotes, inblock) {
  var i;
  var char = 0;
  var prevChar = null;
  var hasLineBreak = false;
  var hasFoldableLine = false;
  var shouldTrackWidth = lineWidth !== -1;
  var previousLineBreak = -1;
  var plain = isPlainSafeFirst(codePointAt(string, 0)) && isPlainSafeLast(codePointAt(string, string.length - 1));
  if (singleLineOnly || forceQuotes) {
    for (i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
  } else {
    for (i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (char === CHAR_LINE_FEED) {
        hasLineBreak = true;
        if (shouldTrackWidth) {
          hasFoldableLine = hasFoldableLine || // Foldable line = too long, and not more-indented.
          i - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ";
          previousLineBreak = i;
        }
      } else if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
    hasFoldableLine = hasFoldableLine || shouldTrackWidth && (i - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ");
  }
  if (!hasLineBreak && !hasFoldableLine) {
    if (plain && !forceQuotes && !testAmbiguousType(string)) {
      return STYLE_PLAIN;
    }
    return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
  }
  if (indentPerLevel > 9 && needIndentIndicator(string)) {
    return STYLE_DOUBLE;
  }
  if (!forceQuotes) {
    return hasFoldableLine ? STYLE_FOLDED : STYLE_LITERAL;
  }
  return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
}
function writeScalar(state, string, level, iskey, inblock) {
  state.dump = (function() {
    if (string.length === 0) {
      return state.quotingType === QUOTING_TYPE_DOUBLE ? '""' : "''";
    }
    if (!state.noCompatMode) {
      if (DEPRECATED_BOOLEANS_SYNTAX.indexOf(string) !== -1 || DEPRECATED_BASE60_SYNTAX.test(string)) {
        return state.quotingType === QUOTING_TYPE_DOUBLE ? '"' + string + '"' : "'" + string + "'";
      }
    }
    var indent = state.indent * Math.max(1, level);
    var lineWidth = state.lineWidth === -1 ? -1 : Math.max(Math.min(state.lineWidth, 40), state.lineWidth - indent);
    var singleLineOnly = iskey || state.flowLevel > -1 && level >= state.flowLevel;
    function testAmbiguity(string2) {
      return testImplicitResolving(state, string2);
    }
    switch (chooseScalarStyle(
      string,
      singleLineOnly,
      state.indent,
      lineWidth,
      testAmbiguity,
      state.quotingType,
      state.forceQuotes && !iskey,
      inblock
    )) {
      case STYLE_PLAIN:
        return string;
      case STYLE_SINGLE:
        return "'" + string.replace(/'/g, "''") + "'";
      case STYLE_LITERAL:
        return "|" + blockHeader(string, state.indent) + dropEndingNewline(indentString(string, indent));
      case STYLE_FOLDED:
        return ">" + blockHeader(string, state.indent) + dropEndingNewline(indentString(foldString(string, lineWidth), indent));
      case STYLE_DOUBLE:
        return '"' + escapeString(string) + '"';
      default:
        throw new exception("impossible error: invalid scalar style");
    }
  })();
}
function blockHeader(string, indentPerLevel) {
  var indentIndicator = needIndentIndicator(string) ? String(indentPerLevel) : "";
  var clip = string[string.length - 1] === "\n";
  var keep = clip && (string[string.length - 2] === "\n" || string === "\n");
  var chomp = keep ? "+" : clip ? "" : "-";
  return indentIndicator + chomp + "\n";
}
function dropEndingNewline(string) {
  return string[string.length - 1] === "\n" ? string.slice(0, -1) : string;
}
function foldString(string, width) {
  var lineRe = /(\n+)([^\n]*)/g;
  var result = (function() {
    var nextLF = string.indexOf("\n");
    nextLF = nextLF !== -1 ? nextLF : string.length;
    lineRe.lastIndex = nextLF;
    return foldLine(string.slice(0, nextLF), width);
  })();
  var prevMoreIndented = string[0] === "\n" || string[0] === " ";
  var moreIndented;
  var match;
  while (match = lineRe.exec(string)) {
    var prefix = match[1], line = match[2];
    moreIndented = line[0] === " ";
    result += prefix + (!prevMoreIndented && !moreIndented && line !== "" ? "\n" : "") + foldLine(line, width);
    prevMoreIndented = moreIndented;
  }
  return result;
}
function foldLine(line, width) {
  if (line === "" || line[0] === " ") return line;
  var breakRe = / [^ ]/g;
  var match;
  var start = 0, end, curr = 0, next = 0;
  var result = "";
  while (match = breakRe.exec(line)) {
    next = match.index;
    if (next - start > width) {
      end = curr > start ? curr : next;
      result += "\n" + line.slice(start, end);
      start = end + 1;
    }
    curr = next;
  }
  result += "\n";
  if (line.length - start > width && curr > start) {
    result += line.slice(start, curr) + "\n" + line.slice(curr + 1);
  } else {
    result += line.slice(start);
  }
  return result.slice(1);
}
function escapeString(string) {
  var result = "";
  var char = 0;
  var escapeSeq;
  for (var i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
    char = codePointAt(string, i);
    escapeSeq = ESCAPE_SEQUENCES[char];
    if (!escapeSeq && isPrintable(char)) {
      result += string[i];
      if (char >= 65536) result += string[i + 1];
    } else {
      result += escapeSeq || encodeHex(char);
    }
  }
  return result;
}
function writeFlowSequence(state, level, object) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level, value, false, false) || typeof value === "undefined" && writeNode(state, level, null, false, false)) {
      if (_result !== "") _result += "," + (!state.condenseFlow ? " " : "");
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = "[" + _result + "]";
}
function writeBlockSequence(state, level, object, compact) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level + 1, value, true, true, false, true) || typeof value === "undefined" && writeNode(state, level + 1, null, true, true, false, true)) {
      if (!compact || _result !== "") {
        _result += generateNextLine(state, level);
      }
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        _result += "-";
      } else {
        _result += "- ";
      }
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = _result || "[]";
}
function writeFlowMapping(state, level, object) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, pairBuffer;
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (_result !== "") pairBuffer += ", ";
    if (state.condenseFlow) pairBuffer += '"';
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level, objectKey, false, false)) {
      continue;
    }
    if (state.dump.length > 1024) pairBuffer += "? ";
    pairBuffer += state.dump + (state.condenseFlow ? '"' : "") + ":" + (state.condenseFlow ? "" : " ");
    if (!writeNode(state, level, objectValue, false, false)) {
      continue;
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = "{" + _result + "}";
}
function writeBlockMapping(state, level, object, compact) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, explicitPair, pairBuffer;
  if (state.sortKeys === true) {
    objectKeyList.sort();
  } else if (typeof state.sortKeys === "function") {
    objectKeyList.sort(state.sortKeys);
  } else if (state.sortKeys) {
    throw new exception("sortKeys must be a boolean or a function");
  }
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (!compact || _result !== "") {
      pairBuffer += generateNextLine(state, level);
    }
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level + 1, objectKey, true, true, true)) {
      continue;
    }
    explicitPair = state.tag !== null && state.tag !== "?" || state.dump && state.dump.length > 1024;
    if (explicitPair) {
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        pairBuffer += "?";
      } else {
        pairBuffer += "? ";
      }
    }
    pairBuffer += state.dump;
    if (explicitPair) {
      pairBuffer += generateNextLine(state, level);
    }
    if (!writeNode(state, level + 1, objectValue, true, explicitPair)) {
      continue;
    }
    if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
      pairBuffer += ":";
    } else {
      pairBuffer += ": ";
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = _result || "{}";
}
function detectType(state, object, explicit) {
  var _result, typeList, index, length, type2, style;
  typeList = explicit ? state.explicitTypes : state.implicitTypes;
  for (index = 0, length = typeList.length; index < length; index += 1) {
    type2 = typeList[index];
    if ((type2.instanceOf || type2.predicate) && (!type2.instanceOf || typeof object === "object" && object instanceof type2.instanceOf) && (!type2.predicate || type2.predicate(object))) {
      if (explicit) {
        if (type2.multi && type2.representName) {
          state.tag = type2.representName(object);
        } else {
          state.tag = type2.tag;
        }
      } else {
        state.tag = "?";
      }
      if (type2.represent) {
        style = state.styleMap[type2.tag] || type2.defaultStyle;
        if (_toString.call(type2.represent) === "[object Function]") {
          _result = type2.represent(object, style);
        } else if (_hasOwnProperty.call(type2.represent, style)) {
          _result = type2.represent[style](object, style);
        } else {
          throw new exception("!<" + type2.tag + '> tag resolver accepts not "' + style + '" style');
        }
        state.dump = _result;
      }
      return true;
    }
  }
  return false;
}
function writeNode(state, level, object, block, compact, iskey, isblockseq) {
  state.tag = null;
  state.dump = object;
  if (!detectType(state, object, false)) {
    detectType(state, object, true);
  }
  var type2 = _toString.call(state.dump);
  var inblock = block;
  var tagStr;
  if (block) {
    block = state.flowLevel < 0 || state.flowLevel > level;
  }
  var objectOrArray = type2 === "[object Object]" || type2 === "[object Array]", duplicateIndex, duplicate;
  if (objectOrArray) {
    duplicateIndex = state.duplicates.indexOf(object);
    duplicate = duplicateIndex !== -1;
  }
  if (state.tag !== null && state.tag !== "?" || duplicate || state.indent !== 2 && level > 0) {
    compact = false;
  }
  if (duplicate && state.usedDuplicates[duplicateIndex]) {
    state.dump = "*ref_" + duplicateIndex;
  } else {
    if (objectOrArray && duplicate && !state.usedDuplicates[duplicateIndex]) {
      state.usedDuplicates[duplicateIndex] = true;
    }
    if (type2 === "[object Object]") {
      if (block && Object.keys(state.dump).length !== 0) {
        writeBlockMapping(state, level, state.dump, compact);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowMapping(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object Array]") {
      if (block && state.dump.length !== 0) {
        if (state.noArrayIndent && !isblockseq && level > 0) {
          writeBlockSequence(state, level - 1, state.dump, compact);
        } else {
          writeBlockSequence(state, level, state.dump, compact);
        }
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowSequence(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object String]") {
      if (state.tag !== "?") {
        writeScalar(state, state.dump, level, iskey, inblock);
      }
    } else if (type2 === "[object Undefined]") {
      return false;
    } else {
      if (state.skipInvalid) return false;
      throw new exception("unacceptable kind of an object to dump " + type2);
    }
    if (state.tag !== null && state.tag !== "?") {
      tagStr = encodeURI(
        state.tag[0] === "!" ? state.tag.slice(1) : state.tag
      ).replace(/!/g, "%21");
      if (state.tag[0] === "!") {
        tagStr = "!" + tagStr;
      } else if (tagStr.slice(0, 18) === "tag:yaml.org,2002:") {
        tagStr = "!!" + tagStr.slice(18);
      } else {
        tagStr = "!<" + tagStr + ">";
      }
      state.dump = tagStr + " " + state.dump;
    }
  }
  return true;
}
function getDuplicateReferences(object, state) {
  var objects = [], duplicatesIndexes = [], index, length;
  inspectNode(object, objects, duplicatesIndexes);
  for (index = 0, length = duplicatesIndexes.length; index < length; index += 1) {
    state.duplicates.push(objects[duplicatesIndexes[index]]);
  }
  state.usedDuplicates = new Array(length);
}
function inspectNode(object, objects, duplicatesIndexes) {
  var objectKeyList, index, length;
  if (object !== null && typeof object === "object") {
    index = objects.indexOf(object);
    if (index !== -1) {
      if (duplicatesIndexes.indexOf(index) === -1) {
        duplicatesIndexes.push(index);
      }
    } else {
      objects.push(object);
      if (Array.isArray(object)) {
        for (index = 0, length = object.length; index < length; index += 1) {
          inspectNode(object[index], objects, duplicatesIndexes);
        }
      } else {
        objectKeyList = Object.keys(object);
        for (index = 0, length = objectKeyList.length; index < length; index += 1) {
          inspectNode(object[objectKeyList[index]], objects, duplicatesIndexes);
        }
      }
    }
  }
}
function dump$1(input, options) {
  options = options || {};
  var state = new State(options);
  if (!state.noRefs) getDuplicateReferences(input, state);
  var value = input;
  if (state.replacer) {
    value = state.replacer.call({ "": value }, "", value);
  }
  if (writeNode(state, 0, value, true, true)) return state.dump + "\n";
  return "";
}
var dump_1 = dump$1;
var dumper = {
  dump: dump_1
};
function renamed(from, to) {
  return function() {
    throw new Error("Function yaml." + from + " is removed in js-yaml 4. Use yaml." + to + " instead, which is now safe by default.");
  };
}
var Type = type;
var Schema = schema;
var FAILSAFE_SCHEMA = failsafe;
var JSON_SCHEMA = json;
var CORE_SCHEMA = core;
var DEFAULT_SCHEMA = _default;
var load = loader.load;
var loadAll = loader.loadAll;
var dump = dumper.dump;
var YAMLException = exception;
var types = {
  binary,
  float,
  map,
  null: _null,
  pairs,
  set,
  timestamp,
  bool,
  int,
  merge,
  omap,
  seq,
  str
};
var safeLoad = renamed("safeLoad", "load");
var safeLoadAll = renamed("safeLoadAll", "loadAll");
var safeDump = renamed("safeDump", "dump");
var jsYaml = {
  Type,
  Schema,
  FAILSAFE_SCHEMA,
  JSON_SCHEMA,
  CORE_SCHEMA,
  DEFAULT_SCHEMA,
  load,
  loadAll,
  dump,
  YAMLException,
  types,
  safeLoad,
  safeLoadAll,
  safeDump
};

// src/utils/sanitize.ts
var DANGEROUS_KEYS = /* @__PURE__ */ new Set(["__proto__", "constructor", "prototype"]);
function safeJsonParse(content) {
  return JSON.parse(stripBom(content), (key, value) => {
    if (DANGEROUS_KEYS.has(key)) return void 0;
    return value;
  });
}
function stripBom(content) {
  return content.replace(/^\uFEFF/, "");
}
function isValidLockfilePath(pathKey) {
  if (pathKey === "") return true;
  if (pathKey.includes("\0")) return false;
  if (pathKey.includes("\\")) return false;
  if (pathKey.includes("..")) return false;
  return true;
}
var GHSA_RE = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
var CVE_RE = /^CVE-\d{4}-\d{4,}$/;
var MAL_RE = /^MAL-\d{4}-\d+$/;
function isValidAdvisoryId(id) {
  return GHSA_RE.test(id) || CVE_RE.test(id) || MAL_RE.test(id) || id.startsWith("PYSEC-") || id.startsWith("RUSTSEC-");
}
function stripProtoKeys(value, seen = /* @__PURE__ */ new WeakSet()) {
  if (value === null || typeof value !== "object") return value;
  const node = value;
  if (seen.has(node)) return value;
  seen.add(node);
  if (Array.isArray(value)) {
    for (const item of value) stripProtoKeys(item, seen);
    return value;
  }
  for (const key of Object.keys(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      delete value[key];
      continue;
    }
    stripProtoKeys(value[key], seen);
  }
  return value;
}
function safeYamlParse(content) {
  const parsed = jsYaml.load(stripBom(content), {
    schema: jsYaml.DEFAULT_SCHEMA,
    json: true
  });
  return stripProtoKeys(parsed);
}

// src/utils/semver.ts
var import_semver = __toESM(require_semver2(), 1);
var MAX_VERSION_LENGTH = 256;
var PRERELEASE_OPTS = { includePrerelease: true };
function isValidVersion(version) {
  if (version.length > MAX_VERSION_LENGTH) return false;
  return import_semver.default.valid(version) !== null;
}
function satisfies(version, range) {
  if (!isValidVersion(version)) return false;
  try {
    return import_semver.default.satisfies(version, range, PRERELEASE_OPTS);
  } catch {
    return false;
  }
}
function compileRange(range) {
  try {
    return new import_semver.default.Range(range, PRERELEASE_OPTS);
  } catch {
    return null;
  }
}
function testRange(version, range) {
  if (!isValidVersion(version)) return false;
  try {
    return range.test(version);
  } catch {
    return false;
  }
}

// src/core/lockfile/npm.ts
var import_semver3 = __toESM(require_semver2(), 1);
function parseNpmLockfile(content) {
  const lockfile = safeJsonParse(content);
  if (!lockfile.lockfileVersion || lockfile.lockfileVersion < 2) {
    throw new Error(
      `Unsupported npm lockfile version ${lockfile.lockfileVersion}. auditfix requires lockfileVersion 2 or 3. Run \`npm install\` with npm 7+ to upgrade.`
    );
  }
  const type2 = lockfile.lockfileVersion >= 3 ? "npm-v3" : "npm-v2";
  const packages = lockfile.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error('Invalid lockfile: missing "packages" field.');
  }
  const graph = /* @__PURE__ */ new Map();
  const skipped = [];
  for (const [pathKey, entry] of Object.entries(packages)) {
    if (pathKey === "") continue;
    if (!isValidLockfilePath(pathKey)) {
      skipped.push({ key: pathKey, reason: "unparseable" });
      continue;
    }
    if (entry.link) {
      skipped.push({ key: pathKey, reason: "local-file" });
      continue;
    }
    const resolved = entry.resolved ?? "";
    if (resolved.startsWith("git+") || resolved.startsWith("git://")) {
      skipped.push({ key: pathKey, reason: "git-dep" });
      continue;
    }
    if (resolved.startsWith("file:")) {
      skipped.push({ key: pathKey, reason: "local-file" });
      continue;
    }
    const version = entry.version;
    if (!version) {
      skipped.push({ key: pathKey, reason: "unparseable" });
      continue;
    }
    const name = entry.name ?? extractPackageName(pathKey);
    if (name && (name.includes("..") || name.includes("\0") || name.includes("\\"))) {
      skipped.push({ key: pathKey, reason: "invalid-name" });
      continue;
    }
    if (!isValidVersion(version)) {
      skipped.push({ key: pathKey, reason: "unparseable" });
      continue;
    }
    const graphKey = `${name}@${version}`;
    const isDev = entry.dev === true;
    const isOptional = entry.optional === true;
    const isDevOptional = entry.devOptional === true;
    const isProduction = !isDev && !isOptional && !isDevOptional;
    const node = {
      name,
      version,
      resolved,
      integrity: entry.integrity ?? "",
      dependencies: [],
      // populated in second pass
      isProduction,
      isDev: isDev || isDevOptional,
      isOptional,
      depth: countDepth(pathKey),
      dependencyPath: []
      // populated later if needed
    };
    const existing = graph.get(graphKey);
    if (existing) {
      if (isProduction && !existing.isProduction) {
        existing.isProduction = true;
        existing.isDev = false;
      }
    } else {
      graph.set(graphKey, node);
    }
  }
  const nameIndex = /* @__PURE__ */ new Map();
  for (const [graphKey, node] of graph) {
    const keys = nameIndex.get(node.name);
    if (keys) {
      keys.push(graphKey);
    } else {
      nameIndex.set(node.name, [graphKey]);
    }
  }
  for (const [pathKey, entry] of Object.entries(packages)) {
    if (pathKey === "" || !entry.version) continue;
    const name = entry.name ?? extractPackageName(pathKey);
    const graphKey = `${name}@${entry.version}`;
    const node = graph.get(graphKey);
    if (!node) continue;
    if (entry.dependencies) {
      for (const [depName, depRange] of Object.entries(entry.dependencies)) {
        const resolvedDep = findResolvedDep(graph, nameIndex, depName, depRange);
        if (resolvedDep) {
          node.dependencies.push(resolvedDep);
        }
      }
    }
  }
  return { type: type2, graph, skipped };
}
function extractPackageName(pathKey) {
  const parts = pathKey.split("node_modules/");
  const last = parts[parts.length - 1];
  return last.endsWith("/") ? last.slice(0, -1) : last;
}
function countDepth(pathKey) {
  return (pathKey.match(/node_modules\//g) || []).length;
}
function findResolvedDep(graph, nameIndex, name, range) {
  const candidates = nameIndex.get(name);
  if (!candidates || candidates.length === 0) return null;
  for (const key of candidates) {
    const node = graph.get(key);
    if (!node) continue;
    if (satisfiesRange(node.version, range)) {
      return key;
    }
  }
  const versions = candidates.map((k) => graph.get(k)?.version).filter((v) => typeof v === "string");
  let best = null;
  try {
    best = import_semver3.default.maxSatisfying(versions, range, { includePrerelease: true });
  } catch {
    best = null;
  }
  if (!best) return null;
  for (const key of candidates) {
    const node = graph.get(key);
    if (node?.version === best) return key;
  }
  return null;
}
function satisfiesRange(version, range) {
  try {
    return import_semver3.default.satisfies(version, range, { includePrerelease: true });
  } catch {
    return false;
  }
}

// src/core/lockfile/yarn-classic.ts
import { createRequire } from "module";

// src/utils/logger.ts
var LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};
var TOKEN_PATTERNS = [
  /gh[ps]_[A-Za-z0-9_]{36,}/g,
  /github_pat_[A-Za-z0-9_]{82,}/g,
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /Authorization:\s*[^\s]+/gi,
  /npm_[A-Za-z0-9]{36,}/g,
  // npm tokens
  /glpat-[A-Za-z0-9_-]{20,}/g,
  // GitLab PATs
  /AKIA[A-Z0-9]{16}/g
  // AWS access keys
];
function redact(message) {
  let result = message;
  for (const pattern of TOKEN_PATTERNS) {
    result = result.replace(pattern, "[REDACTED]");
  }
  return result;
}
var currentLevel = "info";
function shouldLog(level) {
  return LOG_LEVELS[level] >= LOG_LEVELS[currentLevel];
}
function debug(message) {
  if (shouldLog("debug")) {
    console.error(redact(`[debug] ${message}`));
  }
}
function info(message) {
  if (shouldLog("info")) {
    console.error(redact(`[info] ${message}`));
  }
}
function warn(message) {
  if (shouldLog("warn")) {
    console.error(redact(`[warn] ${message}`));
  }
}
function error(message) {
  if (shouldLog("error")) {
    console.error(redact(`[error] ${message}`));
  }
}

// src/core/lockfile/yarn-classic.ts
var require2 = createRequire(import.meta.url);
var { parse: parseYarnLock } = require2("@yarnpkg/lockfile");
function parseYarnClassicLockfile(content, manifest) {
  const result = parseYarnLock(content);
  if (result.type !== "success") {
    throw new Error("Failed to parse yarn.lock: invalid format or merge conflict markers present.");
  }
  const entries = result.object;
  const graph = /* @__PURE__ */ new Map();
  const skipped = [];
  const versionMap = /* @__PURE__ */ new Map();
  for (const [requestKey, entry] of Object.entries(entries)) {
    const name = extractNameFromRequestKey(requestKey);
    if (!name) {
      skipped.push({ key: requestKey, reason: "unparseable" });
      continue;
    }
    const version = entry.version;
    if (!version || !isValidVersion(version)) {
      skipped.push({ key: requestKey, reason: "unparseable" });
      continue;
    }
    const resolved = entry.resolved ?? "";
    if (resolved.startsWith("git+") || resolved.startsWith("git://") || resolved.includes("#commit=")) {
      skipped.push({ key: requestKey, reason: "git-dep" });
      continue;
    }
    if (resolved.startsWith("file:") || resolved.startsWith("link:")) {
      skipped.push({ key: requestKey, reason: "local-file" });
      continue;
    }
    const graphKey = `${name}@${version}`;
    if (!versionMap.has(name)) {
      versionMap.set(name, /* @__PURE__ */ new Set());
    }
    versionMap.get(name).add(version);
    if (graph.has(graphKey)) continue;
    const node = {
      name,
      version,
      resolved,
      integrity: entry.integrity ?? "",
      dependencies: [],
      isProduction: false,
      // set in reachability pass
      isDev: false,
      isOptional: false,
      depth: 0,
      // set in reachability pass
      dependencyPath: []
    };
    graph.set(graphKey, node);
  }
  const nameIndex = /* @__PURE__ */ new Map();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }
  const processed = /* @__PURE__ */ new Set();
  for (const [requestKey, entry] of Object.entries(entries)) {
    const name = extractNameFromRequestKey(requestKey);
    if (!name || !entry.version) continue;
    const graphKey = `${name}@${entry.version}`;
    if (processed.has(graphKey)) continue;
    processed.add(graphKey);
    const node = graph.get(graphKey);
    if (!node) continue;
    const seen = new Set(node.dependencies);
    const pushEdge = (depName, depRange) => {
      const depKey = `${depName}@${depRange}`;
      const depEntry = entries[depKey];
      if (!depEntry?.version) return;
      const depGraphKey = `${depName}@${depEntry.version}`;
      if (graph.has(depGraphKey) && !seen.has(depGraphKey)) {
        seen.add(depGraphKey);
        node.dependencies.push(depGraphKey);
      }
    };
    if (entry.dependencies) {
      for (const [depName, depRange] of Object.entries(entry.dependencies)) {
        pushEdge(depName, depRange);
      }
    }
    if (entry.optionalDependencies) {
      for (const [depName, depRange] of Object.entries(entry.optionalDependencies)) {
        pushEdge(depName, depRange);
      }
    }
  }
  classifyReachability(graph, entries, manifest, nameIndex);
  return { graph, skipped };
}
function extractNameFromRequestKey(requestKey) {
  const key = requestKey.split(",")[0].trim();
  if (key.startsWith("@")) {
    const atIdx2 = key.indexOf("@", 1);
    if (atIdx2 === -1) return null;
    return key.slice(0, atIdx2);
  }
  const atIdx = key.indexOf("@");
  if (atIdx === -1) return null;
  return key.slice(0, atIdx);
}
function classifyReachability(graph, entries, manifest, _nameIndex) {
  const prodRoots = Object.entries(manifest.dependencies ?? {});
  const devRoots = Object.entries(manifest.devDependencies ?? {});
  const optionalRoots = Object.entries(manifest.optionalDependencies ?? {});
  function resolveRoot(name, range) {
    const entryKey = `${name}@${range}`;
    const entry = entries[entryKey];
    if (entry?.version) {
      const graphKey = `${name}@${entry.version}`;
      return graph.has(graphKey) ? graphKey : null;
    }
    for (const [requestKey, e] of Object.entries(entries)) {
      if (!e?.version) continue;
      const parts = requestKey.split(",").map((s) => s.trim());
      if (parts.includes(entryKey)) {
        const graphKey = `${name}@${e.version}`;
        return graph.has(graphKey) ? graphKey : null;
      }
    }
    return null;
  }
  function bfs(roots, markFn) {
    const visited = /* @__PURE__ */ new Set();
    const queue = [];
    for (const [name, range] of roots) {
      const key = resolveRoot(name, range);
      if (key && !visited.has(key)) {
        visited.add(key);
        queue.push({ key, depth: 1 });
      }
    }
    let qi = 0;
    while (qi < queue.length) {
      const { key, depth } = queue[qi++];
      const node = graph.get(key);
      if (!node) continue;
      markFn(node);
      if (node.depth === 0 || depth < node.depth) {
        node.depth = depth;
      }
      for (const depKey of node.dependencies) {
        if (!visited.has(depKey)) {
          visited.add(depKey);
          queue.push({ key: depKey, depth: depth + 1 });
        }
      }
    }
  }
  bfs(prodRoots, (node) => {
    node.isProduction = true;
  });
  bfs(optionalRoots, (node) => {
    node.isOptional = true;
  });
  bfs(devRoots, (node) => {
    if (!node.isProduction) {
      node.isDev = true;
    }
  });
  for (const node of graph.values()) {
    if (!node.isProduction && !node.isDev && !node.isOptional) {
      node.isDev = true;
    }
  }
  debug(`Yarn reachability: ${[...graph.values()].filter((n) => n.isProduction).length} prod, ${[...graph.values()].filter((n) => n.isDev).length} dev`);
}

// src/core/lockfile/yarn-berry.ts
var MAX_KEY_LENGTH = 1024;
function parseYarnBerryLockfile(content, manifest) {
  const raw = safeYamlParse(content);
  if (!raw || typeof raw !== "object") {
    throw new Error("Failed to parse yarn.lock: invalid YAML format.");
  }
  const graph = /* @__PURE__ */ new Map();
  const skipped = [];
  const requestToGraph = /* @__PURE__ */ new Map();
  for (const [requestKey, entry] of Object.entries(raw)) {
    if (requestKey.startsWith("__")) continue;
    if (requestKey.length > MAX_KEY_LENGTH) {
      warn(`yarn-berry: skipping oversized request key (${requestKey.length} bytes, max ${MAX_KEY_LENGTH})`);
      skipped.push({ key: requestKey.slice(0, 80) + "...", reason: "unparseable" });
      continue;
    }
    if (!entry || typeof entry !== "object" || !entry.version) {
      skipped.push({ key: requestKey, reason: "unparseable" });
      continue;
    }
    const name = extractNameFromBerryKey(requestKey, entry.resolution);
    if (!name) {
      skipped.push({ key: requestKey, reason: "unparseable" });
      continue;
    }
    const version = entry.version;
    if (!isValidVersion(version)) {
      skipped.push({ key: requestKey, reason: "unparseable" });
      continue;
    }
    const resolution = entry.resolution ?? "";
    if (resolution.includes("@workspace:") || resolution.startsWith("workspace:")) {
      skipped.push({ key: requestKey, reason: "workspace" });
      continue;
    }
    if (resolution.includes("@git+") || resolution.includes("@git://")) {
      skipped.push({ key: requestKey, reason: "git-dep" });
      continue;
    }
    if (resolution.includes("@file:") || resolution.includes("@link:") || resolution.includes("@portal:")) {
      skipped.push({ key: requestKey, reason: "local-file" });
      continue;
    }
    const graphKey = `${name}@${version}`;
    for (const rk of requestKey.split(",")) {
      requestToGraph.set(rk.trim(), graphKey);
    }
    if (graph.has(graphKey)) continue;
    const node = {
      name,
      version,
      resolved: resolution,
      integrity: entry.checksum ?? "",
      dependencies: [],
      isProduction: false,
      isDev: false,
      isOptional: false,
      depth: 0,
      dependencyPath: []
    };
    graph.set(graphKey, node);
  }
  const nameIndex = /* @__PURE__ */ new Map();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }
  const processed = /* @__PURE__ */ new Set();
  for (const [requestKey, entry] of Object.entries(raw)) {
    if (requestKey.startsWith("__") || !entry?.version) continue;
    if (requestKey.length > MAX_KEY_LENGTH) continue;
    const name = extractNameFromBerryKey(requestKey, entry.resolution);
    if (!name) continue;
    const graphKey = `${name}@${entry.version}`;
    if (processed.has(graphKey)) continue;
    processed.add(graphKey);
    const node = graph.get(graphKey);
    if (!node) continue;
    const seen = new Set(node.dependencies);
    if (entry.dependencies) {
      for (const [depName, depRange] of Object.entries(entry.dependencies)) {
        const cleanRange = depRange.startsWith("npm:") ? depRange.slice(4) : depRange;
        const lookupKey = `${depName}@npm:${cleanRange}`;
        let depGraphKey = requestToGraph.get(lookupKey);
        if (!depGraphKey) {
          const bucket = nameIndex.get(depName);
          if (bucket && bucket.length > 0) depGraphKey = bucket[0];
        }
        if (depGraphKey && graph.has(depGraphKey) && !seen.has(depGraphKey)) {
          seen.add(depGraphKey);
          node.dependencies.push(depGraphKey);
        }
      }
    }
  }
  classifyReachability2(graph, requestToGraph, manifest, nameIndex);
  return { graph, skipped };
}
function extractNameFromBerryKey(requestKey, resolution) {
  const key = requestKey.split(",")[0].trim();
  const cleaned = key.replace(/^"|"$/g, "");
  const protocols = ["@npm:", "@patch:", "@workspace:", "@git+", "@file:", "@link:", "@portal:"];
  for (const proto2 of protocols) {
    const idx = cleaned.indexOf(proto2);
    if (idx !== -1) {
      const name = cleaned.slice(0, idx);
      return name || null;
    }
  }
  if (resolution) {
    const resMatch = resolution.match(/^(@?[^@]+)@/);
    if (resMatch) return resMatch[1];
  }
  return null;
}
function classifyReachability2(graph, requestToGraph, manifest, _nameIndex) {
  function resolveRoot(name, range) {
    const lookupKey = `${name}@npm:${range}`;
    const key = requestToGraph.get(lookupKey);
    if (key && graph.has(key)) return key;
    const bareKey = `${name}@${range}`;
    const key2 = requestToGraph.get(bareKey);
    if (key2 && graph.has(key2)) return key2;
    return null;
  }
  function bfs(roots, markFn) {
    const visited = /* @__PURE__ */ new Set();
    const queue = [];
    for (const [name, range] of roots) {
      const key = resolveRoot(name, range);
      if (key && !visited.has(key)) {
        visited.add(key);
        queue.push({ key, depth: 1 });
      }
    }
    let qi = 0;
    while (qi < queue.length) {
      const { key, depth } = queue[qi++];
      const node = graph.get(key);
      if (!node) continue;
      markFn(node);
      if (node.depth === 0 || depth < node.depth) {
        node.depth = depth;
      }
      for (const depKey of node.dependencies) {
        if (!visited.has(depKey)) {
          visited.add(depKey);
          queue.push({ key: depKey, depth: depth + 1 });
        }
      }
    }
  }
  const prodRoots = Object.entries(manifest.dependencies ?? {});
  const devRoots = Object.entries(manifest.devDependencies ?? {});
  const optionalRoots = Object.entries(manifest.optionalDependencies ?? {});
  bfs(prodRoots, (node) => {
    node.isProduction = true;
  });
  bfs(optionalRoots, (node) => {
    node.isOptional = true;
  });
  bfs(devRoots, (node) => {
    if (!node.isProduction) node.isDev = true;
  });
  for (const node of graph.values()) {
    if (!node.isProduction && !node.isDev && !node.isOptional) {
      node.isDev = true;
    }
  }
  debug(`Berry reachability: ${[...graph.values()].filter((n) => n.isProduction).length} prod, ${[...graph.values()].filter((n) => n.isDev).length} dev`);
}

// src/core/lockfile/pnpm.ts
var MAX_KEY_LENGTH2 = 1024;
var SUPPORTED_LOCKFILE_VERSIONS = /* @__PURE__ */ new Set(["5", "5.0", "5.1", "5.2", "5.3", "5.4", "6", "6.0", "6.1", "9", "9.0"]);
function parseLockfileVersion(rawVersion) {
  if (typeof rawVersion === "number") {
    if (!Number.isFinite(rawVersion)) return 0;
    if (rawVersion === 5 || rawVersion === 6 || rawVersion === 9) return rawVersion;
    return 0;
  }
  if (typeof rawVersion !== "string") return 0;
  const trimmed = rawVersion.trim();
  if (!SUPPORTED_LOCKFILE_VERSIONS.has(trimmed)) return 0;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : 0;
}
function parsePnpmLockfile(content) {
  const lockfile = safeYamlParse(content);
  if (!lockfile || typeof lockfile !== "object") {
    throw new Error("Failed to parse pnpm-lock.yaml: invalid YAML format.");
  }
  const rawVersion = lockfile.lockfileVersion;
  const version = parseLockfileVersion(rawVersion);
  let type2;
  if (version === 9) {
    type2 = "pnpm-v9";
  } else if (version === 6) {
    type2 = "pnpm-v6";
  } else if (version === 5) {
    type2 = "pnpm-v5";
  } else {
    throw new Error(
      `Unsupported pnpm lockfile version ${JSON.stringify(rawVersion)}. auditfix supports pnpm lockfileVersion 5, 6, or 9.`
    );
  }
  const packages = lockfile.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error('Invalid pnpm-lock.yaml: missing "packages" field.');
  }
  const graph = /* @__PURE__ */ new Map();
  const skipped = [];
  const importers = [];
  if (lockfile.importers && typeof lockfile.importers === "object") {
    for (const importer of Object.values(lockfile.importers)) {
      if (importer && typeof importer === "object") {
        importers.push(importer);
      }
    }
  }
  if (importers.length === 0) {
    importers.push({
      dependencies: lockfile.dependencies,
      devDependencies: lockfile.devDependencies,
      optionalDependencies: lockfile.optionalDependencies
    });
  }
  const prodRootNames = /* @__PURE__ */ new Set();
  const devRootNames = /* @__PURE__ */ new Set();
  const optionalRootNames = /* @__PURE__ */ new Set();
  for (const importer of importers) {
    for (const name of Object.keys(importer.dependencies ?? {})) {
      prodRootNames.add(name);
    }
    for (const name of Object.keys(importer.devDependencies ?? {})) {
      devRootNames.add(name);
    }
    for (const name of Object.keys(importer.optionalDependencies ?? {})) {
      optionalRootNames.add(name);
    }
  }
  for (const name of prodRootNames) {
    devRootNames.delete(name);
  }
  for (const [pkgKey, entry] of Object.entries(packages)) {
    if (pkgKey.length > MAX_KEY_LENGTH2) {
      warn(`pnpm: skipping oversized package key (${pkgKey.length} bytes, max ${MAX_KEY_LENGTH2})`);
      skipped.push({ key: pkgKey.slice(0, 80) + "...", reason: "unparseable" });
      continue;
    }
    const parsed = parsePnpmPackageKey(pkgKey, entry, version);
    if (!parsed) {
      skipped.push({ key: pkgKey, reason: "unparseable" });
      continue;
    }
    const { name, pkgVersion } = parsed;
    if (entry.resolution?.type === "directory" || entry.resolution?.directory) {
      skipped.push({ key: pkgKey, reason: "workspace" });
      continue;
    }
    const tarball = entry.resolution?.tarball ?? "";
    if (tarball.startsWith("git+") || tarball.startsWith("git://")) {
      skipped.push({ key: pkgKey, reason: "git-dep" });
      continue;
    }
    if (tarball.startsWith("file:")) {
      skipped.push({ key: pkgKey, reason: "local-file" });
      continue;
    }
    if (!isValidVersion(pkgVersion)) {
      skipped.push({ key: pkgKey, reason: "unparseable" });
      continue;
    }
    const graphKey = `${name}@${pkgVersion}`;
    const hasDevField = typeof entry.dev === "boolean";
    const hasOptionalField = typeof entry.optional === "boolean";
    const explicitDev = entry.dev === true;
    const explicitOptional = entry.optional === true;
    const isRootProd = prodRootNames.has(name);
    const isRootDev = devRootNames.has(name);
    const isRootOptional = optionalRootNames.has(name);
    const isRootDep = isRootProd || isRootDev || isRootOptional;
    let isProduction;
    let isDev;
    if (hasDevField) {
      isDev = explicitDev;
      isProduction = !explicitDev;
    } else if (isRootProd) {
      isProduction = true;
      isDev = false;
    } else if (isRootDev) {
      isProduction = false;
      isDev = true;
    } else {
      isProduction = false;
      isDev = true;
    }
    const isOptional = hasOptionalField ? explicitOptional : isRootOptional;
    const node = {
      name,
      version: pkgVersion,
      resolved: tarball || entry.resolution?.integrity || "",
      integrity: entry.resolution?.integrity ?? "",
      dependencies: [],
      isProduction,
      isDev,
      isOptional,
      depth: isRootDep ? 1 : 2,
      dependencyPath: []
    };
    const existing = graph.get(graphKey);
    if (existing) {
      if (node.isProduction && !existing.isProduction) {
        existing.isProduction = true;
        existing.isDev = false;
      }
    } else {
      graph.set(graphKey, node);
    }
  }
  const nameIndex = /* @__PURE__ */ new Map();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }
  for (const [pkgKey, entry] of Object.entries(packages)) {
    if (pkgKey.length > MAX_KEY_LENGTH2) continue;
    const parsed = parsePnpmPackageKey(pkgKey, entry, version);
    if (!parsed) continue;
    const graphKey = `${parsed.name}@${parsed.pkgVersion}`;
    const node = graph.get(graphKey);
    if (!node) continue;
    const seen = new Set(node.dependencies);
    const pushEdge = (depName, depVersion) => {
      if (!depVersion) return;
      const cleanVersion = cleanPnpmVersion(depVersion);
      if (!cleanVersion) return;
      const directKey = `${depName}@${cleanVersion}`;
      if (graph.has(directKey)) {
        if (!seen.has(directKey)) {
          seen.add(directKey);
          node.dependencies.push(directKey);
        }
        return;
      }
      const bucket = nameIndex.get(depName);
      if (!bucket) return;
      for (const candidate of bucket) {
        if (!seen.has(candidate)) {
          seen.add(candidate);
          node.dependencies.push(candidate);
          return;
        }
      }
    };
    if (entry.dependencies) {
      for (const [depName, depVersion] of Object.entries(entry.dependencies)) {
        pushEdge(depName, depVersion);
      }
    }
    if (entry.optionalDependencies) {
      for (const [depName, depVersion] of Object.entries(entry.optionalDependencies)) {
        pushEdge(depName, depVersion);
      }
    }
  }
  propagateReachability(graph);
  debug(`pnpm: ${graph.size} packages, ${[...graph.values()].filter((n) => n.isProduction).length} prod`);
  return { type: type2, graph, skipped };
}
function parsePnpmPackageKey(key, entry, lockfileVersion) {
  if (lockfileVersion >= 9 || !key.startsWith("/")) {
    if (entry.name && entry.version) {
      return { name: entry.name, pkgVersion: entry.version };
    }
    let atIdx;
    if (key.startsWith("@")) {
      atIdx = key.indexOf("@", 1);
    } else {
      atIdx = key.indexOf("@");
    }
    if (atIdx === -1) return null;
    const name2 = key.slice(0, atIdx);
    const ver2 = key.slice(atIdx + 1);
    if (!name2 || !ver2) return null;
    return { name: name2, pkgVersion: ver2 };
  }
  const withoutSlash = key.slice(1);
  if (withoutSlash.startsWith("@")) {
    const parts = withoutSlash.split("/");
    if (parts.length < 3) return null;
    const name2 = `${parts[0]}/${parts[1]}`;
    const ver2 = parts[2];
    return { name: name2, pkgVersion: ver2 };
  }
  const slashIdx = withoutSlash.indexOf("/");
  if (slashIdx === -1) return null;
  const name = withoutSlash.slice(0, slashIdx);
  const ver = withoutSlash.slice(slashIdx + 1);
  const cleanVer = ver.split("_")[0];
  return { name, pkgVersion: cleanVer };
}
function cleanPnpmVersion(version) {
  if (!version) return null;
  const clean = version.split("_")[0].split("(")[0];
  return clean || null;
}
function propagateReachability(graph) {
  const visited = /* @__PURE__ */ new Set();
  const queue = [];
  for (const [key, node] of graph) {
    if (node.isProduction) {
      queue.push(key);
      visited.add(key);
    }
  }
  let qi = 0;
  while (qi < queue.length) {
    const key = queue[qi++];
    const node = graph.get(key);
    if (!node) continue;
    for (const depKey of node.dependencies) {
      if (visited.has(depKey)) continue;
      visited.add(depKey);
      const dep = graph.get(depKey);
      if (dep) {
        dep.isProduction = true;
        dep.isDev = false;
        queue.push(depKey);
      }
    }
  }
}

// src/core/lockfile/parser.ts
var LOCKFILE_PRIORITY = [
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml"
];
function detectAndParseLockfile(projectDir) {
  for (const lockfileName of LOCKFILE_PRIORITY) {
    const lockfilePath = join(projectDir, lockfileName);
    if (existsSync(lockfilePath)) {
      debug(`Found lockfile: ${lockfilePath}`);
      return parseLockfile(projectDir, lockfilePath, lockfileName);
    }
  }
  throw new Error(
    "No lockfile found. auditfix requires a package-lock.json, yarn.lock, or pnpm-lock.yaml. Run `npm install` to generate one."
  );
}
function parseLockfile(projectDir, path3, filename) {
  const content = readFileSync(path3, "utf-8");
  if (content.trim().length === 0) {
    throw new Error(`Lockfile ${filename} is empty. Run \`npm install\` to regenerate.`);
  }
  switch (filename) {
    case "package-lock.json": {
      const result = parseNpmLockfile(content);
      return {
        type: result.type,
        graph: result.graph,
        packageCount: result.graph.size,
        skipped: result.skipped
      };
    }
    case "yarn.lock": {
      const manifest = readManifest(projectDir);
      const isBerry = content.includes("__metadata");
      if (isBerry) {
        const result = parseYarnBerryLockfile(content, manifest);
        return {
          type: "yarn-berry",
          graph: result.graph,
          packageCount: result.graph.size,
          skipped: result.skipped
        };
      } else {
        const result = parseYarnClassicLockfile(content, manifest);
        return {
          type: "yarn-classic",
          graph: result.graph,
          packageCount: result.graph.size,
          skipped: result.skipped
        };
      }
    }
    case "pnpm-lock.yaml": {
      const result = parsePnpmLockfile(content);
      return {
        type: result.type,
        graph: result.graph,
        packageCount: result.graph.size,
        skipped: result.skipped
      };
    }
    default:
      throw new Error(`Unknown lockfile: ${filename}`);
  }
}
function readManifest(projectDir) {
  try {
    const content = readFileSync(join(projectDir, "package.json"), "utf-8");
    return safeJsonParse(content);
  } catch {
    return {};
  }
}

// src/core/graph/reachability.ts
var parentLinks = /* @__PURE__ */ new WeakMap();
function computeDependencyPaths(graph) {
  const parents = /* @__PURE__ */ new Map();
  const queue = [];
  for (const [key, node] of graph) {
    if (node.depth === 1) {
      parents.set(key, null);
      queue.push(key);
    }
  }
  for (let qi = 0; qi < queue.length; qi++) {
    const current = queue[qi];
    const node = graph.get(current);
    if (!node) continue;
    for (const depKey of node.dependencies) {
      if (parents.has(depKey)) continue;
      parents.set(depKey, current);
      queue.push(depKey);
    }
  }
  parentLinks.set(graph, parents);
}
function resolveDependencyPath(graph, key) {
  const parents = parentLinks.get(graph);
  if (!parents) return [];
  const names = [];
  let cursor = key;
  const seen = /* @__PURE__ */ new Set();
  while (cursor != null && !seen.has(cursor)) {
    seen.add(cursor);
    const node = graph.get(cursor);
    if (!node) break;
    names.push(node.name);
    cursor = parents.get(cursor) ?? null;
  }
  return names.reverse();
}

// src/core/advisory/osv-ranges.ts
function eventsToSemverRange(events) {
  const ranges = [];
  let currentIntroduced = null;
  for (const event of events) {
    if (event.introduced !== void 0) {
      currentIntroduced = event.introduced === "0" ? "0.0.0" : event.introduced;
    }
    if (event.fixed !== void 0 && currentIntroduced) {
      ranges.push(`>=${currentIntroduced} <${event.fixed}`);
      currentIntroduced = null;
    }
    if (event.last_affected !== void 0 && currentIntroduced) {
      ranges.push(`>=${currentIntroduced} <=${event.last_affected}`);
      currentIntroduced = null;
    }
  }
  if (currentIntroduced !== null) {
    ranges.push(`>=${currentIntroduced}`);
  }
  return ranges.join(" || ");
}
function extractFixVersion(events) {
  for (const event of events) {
    if (event.fixed !== void 0) {
      return event.fixed;
    }
  }
  return null;
}
function affectedToSemverRange(affected) {
  const allRanges = [];
  for (const range of affected.ranges) {
    if (range.type === "GIT") continue;
    const converted = eventsToSemverRange(range.events);
    if (converted) {
      allRanges.push(converted);
    }
  }
  return allRanges.join(" || ");
}
function affectedFixVersion(affected) {
  for (const range of affected.ranges) {
    if (range.type === "GIT") continue;
    const fix = extractFixVersion(range.events);
    if (fix) return fix;
  }
  return null;
}

// src/core/advisory/source-osv.ts
var OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
var OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
var MAX_BATCH_SIZE = 1e3;
var MAX_CONCURRENT_FETCHES = 10;
var MAX_CONCURRENT_BATCHES = 5;
var MAX_RESPONSE_SIZE = 50 * 1024 * 1024;
var MAX_INDIVIDUAL_SIZE = 1 * 1024 * 1024;
async function fetchOsvAdvisories(graph) {
  const errors = [];
  const uniquePackages = /* @__PURE__ */ new Map();
  for (const [, node] of graph) {
    const key = `${node.name}@${node.version}`;
    if (!uniquePackages.has(key)) {
      uniquePackages.set(key, { name: node.name, version: node.version });
    }
  }
  const packages = Array.from(uniquePackages.values());
  const batches = [];
  for (let i = 0; i < packages.length; i += MAX_BATCH_SIZE) {
    batches.push(packages.slice(i, i + MAX_BATCH_SIZE));
  }
  const allVulnIds = /* @__PURE__ */ new Set();
  const runBatch = async (batch) => {
    const query = {
      queries: batch.map((pkg) => ({
        version: pkg.version,
        package: {
          name: pkg.name,
          ecosystem: "npm"
        }
      }))
    };
    const response = await fetchWithValidation(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(query)
    }, MAX_RESPONSE_SIZE);
    return response;
  };
  for (let i = 0; i < batches.length; i += MAX_CONCURRENT_BATCHES) {
    const chunk = batches.slice(i, i + MAX_CONCURRENT_BATCHES);
    const results = await Promise.allSettled(chunk.map((batch) => runBatch(batch)));
    for (const result of results) {
      if (result.status === "fulfilled") {
        const batchResponse = result.value;
        if (batchResponse.results) {
          for (const r of batchResponse.results) {
            if (r.vulns) {
              for (const vuln of r.vulns) {
                allVulnIds.add(vuln.id);
              }
            }
          }
        }
      } else {
        const msg = result.reason instanceof Error ? result.reason.message : String(result.reason);
        errors.push(`OSV batch query failed: ${msg}`);
        warn(`OSV batch query failed: ${msg}`);
      }
    }
  }
  if (allVulnIds.size === 0) {
    return { advisories: /* @__PURE__ */ new Map(), fetchedIds: [], errors };
  }
  debug(`OSV batch found ${allVulnIds.size} vulnerability IDs, fetching details...`);
  const vulnIds = Array.from(allVulnIds);
  const fullVulns = [];
  for (let i = 0; i < vulnIds.length; i += MAX_CONCURRENT_FETCHES) {
    const chunk = vulnIds.slice(i, i + MAX_CONCURRENT_FETCHES);
    const results = await Promise.allSettled(
      chunk.map((id) => fetchVulnDetail(id))
    );
    for (const result of results) {
      if (result.status === "fulfilled" && result.value) {
        fullVulns.push(result.value);
      } else if (result.status === "rejected") {
        errors.push(`Failed to fetch vuln detail: ${result.reason}`);
      }
    }
  }
  const advisories = /* @__PURE__ */ new Map();
  for (const vuln of fullVulns) {
    if (!vuln || !Array.isArray(vuln.affected)) continue;
    for (const affected of vuln.affected) {
      try {
        if (!affected?.package?.ecosystem || !affected.package.name) continue;
        if (affected.package.ecosystem.toLowerCase() !== "npm") continue;
        if (!Array.isArray(affected.ranges)) continue;
        const pkgName = affected.package.name;
        const advisory = {
          id: vuln.id,
          aliases: vuln.aliases ?? [],
          summary: vuln.summary ?? "",
          details: vuln.details ?? "",
          severity: vuln.severity ?? [],
          affectedRange: affectedToSemverRange(affected),
          fixVersion: affectedFixVersion(affected),
          publishedAt: vuln.published ?? vuln.modified,
          modifiedAt: vuln.modified,
          references: vuln.references ?? [],
          source: "osv-api"
        };
        const existing = advisories.get(pkgName) ?? [];
        existing.push(advisory);
        advisories.set(pkgName, existing);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warn(`Skipping malformed OSV affected entry in ${vuln.id}: ${msg}`);
      }
    }
  }
  return {
    advisories,
    fetchedIds: vulnIds,
    errors
  };
}
async function fetchVulnDetail(id) {
  try {
    return await fetchWithValidation(
      `${OSV_VULN_URL}/${encodeURIComponent(id)}`,
      { method: "GET" },
      MAX_INDIVIDUAL_SIZE
    );
  } catch (err) {
    warn(`Failed to fetch OSV vuln ${id}: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}
async function fetchWithValidation(url, init, maxSize) {
  const response = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(3e4)
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error(`Unexpected Content-Type: ${contentType}. Expected application/json.`);
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new Error(`Response too large: ${contentLength} bytes (max ${maxSize})`);
  }
  const text = await response.text();
  if (text.length > maxSize) {
    throw new Error(`Response body too large: ${text.length} chars (max ${maxSize})`);
  }
  return safeJsonParse(text);
}

// src/core/advisory/source-npm.ts
var NPM_BULK_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";
var MAX_RESPONSE_SIZE2 = 50 * 1024 * 1024;
var SEVERITY_MAP = {
  critical: 9.5,
  high: 8,
  medium: 5.5,
  low: 3,
  info: 0
};
function npmSeverityToOsv(severity) {
  if (!severity) return [];
  const normalized = severity.toLowerCase();
  const score = SEVERITY_MAP[normalized];
  if (score === void 0) return [];
  return [
    {
      type: "CVSS_V3",
      score: approximateCvssVector(normalized)
    }
  ];
}
function approximateCvssVector(severity) {
  switch (severity) {
    case "critical":
      return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    case "high":
      return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N";
    case "medium":
      return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N";
    case "low":
      return "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N";
    default:
      return "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N";
  }
}
function extractFixVersion2(patchedVersions) {
  if (!patchedVersions) return null;
  const trimmed = patchedVersions.trim();
  if (trimmed === "<0.0.0" || trimmed === "") return null;
  const match = trimmed.match(/(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/);
  return match ? match[1] : trimmed;
}
function buildRequestBody(graph) {
  const packageVersions = /* @__PURE__ */ new Map();
  for (const [, node] of graph) {
    if (!node.name || !node.version) continue;
    const versions = packageVersions.get(node.name) ?? /* @__PURE__ */ new Set();
    versions.add(node.version);
    packageVersions.set(node.name, versions);
  }
  if (packageVersions.size === 0) return null;
  const body = {};
  for (const [name, versions] of packageVersions) {
    body[name] = Array.from(versions);
  }
  return body;
}
async function fetchNpmAdvisories(graph) {
  const errors = [];
  if (graph.size === 0) {
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  const body = buildRequestBody(graph);
  if (!body) {
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  let response;
  try {
    response = await fetch(NPM_BULK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(3e4)
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`npm bulk request failed: ${msg}`);
    warn(`npm bulk request failed: ${msg}`);
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  if (!response.ok) {
    errors.push(`npm bulk HTTP ${response.status}: ${response.statusText}`);
    warn(`npm bulk HTTP ${response.status}: ${response.statusText}`);
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    errors.push(
      `npm bulk unexpected Content-Type: ${contentType}. Expected application/json.`
    );
    warn(
      `npm bulk unexpected Content-Type: ${contentType}. Expected application/json.`
    );
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_SIZE2) {
    errors.push(
      `npm bulk response too large: ${contentLength} bytes (max ${MAX_RESPONSE_SIZE2})`
    );
    warn(`npm bulk response too large: ${contentLength} bytes`);
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  let text;
  try {
    text = await response.text();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`npm bulk failed to read response body: ${msg}`);
    warn(`npm bulk failed to read body: ${msg}`);
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  if (text.length > MAX_RESPONSE_SIZE2) {
    errors.push(
      `npm bulk response body too large: ${text.length} chars (max ${MAX_RESPONSE_SIZE2})`
    );
    warn(`npm bulk response body too large: ${text.length} chars`);
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  let parsed;
  try {
    parsed = safeJsonParse(text);
  } catch (err) {
    const preview = text.slice(0, 200);
    errors.push(
      `npm bulk response is not valid JSON (possible outage). Preview: ${preview}`
    );
    warn(`npm bulk response is not valid JSON. Preview: ${preview}`);
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    errors.push("npm bulk response is not an object");
    return { advisories: /* @__PURE__ */ new Map(), errors };
  }
  const advisories = /* @__PURE__ */ new Map();
  for (const [, npmAdvisory] of Object.entries(parsed)) {
    if (!npmAdvisory || typeof npmAdvisory !== "object") continue;
    const pkgName = npmAdvisory.module_name;
    if (!pkgName) continue;
    const advisory = {
      id: npmAdvisory.id != null ? `npm-${pkgName}-${npmAdvisory.id}` : `npm-${pkgName}-unknown`,
      aliases: npmAdvisory.cves ?? [],
      summary: npmAdvisory.title ?? "",
      details: npmAdvisory.overview ?? "",
      severity: npmSeverityToOsv(npmAdvisory.severity),
      affectedRange: npmAdvisory.vulnerable_versions ?? "*",
      fixVersion: extractFixVersion2(npmAdvisory.patched_versions),
      publishedAt: npmAdvisory.created ?? "",
      modifiedAt: npmAdvisory.updated ?? npmAdvisory.created ?? "",
      references: npmAdvisory.url ? [{ type: "WEB", url: npmAdvisory.url }] : [],
      source: "npm-bulk"
    };
    const existing = advisories.get(pkgName) ?? [];
    existing.push(advisory);
    advisories.set(pkgName, existing);
  }
  debug(
    `npm bulk returned ${advisories.size} affected packages with advisories`
  );
  return { advisories, errors };
}

// src/core/advisory/cache.ts
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as os from "os";
var CACHE_TTL_MS = 4 * 60 * 60 * 1e3;
var CACHE_FRESH_MS = 1 * 60 * 60 * 1e3;
var CACHE_STALE_MS = 4 * 60 * 60 * 1e3;
var CACHE_EXPIRED_MS = 24 * 60 * 60 * 1e3;
var HMAC_ALGORITHM = "sha256";
function isPathWithinCache(filePath, cacheDir) {
  const resolvedPath = path.resolve(filePath);
  const resolvedCacheDir = path.resolve(cacheDir);
  return resolvedPath.startsWith(resolvedCacheDir + path.sep);
}
function isSymlink(filePath) {
  try {
    const stats = fs.lstatSync(filePath);
    return stats.isSymbolicLink();
  } catch {
    return false;
  }
}
function validatePackageName(name) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (name.includes("\0")) return false;
  return true;
}
function getDefaultCacheDir() {
  return path.join(os.homedir(), ".auditfix", "cache");
}
function getCacheKeyPath(cacheDir) {
  return path.join(path.dirname(cacheDir), "cache-key");
}
function ensureCacheDir(cacheDir) {
  fs.mkdirSync(cacheDir, { recursive: true, mode: 448 });
  const parentDir = path.dirname(cacheDir);
  fs.mkdirSync(parentDir, { recursive: true, mode: 448 });
}
function getHmacKey(cacheDir) {
  const keyPath = getCacheKeyPath(cacheDir);
  try {
    return fs.readFileSync(keyPath);
  } catch {
    const key = crypto.randomBytes(32);
    ensureCacheDir(cacheDir);
    fs.writeFileSync(keyPath, key, { mode: 384 });
    return key;
  }
}
function computeHmac(data, key) {
  return crypto.createHmac(HMAC_ALGORITHM, key).update(data).digest("hex");
}
function buildPackagePath(packageName, cacheDir) {
  const hash = crypto.createHash("sha256").update(packageName).digest("hex").slice(0, 16);
  const filePath = path.join(cacheDir, `pkg-${hash}.json`);
  if (!isPathWithinCache(filePath, cacheDir)) return null;
  return filePath;
}
function atomicWrite(filePath, content) {
  if (isSymlink(filePath)) {
    throw new Error(`Refusing to write to symlink: ${filePath}`);
  }
  const tempPath = filePath + `.tmp.${crypto.randomBytes(4).toString("hex")}`;
  if (isSymlink(tempPath)) {
    throw new Error(`Refusing to write to symlink: ${tempPath}`);
  }
  fs.writeFileSync(tempPath, content, { mode: 384 });
  fs.renameSync(tempPath, filePath);
}
function readVerifiedEntry(filePath, hmacKey) {
  try {
    if (isSymlink(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf-8");
    const entry = safeJsonParse(raw);
    if (typeof entry.timestamp !== "number" || typeof entry.hmac !== "string" || entry.data === void 0 || entry.data === null) {
      return null;
    }
    const payload = JSON.stringify(entry.data) + "|" + String(entry.timestamp);
    const expectedHmac = computeHmac(payload, hmacKey);
    if (!crypto.timingSafeEqual(Buffer.from(entry.hmac, "hex"), Buffer.from(expectedHmac, "hex"))) {
      return null;
    }
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
      return null;
    }
    return entry;
  } catch {
    return null;
  }
}
async function cacheAdvisoryBatch(advisories, cacheDir = getDefaultCacheDir()) {
  ensureCacheDir(cacheDir);
  const hmacKey = getHmacKey(cacheDir);
  for (const [packageName, advisoryList] of advisories) {
    if (!validatePackageName(packageName)) continue;
    if (!Array.isArray(advisoryList) || advisoryList.length === 0) continue;
    const filePath = buildPackagePath(packageName, cacheDir);
    if (!filePath) continue;
    try {
      const timestamp2 = Date.now();
      const payload = JSON.stringify(advisoryList) + "|" + String(timestamp2);
      const hmac = computeHmac(payload, hmacKey);
      const entry = { data: advisoryList, timestamp: timestamp2, hmac };
      atomicWrite(filePath, JSON.stringify(entry));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      debug(`Cache write failed for package "${packageName}": ${msg}`);
    }
  }
}
function getCachedPackageAdvisories(packageName, cacheDir = getDefaultCacheDir()) {
  if (!validatePackageName(packageName)) return null;
  const filePath = buildPackagePath(packageName, cacheDir);
  if (!filePath) return null;
  const hmacKey = getHmacKey(cacheDir);
  const entry = readVerifiedEntry(filePath, hmacKey);
  if (!entry) return null;
  return entry.data;
}
function readVerifiedEntryWithStaleTolerance(filePath, hmacKey) {
  try {
    if (isSymlink(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf-8");
    const entry = safeJsonParse(raw);
    if (typeof entry.timestamp !== "number" || typeof entry.hmac !== "string" || entry.data === void 0 || entry.data === null) {
      return null;
    }
    const payload = JSON.stringify(entry.data) + "|" + String(entry.timestamp);
    const expectedHmac = computeHmac(payload, hmacKey);
    if (!crypto.timingSafeEqual(Buffer.from(entry.hmac, "hex"), Buffer.from(expectedHmac, "hex"))) {
      return null;
    }
    if (Date.now() - entry.timestamp > CACHE_EXPIRED_MS) {
      return null;
    }
    return entry;
  } catch {
    return null;
  }
}
function getCacheFreshness(timestamp2) {
  const age = Date.now() - timestamp2;
  if (age < CACHE_FRESH_MS) return "fresh";
  if (age < CACHE_STALE_MS) return "stale";
  if (age < CACHE_EXPIRED_MS) return "expired";
  return "missing";
}
function readCachedAdvisoriesForPackages(packageNames, cacheDir = getDefaultCacheDir()) {
  const hmacKey = getHmacKey(cacheDir);
  const results = /* @__PURE__ */ new Map();
  let worstFreshness = "fresh";
  const freshnessOrder = ["fresh", "stale", "expired", "missing"];
  for (const name of packageNames) {
    if (!validatePackageName(name)) return null;
    const filePath = buildPackagePath(name, cacheDir);
    if (!filePath) return null;
    const entry = readVerifiedEntryWithStaleTolerance(filePath, hmacKey);
    if (!entry) return null;
    const freshness = getCacheFreshness(entry.timestamp);
    if (freshnessOrder.indexOf(freshness) > freshnessOrder.indexOf(worstFreshness)) {
      worstFreshness = freshness;
    }
    results.set(name, entry.data);
  }
  return { advisories: results, freshness: worstFreshness };
}

// src/core/advisory/offline-index.ts
var import_semver7 = __toESM(require_semver2(), 1);
import { existsSync as existsSync2 } from "fs";
import path2 from "path";
import { fileURLToPath, pathToFileURL } from "url";
var generatedIndex = null;
var generatedLoaded = false;
var MODULE_NOT_FOUND_CODES = /* @__PURE__ */ new Set(["ERR_MODULE_NOT_FOUND", "MODULE_NOT_FOUND"]);
function isModuleNotFound(err) {
  if (!err || typeof err !== "object") return false;
  const code = err.code;
  return typeof code === "string" && MODULE_NOT_FOUND_CODES.has(code);
}
var defaultLoader = async () => {
  const here = path2.dirname(fileURLToPath(import.meta.url));
  const genPath = path2.join(here, "offline-index.generated.js");
  if (!existsSync2(genPath)) {
    const err = new Error(`generated index not present at ${genPath}`);
    err.code = "ERR_MODULE_NOT_FOUND";
    throw err;
  }
  const mod = await import(pathToFileURL(genPath).href);
  if (Array.isArray(mod.GENERATED_INDEX) && mod.GENERATED_INDEX.length > 0) {
    return mod.GENERATED_INDEX;
  }
  return null;
};
var activeLoader = defaultLoader;
async function loadGeneratedIndex() {
  if (generatedLoaded) return generatedIndex;
  try {
    const loaded = await activeLoader();
    if (loaded) generatedIndex = loaded;
    generatedLoaded = true;
  } catch (err) {
    if (isModuleNotFound(err)) {
      generatedLoaded = true;
      return generatedIndex;
    }
    debug(
      `offline-index: generated load failed (will retry): ${err instanceof Error ? err.message : String(err)}`
    );
    throw err;
  }
  return generatedIndex;
}
var HARDCODED_INDEX = [
  { id: "GHSA-35jh-r3h4-6jhm", pkg: "lodash", range: "<4.17.21", fix: "4.17.21", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", summary: "Prototype Pollution in lodash" },
  { id: "GHSA-jf85-cpcp-j695", pkg: "lodash", range: "<4.17.12", fix: "4.17.12", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", summary: "Prototype Pollution in lodash" },
  { id: "GHSA-4xc9-xhrj-v574", pkg: "minimist", range: "<1.2.6", fix: "1.2.6", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", summary: "Prototype Pollution in minimist" },
  { id: "GHSA-c2qf-rxjj-qqgw", pkg: "semver", range: ">=7.0.0 <7.5.2", fix: "7.5.2", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "ReDoS in semver" },
  { id: "GHSA-952p-6rrq-rcjv", pkg: "jsonwebtoken", range: "<9.0.0", fix: "9.0.0", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", summary: "Insecure default algorithm in jsonwebtoken" },
  { id: "GHSA-36fh-84j7-cv5h", pkg: "express", range: "<4.19.2", fix: "4.19.2", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", summary: "Open redirect in express" },
  { id: "GHSA-rv95-896h-c2vc", pkg: "express", range: "<4.20.0", fix: "4.20.0", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "ReDoS via content-type parsing in express" },
  { id: "GHSA-qw6h-vgh9-j6wx", pkg: "node-fetch", range: "<2.6.7", fix: "2.6.7", severity: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", summary: "Exposure of sensitive information in node-fetch" },
  { id: "GHSA-wf5p-g6vw-rhxx", pkg: "axios", range: ">=0.8.1 <1.6.0", fix: "1.6.0", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", summary: "SSRF in axios" },
  { id: "GHSA-8hc4-vh64-cxmj", pkg: "kind-of", range: ">=6.0.0 <6.0.3", fix: "6.0.3", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", summary: "Type confusion in kind-of" },
  { id: "GHSA-p8p7-x288-28g6", pkg: "http-cache-semantics", range: "<4.1.1", fix: "4.1.1", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "ReDoS in http-cache-semantics" },
  { id: "GHSA-3xgq-45jj-v275", pkg: "tough-cookie", range: "<4.1.3", fix: "4.1.3", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "Prototype pollution in tough-cookie" },
  { id: "GHSA-72xf-g2v4-qvf3", pkg: "ini", range: "<1.3.6", fix: "1.3.6", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", summary: "Prototype pollution in ini" },
  { id: "GHSA-93q8-gq69-wqmw", pkg: "qs", range: ">=6.7.0 <6.7.3", fix: "6.7.3", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "Prototype pollution in qs" },
  { id: "GHSA-hrpp-h998-j3pp", pkg: "qs", range: ">=6.5.0 <6.5.3", fix: "6.5.3", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "Prototype pollution in qs" },
  { id: "GHSA-cph5-m8f7-6c5x", pkg: "got", range: "<11.8.5", fix: "11.8.5", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", summary: "Open redirect in got" },
  { id: "GHSA-pfrx-2q88-qq97", pkg: "json5", range: "<2.2.2", fix: "2.2.2", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", summary: "Prototype pollution in json5" },
  { id: "GHSA-9c47-m6qq-7p4h", pkg: "json-schema", range: "<0.4.0", fix: "0.4.0", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", summary: "Prototype pollution in json-schema" },
  { id: "GHSA-8225-6cvr-8pqp", pkg: "node-forge", range: "<1.3.0", fix: "1.3.0", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", summary: "URL parsing vulnerability in node-forge" },
  { id: "GHSA-2fc9-xpp8-2g9h", pkg: "postcss", range: "<8.4.31", fix: "8.4.31", severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", summary: "Line return parsing issue in postcss" }
];
function buildEffectiveIndex(gen) {
  if (gen === null) {
    return HARDCODED_INDEX;
  }
  const seen = new Set(gen.map((e) => `${e.id}:${e.pkg}`));
  const extras = HARDCODED_INDEX.filter((e) => !seen.has(`${e.id}:${e.pkg}`));
  return [...gen, ...extras];
}
var BUILTIN_INDEX = HARDCODED_INDEX;
var INDEX_BY_NAME = buildNameIndex(HARDCODED_INDEX);
function buildNameIndex(entries) {
  const map2 = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    const list = map2.get(entry.pkg);
    if (list) {
      list.push(entry);
    } else {
      map2.set(entry.pkg, [entry]);
    }
  }
  return map2;
}
var indexReady = null;
var indexLoadFailures = 0;
var MAX_INDEX_LOAD_FAILURES = 3;
function ensureIndex() {
  if (indexReady) return indexReady;
  if (indexLoadFailures >= MAX_INDEX_LOAD_FAILURES) {
    indexReady = Promise.resolve();
    return indexReady;
  }
  indexReady = (async () => {
    try {
      const gen = await loadGeneratedIndex();
      BUILTIN_INDEX = buildEffectiveIndex(gen);
      INDEX_BY_NAME = buildNameIndex(BUILTIN_INDEX);
      indexLoadFailures = 0;
    } catch (err) {
      indexLoadFailures += 1;
      debug(
        `offline-index: load attempt ${indexLoadFailures} failed: ${err instanceof Error ? err.message : String(err)}`
      );
      if (indexLoadFailures < MAX_INDEX_LOAD_FAILURES) {
        indexReady = null;
      } else {
        warn(
          `offline-index: generated load failed ${indexLoadFailures} times; using hardcoded fallback`
        );
      }
    }
  })();
  return indexReady;
}
function queryOfflineIndex(packageName, version) {
  const results = [];
  const entries = INDEX_BY_NAME.get(packageName);
  if (!entries) return results;
  for (const entry of entries) {
    try {
      if (import_semver7.default.satisfies(version, entry.range, { includePrerelease: true })) {
        results.push({
          id: entry.id,
          aliases: [],
          summary: entry.summary,
          details: "",
          severity: [{ type: "CVSS_V3", score: entry.severity }],
          affectedRange: entry.range,
          fixVersion: entry.fix,
          publishedAt: "",
          modifiedAt: "",
          references: [{ type: "ADVISORY", url: `https://github.com/advisories/${entry.id}` }],
          source: "offline-index"
        });
      }
    } catch {
    }
  }
  return results;
}
async function queryOfflineIndexBatch(graph) {
  await ensureIndex();
  const result = /* @__PURE__ */ new Map();
  const checked = /* @__PURE__ */ new Set();
  for (const [, node] of graph) {
    const key = `${node.name}@${node.version}`;
    if (checked.has(key)) continue;
    checked.add(key);
    const advisories = queryOfflineIndex(node.name, node.version);
    if (advisories.length > 0) {
      const existing = result.get(node.name) ?? [];
      existing.push(...advisories);
      result.set(node.name, existing);
    }
  }
  return result;
}

// src/core/advisory/resolver.ts
var SOURCE_LABELS = {
  "osv": "OSV.dev API (real-time)",
  "osv-partial": "OSV.dev API (partial)",
  "cache": "Local cache",
  "cache-stale": "Local cache (stale)",
  "offline": "Bundled offline index",
  "npm-bulk": "npm bulk advisory endpoint"
};
function buildResult(advisories, sourceId, confidence, errors) {
  return {
    advisories,
    source: SOURCE_LABELS[sourceId],
    sourceId,
    confidence,
    errors
  };
}
async function resolveAdvisories(graph) {
  const errors = [];
  info("Fetching advisories from OSV.dev...");
  try {
    const osvResult = await fetchOsvAdvisories(graph);
    if (osvResult.errors.length === 0 && osvResult.advisories.size > 0) {
      cacheAdvisoryBatch(osvResult.advisories).catch((err) => {
        debug(`Cache write failed: ${err}`);
      });
      return buildResult(osvResult.advisories, "osv", "HIGH", []);
    }
    if (osvResult.advisories.size > 0) {
      errors.push(...osvResult.errors);
      cacheAdvisoryBatch(osvResult.advisories).catch(() => {
      });
      return buildResult(
        osvResult.advisories,
        "osv-partial",
        "MEDIUM",
        errors
      );
    }
    errors.push(...osvResult.errors);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`OSV API failed: ${msg}`);
    warn(`OSV API failed: ${msg}`);
  }
  info("OSV unavailable, checking local cache...");
  const cachedAdvisories = getCachedAdvisoriesForGraph(graph);
  if (cachedAdvisories.size > 0) {
    info(`Using ${cachedAdvisories.size} cached advisory entries`);
    return buildResult(cachedAdvisories, "cache", "MEDIUM", errors);
  }
  info("Checking bundled offline advisory index...");
  const offlineAdvisories = await queryOfflineIndexBatch(graph);
  if (offlineAdvisories.size > 0) {
    info(`Using ${offlineAdvisories.size} entries from offline index`);
    return buildResult(offlineAdvisories, "offline", "LOW", errors);
  }
  info("Offline index empty, trying npm bulk advisory endpoint...");
  try {
    const npmResult = await fetchNpmAdvisories(graph);
    if (npmResult.errors.length === 0 || npmResult.advisories.size > 0) {
      cacheAdvisoryBatch(npmResult.advisories).catch(() => {
      });
      errors.push(...npmResult.errors);
      return buildResult(
        npmResult.advisories,
        "npm-bulk",
        npmResult.errors.length > 0 ? "LOW" : "MEDIUM",
        errors
      );
    }
    errors.push(...npmResult.errors);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`npm bulk endpoint failed: ${msg}`);
    warn(`npm bulk endpoint failed: ${msg}`);
  }
  errors.push("All advisory sources failed. Cannot produce reliable results.");
  throw new AdvisoryResolutionError(
    "All advisory sources failed (OSV API, local cache, npm bulk endpoint). Check network connectivity or update the auditfix package for a fresh bundled index.",
    errors
  );
}
var AdvisoryResolutionError = class extends Error {
  errors;
  constructor(message, errors) {
    super(message);
    this.name = "AdvisoryResolutionError";
    this.errors = errors;
  }
};
async function resolveAdvisoriesWithCache(graph, options) {
  if (options?.noCache) {
    return resolveAdvisories(graph);
  }
  const packageNames = [];
  const seen = /* @__PURE__ */ new Set();
  for (const [, node] of graph) {
    if (!seen.has(node.name)) {
      seen.add(node.name);
      packageNames.push(node.name);
    }
  }
  const cached = readCachedAdvisoriesForPackages(packageNames);
  if (cached) {
    if (cached.freshness === "fresh") {
      info(`All ${packageNames.length} packages served from fresh cache (<1h)`);
      return {
        advisories: cached.advisories,
        sourceId: "cache",
        source: "Local cache (fresh)",
        confidence: "HIGH",
        errors: []
      };
    }
    if (cached.freshness === "stale") {
      info(`All ${packageNames.length} packages served from stale cache (1-4h), refreshing in background`);
      resolveAdvisories(graph).catch((err) => {
        debug(`Background cache refresh failed: ${err}`);
      });
      return {
        advisories: cached.advisories,
        sourceId: "cache-stale",
        source: "Local cache (stale, refreshing)",
        confidence: "HIGH",
        errors: []
      };
    }
  }
  return resolveAdvisories(graph);
}
function getCachedAdvisoriesForGraph(graph) {
  const result = /* @__PURE__ */ new Map();
  const checkedNames = /* @__PURE__ */ new Set();
  for (const [, node] of graph) {
    if (checkedNames.has(node.name)) continue;
    checkedNames.add(node.name);
    const cached = getCachedPackageAdvisories(node.name);
    if (cached && cached.length > 0) {
      result.set(node.name, cached);
    }
  }
  return result;
}

// src/core/advisory/matcher.ts
var import_semver8 = __toESM(require_semver2(), 1);
function matchAdvisories(graph, advisories) {
  const matches = [];
  const compiled = /* @__PURE__ */ new WeakMap();
  for (const [key, node] of graph) {
    const pkgAdvisories = advisories.get(node.name);
    if (!pkgAdvisories) continue;
    for (const advisory of pkgAdvisories) {
      if (!advisory.affectedRange) continue;
      let range = compiled.get(advisory);
      if (range === void 0) {
        range = compileRange(advisory.affectedRange);
        compiled.set(advisory, range);
      }
      const isAffected = range ? testRange(node.version, range) : satisfies(node.version, advisory.affectedRange);
      if (isAffected) {
        const path3 = node.dependencyPath.length > 0 ? node.dependencyPath : resolveDependencyPath(graph, key);
        matches.push({
          advisory,
          package: node.name,
          installedVersion: node.version,
          dependencyPath: path3,
          isProduction: node.isProduction
        });
      }
    }
  }
  return matches;
}

// src/core/advisory/cvss.ts
var METRIC_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    N: 0.85,
    // unchanged scope
    L: 0.62,
    // unchanged scope
    H: 0.27
    // unchanged scope
  },
  PR_CHANGED: {
    N: 0.85,
    L: 0.68,
    H: 0.5
  },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 0, C: 1 },
  // 0=unchanged, 1=changed
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 }
};
function parseCvssVector(vector) {
  if (!vector || !vector.startsWith("CVSS:3")) {
    return { score: 0, vector: vector ?? "" };
  }
  try {
    const metrics = parseMetrics(vector);
    const score = computeBaseScore(metrics);
    return { score, vector };
  } catch {
    return { score: 0, vector };
  }
}
function parseMetrics(vector) {
  const parts = vector.split("/");
  const metrics = {};
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key && value) {
      metrics[key] = value;
    }
  }
  return metrics;
}
function computeBaseScore(m) {
  const requiredMetrics = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  for (const metric of requiredMetrics) {
    if (!m[metric]) return 0;
  }
  const av = METRIC_WEIGHTS.AV[m.AV];
  const ac = METRIC_WEIGHTS.AC[m.AC];
  const ui = METRIC_WEIGHTS.UI[m.UI];
  const scopeChanged = m.S === "C";
  const prWeights = scopeChanged ? METRIC_WEIGHTS.PR_CHANGED : METRIC_WEIGHTS.PR;
  const pr = prWeights[m.PR];
  const c = METRIC_WEIGHTS.C[m.C];
  const i = METRIC_WEIGHTS.I[m.I];
  const a = METRIC_WEIGHTS.A[m.A];
  if (av === void 0 || ac === void 0 || ui === void 0 || pr === void 0 || c === void 0 || i === void 0 || a === void 0) {
    return 0;
  }
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  let baseScore;
  if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }
  return Math.ceil(baseScore * 10) / 10;
}

// src/utils/fetch.ts
var FetchValidationError = class extends Error {
  kind;
  url;
  status;
  constructor(kind, url, message, status) {
    super(message);
    this.name = "FetchValidationError";
    this.kind = kind;
    this.url = url;
    this.status = status;
  }
};
var HTML_SNIFF_PREFIXES = ["<!doctype html", "<html", "<?xml"];
var HTML_SNIFF_LENGTH = 32;
function contentTypeMatches(actual, expected) {
  if (!actual) return false;
  const lowered = actual.toLowerCase();
  if (typeof expected === "string") {
    return lowered.startsWith(expected.toLowerCase());
  }
  return expected.test(actual);
}
function startsWithHtml(prefix) {
  const trimmed = prefix.trimStart().toLowerCase();
  return HTML_SNIFF_PREFIXES.some((p) => trimmed.startsWith(p));
}
async function fetchWithValidation2(url, options) {
  const { maxBytes, timeoutMs = 3e4, contentType, signal: externalSignal, ...init } = options;
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
    throw new FetchValidationError("oversize", url, `Invalid maxBytes: ${maxBytes}`);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const externalAbort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener("abort", externalAbort, { once: true });
  }
  let response;
  try {
    response = await fetch(url, { ...init, signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener("abort", externalAbort);
    const name = err?.name;
    if (name === "AbortError" || name === "TimeoutError") {
      throw new FetchValidationError("timeout", url, `Request timed out after ${timeoutMs}ms`);
    }
    throw new FetchValidationError(
      "network",
      url,
      `Network failure: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  try {
    if (!response.ok) {
      throw new FetchValidationError(
        "http-status",
        url,
        `HTTP ${response.status}: ${response.statusText}`,
        response.status
      );
    }
    const rawCt = response.headers.get("content-type") ?? "";
    if (!contentTypeMatches(rawCt, contentType)) {
      throw new FetchValidationError(
        "content-type",
        url,
        `Unexpected Content-Type: ${rawCt || "(missing)"}. Expected ${String(contentType)}.`
      );
    }
    const clHeader = response.headers.get("content-length");
    if (clHeader !== null) {
      const declared = Number.parseInt(clHeader, 10);
      if (Number.isFinite(declared) && declared > maxBytes) {
        throw new FetchValidationError(
          "oversize",
          url,
          `Response too large (Content-Length ${declared} > ${maxBytes})`
        );
      }
    }
    const body = response.body;
    if (!body) {
      const text = await response.text();
      if (text.length > maxBytes) {
        throw new FetchValidationError(
          "oversize",
          url,
          `Response body too large (${text.length} > ${maxBytes} bytes)`
        );
      }
      if (startsWithHtml(text.slice(0, HTML_SNIFF_LENGTH))) {
        throw new FetchValidationError(
          "html-body",
          url,
          "Response body starts with HTML markup despite JSON content-type"
        );
      }
      return text;
    }
    const reader = body.getReader();
    const decoder = new TextDecoder();
    const chunks = [];
    let received = 0;
    let sniffed = false;
    let sniffBuf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      received += value.byteLength;
      if (received > maxBytes) {
        try {
          await reader.cancel();
        } catch {
        }
        throw new FetchValidationError(
          "oversize",
          url,
          `Response body exceeded ${maxBytes} bytes during streaming (read ${received})`
        );
      }
      const piece = decoder.decode(value, { stream: true });
      chunks.push(piece);
      if (!sniffed) {
        sniffBuf += piece;
        if (sniffBuf.length >= HTML_SNIFF_LENGTH || sniffBuf.trimStart().length >= HTML_SNIFF_LENGTH) {
          if (startsWithHtml(sniffBuf.slice(0, HTML_SNIFF_LENGTH + 8))) {
            try {
              await reader.cancel();
            } catch {
            }
            throw new FetchValidationError(
              "html-body",
              url,
              "Response body starts with HTML markup despite JSON content-type"
            );
          }
          sniffed = true;
          sniffBuf = "";
        }
      }
    }
    chunks.push(decoder.decode());
    if (!sniffed && startsWithHtml(chunks.join("").slice(0, HTML_SNIFF_LENGTH))) {
      throw new FetchValidationError(
        "html-body",
        url,
        "Response body starts with HTML markup despite JSON content-type"
      );
    }
    return chunks.join("");
  } finally {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener("abort", externalAbort);
  }
}
async function fetchJsonWithValidation(url, options) {
  const body = await fetchWithValidation2(url, options);
  try {
    return JSON.parse(body);
  } catch (err) {
    throw new FetchValidationError(
      "content-type",
      url,
      `Response body failed to parse as JSON: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// src/core/advisory/epss.ts
var EPSS_MAX_BYTES = 10 * 1024 * 1024;
var KEV_MAX_BYTES = 20 * 1024 * 1024;
var EPSS_TIMEOUT_MS = 3e4;
var KEV_TIMEOUT_MS = 3e4;
var EPSS_BATCH_SIZE = 50;
var EPSS_BATCH_CONCURRENCY = 5;
function makeKevCache(ttlMs) {
  const state = {
    cache: null,
    cachedAt: 0,
    ttlMs,
    reset() {
      state.cache = null;
      state.cachedAt = 0;
    }
  };
  return state;
}
var kevState = makeKevCache(4 * 60 * 60 * 1e3);
async function pMap(items, fn, concurrency) {
  const results = new Array(items.length);
  let cursor = 0;
  const workerCount = Math.max(1, Math.min(concurrency, items.length));
  async function worker() {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}
async function fetchEpssBatch(batch) {
  const param = batch.join(",");
  const url = `https://api.first.org/data/v1/epss?cve=${param}`;
  try {
    const data = await fetchJsonWithValidation(url, {
      maxBytes: EPSS_MAX_BYTES,
      timeoutMs: EPSS_TIMEOUT_MS,
      contentType: "application/json"
    });
    return data.data ?? [];
  } catch (err) {
    if (err instanceof FetchValidationError) {
      debug(`EPSS batch query failed (${err.kind}): ${err.message}`);
    } else {
      debug(`EPSS batch query failed: ${err instanceof Error ? err.message : err}`);
    }
    return [];
  }
}
async function fetchEpssScores(cveIds) {
  const results = /* @__PURE__ */ new Map();
  if (cveIds.length === 0) return results;
  const batches = [];
  for (let i = 0; i < cveIds.length; i += EPSS_BATCH_SIZE) {
    batches.push(cveIds.slice(i, i + EPSS_BATCH_SIZE));
  }
  const batchResults = await pMap(batches, fetchEpssBatch, EPSS_BATCH_CONCURRENCY);
  for (const data of batchResults) {
    for (const entry of data ?? []) {
      results.set(entry.cve, {
        cve: entry.cve,
        epss: parseFloat(entry.epss),
        percentile: parseFloat(entry.percentile)
      });
    }
  }
  return results;
}
async function fetchKevCatalog() {
  if (kevState.cache && Date.now() - kevState.cachedAt < kevState.ttlMs) {
    return kevState.cache;
  }
  try {
    const data = await fetchJsonWithValidation(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      {
        maxBytes: KEV_MAX_BYTES,
        timeoutMs: KEV_TIMEOUT_MS,
        contentType: "application/json"
      }
    );
    const next = new Set((data.vulnerabilities ?? []).map((v) => v.cveID));
    kevState.cache = next;
    kevState.cachedAt = Date.now();
    debug(`CISA KEV loaded: ${next.size} entries`);
    return next;
  } catch (err) {
    if (err instanceof FetchValidationError) {
      debug(`CISA KEV fetch failed (${err.kind}): ${err.message}`);
    } else {
      debug(`CISA KEV fetch failed: ${err instanceof Error ? err.message : err}`);
    }
    return kevState.cache ?? /* @__PURE__ */ new Set();
  }
}
function extractCveIds(aliases) {
  return aliases.filter((a) => a.startsWith("CVE-"));
}
function computeExploitScore(cveIds, epssScores, kevSet) {
  const inKev = cveIds.some((id) => kevSet.has(id));
  if (inKev) {
    return { score: 20, inKev: true, epssMax: 1 };
  }
  let epssMax = null;
  for (const cve of cveIds) {
    const entry = epssScores.get(cve);
    if (entry && (epssMax === null || entry.epss > epssMax)) {
      epssMax = entry.epss;
    }
  }
  if (epssMax === null) {
    return { score: 0, inKev: false, epssMax: null };
  }
  let score = 0;
  if (epssMax >= 0.5) score = 20;
  else if (epssMax >= 0.1) score = 15;
  else if (epssMax >= 0.01) score = 8;
  else score = 2;
  return { score, inKev: false, epssMax };
}

// src/core/advisory/scorer.ts
function scoreMatch(match, ctx = {}) {
  const { advisory } = match;
  let cvssScore = 0;
  let cvssVector = "";
  if (advisory.severity && advisory.severity.length > 0) {
    const v3 = advisory.severity.find((s) => s.type === "CVSS_V3");
    const v4 = advisory.severity.find((s) => s.type === "CVSS_V4");
    const severity = v3 ?? v4 ?? advisory.severity[0];
    const parsed = parseCvssVector(severity.score);
    cvssScore = parsed.score;
    cvssVector = parsed.vector;
  }
  const fixAvailable = advisory.fixVersion !== null;
  const directDependency = match.dependencyPath.length <= 1;
  const depth = match.dependencyPath.length;
  const cveIds = extractCveIds(advisory.aliases ?? []);
  const exploitResult = computeExploitScore(
    cveIds,
    ctx.epssScores ?? /* @__PURE__ */ new Map(),
    ctx.kevSet ?? /* @__PURE__ */ new Set()
  );
  const urlExploit = hasExploitIndicator(advisory.references?.map((r) => r.url) ?? []);
  const exploitAvailable = exploitResult.inKev || exploitResult.score > 0 || urlExploit;
  const score = computeCompositeScore({
    cvssScore,
    isProduction: match.isProduction,
    isDirectlyImported: match.isDirectlyImported ?? false,
    exploitScore: exploitResult.score > 0 ? exploitResult.score : urlExploit ? 15 : 0,
    fixAvailable,
    depth,
    directDependency
  });
  const label = determineLabel({
    cvssScore,
    isProduction: match.isProduction,
    exploitAvailable
  });
  const risk = {
    score,
    label,
    factors: {
      cvssScore,
      cvssVector,
      productionReachable: match.isProduction,
      directlyImported: match.isDirectlyImported ?? false,
      exploitAvailable,
      epssScore: exploitResult.epssMax,
      inKev: exploitResult.inKev,
      fixAvailable,
      fixVersion: advisory.fixVersion,
      depth,
      directDependency
    }
  };
  return { match, risk };
}
function scoreAllMatches(matches, ctx = {}) {
  return matches.map((m) => scoreMatch(m, ctx)).sort((a, b) => {
    if (a.risk.score !== b.risk.score) return b.risk.score - a.risk.score;
    return a.match.advisory.id.localeCompare(b.match.advisory.id);
  });
}
function computeCompositeScore(factors) {
  let score = 0;
  score += factors.cvssScore * 4;
  if (factors.isProduction) {
    score += 30;
  }
  if (factors.isDirectlyImported) {
    score += 10;
  }
  score += factors.exploitScore;
  if (!factors.fixAvailable) {
    score += 5;
  }
  if (factors.directDependency) {
    score += 5;
  }
  score -= Math.min(factors.depth, 5);
  return Math.max(0, Math.min(100, Math.round(score)));
}
function determineLabel(factors) {
  if (factors.isProduction && factors.exploitAvailable && factors.cvssScore >= 7) {
    return "critical";
  }
  if (factors.isProduction && factors.cvssScore >= 7) {
    return "high";
  }
  if (factors.isProduction && factors.cvssScore >= 4) {
    return "medium";
  }
  if (!factors.isProduction) {
    return "low";
  }
  if (factors.cvssScore >= 4) {
    return "medium";
  }
  return "low";
}
function hasExploitIndicator(urls) {
  const exploitPatterns = [
    "exploit-db.com",
    "packetstormsecurity.com",
    "/cisa.gov/known-exploited"
  ];
  return urls.some(
    (url) => exploitPatterns.some((pattern) => url.includes(pattern))
  );
}

// src/core/allowlist/local.ts
import { readFileSync as readFileSync3, writeFileSync as writeFileSync2, existsSync as existsSync3, lstatSync as lstatSync2 } from "fs";
import { join as join3 } from "path";
var ALLOWLIST_FILENAME = ".auditfixignore";
function loadLocalAllowList(projectDir) {
  const filePath = join3(projectDir, ALLOWLIST_FILENAME);
  if (!existsSync3(filePath)) {
    return { ignore: [] };
  }
  try {
    const content = readFileSync3(filePath, "utf-8");
    const parsed = safeJsonParse(content);
    if (!parsed.ignore || !Array.isArray(parsed.ignore)) {
      warn(`${ALLOWLIST_FILENAME}: missing or invalid "ignore" array \u2014 ignoring file`);
      return { ignore: [] };
    }
    const valid = [];
    for (const entry of parsed.ignore) {
      if (!entry.id || !entry.package || !entry.reason || !entry.expires) {
        warn(`${ALLOWLIST_FILENAME}: skipping entry missing required fields (id, package, reason, expires)`);
        continue;
      }
      if (!isValidAdvisoryId(entry.id)) {
        warn(`${ALLOWLIST_FILENAME}: skipping entry with invalid advisory ID: ${entry.id}`);
        continue;
      }
      const expiryDate = new Date(entry.expires);
      if (isNaN(expiryDate.getTime())) {
        warn(`${ALLOWLIST_FILENAME}: skipping entry with invalid expiry date: ${entry.expires}`);
        continue;
      }
      if (expiryDate < /* @__PURE__ */ new Date()) {
        info(`${ALLOWLIST_FILENAME}: entry expired for ${entry.id} (${entry.package}) \u2014 no longer suppressed`);
        continue;
      }
      valid.push(entry);
    }
    return { ignore: valid };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`Failed to parse ${ALLOWLIST_FILENAME}: ${msg}`);
    return { ignore: [] };
  }
}
function applyAllowList(matches, allowList) {
  const kept = [];
  const ignored = [];
  for (const match of matches) {
    const entry = allowList.ignore.find(
      (e) => e.id === match.advisory.id && e.package === match.package
    );
    if (entry) {
      ignored.push({
        match,
        reason: entry.reason,
        source: "local-allowlist"
      });
    } else {
      const aliasEntry = allowList.ignore.find(
        (e) => e.package === match.package && match.advisory.aliases.includes(e.id)
      );
      if (aliasEntry) {
        ignored.push({
          match,
          reason: aliasEntry.reason,
          source: "local-allowlist"
        });
      } else {
        kept.push(match);
      }
    }
  }
  return { kept, ignored };
}

// src/core/workspace/detector.ts
import { readFileSync as readFileSync4, existsSync as existsSync4, readdirSync as readdirSync2, statSync as statSync2 } from "fs";
import { join as join4, relative } from "path";
function detectWorkspaces(projectDir) {
  const pnpmWorkspacePath = join4(projectDir, "pnpm-workspace.yaml");
  if (existsSync4(pnpmWorkspacePath)) {
    return detectPnpmWorkspaces(projectDir, pnpmWorkspacePath);
  }
  const packageJsonPath = join4(projectDir, "package.json");
  if (existsSync4(packageJsonPath)) {
    try {
      const content = readFileSync4(packageJsonPath, "utf-8");
      const pkg = safeJsonParse(content);
      const workspacesField = pkg.workspaces;
      if (workspacesField) {
        return detectNpmYarnWorkspaces(projectDir, workspacesField);
      }
    } catch {
    }
  }
  return { isMonorepo: false, workspaces: [] };
}
function detectPnpmWorkspaces(projectDir, configPath) {
  try {
    const content = readFileSync4(configPath, "utf-8");
    const config = safeYamlParse(content);
    if (!config?.packages || !Array.isArray(config.packages)) {
      return { isMonorepo: false, workspaces: [] };
    }
    const workspaces = resolveWorkspaceGlobs(projectDir, config.packages);
    debug(`Detected pnpm monorepo with ${workspaces.length} workspaces`);
    return { isMonorepo: workspaces.length > 0, workspaces };
  } catch {
    return { isMonorepo: false, workspaces: [] };
  }
}
function detectNpmYarnWorkspaces(projectDir, workspacesField) {
  let patterns;
  if (Array.isArray(workspacesField)) {
    patterns = workspacesField.filter((p) => typeof p === "string");
  } else if (typeof workspacesField === "object" && workspacesField !== null && "packages" in workspacesField && Array.isArray(workspacesField.packages)) {
    patterns = workspacesField.packages;
  } else {
    return { isMonorepo: false, workspaces: [] };
  }
  const workspaces = resolveWorkspaceGlobs(projectDir, patterns);
  debug(`Detected npm/yarn monorepo with ${workspaces.length} workspaces`);
  return { isMonorepo: workspaces.length > 0, workspaces };
}
function resolveWorkspaceGlobs(projectDir, patterns) {
  const workspaces = [];
  const seen = /* @__PURE__ */ new Set();
  for (const pattern of patterns) {
    if (pattern.startsWith("!")) continue;
    const cleanPattern = pattern.replace(/\/?\*\*?$/, "");
    const baseDir = join4(projectDir, cleanPattern);
    if (!existsSync4(baseDir) || !statSync2(baseDir).isDirectory()) {
      const directPkg = join4(projectDir, pattern, "package.json");
      if (existsSync4(directPkg)) {
        const ws = readWorkspacePackage(projectDir, pattern);
        if (ws && !seen.has(ws.name)) {
          seen.add(ws.name);
          workspaces.push(ws);
        }
      }
      continue;
    }
    try {
      const entries = readdirSync2(baseDir);
      for (const entry of entries) {
        const entryPath = join4(baseDir, entry);
        const pkgJsonPath = join4(entryPath, "package.json");
        if (statSync2(entryPath).isDirectory() && existsSync4(pkgJsonPath)) {
          const relPath = relative(projectDir, entryPath).replace(/\\/g, "/");
          const ws = readWorkspacePackage(projectDir, relPath);
          if (ws && !seen.has(ws.name)) {
            seen.add(ws.name);
            workspaces.push(ws);
          }
        }
      }
    } catch {
    }
  }
  return workspaces;
}
function readWorkspacePackage(projectDir, relPath) {
  try {
    const pkgPath = join4(projectDir, relPath, "package.json");
    const content = readFileSync4(pkgPath, "utf-8");
    const pkg = safeJsonParse(content);
    const name = pkg.name ?? relPath;
    return {
      name,
      path: relPath,
      dependencies: pkg.dependencies ?? {},
      devDependencies: pkg.devDependencies ?? {}
    };
  } catch {
    return null;
  }
}
function mapDepsToWorkspaces(graph, workspaces) {
  if (workspaces.length === 0) return /* @__PURE__ */ new Map();
  const depToWorkspaces = /* @__PURE__ */ new Map();
  const nameIndex = /* @__PURE__ */ new Map();
  for (const [graphKey, node] of graph) {
    const keys = nameIndex.get(node.name);
    if (keys) {
      keys.push(graphKey);
    } else {
      nameIndex.set(node.name, [graphKey]);
    }
  }
  const transitiveCache = /* @__PURE__ */ new Map();
  function getTransitiveDeps(graphKey) {
    if (transitiveCache.has(graphKey)) return transitiveCache.get(graphKey);
    const result = /* @__PURE__ */ new Set();
    transitiveCache.set(graphKey, result);
    const node = graph.get(graphKey);
    if (!node) return result;
    for (const depKey of node.dependencies) {
      result.add(depKey);
      for (const transKey of getTransitiveDeps(depKey)) {
        result.add(transKey);
      }
    }
    return result;
  }
  for (const ws of workspaces) {
    const allDeps = { ...ws.dependencies, ...ws.devDependencies };
    for (const depName of Object.keys(allDeps)) {
      const candidates = nameIndex.get(depName);
      if (!candidates) continue;
      for (const graphKey of candidates) {
        if (!depToWorkspaces.has(graphKey)) {
          depToWorkspaces.set(graphKey, /* @__PURE__ */ new Set());
        }
        depToWorkspaces.get(graphKey).add(ws.name);
        for (const transKey of getTransitiveDeps(graphKey)) {
          if (!depToWorkspaces.has(transKey)) {
            depToWorkspaces.set(transKey, /* @__PURE__ */ new Set());
          }
          depToWorkspaces.get(transKey).add(ws.name);
        }
      }
    }
  }
  return depToWorkspaces;
}

// src/core/graph/import-chain.ts
import { readFileSync as readFileSync5, existsSync as existsSync5, readdirSync as readdirSync3, statSync as statSync3 } from "fs";
import { join as join5, extname, resolve as resolve3 } from "path";
var JS_EXTENSIONS = /* @__PURE__ */ new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"]);
var NODE_BUILTINS = /* @__PURE__ */ new Set([
  "assert",
  "assert/strict",
  "async_hooks",
  "buffer",
  "child_process",
  "cluster",
  "console",
  "constants",
  "crypto",
  "dgram",
  "diagnostics_channel",
  "dns",
  "dns/promises",
  "domain",
  "events",
  "fs",
  "fs/promises",
  "http",
  "http2",
  "https",
  "inspector",
  "module",
  "net",
  "os",
  "path",
  "path/posix",
  "path/win32",
  "perf_hooks",
  "process",
  "punycode",
  "querystring",
  "readline",
  "readline/promises",
  "repl",
  "stream",
  "stream/consumers",
  "stream/promises",
  "stream/web",
  "string_decoder",
  "sys",
  "test",
  "timers",
  "timers/promises",
  "tls",
  "trace_events",
  "tty",
  "url",
  "util",
  "util/types",
  "v8",
  "vm",
  "wasi",
  "worker_threads",
  "zlib"
]);
var IMPORT_PATTERN = /(?:import\s+(?:[\w{},*\s]+\s+from\s+)?['"]([^'"./][^'"]*)['"])|(?:export\s+(?:[\w{},*\s]+\s+from\s+)['"]([^'"./][^'"]*)['"])|(?:require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\))|(?:import\s*\(\s*['"`]([^'"`./][^'"`]*?)['"`]\s*\))/g;
function stripComments(source) {
  const len = source.length;
  let out = "";
  let i = 0;
  let segStart = 0;
  while (i < len) {
    const ch = source.charCodeAt(i);
    if (ch === 47 && i + 1 < len) {
      const next = source.charCodeAt(i + 1);
      if (next === 47) {
        out += source.slice(segStart, i);
        i += 2;
        while (i < len && source.charCodeAt(i) !== 10) i++;
        segStart = i;
        continue;
      }
      if (next === 42) {
        out += source.slice(segStart, i);
        i += 2;
        while (i + 1 < len) {
          if (source.charCodeAt(i) === 42 && source.charCodeAt(i + 1) === 47) {
            i += 2;
            break;
          }
          i++;
        }
        if (i + 1 >= len) i = len;
        out += " ";
        segStart = i;
        continue;
      }
    }
    if (ch === 34 || ch === 39 || ch === 96) {
      const quote = ch;
      i++;
      while (i < len) {
        const sc = source.charCodeAt(i);
        if (sc === 92) {
          i += 2;
          continue;
        }
        if (sc === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    i++;
  }
  out += source.slice(segStart, len);
  return out;
}
function isNodeBuiltin(specifier) {
  if (specifier.startsWith("node:")) return true;
  return NODE_BUILTINS.has(specifier);
}
function extractPackageName2(specifier) {
  if (specifier.startsWith("@")) {
    const first = specifier.indexOf("/");
    if (first < 0) return specifier;
    const second = specifier.indexOf("/", first + 1);
    return second < 0 ? specifier : specifier.slice(0, second);
  }
  const slash = specifier.indexOf("/");
  return slash < 0 ? specifier : specifier.slice(0, slash);
}
function extractImports(content) {
  const imports = /* @__PURE__ */ new Set();
  const cleaned = stripComments(content);
  IMPORT_PATTERN.lastIndex = 0;
  let m;
  while ((m = IMPORT_PATTERN.exec(cleaned)) !== null) {
    const specifier = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (!specifier) continue;
    if (specifier.charCodeAt(0) === 46) continue;
    if (isNodeBuiltin(specifier)) continue;
    const pkgName = extractPackageName2(specifier);
    if (pkgName) imports.add(pkgName);
  }
  return imports;
}
var fileCache = /* @__PURE__ */ new Map();
function scanImportChains(projectDir, entryDirs = ["src", "lib", "app", "pages", "routes"]) {
  const importedPackages = /* @__PURE__ */ new Set();
  const scannedFiles = /* @__PURE__ */ new Set();
  for (const dir of entryDirs) {
    const fullDir = join5(projectDir, dir);
    if (existsSync5(fullDir)) {
      try {
        if (statSync3(fullDir).isDirectory()) {
          walkDir(fullDir, scannedFiles, importedPackages);
        }
      } catch {
      }
    }
  }
  for (const entry of ["index.js", "index.ts", "index.mjs", "server.js", "server.ts", "main.js", "main.ts"]) {
    const entryPath = join5(projectDir, entry);
    if (existsSync5(entryPath)) {
      scanFile(entryPath, scannedFiles, importedPackages);
    }
  }
  debug(`Import chain scan: ${scannedFiles.size} files scanned, ${importedPackages.size} packages imported`);
  return importedPackages;
}
var MAX_SCAN_DEPTH = 15;
var MAX_SCAN_FILES = 1e4;
var SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", "dist", "build", "coverage"]);
function walkDir(dir, scanned, imports, depth = 0) {
  if (depth > MAX_SCAN_DEPTH || scanned.size > MAX_SCAN_FILES) return;
  let entries;
  try {
    entries = readdirSync3(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const name = entry.name;
    if (SKIP_DIRS.has(name)) continue;
    const fullPath = join5(dir, name);
    if (entry.isDirectory()) {
      walkDir(fullPath, scanned, imports, depth + 1);
    } else if (entry.isFile() && JS_EXTENSIONS.has(extname(name))) {
      scanFile(fullPath, scanned, imports);
    }
  }
}
function scanFile(filePath, scanned, imports) {
  const resolved = resolve3(filePath);
  if (scanned.has(resolved)) return;
  scanned.add(resolved);
  let mtimeMs;
  try {
    mtimeMs = statSync3(resolved).mtimeMs;
  } catch {
    return;
  }
  const cached = fileCache.get(resolved);
  if (cached && cached.mtimeMs === mtimeMs) {
    for (const pkg of cached.packages) imports.add(pkg);
    return;
  }
  try {
    const content = readFileSync5(resolved, "utf-8");
    const pkgs = extractImports(content);
    fileCache.set(resolved, { mtimeMs, packages: pkgs });
    for (const pkg of pkgs) imports.add(pkg);
  } catch {
  }
}
function isDirectlyImported(packageName, importedPackages) {
  return importedPackages.has(packageName);
}

// src/core/analyzer.ts
async function analyze(options) {
  const startTime = Date.now();
  info("Detecting and parsing lockfile...");
  const lockfileResult = detectAndParseLockfile(options.projectDir);
  info(`Parsed ${lockfileResult.packageCount} packages (${lockfileResult.type})`);
  if (lockfileResult.skipped.length > 0) {
    debug(`Skipped ${lockfileResult.skipped.length} entries: ${lockfileResult.skipped.map((s) => `${s.key} (${s.reason})`).join(", ")}`);
  }
  const wsConfig = detectWorkspaces(options.projectDir);
  let depToWorkspaces;
  if (wsConfig.isMonorepo) {
    info(`Monorepo detected: ${wsConfig.workspaces.length} workspaces`);
    depToWorkspaces = mapDepsToWorkspaces(lockfileResult.graph, wsConfig.workspaces);
  }
  const importedPackages = scanImportChains(options.projectDir);
  computeDependencyPaths(lockfileResult.graph);
  let advisorySource;
  let confidence;
  let advisoryCount;
  let advisories;
  try {
    const resolved = await resolveAdvisoriesWithCache(lockfileResult.graph, { noCache: options.noCache });
    advisories = resolved.advisories;
    advisorySource = resolved.source;
    confidence = resolved.confidence;
    advisoryCount = countAdvisories(advisories);
    if (resolved.errors.length > 0) {
      for (const err of resolved.errors) {
        warn(err);
      }
    }
  } catch (err) {
    if (err instanceof AdvisoryResolutionError) {
      for (const e of err.errors) {
        warn(e);
      }
      error(err.message);
      return {
        vulnerabilities: [],
        metadata: {
          totalPackages: lockfileResult.packageCount,
          skippedPackages: lockfileResult.skipped.length,
          skippedReasons: lockfileResult.skipped.map((s) => ({ key: s.key, reason: s.reason })),
          advisorySource: "None (all sources failed)",
          advisoryCount: 0,
          confidence: "UNRELIABLE",
          scanDurationMs: Date.now() - startTime,
          lockfileType: lockfileResult.type
        },
        ignored: []
      };
    }
    throw err;
  }
  info("Matching advisories...");
  const allMatches = matchAdvisories(lockfileResult.graph, advisories);
  for (const match of allMatches) {
    if (depToWorkspaces) {
      const graphKey = `${match.package}@${match.installedVersion}`;
      const ws = depToWorkspaces.get(graphKey);
      if (ws && ws.size > 0) {
        match.workspaces = [...ws];
      }
    }
    match.isDirectlyImported = isDirectlyImported(match.package, importedPackages);
  }
  info(`Found ${allMatches.length} vulnerability matches`);
  const allowList = loadLocalAllowList(options.projectDir);
  const { kept: matches, ignored } = applyAllowList(allMatches, allowList);
  if (ignored.length > 0) {
    info(`${ignored.length} vulnerabilities suppressed by allow-list`);
  }
  const allCveIds = /* @__PURE__ */ new Set();
  for (const m of matches) {
    for (const cve of extractCveIds(m.advisory.aliases ?? [])) {
      allCveIds.add(cve);
    }
  }
  let scorerCtx = {};
  if (allCveIds.size > 0) {
    info(`Fetching EPSS/KEV data for ${allCveIds.size} CVEs...`);
    const [epssScores, kevSet] = await Promise.all([
      fetchEpssScores([...allCveIds]).catch(() => /* @__PURE__ */ new Map()),
      fetchKevCatalog().catch(() => /* @__PURE__ */ new Set())
    ]);
    scorerCtx = { epssScores, kevSet };
    debug(`EPSS: ${epssScores.size} scores, KEV: ${kevSet.size} entries`);
  }
  const severityRank = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0
  };
  const minRank = options.severityThreshold && options.severityThreshold !== "info" ? severityRank[options.severityThreshold] ?? 0 : 0;
  let scored = scoreAllMatches(matches, scorerCtx).filter((s) => {
    if (options.workspace && !(s.match.workspaces?.includes(options.workspace) ?? false)) return false;
    if (options.productionOnly && !s.match.isProduction) return false;
    if (minRank > 0 && severityRank[s.risk.label] < minRank) return false;
    return true;
  });
  const skipRate = lockfileResult.skipped.length / Math.max(lockfileResult.packageCount, 1);
  if (skipRate > 0.1) {
    confidence = "UNRELIABLE";
  } else if (skipRate > 0.05 && confidence === "HIGH") {
    confidence = "MEDIUM";
  }
  const metadata = {
    totalPackages: lockfileResult.packageCount,
    skippedPackages: lockfileResult.skipped.length,
    skippedReasons: lockfileResult.skipped.map((s) => ({ key: s.key, reason: s.reason })),
    advisorySource,
    advisoryCount,
    confidence,
    scanDurationMs: Date.now() - startTime,
    workspaceCount: wsConfig.isMonorepo ? wsConfig.workspaces.length : void 0,
    lockfileType: lockfileResult.type
  };
  return {
    vulnerabilities: scored,
    metadata,
    ignored
  };
}
function countAdvisories(advisories) {
  let count = 0;
  for (const [, list] of advisories) {
    count += list.length;
  }
  return count;
}

// src/cli/output/sarif.ts
var SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
var SARIF_VERSION = "2.1.0";
function toSarifLevel(label) {
  switch (label) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "note";
  }
}
function formatSecuritySeverity(cvssScore) {
  const clamped = Math.max(0, Math.min(10, cvssScore));
  return clamped.toFixed(1);
}
function buildMessage(vuln) {
  const advisory = vuln.match.advisory;
  const pkg = vuln.match.package;
  const version = vuln.match.installedVersion;
  const summary = advisory.summary || "No description available";
  const fix = vuln.risk.factors.fixVersion;
  const fixNote = fix ? ` Fix available in ${fix}.` : " No fix available.";
  return `${pkg}@${version} is vulnerable: ${summary}.${fixNote}`;
}
function getLockfileUri(report) {
  const type2 = report.metadata?.lockfileType;
  if (type2?.startsWith("pnpm")) return "pnpm-lock.yaml";
  if (type2?.startsWith("yarn")) return "yarn.lock";
  return "package-lock.json";
}
function renderSarifReport(report, version) {
  if (!report) {
    throw new Error("report is required");
  }
  if (!version || typeof version !== "string") {
    throw new Error("version is required and must be a non-empty string");
  }
  const ruleMap = /* @__PURE__ */ new Map();
  const ruleIndexMap = /* @__PURE__ */ new Map();
  for (const vuln of report.vulnerabilities) {
    const advisoryId = vuln.match.advisory.id;
    if (!ruleMap.has(advisoryId)) {
      const advisory = vuln.match.advisory;
      const helpUrl = advisory.references.find((r) => r.type === "WEB" || r.type === "ADVISORY")?.url;
      const rule = {
        id: advisoryId,
        shortDescription: { text: advisory.summary || advisoryId },
        fullDescription: {
          text: advisory.details || advisory.summary || advisoryId
        },
        properties: {
          "security-severity": formatSecuritySeverity(vuln.risk.factors.cvssScore)
        }
      };
      if (helpUrl) {
        rule.helpUri = helpUrl;
      }
      ruleIndexMap.set(advisoryId, ruleMap.size);
      ruleMap.set(advisoryId, rule);
    }
  }
  const rules = Array.from(ruleMap.values());
  const lockfileUri = getLockfileUri(report);
  const results = report.vulnerabilities.map((vuln) => {
    const advisoryId = vuln.match.advisory.id;
    const ruleIndex = ruleIndexMap.get(advisoryId);
    return {
      ruleId: advisoryId,
      ruleIndex,
      level: toSarifLevel(vuln.risk.label),
      message: { text: buildMessage(vuln) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: lockfileUri
            }
          }
        }
      ]
    };
  });
  const sarif = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "auditfix",
            version,
            rules
          }
        },
        results
      }
    ]
  };
  return JSON.stringify(sarif, null, 2);
}

// src/cli/output/json.ts
function renderJsonReport(report) {
  const output = {
    vulnerabilities: report.vulnerabilities.map((v) => ({
      id: v.match.advisory.id,
      package: v.match.package,
      installedVersion: v.match.installedVersion,
      severity: v.risk.label,
      score: v.risk.score,
      summary: v.match.advisory.summary,
      production: v.match.isProduction,
      fixVersion: v.risk.factors.fixVersion,
      dependencyPath: v.match.dependencyPath,
      cvss: {
        score: v.risk.factors.cvssScore,
        vector: v.risk.factors.cvssVector
      }
    })),
    ignored: report.ignored.map((i) => ({
      id: i.match.advisory.id,
      package: i.match.package,
      reason: i.reason,
      source: i.source
    })),
    metadata: report.metadata
  };
  return JSON.stringify(output, null, 2);
}

// src/core/notify/pr-comment.ts
import { readFileSync as readFileSync6 } from "fs";
var COMMENT_MARKER = "<!-- auditfix-scan -->";
var API_BASE = "https://api.github.com";
var TIMEOUT_MS = 15e3;
var VERSION = "2.0.0";
function getPrNumber() {
  const ref = process.env.GITHUB_REF ?? "";
  const refMatch = /^refs\/pull\/(\d+)\/merge$/.exec(ref);
  if (refMatch) {
    return Number(refMatch[1]);
  }
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath) {
    try {
      const raw = readFileSync6(eventPath, "utf-8");
      const event = JSON.parse(raw);
      if (typeof event === "object" && event !== null && "pull_request" in event) {
        const pr = event.pull_request;
        if (typeof pr === "object" && pr !== null && "number" in pr) {
          const num = pr.number;
          if (typeof num === "number" && Number.isInteger(num) && num > 0) {
            return num;
          }
        }
      }
    } catch {
      debug(`Failed to read event payload at ${eventPath}`);
    }
  }
  return null;
}
function apiHeaders(token) {
  return {
    Authorization: `token ${token}`,
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "auditfix",
    "Content-Type": "application/json"
  };
}
async function findExistingComment(token, repo, prNumber) {
  const url = `${API_BASE}/repos/${repo}/issues/${prNumber}/comments`;
  let page = 1;
  while (page <= 10) {
    const res = await fetch(`${url}?per_page=100&page=${page}`, {
      method: "GET",
      headers: apiHeaders(token),
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) {
      warn(`Failed to list PR comments: HTTP ${res.status}`);
      return null;
    }
    const comments = await res.json();
    if (comments.length === 0) break;
    const existing = comments.find(
      (c) => typeof c.body === "string" && c.body.includes(COMMENT_MARKER)
    );
    if (existing) return existing;
    page++;
  }
  return null;
}
function escapeMarkdown(s) {
  if (s == null) return "";
  const str2 = String(s);
  let out = "";
  for (let i = 0; i < str2.length; i++) {
    const ch = str2[i];
    switch (ch) {
      case "\\":
        out += "\\\\";
        break;
      case "`":
        out += "\\`";
        break;
      case "|":
        out += "\\|";
        break;
      case "[":
        out += "\\[";
        break;
      case "]":
        out += "\\]";
        break;
      case "(":
        out += "\\(";
        break;
      case ")":
        out += "\\)";
        break;
      case "<":
        out += "&lt;";
        break;
      case ">":
        out += "&gt;";
        break;
      case "@":
        out += "@\u200B";
        break;
      // zero-width space defeats @mention autolink
      case "\r":
        out += " ";
        break;
      case "\n":
        out += " ";
        break;
      default:
        out += ch;
    }
  }
  return out;
}
function severityEmoji(label) {
  switch (label) {
    case "critical":
      return "\u{1F534}";
    case "high":
      return "\u{1F7E0}";
    case "medium":
      return "\u{1F7E1}";
    case "low":
      return "\u{1F7E2}";
    default:
      return "\u26AA";
  }
}
function headerEmoji(report) {
  const labels = report.vulnerabilities.map((v) => v.risk.label);
  if (labels.includes("critical")) return "\u{1F6A8}";
  if (labels.includes("high")) return "\u26A0\uFE0F";
  if (report.vulnerabilities.length > 0) return "\u2139\uFE0F";
  return "\u2705";
}
function buildCommentBody(report) {
  const vulns = report.vulnerabilities;
  const total = vulns.length;
  const prod = vulns.filter((v) => v.match.isProduction).length;
  const crit = vulns.filter((v) => v.risk.label === "critical").length;
  const high = vulns.filter((v) => v.risk.label === "high").length;
  const med = vulns.filter((v) => v.risk.label === "medium").length;
  const low = vulns.filter((v) => v.risk.label === "low").length;
  const emoji = headerEmoji(report);
  const lines = [];
  lines.push(COMMENT_MARKER);
  lines.push("");
  if (total === 0) {
    lines.push(`## ${emoji} auditfix \u2014 No vulnerabilities found`);
  } else {
    lines.push(`## ${emoji} auditfix \u2014 ${total} ${total === 1 ? "vulnerability" : "vulnerabilities"} found`);
  }
  lines.push("");
  lines.push("### Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("| --- | --- |");
  lines.push(`| Total | ${total} |`);
  lines.push(`| Production | ${prod} |`);
  lines.push(`| ${severityEmoji("critical")} Critical | ${crit} |`);
  lines.push(`| ${severityEmoji("high")} High | ${high} |`);
  lines.push(`| ${severityEmoji("medium")} Medium | ${med} |`);
  lines.push(`| ${severityEmoji("low")} Low | ${low} |`);
  lines.push("");
  if (total > 0) {
    const top = vulns.slice(0, 10);
    lines.push("### Top vulnerabilities");
    lines.push("");
    lines.push("| Package | Version | Severity | Score | Fix |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const v of top) {
      const fix = v.risk.factors.fixVersion ? escapeMarkdown(v.risk.factors.fixVersion) : "\u2014";
      const sev = `${severityEmoji(v.risk.label)} ${escapeMarkdown(v.risk.label)}`;
      const pkg = escapeMarkdown(v.match.package);
      const ver = escapeMarkdown(v.match.installedVersion);
      lines.push(`| \`${pkg}\` | ${ver} | ${sev} | ${v.risk.score} | ${fix} |`);
    }
    if (total > 10) {
      lines.push("");
      lines.push(`> _...and ${total - 10} more not shown._`);
    }
    lines.push("");
  }
  const fixable = vulns.filter((v) => v.risk.factors.fixAvailable && v.risk.factors.fixVersion);
  if (fixable.length > 0) {
    lines.push("### Auto-fix suggestions");
    lines.push("");
    lines.push(`${fixable.length} ${fixable.length === 1 ? "vulnerability has" : "vulnerabilities have"} a known fix:`);
    lines.push("");
    for (const v of fixable.slice(0, 10)) {
      const pkg = escapeMarkdown(v.match.package);
      const ver = escapeMarkdown(v.match.installedVersion);
      const fix = escapeMarkdown(v.risk.factors.fixVersion ?? "");
      lines.push(`- \`${pkg}\` ${ver} \u2192 **${fix}**`);
    }
    if (fixable.length > 10) {
      lines.push(`- _...and ${fixable.length - 10} more_`);
    }
    lines.push("");
  }
  lines.push("---");
  lines.push(
    `<sub>auditfix v${VERSION} | ${escapeMarkdown(report.metadata.advisorySource)} | ${report.metadata.totalPackages} packages scanned | confidence: ${escapeMarkdown(report.metadata.confidence)} | ${report.metadata.scanDurationMs}ms</sub>`
  );
  return lines.join("\n");
}
async function postPrComment(report, options) {
  const token = options?.token ?? process.env.GITHUB_TOKEN;
  if (!token) {
    return { success: false, error: "No GitHub token available (set GITHUB_TOKEN or pass options.token)" };
  }
  const repo = options?.repo ?? process.env.GITHUB_REPOSITORY;
  if (!repo) {
    return { success: false, error: "No repository detected (set GITHUB_REPOSITORY or pass options.repo)" };
  }
  const prNumber = options?.prNumber ?? getPrNumber();
  if (!prNumber) {
    return { success: false, error: "Could not detect PR number from environment (set GITHUB_REF, provide GITHUB_EVENT_PATH, or pass options.prNumber)" };
  }
  const updateExisting = options?.updateExisting ?? true;
  const body = buildCommentBody(report);
  try {
    if (updateExisting) {
      const existing = await findExistingComment(token, repo, prNumber);
      if (existing) {
        info(`Updating existing PR comment ${existing.id}`);
        const patchUrl = `${API_BASE}/repos/${repo}/issues/comments/${existing.id}`;
        const res2 = await fetch(patchUrl, {
          method: "PATCH",
          headers: apiHeaders(token),
          body: JSON.stringify({ body }),
          signal: AbortSignal.timeout(TIMEOUT_MS)
        });
        if (!res2.ok) {
          const text = await res2.text().catch(() => "");
          return { success: false, error: `Failed to update comment: HTTP ${res2.status} ${text.slice(0, 200)}` };
        }
        const updated = await res2.json();
        info(`PR comment updated: ${updated.html_url}`);
        return { success: true, commentUrl: updated.html_url };
      }
    }
    info(`Posting new PR comment on ${repo}#${prNumber}`);
    const postUrl = `${API_BASE}/repos/${repo}/issues/${prNumber}/comments`;
    const res = await fetch(postUrl, {
      method: "POST",
      headers: apiHeaders(token),
      body: JSON.stringify({ body }),
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { success: false, error: `Failed to create comment: HTTP ${res.status} ${text.slice(0, 200)}` };
    }
    const created = await res.json();
    info(`PR comment created: ${created.html_url}`);
    return { success: true, commentUrl: created.html_url };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    error(`PR comment failed: ${msg}`);
    return { success: false, error: msg };
  }
}

// src/core/notify/webhook.ts
import * as dns from "dns/promises";
import * as net from "net";
var ALLOWED_PORTS = /* @__PURE__ */ new Set([80, 443]);
var ALLOWED_PROTOCOLS = /* @__PURE__ */ new Set(["http:", "https:"]);
function isPrivateIp(ip) {
  if (!ip) return true;
  const bare = ip.includes("%") ? ip.slice(0, ip.indexOf("%")) : ip;
  const family = net.isIP(bare);
  if (family === 4) return isPrivateIPv4(bare);
  if (family === 6) return isPrivateIPv6(bare);
  return true;
}
function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return true;
  if (a === 203 && b === 0) return true;
  if (a >= 224) return true;
  return false;
}
function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1" || lower === "0:0:0:0:0:0:0:0" || lower === "0:0:0:0:0:0:0:1") return true;
  const mapped = /^::ffff:([0-9a-f:.]+)$/i.exec(ip);
  if (mapped) {
    const inner = mapped[1];
    if (net.isIPv4(inner)) return isPrivateIPv4(inner);
    const hexParts = inner.split(":");
    if (hexParts.length === 2 && /^[0-9a-f]{1,4}$/i.test(hexParts[0]) && /^[0-9a-f]{1,4}$/i.test(hexParts[1])) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      const a = hi >> 8 & 255;
      const b = hi & 255;
      const c = lo >> 8 & 255;
      const d = lo & 255;
      return isPrivateIPv4(`${a}.${b}.${c}.${d}`);
    }
    return true;
  }
  const compat = /^::([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/.exec(lower);
  if (compat && net.isIPv4(compat[1])) return isPrivateIPv4(compat[1]);
  const groups = expandIPv6(lower);
  if (!groups) return true;
  const first = groups[0];
  if ((first & 65024) === 64512) return true;
  if ((first & 65472) === 65152) return true;
  if ((first & 65280) === 65280) return true;
  if (first === 8193 && groups[1] === 3512) return true;
  if (groups.every((g) => g === 0)) return true;
  return false;
}
function expandIPv6(ip) {
  let head;
  let tail;
  if (ip.includes("::")) {
    const parts = ip.split("::");
    if (parts.length !== 2) return null;
    head = parts[0] ? parts[0].split(":") : [];
    tail = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    const fill = new Array(missing).fill("0");
    const all = [...head, ...fill, ...tail];
    return all.map((g) => parseInt(g || "0", 16));
  }
  const groups = ip.split(":");
  if (groups.length !== 8) return null;
  return groups.map((g) => parseInt(g || "0", 16));
}
async function isValidWebhookUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, reason: "Invalid URL" };
  }
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return { valid: false, reason: `Protocol ${parsed.protocol} not allowed` };
  }
  if (parsed.port !== "") {
    const portNum = Number(parsed.port);
    if (!ALLOWED_PORTS.has(portNum)) {
      return { valid: false, reason: `Port ${parsed.port} not allowed` };
    }
  }
  const hostname = parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  if (!hostname) {
    return { valid: false, reason: "Missing hostname" };
  }
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      return { valid: false, reason: `Resolved address ${hostname} is in a private/reserved range` };
    }
    return { valid: true };
  }
  if (hostname.toLowerCase() === "localhost") {
    return { valid: false, reason: "Hostname localhost is not allowed" };
  }
  try {
    const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    if (addresses.length === 0) {
      return { valid: false, reason: `DNS resolution returned no addresses for ${hostname}` };
    }
    for (const addr of addresses) {
      if (isPrivateIp(addr.address)) {
        return { valid: false, reason: `Resolved address ${addr.address} is in a private/reserved range` };
      }
    }
    return { valid: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { valid: false, reason: `DNS resolution failed: ${msg}` };
  }
}
async function sendWebhook(webhookUrl, report, projectName) {
  const validation = await isValidWebhookUrl(webhookUrl);
  if (!validation.valid) {
    const reason = validation.reason ?? "Invalid webhook URL";
    warn(`Webhook URL rejected: ${reason}`);
    return { success: false, error: `Webhook URL rejected: ${reason}` };
  }
  const platform = detectPlatform(webhookUrl);
  const body = platform === "slack" ? buildSlackPayload(report, projectName) : platform === "teams" ? buildTeamsPayload(report, projectName) : platform === "discord" ? buildDiscordPayload(report, projectName) : buildGenericPayload(report, projectName);
  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(1e4)
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      return { success: false, statusCode: response.status, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
    }
    info(`Webhook notification sent successfully (${response.status})`);
    return { success: true, statusCode: response.status };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
}
function detectPlatform(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (hostname === "hooks.slack.com" || hostname === "hooks.slack-gov.com") return "slack";
    if (hostname.endsWith(".webhook.office.com") || hostname === "webhook.office.com" || hostname.endsWith(".outlook.office.com") || hostname === "outlook.office.com") return "teams";
    if (hostname === "discord.com" || hostname === "discordapp.com") return "discord";
  } catch {
  }
  return "generic";
}
function severityColor(report) {
  const crit = report.vulnerabilities.some((v) => v.risk.label === "critical");
  const high = report.vulnerabilities.some((v) => v.risk.label === "high");
  if (crit) return "FF0000";
  if (high) return "FF8C00";
  if (report.vulnerabilities.length > 0) return "FFD700";
  return "00CC00";
}
function vulnSummary(report) {
  const total = report.vulnerabilities.length;
  const prod = report.vulnerabilities.filter((v) => v.match.isProduction).length;
  const crit = report.vulnerabilities.filter((v) => v.risk.label === "critical").length;
  const high = report.vulnerabilities.filter((v) => v.risk.label === "high").length;
  const med = report.vulnerabilities.filter((v) => v.risk.label === "medium").length;
  const low = report.vulnerabilities.filter((v) => v.risk.label === "low").length;
  return { total, prod, crit, high, med, low };
}
function buildTeamsPayload(report, projectName) {
  const s = vulnSummary(report);
  const color = severityColor(report);
  const title = s.total === 0 ? `No vulnerabilities found${projectName ? ` in ${projectName}` : ""}` : `${s.total} vulnerabilities found${projectName ? ` in ${projectName}` : ""}`;
  const facts = [
    { name: "Packages", value: String(report.metadata.totalPackages) },
    { name: "Critical", value: String(s.crit) },
    { name: "High", value: String(s.high) },
    { name: "Medium", value: String(s.med) },
    { name: "Low", value: String(s.low) },
    { name: "Production", value: String(s.prod) },
    { name: "Confidence", value: report.metadata.confidence }
  ];
  const payload = {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    themeColor: color,
    summary: title,
    sections: [{
      activityTitle: `auditfix: ${title}`,
      facts,
      markdown: true
    }]
  };
  const ghRepo = process.env.GITHUB_REPOSITORY;
  if (ghRepo) {
    payload.potentialAction = [{
      "@type": "OpenUri",
      name: "View on GitHub",
      targets: [{ os: "default", uri: `https://github.com/${ghRepo}/security` }]
    }];
  }
  return payload;
}
function buildDiscordPayload(report, projectName) {
  const s = vulnSummary(report);
  const color = parseInt(severityColor(report), 16);
  const title = s.total === 0 ? `No vulnerabilities found${projectName ? ` in ${projectName}` : ""}` : `${s.total} vulnerabilities found${projectName ? ` in ${projectName}` : ""}`;
  const description = [
    `**Packages scanned:** ${report.metadata.totalPackages}`,
    `**Critical:** ${s.crit} | **High:** ${s.high} | **Medium:** ${s.med} | **Low:** ${s.low}`,
    `**Production:** ${s.prod} | **Confidence:** ${report.metadata.confidence}`
  ].join("\n");
  const fields = report.vulnerabilities.slice(0, 5).map((v) => ({
    name: `${v.risk.label.toUpperCase()}: ${v.match.package}@${v.match.installedVersion}`,
    value: `${v.match.advisory.id} (score: ${v.risk.score})${v.risk.factors.fixVersion ? ` \u2192 fix: ${v.risk.factors.fixVersion}` : ""}`,
    inline: false
  }));
  return {
    embeds: [{
      title: `auditfix: ${title}`,
      description,
      color,
      fields,
      footer: { text: `auditfix | ${report.metadata.advisorySource}` },
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }]
  };
}
function buildSlackPayload(report, projectName) {
  const vulnCount = report.vulnerabilities.length;
  const prodCount = report.vulnerabilities.filter((v) => v.match.isProduction).length;
  const critCount = report.vulnerabilities.filter((v) => v.risk.label === "critical").length;
  const highCount = report.vulnerabilities.filter((v) => v.risk.label === "high").length;
  const emoji = critCount > 0 ? ":rotating_light:" : highCount > 0 ? ":warning:" : vulnCount > 0 ? ":information_source:" : ":white_check_mark:";
  const project = projectName ? ` for *${projectName}*` : "";
  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `${vulnCount === 0 ? "No vulnerabilities" : `${vulnCount} vulnerabilities`} found${projectName ? ` in ${projectName}` : ""}` }
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: [
          `${emoji} *auditfix scan results*${project}`,
          `Packages scanned: ${report.metadata.totalPackages}`,
          `Vulnerabilities: ${vulnCount} (${prodCount} production)`,
          critCount > 0 ? `:rotating_light: Critical: ${critCount}` : null,
          highCount > 0 ? `:warning: High: ${highCount}` : null,
          `Confidence: ${report.metadata.confidence}`,
          `Source: ${report.metadata.advisorySource}`
        ].filter(Boolean).join("\n")
      }
    }
  ];
  if (vulnCount > 0) {
    const top5 = report.vulnerabilities.slice(0, 5);
    const vulnLines = top5.map(
      (v) => `\u2022 \`${v.match.package}@${v.match.installedVersion}\` \u2014 ${v.risk.label.toUpperCase()} (score: ${v.risk.score})${v.risk.factors.fixVersion ? ` \u2192 fix: ${v.risk.factors.fixVersion}` : ""}`
    );
    if (vulnCount > 5) vulnLines.push(`_...and ${vulnCount - 5} more_`);
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: vulnLines.join("\n") }
    });
  }
  return { blocks };
}
function buildGenericPayload(report, projectName) {
  return {
    event: "auditfix.scan",
    project: projectName ?? null,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    summary: {
      totalPackages: report.metadata.totalPackages,
      vulnerabilities: report.vulnerabilities.length,
      production: report.vulnerabilities.filter((v) => v.match.isProduction).length,
      critical: report.vulnerabilities.filter((v) => v.risk.label === "critical").length,
      high: report.vulnerabilities.filter((v) => v.risk.label === "high").length,
      medium: report.vulnerabilities.filter((v) => v.risk.label === "medium").length,
      low: report.vulnerabilities.filter((v) => v.risk.label === "low").length,
      ignored: report.ignored.length,
      confidence: report.metadata.confidence,
      source: report.metadata.advisorySource
    },
    vulnerabilities: report.vulnerabilities.map((v) => ({
      id: v.match.advisory.id,
      package: v.match.package,
      version: v.match.installedVersion,
      severity: v.risk.label,
      score: v.risk.score,
      production: v.match.isProduction,
      fixVersion: v.risk.factors.fixVersion
    }))
  };
}

// node_modules/chalk/source/vendor/ansi-styles/index.js
var ANSI_BACKGROUND_OFFSET = 10;
var wrapAnsi16 = (offset = 0) => (code) => `\x1B[${code + offset}m`;
var wrapAnsi256 = (offset = 0) => (code) => `\x1B[${38 + offset};5;${code}m`;
var wrapAnsi16m = (offset = 0) => (red, green, blue) => `\x1B[${38 + offset};2;${red};${green};${blue}m`;
var styles = {
  modifier: {
    reset: [0, 0],
    // 21 isn't widely supported and 22 does the same thing
    bold: [1, 22],
    dim: [2, 22],
    italic: [3, 23],
    underline: [4, 24],
    overline: [53, 55],
    inverse: [7, 27],
    hidden: [8, 28],
    strikethrough: [9, 29]
  },
  color: {
    black: [30, 39],
    red: [31, 39],
    green: [32, 39],
    yellow: [33, 39],
    blue: [34, 39],
    magenta: [35, 39],
    cyan: [36, 39],
    white: [37, 39],
    // Bright color
    blackBright: [90, 39],
    gray: [90, 39],
    // Alias of `blackBright`
    grey: [90, 39],
    // Alias of `blackBright`
    redBright: [91, 39],
    greenBright: [92, 39],
    yellowBright: [93, 39],
    blueBright: [94, 39],
    magentaBright: [95, 39],
    cyanBright: [96, 39],
    whiteBright: [97, 39]
  },
  bgColor: {
    bgBlack: [40, 49],
    bgRed: [41, 49],
    bgGreen: [42, 49],
    bgYellow: [43, 49],
    bgBlue: [44, 49],
    bgMagenta: [45, 49],
    bgCyan: [46, 49],
    bgWhite: [47, 49],
    // Bright color
    bgBlackBright: [100, 49],
    bgGray: [100, 49],
    // Alias of `bgBlackBright`
    bgGrey: [100, 49],
    // Alias of `bgBlackBright`
    bgRedBright: [101, 49],
    bgGreenBright: [102, 49],
    bgYellowBright: [103, 49],
    bgBlueBright: [104, 49],
    bgMagentaBright: [105, 49],
    bgCyanBright: [106, 49],
    bgWhiteBright: [107, 49]
  }
};
var modifierNames = Object.keys(styles.modifier);
var foregroundColorNames = Object.keys(styles.color);
var backgroundColorNames = Object.keys(styles.bgColor);
var colorNames = [...foregroundColorNames, ...backgroundColorNames];
function assembleStyles() {
  const codes = /* @__PURE__ */ new Map();
  for (const [groupName, group] of Object.entries(styles)) {
    for (const [styleName, style] of Object.entries(group)) {
      styles[styleName] = {
        open: `\x1B[${style[0]}m`,
        close: `\x1B[${style[1]}m`
      };
      group[styleName] = styles[styleName];
      codes.set(style[0], style[1]);
    }
    Object.defineProperty(styles, groupName, {
      value: group,
      enumerable: false
    });
  }
  Object.defineProperty(styles, "codes", {
    value: codes,
    enumerable: false
  });
  styles.color.close = "\x1B[39m";
  styles.bgColor.close = "\x1B[49m";
  styles.color.ansi = wrapAnsi16();
  styles.color.ansi256 = wrapAnsi256();
  styles.color.ansi16m = wrapAnsi16m();
  styles.bgColor.ansi = wrapAnsi16(ANSI_BACKGROUND_OFFSET);
  styles.bgColor.ansi256 = wrapAnsi256(ANSI_BACKGROUND_OFFSET);
  styles.bgColor.ansi16m = wrapAnsi16m(ANSI_BACKGROUND_OFFSET);
  Object.defineProperties(styles, {
    rgbToAnsi256: {
      value(red, green, blue) {
        if (red === green && green === blue) {
          if (red < 8) {
            return 16;
          }
          if (red > 248) {
            return 231;
          }
          return Math.round((red - 8) / 247 * 24) + 232;
        }
        return 16 + 36 * Math.round(red / 255 * 5) + 6 * Math.round(green / 255 * 5) + Math.round(blue / 255 * 5);
      },
      enumerable: false
    },
    hexToRgb: {
      value(hex) {
        const matches = /[a-f\d]{6}|[a-f\d]{3}/i.exec(hex.toString(16));
        if (!matches) {
          return [0, 0, 0];
        }
        let [colorString] = matches;
        if (colorString.length === 3) {
          colorString = [...colorString].map((character) => character + character).join("");
        }
        const integer = Number.parseInt(colorString, 16);
        return [
          /* eslint-disable no-bitwise */
          integer >> 16 & 255,
          integer >> 8 & 255,
          integer & 255
          /* eslint-enable no-bitwise */
        ];
      },
      enumerable: false
    },
    hexToAnsi256: {
      value: (hex) => styles.rgbToAnsi256(...styles.hexToRgb(hex)),
      enumerable: false
    },
    ansi256ToAnsi: {
      value(code) {
        if (code < 8) {
          return 30 + code;
        }
        if (code < 16) {
          return 90 + (code - 8);
        }
        let red;
        let green;
        let blue;
        if (code >= 232) {
          red = ((code - 232) * 10 + 8) / 255;
          green = red;
          blue = red;
        } else {
          code -= 16;
          const remainder = code % 36;
          red = Math.floor(code / 36) / 5;
          green = Math.floor(remainder / 6) / 5;
          blue = remainder % 6 / 5;
        }
        const value = Math.max(red, green, blue) * 2;
        if (value === 0) {
          return 30;
        }
        let result = 30 + (Math.round(blue) << 2 | Math.round(green) << 1 | Math.round(red));
        if (value === 2) {
          result += 60;
        }
        return result;
      },
      enumerable: false
    },
    rgbToAnsi: {
      value: (red, green, blue) => styles.ansi256ToAnsi(styles.rgbToAnsi256(red, green, blue)),
      enumerable: false
    },
    hexToAnsi: {
      value: (hex) => styles.ansi256ToAnsi(styles.hexToAnsi256(hex)),
      enumerable: false
    }
  });
  return styles;
}
var ansiStyles = assembleStyles();
var ansi_styles_default = ansiStyles;

// node_modules/chalk/source/vendor/supports-color/index.js
import process2 from "process";
import os2 from "os";
import tty from "tty";
function hasFlag(flag, argv = globalThis.Deno ? globalThis.Deno.args : process2.argv) {
  const prefix = flag.startsWith("-") ? "" : flag.length === 1 ? "-" : "--";
  const position = argv.indexOf(prefix + flag);
  const terminatorPosition = argv.indexOf("--");
  return position !== -1 && (terminatorPosition === -1 || position < terminatorPosition);
}
var { env } = process2;
var flagForceColor;
if (hasFlag("no-color") || hasFlag("no-colors") || hasFlag("color=false") || hasFlag("color=never")) {
  flagForceColor = 0;
} else if (hasFlag("color") || hasFlag("colors") || hasFlag("color=true") || hasFlag("color=always")) {
  flagForceColor = 1;
}
function envForceColor() {
  if ("FORCE_COLOR" in env) {
    if (env.FORCE_COLOR === "true") {
      return 1;
    }
    if (env.FORCE_COLOR === "false") {
      return 0;
    }
    return env.FORCE_COLOR.length === 0 ? 1 : Math.min(Number.parseInt(env.FORCE_COLOR, 10), 3);
  }
}
function translateLevel(level) {
  if (level === 0) {
    return false;
  }
  return {
    level,
    hasBasic: true,
    has256: level >= 2,
    has16m: level >= 3
  };
}
function _supportsColor(haveStream, { streamIsTTY, sniffFlags = true } = {}) {
  const noFlagForceColor = envForceColor();
  if (noFlagForceColor !== void 0) {
    flagForceColor = noFlagForceColor;
  }
  const forceColor = sniffFlags ? flagForceColor : noFlagForceColor;
  if (forceColor === 0) {
    return 0;
  }
  if (sniffFlags) {
    if (hasFlag("color=16m") || hasFlag("color=full") || hasFlag("color=truecolor")) {
      return 3;
    }
    if (hasFlag("color=256")) {
      return 2;
    }
  }
  if ("TF_BUILD" in env && "AGENT_NAME" in env) {
    return 1;
  }
  if (haveStream && !streamIsTTY && forceColor === void 0) {
    return 0;
  }
  const min = forceColor || 0;
  if (env.TERM === "dumb") {
    return min;
  }
  if (process2.platform === "win32") {
    const osRelease = os2.release().split(".");
    if (Number(osRelease[0]) >= 10 && Number(osRelease[2]) >= 10586) {
      return Number(osRelease[2]) >= 14931 ? 3 : 2;
    }
    return 1;
  }
  if ("CI" in env) {
    if (["GITHUB_ACTIONS", "GITEA_ACTIONS", "CIRCLECI"].some((key) => key in env)) {
      return 3;
    }
    if (["TRAVIS", "APPVEYOR", "GITLAB_CI", "BUILDKITE", "DRONE"].some((sign) => sign in env) || env.CI_NAME === "codeship") {
      return 1;
    }
    return min;
  }
  if ("TEAMCITY_VERSION" in env) {
    return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env.TEAMCITY_VERSION) ? 1 : 0;
  }
  if (env.COLORTERM === "truecolor") {
    return 3;
  }
  if (env.TERM === "xterm-kitty") {
    return 3;
  }
  if (env.TERM === "xterm-ghostty") {
    return 3;
  }
  if (env.TERM === "wezterm") {
    return 3;
  }
  if ("TERM_PROGRAM" in env) {
    const version = Number.parseInt((env.TERM_PROGRAM_VERSION || "").split(".")[0], 10);
    switch (env.TERM_PROGRAM) {
      case "iTerm.app": {
        return version >= 3 ? 3 : 2;
      }
      case "Apple_Terminal": {
        return 2;
      }
    }
  }
  if (/-256(color)?$/i.test(env.TERM)) {
    return 2;
  }
  if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env.TERM)) {
    return 1;
  }
  if ("COLORTERM" in env) {
    return 1;
  }
  return min;
}
function createSupportsColor(stream, options = {}) {
  const level = _supportsColor(stream, {
    streamIsTTY: stream && stream.isTTY,
    ...options
  });
  return translateLevel(level);
}
var supportsColor = {
  stdout: createSupportsColor({ isTTY: tty.isatty(1) }),
  stderr: createSupportsColor({ isTTY: tty.isatty(2) })
};
var supports_color_default = supportsColor;

// node_modules/chalk/source/utilities.js
function stringReplaceAll(string, substring, replacer) {
  let index = string.indexOf(substring);
  if (index === -1) {
    return string;
  }
  const substringLength = substring.length;
  let endIndex = 0;
  let returnValue = "";
  do {
    returnValue += string.slice(endIndex, index) + substring + replacer;
    endIndex = index + substringLength;
    index = string.indexOf(substring, endIndex);
  } while (index !== -1);
  returnValue += string.slice(endIndex);
  return returnValue;
}
function stringEncaseCRLFWithFirstIndex(string, prefix, postfix, index) {
  let endIndex = 0;
  let returnValue = "";
  do {
    const gotCR = string[index - 1] === "\r";
    returnValue += string.slice(endIndex, gotCR ? index - 1 : index) + prefix + (gotCR ? "\r\n" : "\n") + postfix;
    endIndex = index + 1;
    index = string.indexOf("\n", endIndex);
  } while (index !== -1);
  returnValue += string.slice(endIndex);
  return returnValue;
}

// node_modules/chalk/source/index.js
var { stdout: stdoutColor, stderr: stderrColor } = supports_color_default;
var GENERATOR = /* @__PURE__ */ Symbol("GENERATOR");
var STYLER = /* @__PURE__ */ Symbol("STYLER");
var IS_EMPTY = /* @__PURE__ */ Symbol("IS_EMPTY");
var levelMapping = [
  "ansi",
  "ansi",
  "ansi256",
  "ansi16m"
];
var styles2 = /* @__PURE__ */ Object.create(null);
var applyOptions = (object, options = {}) => {
  if (options.level && !(Number.isInteger(options.level) && options.level >= 0 && options.level <= 3)) {
    throw new Error("The `level` option should be an integer from 0 to 3");
  }
  const colorLevel = stdoutColor ? stdoutColor.level : 0;
  object.level = options.level === void 0 ? colorLevel : options.level;
};
var chalkFactory = (options) => {
  const chalk2 = (...strings) => strings.join(" ");
  applyOptions(chalk2, options);
  Object.setPrototypeOf(chalk2, createChalk.prototype);
  return chalk2;
};
function createChalk(options) {
  return chalkFactory(options);
}
Object.setPrototypeOf(createChalk.prototype, Function.prototype);
for (const [styleName, style] of Object.entries(ansi_styles_default)) {
  styles2[styleName] = {
    get() {
      const builder = createBuilder(this, createStyler(style.open, style.close, this[STYLER]), this[IS_EMPTY]);
      Object.defineProperty(this, styleName, { value: builder });
      return builder;
    }
  };
}
styles2.visible = {
  get() {
    const builder = createBuilder(this, this[STYLER], true);
    Object.defineProperty(this, "visible", { value: builder });
    return builder;
  }
};
var getModelAnsi = (model, level, type2, ...arguments_) => {
  if (model === "rgb") {
    if (level === "ansi16m") {
      return ansi_styles_default[type2].ansi16m(...arguments_);
    }
    if (level === "ansi256") {
      return ansi_styles_default[type2].ansi256(ansi_styles_default.rgbToAnsi256(...arguments_));
    }
    return ansi_styles_default[type2].ansi(ansi_styles_default.rgbToAnsi(...arguments_));
  }
  if (model === "hex") {
    return getModelAnsi("rgb", level, type2, ...ansi_styles_default.hexToRgb(...arguments_));
  }
  return ansi_styles_default[type2][model](...arguments_);
};
var usedModels = ["rgb", "hex", "ansi256"];
for (const model of usedModels) {
  styles2[model] = {
    get() {
      const { level } = this;
      return function(...arguments_) {
        const styler = createStyler(getModelAnsi(model, levelMapping[level], "color", ...arguments_), ansi_styles_default.color.close, this[STYLER]);
        return createBuilder(this, styler, this[IS_EMPTY]);
      };
    }
  };
  const bgModel = "bg" + model[0].toUpperCase() + model.slice(1);
  styles2[bgModel] = {
    get() {
      const { level } = this;
      return function(...arguments_) {
        const styler = createStyler(getModelAnsi(model, levelMapping[level], "bgColor", ...arguments_), ansi_styles_default.bgColor.close, this[STYLER]);
        return createBuilder(this, styler, this[IS_EMPTY]);
      };
    }
  };
}
var proto = Object.defineProperties(() => {
}, {
  ...styles2,
  level: {
    enumerable: true,
    get() {
      return this[GENERATOR].level;
    },
    set(level) {
      this[GENERATOR].level = level;
    }
  }
});
var createStyler = (open, close, parent) => {
  let openAll;
  let closeAll;
  if (parent === void 0) {
    openAll = open;
    closeAll = close;
  } else {
    openAll = parent.openAll + open;
    closeAll = close + parent.closeAll;
  }
  return {
    open,
    close,
    openAll,
    closeAll,
    parent
  };
};
var createBuilder = (self, _styler, _isEmpty) => {
  const builder = (...arguments_) => applyStyle(builder, arguments_.length === 1 ? "" + arguments_[0] : arguments_.join(" "));
  Object.setPrototypeOf(builder, proto);
  builder[GENERATOR] = self;
  builder[STYLER] = _styler;
  builder[IS_EMPTY] = _isEmpty;
  return builder;
};
var applyStyle = (self, string) => {
  if (self.level <= 0 || !string) {
    return self[IS_EMPTY] ? "" : string;
  }
  let styler = self[STYLER];
  if (styler === void 0) {
    return string;
  }
  const { openAll, closeAll } = styler;
  if (string.includes("\x1B")) {
    while (styler !== void 0) {
      string = stringReplaceAll(string, styler.close, styler.open);
      styler = styler.parent;
    }
  }
  const lfIndex = string.indexOf("\n");
  if (lfIndex !== -1) {
    string = stringEncaseCRLFWithFirstIndex(string, closeAll, openAll, lfIndex);
  }
  return openAll + string + closeAll;
};
Object.defineProperties(createChalk.prototype, styles2);
var chalk = createChalk();
var chalkStderr = createChalk({ level: stderrColor ? stderrColor.level : 0 });
var source_default = chalk;

// src/core/exit-code.ts
function getExitCode(report) {
  if (report.metadata.confidence === "UNRELIABLE") return 2;
  const hasProdVulns = report.vulnerabilities.some(
    (v) => v.match.isProduction && (v.risk.label === "critical" || v.risk.label === "high")
  );
  return hasProdVulns ? 1 : 0;
}
function getExitCodeForStrategy(report, strategy) {
  if (report.metadata.confidence === "UNRELIABLE") return 2;
  switch (strategy) {
    case "production-critical":
      return report.vulnerabilities.some(
        (v) => v.match.isProduction && v.risk.label === "critical"
      ) ? 1 : 0;
    case "any":
      return report.vulnerabilities.length > 0 ? 1 : 0;
    case "production-high":
    default:
      return getExitCode(report);
  }
}

// src/cli/output/terminal.ts
var SEVERITY_COLORS = {
  critical: source_default.bgRed.white.bold,
  high: source_default.red.bold,
  medium: source_default.yellow,
  low: source_default.dim,
  info: source_default.gray
};

// action/index.ts
function encodeWorkflowCommand(value) {
  return String(value).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/::/g, "%3A%3A");
}
function encodeWorkflowCommandProperty(value) {
  return encodeWorkflowCommand(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}
function getInput(name) {
  return process.env[`INPUT_${name.replace(/-/g, "_").toUpperCase()}`] ?? "";
}
function getBooleanInput(name) {
  return getInput(name).toLowerCase() === "true";
}
function setOutput(name, value) {
  const filePath = process.env.GITHUB_OUTPUT;
  if (filePath) {
    appendFileSync(filePath, `${name}=${value}
`);
  }
}
function setFailed(message) {
  console.log(`::error::${encodeWorkflowCommand(message)}`);
  process.exitCode = 1;
}
function warning(message, title) {
  const titlePart = title ? ` title=${encodeWorkflowCommandProperty(title)}` : "";
  console.log(`::warning${titlePart}::${encodeWorkflowCommand(message)}`);
}
function startGroup(name) {
  console.log(`::group::${encodeWorkflowCommand(name)}`);
}
function endGroup() {
  console.log(`::endgroup::`);
}
async function uploadSarif(sarifContent, category) {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const sha = process.env.GITHUB_SHA;
  const ref = process.env.GITHUB_REF;
  if (!token || !repo || !sha || !ref) {
    warning("Cannot upload SARIF: missing GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA, or GITHUB_REF");
    return;
  }
  try {
    const gzipped = gzipSync(Buffer.from(sarifContent));
    const encoded = gzipped.toString("base64");
    const res = await fetch(
      `https://api.github.com/repos/${repo}/code-scanning/sarifs`,
      {
        method: "POST",
        headers: {
          Authorization: `token ${token}`,
          Accept: "application/vnd.github.v3+json",
          "User-Agent": "auditfix-action",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          commit_sha: sha,
          ref,
          sarif: encoded,
          tool_name: "auditfix",
          checkout_uri: `file://${process.cwd()}`
        }),
        signal: AbortSignal.timeout(3e4)
      }
    );
    if (res.ok) {
      console.log("SARIF uploaded to GitHub Code Scanning");
    } else {
      const text = await res.text().catch(() => "");
      warning(`SARIF upload failed: HTTP ${res.status} ${text.slice(0, 200)}`);
    }
  } catch (err) {
    warning(`SARIF upload error: ${err instanceof Error ? err.message : err}`);
  }
}
var VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"];
var VALID_FAIL_ON = ["production-critical", "production-high", "any", "none"];
async function run() {
  try {
    const severityRaw = getInput("severity") || "low";
    if (!VALID_SEVERITIES.includes(severityRaw)) {
      setFailed(`Invalid severity: ${severityRaw}. Must be one of: ${VALID_SEVERITIES.join(", ")}`);
      return;
    }
    const severity = severityRaw;
    const failOnRaw = getInput("fail-on") || "any";
    if (!VALID_FAIL_ON.includes(failOnRaw)) {
      setFailed(`Invalid fail-on: ${failOnRaw}. Must be one of: ${VALID_FAIL_ON.join(", ")}`);
      return;
    }
    const failOn = failOnRaw;
    const prodOnly = getBooleanInput("production-only");
    const workDir = resolve4(getInput("working-directory") || ".");
    const generateSarif = getBooleanInput("sarif");
    const prComment = getBooleanInput("pr-comment");
    const jsonOutputPath = getInput("json-output");
    const webhookUrl = getInput("webhook-url");
    const sarifCategory = getInput("sarif-category") || "auditfix";
    startGroup("Running auditfix scan");
    const report = await analyze({
      projectDir: workDir,
      productionOnly: prodOnly,
      severityThreshold: severity
    });
    endGroup();
    const vulns = report.vulnerabilities;
    setOutput("vulnerability-count", vulns.length);
    setOutput("critical-count", vulns.filter((v) => v.risk.label === "critical").length);
    setOutput("high-count", vulns.filter((v) => v.risk.label === "high").length);
    setOutput("production-count", vulns.filter((v) => v.match.isProduction).length);
    setOutput("fixable-count", vulns.filter((v) => v.risk.factors.fixAvailable).length);
    setOutput("exit-code", failOn === "none" ? 0 : getExitCodeForStrategy(report, failOn));
    if (generateSarif) {
      const sarifContent = renderSarifReport(report, "2.0.0");
      writeFileSync3("auditfix-results.sarif", sarifContent);
      setOutput("sarif-file", "auditfix-results.sarif");
      await uploadSarif(sarifContent, sarifCategory);
    }
    if (jsonOutputPath) {
      writeFileSync3(jsonOutputPath, renderJsonReport(report));
      setOutput("json-file", jsonOutputPath);
    }
    if (prComment && process.env.GITHUB_EVENT_NAME === "pull_request") {
      const prResult = await postPrComment(report);
      if (!prResult.success) {
        warning(`PR comment failed: ${prResult.error}`);
      }
    }
    if (webhookUrl) {
      const whResult = await sendWebhook(webhookUrl, report);
      if (!whResult.success) {
        warning(`Webhook failed: ${whResult.error}`);
      }
    }
    for (const vuln of vulns.filter((v) => v.risk.label === "critical" || v.risk.label === "high")) {
      warning(
        `${vuln.match.package}@${vuln.match.installedVersion}: ${vuln.match.advisory.summary}`,
        vuln.match.advisory.id
      );
    }
    console.log(`
auditfix: ${vulns.length} vulnerabilities found`);
    if (vulns.length > 0) {
      const crit = vulns.filter((v) => v.risk.label === "critical").length;
      const high = vulns.filter((v) => v.risk.label === "high").length;
      const prod = vulns.filter((v) => v.match.isProduction).length;
      console.log(`  Critical: ${crit} | High: ${high} | Production: ${prod}`);
    }
    if (failOn !== "none") {
      const exitCode = getExitCodeForStrategy(report, failOn);
      if (exitCode !== 0) {
        setFailed(`auditfix found ${vulns.length} vulnerabilities (fail-on: ${failOn})`);
      }
    }
  } catch (error2) {
    setFailed(error2 instanceof Error ? error2.message : String(error2));
  }
}
run();
/*! Bundled license information:

js-yaml/dist/js-yaml.mjs:
  (*! js-yaml 4.1.1 https://github.com/nodeca/js-yaml @license MIT *)
*/
//# sourceMappingURL=index.js.map