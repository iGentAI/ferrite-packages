#!/usr/bin/env node
// ferrite-pkg — source-level package composition for constrained Ferrite apps.
//
// WHY THIS EXISTS, AND WHY IT IS NOT A PACKAGE MANAGER
//
// A deployed Ferrite app may depend on exactly one crate. That is not a
// convention, it is enforced: the platform's code gate carries
//
//     pub const DEFAULT_ALLOWED_DEPS: &[&str] = &["ferrite-app"];
//
// and every `[dependencies]` entry outside that list is a blocking
// `CODE_DEP_UNLISTED` violation. The rule is deliberate — the injected surface
// IS the app's authority, so an app that could link a second crate could reach
// the world through it — and it applies to workspace path dependencies exactly
// as it applies to registry ones, because the gate matches on the dependency's
// NAME and never looks at where it resolves from.
//
// The consequence is unavoidable: two apps that need the same subsystem cannot
// share a crate. They can only share SOURCE. That is already what happens here,
// and it happens by hand:
//
//   * two applications carried copies of one WASM interpreter, 35 files
//     each, 7 of them drifted;
//   * two applications shared 25 file paths of an agent runtime, 15 of them
//     drifted.
//
// Copying is therefore not the mistake. Under a one-dependency rule it is the
// only mechanism available, and vendoring is the honest name for it. The
// mistake is that a hand copy records nothing: not where it came from, not
// which revision, and above all not whether it still matches. Drift is silent,
// and silence is what turns one subsystem into several.
//
// So this tool does not resolve versions from a registry or fetch anything. It
// makes the copy an ACCOUNTED-FOR operation:
//
//   one canonical source  —  packages/<name>/src
//   a declared mount      —  <app>/ferrite-packages.json
//   a content ledger      —  <app>/ferrite-packages.lock.json
//   a drift check         —  `check`, which exits non-zero
//
// COMMANDS
//
//   list              every package, its version, and who consumes it
//   graph             the dependency and host-import edges
//   scan              cross-crate duplication a package could absorb
//   sync   [app...]   write vendored copies from the canonical sources
//   check  [app...]   verify vendored copies match; exit 1 on any drift
//   registry          write packages/registry.json, the published index
//                     `ferrite add` installs from
//   mcp-packages [--check] [--package <name>]...
//                     write mcp-packages.json,
//                     the packages as the platform MCP serves them
//   status            one line, for a CI summary
//
// WHAT A PACKAGE IS
//
// `packages/<name>/ferrite-package.json` plus a `src/` tree. Every file in that
// tree is part of the package: `.rs` files are composed with a provenance header
// and self-reference rewriting, and anything else — templates, prompts, static
// assets — is copied verbatim. That is not incidental. The agent runtime's `.rs`
// files `include_str!` their base instructions and compaction prompts, so a
// version of this tool that composed only Rust would leave an agent's PROMPT as
// an unmanaged hand copy while reporting the runtime as shared.
//
// The manifest declares three things that a hand copy leaves implicit:
//
//   root         the module path the source refers to itself by (`crate::wasm`).
//                A consumer mounting it elsewhere gets the references rewritten.
//   dependencies other packages it needs, which are mounted transitively.
//   hostImports  modules the CONSUMING app must provide. This is the important
//                one. `buzz/src/agents` reaches into `crate::relay` and
//                `crate::llm`; before this manifest existed, that coupling was
//                discoverable only by compiling and reading the errors.
//
// A consumer may also declare `hostFiles`: paths inside the mount that IT owns.
// A mount is otherwise exclusive, and that default is what catches a file added
// to the copy instead of to the package — but a package with a deliberate
// extension point needs a way to say so. The agent runtime is the case in
// point: two apps share 20 files and each supplies its own `tools/`, because one
// calls the relay in-process and the other publishes to a queue.
//
// WHAT A PACKAGE IS NOT
//
// Not a crate, so it has no `Cargo.toml` and cannot be built alone — it is a
// module tree, and a module tree needs a crate root. Its tests live with the
// app that mounts it. Not a service: a subsystem is compiled in rather than
// reached over a queue, so the call is a function
// call and the authority is the host app's.
//
// Host-side library crates (`ferrite-memory`, `ferrite-search`, and the rest)
// are deliberately NOT packages. They depend on serde, tokio and thiserror, and
// nothing stops them: the one-dependency rule binds deployable apps, not
// ordinary crates. Where Cargo works, Cargo is the right answer, and reaching
// for this tool there would be strictly worse.

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
// The workspace this tool composes. Overridable ONLY so the test suite can
// exercise refusals against a scratch tree — a tool that deletes files needs
// its guarantees to be executable, and they cannot be tested against the real
// workspace without risking exactly the damage they exist to prevent.
const ROOT = process.env.FERRITE_PKG_ROOT
  ? resolve(process.env.FERRITE_PKG_ROOT)
  : resolve(HERE, "..", "..");
const PACKAGES_DIR = join(ROOT, "packages");

const PACKAGE_MANIFEST = "ferrite-package.json";
const CONSUMER_MANIFEST = "ferrite-packages.json";
const LOCKFILE = "ferrite-packages.lock.json";

/**
 * The extension that gets composed rather than copied.
 *
 * A `.rs` file receives the provenance header and self-reference rewriting.
 * Every other file is the package's bytes, verbatim — there is no comment syntax
 * safe across `.md`, `.json` and `.html`, and inventing one per extension would
 * be a worse contract than "these bytes are the package's".
 */
const RUST_EXT = ".rs";

function die(message) {
  console.error(`ferrite-pkg: ${message}`);
  process.exit(2);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    die(`${relative(ROOT, path)} is not readable JSON: ${error.message}`);
  }
}

/** Hash a file's content, which may be text (`.rs`) or raw bytes (an asset). */
function sha256(content) {
  return createHash("sha256")
    .update(typeof content === "string" ? Buffer.from(content, "utf8") : content)
    .digest("hex");
}

/** Does the file at `target` already hold exactly `contents`? */
function alreadyHolds(target, contents) {
  if (!existsSync(target)) return false;
  const current = readFileSync(target);
  return typeof contents === "string"
    ? current.toString("utf8") === contents
    : current.equals(contents);
}

/**
 * A mount and a root are Rust module identifiers, and they are also PATH
 * components. Both facts have to hold, and the second is the dangerous one:
 * `sync` deletes `.rs` files it finds under a mount, so an unvalidated mount of
 * `../../other-crate/src` would delete another crate's sources. Restricting the
 * value to a single identifier makes traversal unrepresentable rather than
 * merely unlikely.
 */
const RUST_IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Words that are a valid identifier shape but cannot name a module. */
const RESERVED = new Set([
  "crate", "self", "Self", "super", "mod", "use", "as", "fn", "let", "type",
  "impl", "trait", "struct", "enum", "const", "static", "pub", "move", "ref",
  "where", "match", "loop", "while", "for", "if", "else", "return", "true",
  "false", "unsafe", "extern", "dyn", "async", "await", "box", "in",
]);

function isModuleIdent(value) {
  return typeof value === "string" && RUST_IDENT.test(value) && !RESERVED.has(value);
}

function requireModuleIdent(value, what) {
  if (!isModuleIdent(value)) {
    die(
      `${what} must be a single Rust module identifier ([A-Za-z_][A-Za-z0-9_]*, not a keyword); got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

/** Package names are directory names, so they get their own narrow charset. */
function requirePackageName(value, what) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]*$/.test(value)) {
    die(`${what} must match [a-z0-9][a-z0-9-]*; got ${JSON.stringify(value)}`);
  }
  return value;
}

/**
 * A `hostFiles` pattern: a mount-relative path, with `*` inside a segment and
 * `**` spanning segments.
 *
 * Validated for the same reason every other path here is: these patterns decide
 * which files `sync` will NOT delete, so one that could escape the mount would
 * quietly extend that protection somewhere it was never meant to reach.
 */
function requireHostPattern(value, what) {
  if (typeof value !== "string" || value === "") {
    die(`${what} must be a non-empty mount-relative path; got ${JSON.stringify(value)}`);
  }
  if (value.startsWith("/") || value.split("/").some((p) => p === ".." || p === "")) {
    die(
      `${what} must not be absolute or contain ".." or empty segments; got ${JSON.stringify(value)}`,
    );
  }
  // A backslash is neither a separator nor an escape here, so a pattern that
  // carries one looks like a path or an escape and silently matches neither.
  if (value.includes("\\")) {
    die(`${what} must not contain a backslash; got ${JSON.stringify(value)}`);
  }
  // One `**` is all a mount-relative pattern needs; more of them only make
  // the pattern harder to read (the matcher itself stays bounded either way).
  if (value.split("/").filter((p) => p === "**").length > 1) {
    die(`${what} may contain at most one "**" segment; got ${JSON.stringify(value)}`);
  }
  return value;
}

/**
 * Compile host-file patterns into a predicate over mount-relative POSIX paths.
 *
 * Every character outside `*` is literal: `*` matches any run of characters
 * within one segment, and nothing else is special (`x?.rs` matches only the
 * file literally named that, never `xy.rs`).
 *
 * `**` means ZERO or more whole segments, as it does in every standard glob:
 * a doubled star between `a/` and `/b` covers `a/b` as well as `a/x/y/b`. A
 * trailing `**` still requires a file name, because these patterns match
 * FILES and `tools/` followed by `**` means "everything inside tools/", not
 * the directory itself. (The examples are spelled out in words because the
 * literal patterns contain the character pair that ends this comment.)
 *
 * The patterns come from a checked-in manifest, so a pull request can choose
 * them, and `sync`/`check` test every file of every mount against them. They
 * are therefore NOT compiled to a RegExp: a backtracking engine takes time
 * polynomial in the name length with a degree that grows with the number of
 * stars, so a pattern of stars separated by one repeated letter, tested
 * against a long name made of that letter, hangs the tool. The matcher below
 * does at most (pattern length x name length) steps per segment and (pattern
 * segments x path segments) steps across segments, whatever the pattern.
 */
function hostFileMatcher(patterns) {
  const compiled = patterns.map((pattern) => pattern.split("/"));
  return (relPath) => {
    const segments = relPath.split("/");
    return compiled.some((pattern) => globPathMatches(pattern, segments));
  };
}

/**
 * Whether one path segment matches one pattern segment, where `*` matches any
 * run of characters and everything else is literal.
 *
 * The classic two-pointer wildcard match: on a mismatch it resumes from the
 * most recent star, one character further along the name. An earlier star
 * never needs revisiting (the later star can absorb whatever it would have),
 * so the loop is bounded by pattern length x name length.
 */
function globSegmentMatches(pattern, name) {
  let p = 0;
  let n = 0;
  let star = -1;
  let resume = 0;
  while (n < name.length) {
    if (p < pattern.length && pattern[p] === "*") {
      star = p;
      p += 1;
      resume = n;
    } else if (p < pattern.length && pattern[p] === name[n]) {
      p += 1;
      n += 1;
    } else if (star !== -1) {
      p = star + 1;
      resume += 1;
      n = resume;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === "*") p += 1;
  return p === pattern.length;
}

/**
 * Whether a path (already split into segments) matches a pattern (split the
 * same way), one pattern segment at a time over the set of path prefixes it
 * can reach, so `**` costs one pass over the path rather than a search.
 */
function globPathMatches(pattern, segments) {
  const count = segments.length;
  // reach[j]: the pattern segments consumed so far match segments[0..j).
  let reach = new Array(count + 1).fill(false);
  reach[0] = true;
  for (let i = 0; i < pattern.length; i += 1) {
    const seg = pattern[i];
    const next = new Array(count + 1).fill(false);
    if (seg === "**") {
      const last = i === pattern.length - 1;
      // carry: some k < j was reached and segments[k..j) are all non-empty.
      let carry = false;
      for (let j = 0; j <= count; j += 1) {
        next[j] = carry || (!last && reach[j]);
        if (j < count) carry = (carry || reach[j]) && segments[j] !== "";
      }
    } else {
      for (let j = 0; j < count; j += 1) {
        if (reach[j] && globSegmentMatches(seg, segments[j])) next[j + 1] = true;
      }
    }
    reach = next;
  }
  return reach[count];
}

/**
 * The directory a package mounts into, proven to be beneath `<consumer>/src`.
 *
 * Belt and braces on top of [`requireModuleIdent`]: this is the value handed to
 * a recursive delete, so it is re-derived and checked rather than trusted
 * because it was validated somewhere earlier.
 *
 * The check is deliberately made against the REAL filesystem. `resolve` only
 * normalises text — it collapses `..` and knows nothing about symlinks — so a
 * mount directory that is itself a symlink into another crate would satisfy a
 * lexical test and then be walked and deleted straight through. A vendored
 * mount is a plain directory this tool owns, so a symlink there is refused
 * rather than followed: there is no legitimate reason for one, and "refuse the
 * shape" is a smaller rule than "decide which targets are acceptable".
 */
function mountDir(consumer, mount) {
  const base = resolve(consumer.dir, "src");
  const dir = resolve(base, mount);
  if (dir === base || !dir.startsWith(base + sep)) {
    die(`mount ${JSON.stringify(mount)} does not name a directory beneath ${relative(ROOT, base)}`);
  }
  return assertRealDescendant(base, dir);
}

/** The consumer's `src`, which every target must sit beneath. */
function srcDirOf(consumer) {
  return resolve(consumer.dir, "src");
}

/**
 * Every file under `dir`, as POSIX-relative paths, sorted.
 *
 * Deliberately not filtered by extension. A package's templates are as much a
 * part of it as its modules, and a mount is owned as a whole — so a stale asset
 * left behind by a package that no longer ships it must be as visible as a
 * stale module.
 */
function treeFiles(dir) {
  const out = [];
  const walk = (d) => {
    if (!existsSync(d)) return;
    for (const entry of readdirSync(d, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    )) {
      const full = join(d, entry.name);
      // REFUSED, not skipped. Skipping answers "should this file be copied?",
      // but the question that matters is "is this tree the shape the tool
      // requires?" — and a link here is followed by the write phase even when
      // the read phase steps over it.
      if (entry.isSymbolicLink()) {
        die(`${relative(ROOT, full)} is a symlink; package and mount trees must be real files`);
      }
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        out.push(relative(dir, full).split(sep).join("/"));
      }
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * Prove `target` is reachable from `base` without traversing a symlink.
 *
 * This is the one rule that makes writing and deleting safe, and it is applied
 * at EVERY mutation rather than once per run. Lexical containment is not
 * enough: `resolve` collapses `..` but has no idea that `src` — or any
 * directory beneath it — might be a link pointing somewhere else entirely, and
 * `mkdirSync`/`writeFileSync`/`rmSync` all follow links happily.
 *
 * A component that does not exist yet is accepted: `mkdir` will create a real
 * directory there. That is what keeps the check cheap enough to run before
 * every single write.
 */
/**
 * Whether `path` is itself a symlink, dangling or not. `existsSync` follows
 * links, so it reports a dangling link as absent and would let it through.
 */
function isSymlink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return false;
    throw error;
  }
}

/** True when `rel` (from path.relative) names `from` itself or a path beneath it. */
function insideRel(rel) {
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

function assertRealDescendant(base, target) {
  // Every component from the workspace root down to `base` must be a real
  // directory too: a symlinked `apps/` would otherwise carry every write
  // beneath it out of the workspace while each check below passed.
  const fromRoot = relative(ROOT, base);
  if (fromRoot && insideRel(fromRoot)) {
    let at = ROOT;
    for (const part of fromRoot.split(sep)) {
      at = join(at, part);
      if (isSymlink(at)) {
        die(`${relative(ROOT, at)} is a symlink; ferrite-pkg writes only inside real directories`);
      }
    }
  } else {
    // A base outside the workspace (an explicit --out) is checked from its
    // filesystem root (a drive or UNC root on Windows): a symlinked ancestor
    // would redirect the write. Pass a real path.
    const absolute = resolve(base);
    const { root } = parse(absolute);
    let at = root;
    for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
      at = join(at, part);
      if (isSymlink(at)) {
        die(`${at} is a symlink; ferrite-pkg writes only through real directories (pass a real path)`);
      }
    }
  }
  const rel = relative(base, target);
  if (!insideRel(rel) || rel === "") {
    die(`${relative(ROOT, target)} is not beneath ${relative(ROOT, base)}`);
  }
  let at = base;
  for (const part of rel.split(sep)) {
    at = join(at, part);
    if (isSymlink(at)) {
      die(
        `${relative(ROOT, at)} is a symlink; ferrite-pkg writes and deletes only through real directories`,
      );
    }
  }
  return target;
}

/**
 * The ONLY way this tool writes a file.
 *
 * Every write is a mutation that can be redirected by a symlink, and a guard
 * applied per call site can miss a write. One choke point
 * cannot be forgotten in a second place, because there is no second place.
 */
function safeWrite(base, target, contents) {
  assertRealDescendant(base, target);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

/**
 * The ONLY way this tool deletes a file — `safeWrite`'s mirror. Every delete
 * re-proves real-descendant containment at the moment it happens, so a second
 * prune site cannot forget the guard: there is nothing to forget.
 */
function safeUnlink(base, target) {
  assertRealDescendant(base, target);
  rmSync(target);
}

/** The marker every composed `.rs` file carries in its provenance header. */
const GENERATED_MARKER = "@generated by ferrite-pkg";

/**
 * Does this file's head carry the provenance marker?
 *
 * Only the first few lines are consulted, because that is where `sync` puts
 * the header — a file that merely MENTIONS the marker somewhere in its body
 * (this tool's own source, a doc) is not a vendored copy.
 */
function hasGeneratedMarker(path) {
  const head = readFileSync(path).subarray(0, 4096).toString("utf8");
  return head
    .split("\n", 3)
    .some((line) => line.includes(GENERATED_MARKER));
}

/**
 * Every file under `dir`, like [`treeFiles`], but for READ-ONLY scans over
 * app-owned territory: a symlink is stepped over instead of refused.
 *
 * The distinction is deliberate, not a relaxation. `treeFiles` refuses links
 * because the write/delete phase that follows it would traverse them; this
 * walk feeds no mutation — it only looks for stray provenance markers — and
 * refusing a link here would put an app's own `src` layout under this tool's
 * jurisdiction, which is exactly where its authority ends.
 */
function scanTreeFiles(dir, skipDirs = []) {
  const out = [];
  // Directories another tool owns are not descended into at all.
  const skip = new Set(skipDirs.map((d) => resolve(d)));
  const walk = (d) => {
    if (!existsSync(d) || skip.has(resolve(d))) return;
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(relative(dir, full).split(sep).join("/"));
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * Every package under `packages/`, keyed by name.
 *
 * A package is a DIRECTORY with a manifest, not an entry in a central index:
 * adding one is `mkdir` plus a manifest, and there is no list to keep in step.
 */
function loadPackages() {
  const packages = new Map();
  if (!existsSync(PACKAGES_DIR)) return packages;
  for (const entry of readdirSync(PACKAGES_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = join(PACKAGES_DIR, entry.name);
    const manifestPath = join(dir, PACKAGE_MANIFEST);
    if (!existsSync(manifestPath)) continue;
    const manifest = readJson(manifestPath);
    if (manifest.name !== entry.name) {
      die(
        `packages/${entry.name} declares name "${manifest.name}"; the directory IS the name, so they must agree`,
      );
    }
    requirePackageName(manifest.name, `packages/${entry.name} name`);
    if (!manifest.root) {
      die(`packages/${entry.name} declares no "root" module path`);
    }
    requireModuleIdent(manifest.root, `packages/${entry.name} root`);
    if (typeof manifest.version !== "string" || !manifest.version) {
      die(`packages/${entry.name} declares no "version"`);
    }
    packages.set(manifest.name, {
      ...manifest,
      dir,
      srcDir: join(dir, "src"),
      files: treeFiles(join(dir, "src")),
    });
  }
  return packages;
}

/**
 * Every crate that declares a consumer manifest, keyed by directory name.
 *
 * Discovery is one level deep BY CONTRACT: a consumer is `<root>/<app>/`,
 * because that is where a crate is. The contract is enforced, not assumed —
 * a manifest anywhere else (`samples/thing/`, or the repo root itself) would
 * otherwise be silently ignored, and "silently ignored" here means `sync`
 * never composes it while `check` keeps reporting green. A manifest that
 * cannot take effect must be a refusal, not a no-op.
 */
/**
 * Directories a consumer app may live directly under. The top level was
 * categorized (apps/, engines/, frontends/, tools/), so a consumer is now
 * `<root>/<app>` OR `<root>/<category>/<app>`. Discovery covers exactly
 * these; anything deeper is still a misplaced manifest.
 */
const CONSUMER_ROOTS = ["", "apps", "engines", "frontends", "tools"];

/**
 * What marks a consumer as a project the released `ferrite` CLI owns.
 *
 * `ferrite new` vendors the SDK twin at `vendor/ferrite-app`, and `ferrite add`
 * then installs packages in its own form: the same provenance header, the
 * package's `#[cfg(test)]` modules removed, no lockfile, and only the package
 * that was asked for recorded in the manifest. An in-repo consumer depends on
 * the SDK source instead, or was adopted by `sync`
 * and so has a lockfile; either way it is not one of these. Before
 * this distinction existed, a demo built the way an application developer
 * builds one could not live in this repository at all: `check` reported every
 * mount as DRIFTED and demanded a lockfile, and `sync` would have rewritten
 * the tree into a form the developer's own CLI then refuses to update.
 */
const CLI_PROJECT_MARKER = join("vendor", "ferrite-app");

function loadConsumers() {
  const consumers = new Map();
  for (const category of CONSUMER_ROOTS) {
    const base = category ? join(ROOT, category) : ROOT;
    if (!existsSync(base)) continue;
    if (category && isSymlink(base)) {
      die(`${category} is a symlink; consumers are discovered only in real directories`);
    }
    for (const entry of readdirSync(base, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = join(base, entry.name);
      const manifestPath = join(dir, CONSUMER_MANIFEST);
      const cliProject = existsSync(join(dir, CLI_PROJECT_MARKER)) && !existsSync(join(dir, LOCKFILE));
      let manifest;
      if (existsSync(manifestPath)) {
        manifest = readJson(manifestPath);
      } else if (cliProject && nestedInstallDirs(join(dir, "src")).length > 0) {
        // `ferrite new` writes no manifest of its own (only the Alloy
        // template does), and `ferrite add <package> --dir src/<anchor>`
        // records the install in the anchor's manifest, not here. Such a
        // project declares nothing at its root, which is what an empty
        // manifest says; it is still a consumer, so its nested installs are
        // checked below and its own `src/` is still scanned for strays.
        // Without this the nested manifest is reported as
        // misplaced unless the developer adds an empty outer manifest by
        // hand, which the released CLI never asks for.
        manifest = { packages: {} };
      } else {
        continue;
      }
      // The key is the app name; a category prefix is a location, not identity.
      // Two locations with one name would make one of them silently unchecked.
      if (consumers.has(entry.name)) {
        die(
          `two consumers are named ${entry.name}: ${relative(ROOT, consumers.get(entry.name).dir)} and ${relative(ROOT, dir)} — rename one`,
        );
      }
      consumers.set(entry.name, {
        name: entry.name,
        dir,
        manifest,
        // A project the released CLI scaffolded and installed into: it holds
        // the SDK twin `ferrite new` writes (`vendor/ferrite-app`) and no
        // lockfile, and its mounts are what `ferrite add` wrote, not what
        // `sync` writes. A scaffold that was later adopted by `sync`
        // (apps/reminders) carries a lockfile and is an in-repo consumer.
        // See [`expectedTrees`].
        cliProject,
        // Divergences this consumer has declared: `{ "src/wasi.rs": "why" }`.
        // A file listed here is a decision on the record, not an unnoticed
        // copy — `check` reports it as a fork rather than a problem.
        forks: manifest.forks ?? {},
      });
    }
  }
  // A CLI project may hold further install directories beneath its `src/`:
  // `ferrite add <package> --dir src/<anchor>` is how an Rsx application
  // mounts a package at all, because `ferrite rsx sync` regenerates the crate
  // root and declares no directory module there (apps/demo-reading-room).
  // Each such directory has its own manifest and `src/<mount>/` tree, written
  // by the same command, so it is checked the same way instead of being
  // reported as a stray manifest.
  const nested = new Set();
  // `ferrite add --dir` also installs beneath an install directory's own
  // `src/` (CLI 0.1.12: `--dir src/library` then `--dir src/library/src/x`
  // both succeed), so every nested consumer is searched in turn. Each walk
  // stops at the first manifest below it, so a directory is registered once,
  // by its nearest enclosing install, and the work list ends.
  const pending = [...consumers.values()].filter((c) => c.cliProject);
  while (pending.length > 0) {
    const parent = pending.shift();
    for (const anchor of nestedInstallDirs(join(parent.dir, "src"))) {
      const manifestPath = join(anchor, CONSUMER_MANIFEST);
      const manifest = readJson(manifestPath);
      const name = `${parent.name}/${relative(parent.dir, anchor).split(sep).join("/")}`;
      nested.add(relative(ROOT, manifestPath));
      const child = { name, dir: anchor, manifest, cliProject: true, forks: manifest.forks ?? {} };
      consumers.set(name, child);
      pending.push(child);
    }
  }
  const misplaced = findMisplacedManifests().filter((path) => !nested.has(path));
  if (misplaced.length > 0) {
    die(
      `found ${CONSUMER_MANIFEST} outside the places discovery looks (<root>/<app> or <root>/{apps,engines,frontends,tools}/<app>):\n` +
        misplaced.map((p) => `  ${p}`).join("\n") +
        `\nthese would be silently ignored — move the app under a discovered root, or remove the stray manifest`,
    );
  }
  return consumers;
}

/**
 * Directories at or beneath `dir` that hold a consumer manifest of their own.
 *
 * Read-only, like [`findMisplacedManifests`]: symlinks are stepped over, and
 * a directory beneath `dir` that has a manifest is not searched further: its
 * subtree belongs to that manifest's own mounts and to installs nested beneath
 * its own `src/`, which `loadConsumers` searches in turn. When `dir` itself
 * has a manifest, only its own `src/` is left to it.
 */
function nestedInstallDirs(dir) {
  const found = [];
  if (!existsSync(dir) || lstatSync(dir).isSymbolicLink()) return found;
  // `ferrite add <package> --dir src` is accepted whenever the project's
  // `src/` is a crate of its own (CLI 0.1.12 asks only for a Cargo.toml
  // there), and records the install in `src/ferrite-packages.json` with its
  // tree under `src/src/`. That directory is then an install itself. Only its
  // own `src/` belongs to it (and is searched in turn by `loadConsumers`);
  // the rest of `dir` can still hold sibling installs such as
  // `--dir src/library`, so the walk continues there.
  const ownSrc = existsSync(join(dir, CONSUMER_MANIFEST)) ? join(dir, "src") : null;
  if (ownSrc) found.push(dir);
  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if (entry.name === "node_modules" || entry.name === "target") continue;
      const full = join(d, entry.name);
      if (full === ownSrc) continue;
      if (existsSync(join(full, CONSUMER_MANIFEST))) found.push(full);
      else walk(full);
    }
  };
  walk(dir);
  return found.sort();
}

/**
 * Consumer manifests at any depth discovery does NOT cover.
 *
 * A read-only walk, so symlinks are stepped over rather than refused (see
 * [`scanTreeFiles`] for why that is the right rule for app-owned territory).
 * Dependency and build trees are skipped: a manifest inside `node_modules/`
 * or `target/` is somebody's packaging artifact, not an ignored declaration.
 */
function findMisplacedManifests() {
  const SKIP = new Set(["node_modules", "target"]);
  // Durable evaluator workspaces are evidence artifacts, not source-tree
  // consumers. They intentionally preserve generated manifests below a deep
  // report path and must not make normal package checks look dirty. The
  // exemption is exact: a sibling root is still checked.
  const SKIP_ROOTS = new Set(["evidence/eval-reports"]);
  const misplaced = [];
  // A manifest is legitimately placed at <root>/<app> (depth 1) or under a
  // category dir at <root>/{apps,engines,frontends,tools}/<app> (depth 2).
  const CATEGORY = new Set(["apps", "engines", "frontends", "tools"]);
  const walk = (dir, depth, underCategory) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink() || entry.name.startsWith(".")) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP.has(entry.name)) continue;
        if (SKIP_ROOTS.has(relative(ROOT, full).replaceAll("\\", "/"))) continue;
        walk(full, depth + 1, underCategory || (depth === 0 && CATEGORY.has(entry.name)));
      } else if (entry.name === CONSUMER_MANIFEST) {
        const ok = depth === 1 || (depth === 2 && underCategory);
        if (!ok) misplaced.push(relative(ROOT, full));
      }
    }
  };
  walk(ROOT, 0, false);
  return misplaced.sort();
}

/**
 * The published index `ferrite add` installs from.
 *
 * `loadPackages` is the registry in the operative sense — a package is a
 * directory with a manifest, and adding one is `mkdir` — but a standalone
 * consumer outside this workspace cannot run `readdir` over a Git host. This
 * file is that directory listing, flattened into one fetchable document:
 * names, versions, mount roots, dependency edges, and every source file with
 * its SHA-256, so an installer can resolve, fetch, and verify what it fetched
 * before writing it, without ever crawling. A serial and a publish stamp say
 * which revision of the index that client is holding.
 */
const REGISTRY_FILE = "registry.json";

/**
 * The first PROSE paragraph of a package's README — the contract line the
 * registry shows for it. Headings are skipped, because "# serde-codec" tells
 * a browser of the index nothing its name did not.
 */
function readmeSummary(pkgDir) {
  const path = join(pkgDir, "README.md");
  if (!existsSync(path)) return "";
  for (const block of readFileSync(path, "utf8").split(/\n[ \t]*\n/)) {
    const lines = block
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("#"));
    if (lines.length > 0) return lines.join(" ");
  }
  return "";
}

/**
 * The digest a client verifies a downloaded package file against, keyed by the
 * file's package-relative path and sorted, because `pkg.files` is sorted.
 *
 * The bytes hashed are the package SOURCE under `packages/<name>/src/` — what
 * a client actually fetches — through the same `sha256` the lock ledger uses,
 * so a locally computed digest and a published one agree exactly. It is
 * deliberately NOT a vendored copy's digest: composition adds a provenance
 * header and rewrites `crate::<root>` to `crate::<mount>`, which makes that
 * hash a property of one consumer's mount, while the registry describes the
 * package itself.
 */
function fileDigests(pkg) {
  const digests = {};
  for (const relPath of pkg.files) {
    digests[relPath] = sha256(readFileSync(join(pkg.srcDir, relPath)));
  }
  return digests;
}

/**
 * The registry as it is currently published, or null when there is none.
 *
 * A malformed file is treated as absent rather than fatal: the registry is
 * generated state, and the answer to "it is corrupt" is to regenerate it, not
 * to wedge every command that renders it.
 */
function publishedRegistry() {
  const path = join(PACKAGES_DIR, REGISTRY_FILE);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed !== null && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The repo commit this index was published from, or null.
 *
 * Provenance is a courtesy, not a dependency: a checkout without git, an
 * export tarball, or the scratch trees the test suite builds all still produce
 * a registry — they just cannot say which commit it came from.
 */
function gitHead() {
  try {
    const out = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return /^[0-9a-f]{40}$/.test(out) ? out : null;
  } catch {
    return null;
  }
}

/** Is `stamp` a publish record this tool could have written? */
function isPublishStamp(stamp) {
  return (
    stamp !== null &&
    typeof stamp === "object" &&
    (stamp.commit === null || /^[0-9a-f]{40}$/.test(stamp.commit)) &&
    Number.isInteger(stamp.at_ms)
  );
}

/**
 * The registry's exact bytes, derived from the manifests alone so that
 * `check` can recompute and compare instead of trusting the written file.
 * Entries are sorted by name and every list inside one is sorted, because a
 * generated file that varies with directory-walk order produces diffs that
 * mean nothing.
 *
 * `serial` and `published` are the exception to "derived from the manifests
 * alone", and they are why this function reads the file it renders. Both
 * describe the PUBLICATION rather than the packages, so both are carried
 * forward untouched whenever the packages array is identical to what is
 * already published: re-running `registry` on an unchanged tree must be a
 * no-op, and `check` recomputes these same bytes and compares them. The serial
 * advances by one — and only then does a fresh `published` stamp get taken —
 * when the content actually differs, which makes it monotonic without making
 * it a clock.
 */
function renderRegistry(packages, only = null) {
  const previous = publishedRegistry();
  // `sync --package` refreshes only the named packages' entries: every other
  // entry stays exactly as published, so a package another session is still
  // editing does not reach the index through somebody else's sync.
  const publishedEntry = new Map(
    (Array.isArray(previous?.packages) ? previous.packages : []).map((entry) => [entry?.name, entry]),
  );
  const entries = [...packages.values()]
    .sort((a, b) => (a.name < b.name ? -1 : 1))
    .map((pkg) => {
      if (only && !only.has(pkg.name) && publishedEntry.has(pkg.name)) return publishedEntry.get(pkg.name);
      const readme = join(pkg.dir, "README.md");
      return {
        name: pkg.name,
        version: pkg.version,
        root: pkg.root,
        summary: readmeSummary(pkg.dir),
        dependencies: Object.keys(pkg.dependencies ?? {}).sort(),
        // Lines the CONSUMING crate's root must carry for this tree to
        // compile — `extern crate alloc;` for the three packages written
        // against `alloc::` paths. Without publishing it, `ferrite add`
        // prints only the `pub mod` line and the first build fails inside
        // code the developer never wrote.
        crateRoot: Array.isArray(pkg.crateRoot) ? pkg.crateRoot : [],
        // Cargo features the consuming crate must declare. These gate no
        // dependency — they are plain flags the vendored source reads — so
        // they do not touch the one-dependency rule. Without them the tree
        // selects paths for modules it does not ship and will not compile.
        cargoFeatures:
          pkg.cargoFeatures && typeof pkg.cargoFeatures === "object"
            ? pkg.cargoFeatures
            : null,
        files: fileDigests(pkg),
        docs: existsSync(readme) ? `packages/${pkg.name}/README.md` : null,
      };
    });
  const priorSerial =
    Number.isInteger(previous?.serial) && previous.serial >= 0 ? previous.serial : 0;
  // A previous file whose own serial or stamp is unusable counts as changed,
  // so the next render repairs it instead of reproducing the damage.
  const unchanged =
    previous !== null &&
    Number.isInteger(previous.serial) &&
    isPublishStamp(previous.published) &&
    JSON.stringify(previous.packages) === JSON.stringify(entries);
  const registry = {
    note: "generated by ferrite-pkg registry; do not edit",
    serial: unchanged ? previous.serial : priorSerial + 1,
    published: unchanged
      ? previous.published
      : { commit: gitHead(), at_ms: Date.now() },
    packages: entries,
  };
  return `${JSON.stringify(registry, null, 2)}\n`;
}

function cmdRegistry(only = null, packages = loadPackages()) {
  const text = renderRegistry(packages, only);
  const target = join(PACKAGES_DIR, REGISTRY_FILE);
  const { serial } = JSON.parse(text);
  if (alreadyHolds(target, text)) {
    console.log(
      `packages/${REGISTRY_FILE} is current (${packages.size} package(s), serial ${serial})`,
    );
    return 0;
  }
  safeWrite(PACKAGES_DIR, target, text);
  console.log(
    `wrote packages/${REGISTRY_FILE} (${packages.size} package(s), serial ${serial})`,
  );
  return 0;
}

/**
 * The packages as the platform MCP serves them, for an agent that has only the
 * MCP: no shell, so no `ferrite add`. The package-aware platform MCP answers
 * `list_packages` and `read_package` from this document and merges a named
 * package's files into a `code_gate`, `deploy_source` or `rcs_commit` request.
 * `apply-overlays.sh` copies it into the Core export beside the docs corpus.
 *
 * Each file is carried EXACTLY as `ferrite add <package>` writes it at the
 * package's default mount (its root): a `.rs` file gets the provenance header
 * and loses its `#[cfg(test)]` modules, and every other file is the package's
 * bytes. So an app deployed through the MCP holds the same tree as one built
 * with the CLI, and a later `ferrite add` in that tree finds nothing to change.
 * The test suite compares this output with the real CLI's, file by file.
 */
const MCP_PACKAGES_FILE = join(ROOT, "ops", "ferrite", "core-patches", "0040-mcp-packages.json");

/** The standalone installer's header: `add.rs`'s `vendored()`, byte for byte. */
function standaloneHeader(pkg, relPath) {
  return (
    `// ${GENERATED_MARKER} from packages/${pkg.name}/src/${relPath} (${pkg.name} v${pkg.version}).\n` +
    `// DO NOT EDIT HERE — this copy is overwritten. Edit the line above's path,\n` +
    `// then run: node tools/ferrite-pkg/ferrite-pkg.mjs sync\n`
  );
}

/**
 * The Rust token trees `proc-macro2` (fallback lexer, 1.0.107) builds from a
 * source file, reduced to what `strip_cfg_test_modules` reads: punctuation,
 * identifiers, literals and delimited groups, each with its UTF-16 span. A doc
 * comment becomes `#` (`!`) `[doc = "…"]` spanning the comment, as there.
 * Returns null where proc-macro2 would refuse the source, in which case the
 * CLI copies the file unchanged and so does this.
 */
function rustTokens(src) {
  const { n, identAny, skipWhitespace, docComment, literal } = rustLexer(src);
  const PUNCT = "~!@#$%^&*-=+|;:,<.>/?'";
  const OPEN = { "(": ")", "[": "]", "{": "}" };
  const stack = [{ tokens: [], close: null, start: 0 }];
  const push = (token) => stack[stack.length - 1].tokens.push(token);
  let k = 0;
  for (;;) {
    k = skipWhitespace(k);
    const doc = k < n ? docComment(k) : null;
    if (doc) {
      const [end, inner] = doc;
      push({ k: "p", ch: "#", s: k, e: end, doc: true });
      if (inner) push({ k: "p", ch: "!", s: k, e: end, doc: true });
      push({
        k: "g",
        d: "[",
        s: k,
        e: end,
        doc: true,
        inner: [
          { k: "i", text: "doc", s: k, e: end },
          { k: "p", ch: "=", s: k, e: end },
          { k: "l", s: k, e: end, doc: true },
        ],
      });
      k = end;
      continue;
    }
    if (k >= n) return stack.length === 1 ? stack[0].tokens : null;
    const c = src[k];
    if (OPEN[c]) {
      stack.push({ tokens: [], close: OPEN[c], open: c, start: k });
      k += 1;
    } else if (c === ")" || c === "]" || c === "}") {
      const frame = stack.pop();
      if (stack.length === 0 || frame.close !== c) return null;
      push({ k: "g", d: frame.open, s: frame.start, e: k + 1, inner: frame.tokens });
      k += 1;
    } else {
      const lit = literal(k);
      if (lit >= 0) {
        push({ k: "l", s: k, e: lit });
        k = lit;
        continue;
      }
      if (PUNCT.includes(c) && !src.startsWith("//", k) && !src.startsWith("/*", k)) {
        if (c === "'") {
          const end = identAny(k + 1);
          if (end < 0 || src[end] === "'") return null;
        }
        push({ k: "p", ch: c, s: k, e: k + 1 });
        k += 1;
        continue;
      }
      const end = identAny(k);
      if (end < 0) return null;
      push({ k: "i", text: src.slice(k, end), s: k, e: end });
      k = end;
    }
  }
}

/** The character-level scanners of [`rustTokens`], closed over one source text. */
function rustLexer(src) {
  const n = src.length;
  const XID_START = /^[\p{XID_Start}_]$/u;
  const XID_CONTINUE = /^\p{XID_Continue}$/u;
  const WHITE = /^[\p{White_Space}‎‏]$/u;
  const charAt = (k) => (k < n ? String.fromCodePoint(src.codePointAt(k)) : "");
  const isStart = (k) => k < n && XID_START.test(charAt(k));
  const identEnd = (k) => {
    while (k < n && XID_CONTINUE.test(charAt(k))) k += charAt(k).length;
    return k;
  };
  // `r#name` or `name`; the end, or -1.
  const identAny = (k) => {
    if (src.startsWith("r#", k) && isStart(k + 2)) return identEnd(k + 2);
    return isStart(k) ? identEnd(k) : -1;
  };
  const blockCommentEnd = (k) => {
    let depth = 0;
    let j = k;
    while (j < n - 1) {
      if (src[j] === "/" && src[j + 1] === "*") {
        depth += 1;
        j += 1;
      } else if (src[j] === "*" && src[j + 1] === "/") {
        depth -= 1;
        if (depth === 0) return j + 2;
        j += 1;
      }
      j += 1;
    }
    return -1;
  };
  const lineEnd = (k) => {
    for (let j = k; j < n; j += 1) {
      if (src[j] === "\n" || (src[j] === "\r" && src[j + 1] === "\n")) return j;
    }
    return n;
  };
  const skipWhitespace = (k) => {
    while (k < n) {
      if (src[k] === "/") {
        if (src.startsWith("//", k) && (!src.startsWith("///", k) || src.startsWith("////", k)) && !src.startsWith("//!", k)) {
          k = lineEnd(k);
          continue;
        } else if (src.startsWith("/**/", k)) {
          k += 4;
          continue;
        } else if (src.startsWith("/*", k) && (!src.startsWith("/**", k) || src.startsWith("/***", k)) && !src.startsWith("/*!", k)) {
          const end = blockCommentEnd(k);
          if (end < 0) return k;
          k = end;
          continue;
        }
      }
      const ch = charAt(k);
      if (WHITE.test(ch)) {
        k += ch.length;
        continue;
      }
      return k;
    }
    return k;
  };
  // A doc comment at `k`: [end, inner], or null.
  const docComment = (k) => {
    let end;
    let inner;
    let body;
    if (src.startsWith("//!", k)) {
      end = lineEnd(k + 3);
      inner = true;
      body = src.slice(k + 3, end);
    } else if (src.startsWith("/*!", k)) {
      end = blockCommentEnd(k);
      if (end < 0) return null;
      inner = true;
      body = src.slice(k + 3, end - 2);
    } else if (src.startsWith("///", k)) {
      if (src[k + 3] === "/") return null;
      end = lineEnd(k + 3);
      inner = false;
      body = src.slice(k + 3, end);
    } else if (src.startsWith("/**", k) && src[k + 3] !== "*") {
      end = blockCommentEnd(k);
      if (end < 0) return null;
      inner = false;
      body = src.slice(k + 3, end - 2);
    } else {
      return null;
    }
    // A bare CR in a doc comment is refused there too.
    if (/\r(?!\n)/.test(body)) return null;
    return [end, inner];
  };
  // After a literal, an optional suffix identifier.
  const suffix = (k) => (isStart(k) ? identEnd(k) : k);
  // The end of a quoted body starting after the opening quote, or -1.
  const cooked = (k, quote) => {
    for (let j = k; j < n; j += 1) {
      if (src[j] === "\\") j += 1;
      else if (src[j] === quote) return j + 1;
    }
    return -1;
  };
  const raw = (k) => {
    // k is just past the `r`.
    let hashes = 0;
    while (src[k + hashes] === "#") hashes += 1;
    if (src[k + hashes] !== '"') return -1;
    const close = `"${"#".repeat(hashes)}`;
    const at = src.indexOf(close, k + hashes + 1);
    return at < 0 ? -1 : at + close.length;
  };
  // A character (or byte) literal body after its opening `'`: the end, or -1.
  const charLiteral = (k) => {
    let j = k;
    if (src[j] === "\\") {
      const e = src[j + 1];
      if (e === "x") j += 4;
      else if (e === "u") {
        const close = src.indexOf("}", j);
        if (src[j + 2] !== "{" || close < 0) return -1;
        j = close + 1;
      } else if ("nrt\\0'\"".includes(e ?? "\u0000")) j += 2;
      else return -1;
    } else {
      if (j >= n) return -1;
      j += charAt(j).length;
    }
    return src[j] === "'" ? j + 1 : -1;
  };
  // A literal at `k`: its end, or -1.
  const literal = (k) => {
    const c = src[k];
    let end = -1;
    if (c === '"') end = cooked(k + 1, '"');
    else if (c === "r" && (src[k + 1] === '"' || src[k + 1] === "#")) end = raw(k + 1);
    else if (c === "b" && src[k + 1] === '"') end = cooked(k + 2, '"');
    else if (c === "b" && src[k + 1] === "r") end = raw(k + 2);
    else if (c === "c" && src[k + 1] === '"') end = cooked(k + 2, '"');
    else if (c === "c" && src[k + 1] === "r") end = raw(k + 2);
    else if (c === "b" && src[k + 1] === "'") end = charLiteral(k + 2);
    else if (c === "'") end = charLiteral(k + 1);
    else if (c >= "0" && c <= "9") {
      let j = k;
      // In 0x/0b/0o literals `e` is a digit, never an exponent: `0xfe-crate::X` is a subtraction.
      const radix = src[k] === "0" && /[xXbBoO]/.test(src[k + 1] ?? "");
      const digits = () => {
        while (j < n && /[0-9A-Za-z_]/.test(src[j])) {
          const exp = !radix && (src[j] === "e" || src[j] === "E") && (src[j + 1] === "+" || src[j + 1] === "-");
          j += exp ? 2 : 1;
        }
      };
      digits();
      if (src[j] === "." && src[j + 1] !== "." && !isStart(j + 1)) {
        j += 1;
        digits();
      }
      return j;
    }
    return end < 0 ? -1 : suffix(end);
  };
  return { n, identAny, skipWhitespace, docComment, literal };
}

/**
 * `ferrite add`'s `strip_cfg_test_modules` (the CLI vendor command):
 * every `#[cfg(test)] [pub | pub(...)] mod name { ... }` removed with its own
 * line, everything else copied unchanged. The port is exact on every package
 * file; ferrite-pkg.test.mjs holds it to the CLI's output.
 */
function stripCfgTestModules(source) {
  const tokens = rustTokens(source);
  if (!tokens) return source;
  const removals = [];
  const isIdent = (t, text) => t?.k === "i" && t.text === text;
  const outerAttribute = (list, i) =>
    list[i]?.k === "p" && list[i].ch === "#" && list[i + 1]?.k === "g" && list[i + 1].d === "["
      ? list[i + 1]
      : null;
  const isCfgTest = (group) => {
    const [cfg, args, ...rest] = group.inner;
    return (
      rest.length === 0 &&
      isIdent(cfg, "cfg") &&
      args?.k === "g" &&
      args.d === "(" &&
      args.inner.length === 1 &&
      isIdent(args.inner[0], "test")
    );
  };
  const inlineModule = (list, index) => {
    let i = index;
    if (isIdent(list[i], "pub")) {
      i += 1;
      if (list[i]?.k === "g" && list[i].d === "(") i += 1;
    }
    if (!isIdent(list[i], "mod") || list[i + 1]?.k !== "i") return null;
    const body = list[i + 2];
    return body?.k === "g" && body.d === "{" ? [i + 2, body] : null;
  };
  const collect = (list, depth) => {
    if (depth > 64) return;
    let i = 0;
    while (i < list.length) {
      const runStart = i;
      let hasCfgTest = false;
      for (let group = outerAttribute(list, i); group; group = outerAttribute(list, i)) {
        if (isCfgTest(group)) hasCfgTest = true;
        i += 2;
      }
      const module = inlineModule(list, i);
      if (module) {
        const [bodyIndex, body] = module;
        if (i > runStart && hasCfgTest) removals.push([list[runStart].s, body.e]);
        else collect(body.inner, depth + 1);
        i = bodyIndex + 1;
      } else {
        i += 1;
      }
    }
  };
  collect(tokens, 0);
  if (removals.length === 0) return source;
  removals.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let out = "";
  let cursor = 0;
  for (let [start, end] of removals) {
    if (start < cursor || end > source.length) continue;
    while (start > cursor && (source[start - 1] === " " || source[start - 1] === "\t")) start -= 1;
    let lineEnd = end;
    while (source[lineEnd] === " " || source[lineEnd] === "\t") lineEnd += 1;
    if (source[lineEnd] === "\n") end = lineEnd + 1;
    else if (source[lineEnd] === "\r" && source[lineEnd + 1] === "\n") end = lineEnd + 2;
    out += source.slice(cursor, start);
    cursor = end;
  }
  return out + source.slice(cursor);
}

/**
 * The cargo features a Rust source reads: every `feature = "name"` inside an
 * attribute (`#[cfg(...)]`, `#[cfg_attr(...)]`, nested `any`/`all`/`not`).
 * A comment or string that mentions one is not a read. Null when the source
 * does not tokenize.
 */
function featuresRead(src) {
  const tokens = rustTokens(src);
  if (!tokens) return null;
  const found = new Set();
  const inAttribute = (list) => {
    for (let i = 0; i < list.length; i += 1) {
      const [t, eq, lit] = [list[i], list[i + 1], list[i + 2]];
      if (t.k === "g") inAttribute(t.inner);
      if (t.k !== "i" || t.text !== "feature" || eq?.k !== "p" || eq.ch !== "=" || lit?.k !== "l") continue;
      const text = src.slice(lit.s, lit.e);
      if (text.startsWith('"') && text.endsWith('"')) found.add(text.slice(1, -1));
    }
  };
  const walk = (list) => {
    for (let i = 0; i < list.length; i += 1) {
      const t = list[i];
      if (t.k !== "g" || t.doc) continue;
      const attribute =
        t.d === "[" &&
        (list[i - 1]?.k === "p" && list[i - 1].ch === "#" ||
          list[i - 1]?.k === "p" && list[i - 1].ch === "!" && list[i - 2]?.k === "p" && list[i - 2].ch === "#");
      if (attribute) inAttribute(t.inner);
      else walk(t.inner);
    }
  };
  walk(tokens);
  return found;
}

/**
 * Packages whose source reads a cargo feature their manifest does not declare
 * in `cargoFeatures`. A consumer declares only what the package publishes
 * (`ferrite add` prints that block), so an undeclared switch is a
 * configuration nobody selects on purpose and nobody builds: wasm-runtime
 * carried `std`, `canonicalize-nans` and `debug` switches whose off sides did
 * not compile. A package that wants a switch declares it.
 */
function checkPackageFeatures(packages) {
  const problems = [];
  for (const pkg of packages.values()) {
    const declared = new Set(Object.keys(pkg.cargoFeatures && typeof pkg.cargoFeatures === "object" ? pkg.cargoFeatures : {}));
    const undeclared = new Map();
    for (const relPath of pkg.files) {
      if (!relPath.endsWith(".rs")) continue;
      const read = featuresRead(readFileSync(join(pkg.srcDir, relPath), "utf8"));
      for (const name of read ?? []) {
        if (!declared.has(name) && !undeclared.has(name)) undeclared.set(name, relPath);
      }
    }
    for (const [name, relPath] of undeclared) {
      problems.push(
        `packages/${pkg.name}: its source reads cargo feature "${name}" (src/${relPath}), which its ferrite-package.json does not declare in cargoFeatures — declare it, or fold the switch into the package's one configuration`,
      );
    }
  }
  return problems;
}

/** One package file as `ferrite add` writes it at the package's root. */
function standaloneFile(pkg, relPath) {
  const bytes = readFileSync(join(pkg.srcDir, relPath));
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) {
    die(
      `packages/${pkg.name}/src/${relPath} is not UTF-8 text; the MCP carries package files as JSON strings`,
    );
  }
  if (!relPath.endsWith(RUST_EXT)) return text;
  return standaloneHeader(pkg, relPath) + stripCfgTestModules(text);
}

function renderMcpPackages(packages, only = null, previous = null) {
  const registry = publishedRegistry();
  let entries = [...packages.values()]
    .filter((pkg) => !only || only.has(pkg.name))
    .sort((a, b) => (a.name < b.name ? -1 : 1))
    .map((pkg) => {
      const readme = join(pkg.dir, "README.md");
      const files = {};
      for (const relPath of pkg.files) files[relPath] = standaloneFile(pkg, relPath);
      return {
        name: pkg.name,
        version: pkg.version,
        root: pkg.root,
        summary: typeof pkg.summary === "string" && pkg.summary ? pkg.summary : readmeSummary(pkg.dir),
        dependencies: Object.keys(pkg.dependencies ?? {}).sort(),
        crate_root: Array.isArray(pkg.crateRoot) ? pkg.crateRoot : [],
        cargo_features:
          pkg.cargoFeatures && typeof pkg.cargoFeatures === "object" ? pkg.cargoFeatures : null,
        readme: existsSync(readme) ? readFileSync(readme, "utf8") : "",
        setup: pkg.files.includes("SETUP.md") ? "SETUP.md" : null,
        files,
      };
    });
  if (only) {
    const replacements = new Map(entries.map((entry) => [entry.name, entry]));
    entries = previous.packages.map((entry) => {
      const replacement = replacements.get(entry.name);
      replacements.delete(entry.name);
      return replacement ?? entry;
    });
    entries.push(...replacements.values());
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }
  const document = {
    ...(previous ?? {}),
    version: 1,
    note: "generated by ferrite-pkg mcp-packages; do not edit",
    registry_serial: Number.isInteger(registry?.serial) ? registry.serial : null,
    packages: entries,
  };
  return `${JSON.stringify(document)}\n`;
}

function cmdMcpPackages(args) {
  let check = false;
  let target = MCP_PACKAGES_FILE;
  const selected = new Set();
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--check") check = true;
    else if (args[i] === "--package") {
      const name = args[++i];
      if (!name || name.startsWith("--")) die("mcp-packages --package needs a package name");
      selected.add(name);
    } else if (args[i].startsWith("--package=")) {
      const name = args[i].slice("--package=".length);
      if (!name) die("mcp-packages --package needs a package name");
      selected.add(name);
    }
    else if (args[i] === "--out" && args[i + 1]) target = resolve(args[(i += 1)]);
    else die(`mcp-packages: unknown argument ${args[i]} (use --check, --package <name> or --out <file>)`);
  }
  const packages = loadPackages();
  const only = selected.size ? selected : null;
  let previous = null;
  if (only) {
    for (const name of only) {
      if (!packages.has(name)) die(`mcp-packages --package ${name}: no such package under packages/`);
    }
    if (!existsSync(target)) die("mcp-packages --package requires an existing corpus; run mcp-packages without --package first");
    previous = readJson(target);
    if (previous?.version !== 1 || !Array.isArray(previous.packages)
        || previous.packages.some((entry) => !entry || typeof entry.name !== "string")
        || new Set(previous.packages.map((entry) => entry.name)).size !== previous.packages.length) {
      die("mcp-packages --package requires a valid version 1 corpus with unique package names");
    }
  }
  const text = renderMcpPackages(packages, only, previous);
  const shown = relative(ROOT, target);
  const size = `${packages.size} package(s), ${(Buffer.byteLength(text) / 1048576).toFixed(1)} MiB`;
  if (alreadyHolds(target, text)) {
    console.log(`${shown} is current (${size})`);
    return 0;
  }
  if (check) {
    console.error(
      `${shown}: stale — run: node tools/ferrite-pkg/ferrite-pkg.mjs mcp-packages${only ? [...only].map((name) => ` --package ${name}`).join("") : ""}`,
    );
    return 1;
  }
  // The same guarded writer as every other write: inside the workspace the
  // base is its root; an explicit --out elsewhere is guarded from its own
  // directory, which must exist and be real.
  const outside = !insideRel(relative(ROOT, target));
  safeWrite(outside ? dirname(target) : ROOT, target, text);
  console.log(`wrote ${shown} (${size})`);
  return 0;
}

/**
 * Resolve one consumer's package set, including transitive dependencies.
 *
 * Returns mounts in dependency order. A cycle is refused rather than unrolled:
 * two packages that need each other are one package that has not admitted it.
 */
function resolveMounts(consumer, packages) {
  const declared = consumer.manifest.packages ?? {};
  const mounts = [];
  const seen = new Map();
  const byMount = new Map();
  const visiting = new Set();
  const externals = externalMounts(consumer, packages);
  const externalNames = new Set(externals.map(({ name }) => name));

  const visit = (name, requestedMount, via) => {
    const pkg = packages.get(name);
    if (!pkg) {
      die(
        `${consumer.name} wants package "${name}"${via ? ` (via ${via})` : ""}, which does not exist under packages/`,
      );
    }
    // A package mounts at its own root unless the consumer says otherwise.
    const mount = requireModuleIdent(
      requestedMount ?? pkg.root,
      `${consumer.name} mount for package "${name}"`,
    );
    if (seen.has(name)) {
      const already = seen.get(name);
      if (already !== mount) {
        die(
          `${consumer.name} mounts "${name}" at both "${already}" and "${mount}"; a package has one mount per app`,
        );
      }
      return;
    }
    if (visiting.has(name)) {
      die(`package dependency cycle through "${name}"`);
    }
    visiting.add(name);
    for (const [dep, spec] of Object.entries(pkg.dependencies ?? {})) {
      // A dependency another tool manages is already in place; its mount is
      // reserved below and its references are rewritten toward it.
      if (externalNames.has(dep)) continue;
      // The consumer's own declaration for a dependency wins over the
      // dependency's default root, whichever order the manifest lists them
      // in: buzz declares `ferrite-sso` before `sha256-hmac`, and the first
      // must not mount the second at `crypto` before the second's own entry
      // says `crypto_kernel`.
      const consumerMount = declared[dep]?.mount;
      const suggested = typeof spec === "object" ? spec.mount : undefined;
      visit(dep, consumerMount ?? suggested, name);
    }
    visiting.delete(name);
    seen.set(name, mount);
    // A directory belongs to ONE package. Their files being disjoint is not
    // enough: prune and check run per mount entry, so a hostFile declared by
    // one package's entry would be deleted by the other's pass. Two packages
    // sharing a module root also cannot both own its `mod.rs`.
    const owner = byMount.get(mount);
    if (owner !== undefined && owner !== name) {
      die(
        `${consumer.name} mounts both "${owner}" and "${name}" at "${mount}"; a mount belongs to one package`,
      );
    }
    byMount.set(mount, name);
    const hostFiles = (declared[name]?.hostFiles ?? []).map((p) =>
      requireHostPattern(p, `${consumer.name} hostFiles entry for package "${name}"`),
    );
    mounts.push({ pkg, mount, hostFiles });
  };

  // Packages installed and lifecycle-managed by another accepted tool
  // ([`externalMounts`]) are an ownership boundary: their mounts are reserved
  // before anything else is placed, so no package of this tool's can be
  // written or pruned there, and they are never visited, here or as another
  // package's dependency.
  for (const { name, mount, source } of externals) {
    const owner = byMount.get(mount);
    if (owner !== undefined) {
      die(`${consumer.name} declares both "${owner}" and "${name}" (managed by ${source}) at "${mount}"; a mount belongs to one package`);
    }
    byMount.set(mount, name);
  }
  for (const [name, spec] of Object.entries(declared)) {
    if (isExternal(spec)) continue;
    visit(name, spec?.mount, null);
  }
  return mounts;
}

function isExternal(spec) {
  return typeof spec?.source === "string" && spec.source.length > 0;
}

/**
 * The packages a consumer declares as installed and managed by another tool
 * (a `source` marker, e.g. the offline `ferrite auth init` contract), with
 * the directory each one occupies: its declared `mount`, else its package
 * root. ferrite-pkg never writes, prunes, scans or claims these directories.
 */
function externalMounts(consumer, packages) {
  const out = [];
  for (const [name, spec] of Object.entries(consumer.manifest.packages ?? {})) {
    if (!isExternal(spec)) continue;
    const mount = spec.mount ?? packages.get(name)?.root;
    if (mount === undefined) {
      die(
        `${consumer.name} declares "${name}" as managed by ${spec.source} but names no mount, ` +
          `and no package under packages/ gives its root; add "mount" so its directory is known`,
      );
    }
    out.push({ name, mount: requireModuleIdent(mount, `${consumer.name} mount for package "${name}"`), source: spec.source });
  }
  return out;
}

/**
 * The exact content a vendored file must hold.
 *
 * A non-`.rs` file is the package's bytes unchanged. A `.rs` file gets two
 * transformations, both deterministic so that `check` can recompute them and
 * compare rather than trust a recorded hash alone:
 *
 * 1. A provenance header. A vendored file is a COPY, and the single most
 *    expensive mistake available is editing the copy — the edit survives until
 *    the next sync and then vanishes, which reads as the tool eating work. The
 *    header names the canonical path and the command that regenerates it.
 * 2. Reference rewriting. The source says `crate::<root>::…` for itself and
 *    `crate::<dependency root>::…` for each package it declares in
 *    `dependencies`; an app that mounts any of those elsewhere needs
 *    `crate::<mount>::…`. When every root and mount agree — the common case,
 *    and the reason both WASM consumers mount at `wasm` — this is a no-op.
 *
 *    Dependencies are rewritten for the same reason self-references are: a
 *    package cannot know where its consumer put the package it depends on.
 *    `buzz` keeps its own `src/crypto` and mounts `sha256-hmac` (root
 *    `crypto`) at `crypto_kernel`, so `ferrite-sso`'s `crate::crypto::…`
 *    must arrive there as `crate::crypto_kernel::…` or it names buzz's module.
 *    Only DECLARED dependencies are rewritten: a package that reaches into a
 *    package it never declared is not composed around, it is left naming the
 *    wrong module, which is what makes the omission visible.
 *
 * An asset therefore carries no in-band warning against editing it. `check`
 * still catches that edit; the header is a courtesy, and the ledger is the rule.
 */
function renderVendored(pkg, mount, relPath, body, packages, mountOf) {
  if (!relPath.endsWith(RUST_EXT)) return body;
  const canonical = `packages/${pkg.name}/src/${relPath}`;
  const header =
    `// ${GENERATED_MARKER} from ${canonical} (${pkg.name} v${pkg.version}).\n` +
    `// DO NOT EDIT HERE — this copy is overwritten. Edit the line above's path,\n` +
    `// then run: node tools/ferrite-pkg/ferrite-pkg.mjs sync\n`;
  const rewrites = referenceRewrites(pkg, mount, packages, mountOf);
  if (rewrites.size === 0) return header + body;
  return header + rewriteCratePaths(body, rewrites, canonical);
}

/**
 * Rewrite every `crate::<root>` reference in Rust source `body` whose root
 * has a move in `rewrites`.
 *
 * Code is read as Rust tokens ([`rustTokens`], the CLI's own tokenizer
 * port), so a path is found however it is spaced — `crate :: root`, a
 * comment between `crate::` and `root`, `$crate::root` in a macro. Comments
 * and doc comments that name a moved path follow it too (in buzz,
 * `crate::crypto` is the app's own, different module, so a doc line left
 * naming it would point at the wrong code). String, raw-string, byte and
 * char literals are data and keep their exact bytes. Only a root
 * identifier's own span is replaced, and each is looked at once, so a move
 * can never feed a second one (root `a` mounted at `b` beside root `b`
 * mounted at `c` stays two moves).
 */
function rewriteCratePaths(body, rewrites, where) {
  const tokens = rustTokens(body);
  if (tokens === null) {
    die(`${where} is not valid Rust (it does not tokenize), so its crate paths cannot be rewritten`);
  }
  const edits = new Map();
  // Every byte that is code (not whitespace, not a comment): leaf tokens and
  // group delimiters. Doc comments are tokens too, but they are comment text.
  const code = [];
  const walk = (list) => {
    for (let i = 0; i < list.length; i += 1) {
      const t = list[i];
      if (t.doc) continue;
      if (t.k === "g") {
        code.push([t.s, t.s + 1], [t.e - 1, t.e]);
        walk(t.inner);
        continue;
      }
      code.push([t.s, t.e]);
      if (t.k !== "i" || t.text !== "crate") continue;
      const [c1, c2, root] = [list[i + 1], list[i + 2], list[i + 3]];
      if (c1?.k !== "p" || c1.ch !== ":" || c2?.k !== "p" || c2.ch !== ":" || c2.s !== c1.e) continue;
      // A grouped `use crate::{crypto::x, other}`: each item's head is a root too.
      if (root?.k === "g" && root.d === "{") {
        const items = root.inner.filter((item) => !item.doc);
        items.forEach((item, at) => {
          const head = at === 0 || (items[at - 1].k === "p" && items[at - 1].ch === ",");
          if (head && item.k === "i" && rewrites.has(item.text)) edits.set(item.s, [item.e, rewrites.get(item.text)]);
        });
        continue;
      }
      if (root?.k !== "i" || !rewrites.has(root.text)) continue;
      edits.set(root.s, [root.e, rewrites.get(root.text)]);
    }
  };
  walk(tokens);
  // Comment text (plain and doc comments) only: a match that starts inside
  // any code token — a literal, an identifier, a path the token pass already
  // judged — is not touched. Whitespace never holds a `c`, so whatever is
  // left is comment. Boundaries are Unicode identifier characters, as Rust's.
  code.sort((a, b) => a[0] - b[0]);
  const inCode = (at) => {
    let lo = 0;
    let hi = code.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const [s, e] = code[mid];
      if (at < s) hi = mid - 1;
      else if (at >= e) lo = mid + 1;
      else return true;
    }
    return false;
  };
  const pattern = new RegExp(
    `(?<!\\p{XID_Continue})crate::(${[...rewrites.keys()].join("|")})(?!\\p{XID_Continue})`,
    "gu",
  );
  for (const m of body.matchAll(pattern)) {
    if (inCode(m.index)) continue;
    const at = m.index + "crate::".length;
    edits.set(at, [at + m[1].length, rewrites.get(m[1])]);
  }
  let out = "";
  let at = 0;
  for (const [s, [e, text]] of [...edits].sort((a, b) => a[0] - b[0])) {
    out += body.slice(at, s) + text;
    at = e;
  }
  return out + body.slice(at);
}

/**
 * The `crate::<root>` → `crate::<mount>` moves one package's vendored copy
 * needs under one consumer: its own, plus one per declared dependency the
 * consumer mounted away from that dependency's root.
 */
function referenceRewrites(pkg, mount, packages, mountOf) {
  // Every root's destination is recorded, including the ones that stay put:
  // a root that one package keeps where it is and another moves is the same
  // contradiction as two moves, and dropping the no-op first would hide it
  // (every `crate::a` would follow the move, the stay-put package's too).
  const mapping = new Map();
  const add = (root, target, owner) => {
    const already = mapping.get(root);
    if (already !== undefined && already.target !== target) {
      die(
        `${pkg.name}: "${owner}" and "${already.owner}" both use the module root "${root}" but are mounted apart ` +
          `("${target}" and "${already.target}"); a package cannot compose two roots under one name`,
      );
    }
    mapping.set(root, { target, owner });
  };
  add(pkg.root, mount, pkg.name);
  for (const dep of Object.keys(pkg.dependencies ?? {})) {
    const depPkg = packages?.get(dep);
    const depMount = mountOf?.get(dep);
    if (depPkg === undefined || depMount === undefined) continue;
    add(depPkg.root, depMount, dep);
  }
  const rewrites = new Map();
  for (const [root, { target }] of mapping) if (root !== target) rewrites.set(root, target);
  return rewrites;
}

/**
 * What a consumer's vendored trees SHOULD contain, as path -> contents.
 *
 * For a CLI project ([`CLI_PROJECT_MARKER`]) that is each file exactly as
 * `ferrite add` writes it ([`standaloneFile`]), so a package that moved on
 * since the project installed it is reported like any other drift, and the
 * fix is the developer's own command (`ferrite add <package> --force`).
 */
function expectedTrees(consumer, packages) {
  const mounts = resolveMounts(consumer, packages);
  if (consumer.cliProject) {
    for (const { pkg, mount } of mounts) {
      // `ferrite add` installs at the package's root and nowhere else.
      if (mount !== pkg.root) {
        die(
          `${consumer.name} is a CLI project (it has ${CLI_PROJECT_MARKER}) and mounts "${pkg.name}" at "${mount}"; ` +
            `\`ferrite add\` installs a package at its root ("${pkg.root}") only`,
        );
      }
    }
  }
  // Where this consumer put each package, so a package's references to its
  // dependencies can be rewritten alongside its references to itself.
  const mountOf = new Map(mounts.map(({ pkg, mount }) => [pkg.name, mount]));
  for (const { name, mount } of externalMounts(consumer, packages)) mountOf.set(name, mount);
  const expected = new Map();
  for (const { pkg, mount, hostFiles } of mounts) {
    if (pkg.files.length === 0) {
      die(`package "${pkg.name}" has no files under src/`);
    }
    // Two owners for one path is a contradiction, not a precedence question.
    // Resolving it silently — either way — would mean the manifest says one
    // thing and the tool does another.
    const isHostFile = hostFileMatcher(hostFiles);
    for (const relPath of pkg.files) {
      if (isHostFile(relPath)) {
        die(
          `${consumer.name} declares ${JSON.stringify(relPath)} as a hostFile of "${pkg.name}", but the package produces that file`,
        );
      }
    }
    for (const relPath of pkg.files) {
      const path = join(pkg.srcDir, relPath);
      // Rust is text (it is rewritten); anything else stays bytes, so a future
      // binary asset cannot be mangled by a UTF-8 round trip.
      const body = relPath.endsWith(RUST_EXT) ? readFileSync(path, "utf8") : readFileSync(path);
      const target = join(mountDir(consumer, mount), relPath);
      if (expected.has(target)) {
        die(
          `two packages both write ${relative(ROOT, target)}; mounts must not overlap`,
        );
      }
      expected.set(
        target,
        consumer.cliProject
          ? standaloneFile(pkg, relPath)
          : renderVendored(pkg, mount, relPath, body, packages, mountOf),
      );
    }
  }
  return { mounts, expected };
}

const GATE_RUNNER_MANIFEST = null;

/**
 * Each form a package reaches an application in, as path -> contents under the
 * application's `src/`: `vendored` is what `sync` writes into a consumer
 * (the whole source, `#[cfg(test)]` code included); `added` is what `ferrite
 * add` and the platform MCP's package corpus deliver (inline `#[cfg(test)]`
 * modules stripped). The package is mounted at its own root, its dependencies
 * at theirs.
 */
function gateForms(pkg, packages) {
  const mountOf = new Map([[pkg.name, pkg.root]]);
  for (const dep of Object.keys(pkg.dependencies ?? {})) {
    const depPkg = packages.get(dep);
    if (depPkg) mountOf.set(dep, depPkg.root);
  }
  const vendored = new Map();
  const added = new Map();
  for (const relPath of pkg.files) {
    const path = join(pkg.srcDir, relPath);
    const body = relPath.endsWith(RUST_EXT) ? readFileSync(path, "utf8") : readFileSync(path);
    vendored.set(relPath, renderVendored(pkg, pkg.root, relPath, body, packages, mountOf));
    added.set(relPath, standaloneFile(pkg, relPath));
  }
  return { vendored, added };
}

/**
 * The smallest constrained application that carries one package: the one
 * dependency the gate admits, a crate root that forbids unsafe code and
 * declares the package's module, and the package's files at its mount. Any
 * refusal of this crate is the package's.
 */
function writeGateCrate(dir, pkg, files) {
  const crate = `pkg-${pkg.name}`;
  mkdirSync(join(dir, "src", pkg.root), { recursive: true });
  // The gate sees what a consumer receives: the package's crate-root lines in
  // src/lib.rs and its cargo features in Cargo.toml, as `ferrite add` wires them.
  const crateRoot = Array.isArray(pkg.crateRoot) ? pkg.crateRoot : [];
  for (const line of crateRoot) {
    if (typeof line !== "string" || /[\u0000-\u0008\u000a-\u001f\u007f]/.test(line)) die(`packages/${pkg.name}: crateRoot lines must be single printable lines`);
  }
  const features = pkg.cargoFeatures && typeof pkg.cargoFeatures === "object" ? pkg.cargoFeatures : {};
  const featureLines = Object.entries(features).map(([name, deps]) => {
    if (!/^[A-Za-z0-9_][A-Za-z0-9_-]*$/.test(name) || !Array.isArray(deps) || deps.some((d) => typeof d !== "string" || !/^[A-Za-z0-9_][A-Za-z0-9_\/:-]*$/.test(d))) {
      die(`packages/${pkg.name}: cargoFeatures must map feature names to lists of feature names`);
    }
    return `${name} = [${deps.map((d) => JSON.stringify(d)).join(", ")}]`;
  });
  writeFileSync(
    join(dir, "Cargo.toml"),
    `[package]\nname = "${crate}"\nversion = "0.1.0"\nedition = "2021"\n\n` +
      `[dependencies]\nferrite-app = { path = "../ferrite-app" }\n` +
      (featureLines.length ? `\n[features]\n${featureLines.join("\n")}\n` : ""),
  );
  writeFileSync(
    join(dir, "src", "lib.rs"),
    `#![forbid(unsafe_code)]\n\n${crateRoot.map((line) => `${line}\n`).join("")}pub mod ${pkg.root};\n`,
  );
  for (const [relPath, contents] of files) {
    const target = join(dir, "src", pkg.root, relPath);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, contents);
  }
}

/**
 * `gate [--runner <binary>] [package...]`: run the platform's own code gate
 * (the platform admission implementation) over every
 * package in each form an application receives it, and refuse any package
 * that would make a consuming application fail admission. Without --runner
 * the runner is built with cargo first when its source is included.
 * Otherwise an explicit runner is required; admission is never skipped.
 */
function cmdGate(args) {
  let runner = process.env.FERRITE_PKG_GATE_RUNNER || null;
  const names = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--runner") {
      runner = args[++i];
      if (!runner) die("--runner needs the path of a built code-gate-runner");
    } else names.push(args[i]);
  }
  const packages = loadPackages();
  for (const name of names) if (!packages.has(name)) die(`no package "${name}" under packages/`);
  const selected = [...packages.values()]
    .filter((pkg) => names.length === 0 || names.includes(pkg.name))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (!runner) {
    if (!GATE_RUNNER_MANIFEST || !existsSync(GATE_RUNNER_MANIFEST)) {
      die("gate requires --runner <binary> (or FERRITE_PKG_GATE_RUNNER): runner source is not included");
    }
    const build = spawnSync(
      "cargo",
      ["build", "--release", "--locked", "--quiet", "--manifest-path", GATE_RUNNER_MANIFEST],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    if (build.status !== 0) die(`building the code gate runner failed (exit ${build.status})`);
    runner = join(dirname(GATE_RUNNER_MANIFEST), "target", "release", "code-gate-runner");
  }

  const work = mkdtempSync(join(tmpdir(), "ferrite-pkg-gate-"));
  try {
    const dirs = [];
    const owner = new Map();
    for (const pkg of selected) {
      if (pkg.files.length === 0) die(`package "${pkg.name}" has no files under src/`);
      const forms = gateForms(pkg, packages);
      for (const form of ["vendored", "added"]) {
        // The runner names a crate by its directory: <form>~<package>.
        const dir = join(work, `${form}~${pkg.name}`);
        writeGateCrate(dir, pkg, forms[form]);
        dirs.push(dir);
        owner.set(`${form}~${pkg.name}`, { pkg, form });
      }
    }
    const run = spawnSync(runner, dirs, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (run.error) die(`could not run ${runner}: ${run.error.message}`);
    // The runner prints `ADMITTED <crate>` or `REFUSED <crate> (n violations)`
    // followed by one indented `<CODE>  <detail>` line per violation.
    const refused = new Map();
    let current = null;
    let admitted = 0;
    for (const line of run.stdout.split("\n")) {
      const head = /^(ADMITTED|REFUSED|ERROR)\s+(\S+)(.*)$/.exec(line);
      if (head) {
        current = owner.get(head[2]) ? head[2] : null;
        if (head[1] === "ADMITTED") admitted += 1;
        else if (current) refused.set(current, head[1] === "ERROR" ? [head[3].trim()] : []);
        continue;
      }
      const violation = /^\s{4}(\S+)\s+(.*)$/.exec(line);
      if (violation && current && refused.has(current)) {
        refused.get(current).push(`${violation[1]}  ${violation[2].replace(/^src\//, "")}`);
      }
    }
    if (admitted + refused.size !== dirs.length) {
      process.stderr.write(run.stdout + run.stderr);
      die(`the runner judged ${admitted + refused.size} of ${dirs.length} crates (exit ${run.status})`);
    }
    // Every package can be installed with `ferrite add` (the registry) or sent
    // from the MCP corpus, so its `added` form must always pass. The `vendored`
    // form reaches the platform only through a deployable consumer (one
    // with a ferrite.json) that `sync` writes the full source into; a refusal
    // there is a broken deploy, and elsewhere a note.
    const vendoredBy = new Map();
    for (const consumer of loadConsumers().values()) {
      if (consumer.cliProject || !existsSync(join(consumer.dir, "ferrite.json"))) continue;
      for (const { pkg } of resolveMounts(consumer, packages)) {
        if (!vendoredBy.has(pkg.name)) vendoredBy.set(pkg.name, []);
        vendoredBy.get(pkg.name).push(consumer.name);
      }
    }
    const byPackage = new Map();
    const notes = [];
    for (const [key, violations] of refused) {
      const { pkg, form } = owner.get(key);
      if (form === "vendored" && !vendoredBy.has(pkg.name)) {
        notes.push({ pkg, violations });
        continue;
      }
      if (!byPackage.has(pkg.name)) byPackage.set(pkg.name, []);
      byPackage.get(pkg.name).push({ form, violations });
    }
    for (const [name, forms] of byPackage) {
      console.log(`REFUSED ${name}: an application that carries it fails the platform's code gate`);
      for (const { form, violations } of forms) {
        const how =
          form === "vendored"
            ? `as \`sync\` vendors it into ${vendoredBy.get(name).sort().join(", ")}`
            : "as `ferrite add` and the MCP corpus deliver it";
        console.log(`  ${how}:`);
        for (const v of violations) console.log(`    ${v}`);
      }
    }
    for (const { pkg, violations } of notes) {
      console.log(
        `note: ${pkg.name} in full (as \`sync\` vendors it) would be refused; no deployable consumer vendors it that way yet:`,
      );
      for (const v of violations) console.log(`    ${v}`);
    }
    console.log(
      `ferrite-pkg gate: ${selected.length - byPackage.size} of ${selected.length} package(s) admitted ` +
        `by the platform's code gate (${readGateRevision()})`,
    );
    return byPackage.size === 0 ? 0 : 1;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function readGateRevision() {
  if (!GATE_RUNNER_MANIFEST) return "Core revision unrecorded";
  const record = join(dirname(GATE_RUNNER_MANIFEST), "CORE_GATE_REVISION");
  const match = existsSync(record) && /^revision ([0-9a-f]{40})$/m.exec(readFileSync(record, "utf8"));
  return match ? `Core ${match[1].slice(0, 7)}` : "Core revision unrecorded";
}

function cmdList() {
  const packages = loadPackages();
  const consumers = loadConsumers();
  if (packages.size === 0) {
    console.log("no packages under packages/");
    return 0;
  }
  const usedBy = new Map();
  for (const consumer of consumers.values()) {
    for (const { pkg, mount } of resolveMounts(consumer, packages)) {
      if (!usedBy.has(pkg.name)) usedBy.set(pkg.name, []);
      usedBy.get(pkg.name).push(`${consumer.name}:${mount}`);
    }
  }
  console.log("PACKAGES\n");
  for (const pkg of [...packages.values()].sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const rs = pkg.files.filter((f) => f.endsWith(RUST_EXT));
    const loc = rs.reduce(
      (n, f) => n + readFileSync(join(pkg.srcDir, f), "utf8").split("\n").length,
      0,
    );
    const assets = pkg.files.length - rs.length;
    console.log(`  ${pkg.name}  v${pkg.version}`);
    console.log(`    ${pkg.summary ?? ""}`);
    console.log(
      `    root=${pkg.root}  rust=${rs.length} (${loc} lines)` +
        (assets > 0 ? `  assets=${assets}` : ""),
    );
    const deps = Object.keys(pkg.dependencies ?? {});
    if (deps.length) console.log(`    packages: ${deps.join(", ")}`);
    if ((pkg.hostImports ?? []).length) {
      console.log(`    host must provide: ${pkg.hostImports.join(", ")}`);
    }
    console.log(`    consumed by: ${(usedBy.get(pkg.name) ?? ["(nobody)"]).join(", ")}`);
    console.log();
  }
  return 0;
}

function cmdGraph() {
  const packages = loadPackages();
  const consumers = loadConsumers();
  console.log("COMPOSITION GRAPH\n");
  for (const consumer of [...consumers.values()].sort((a, b) => (a.name < b.name ? -1 : 1))) {
    console.log(`  ${consumer.name}`);
    for (const { pkg, mount, hostFiles } of resolveMounts(consumer, packages)) {
      const host = (pkg.hostImports ?? []).length
        ? `   [needs crate::${pkg.hostImports.join(", crate::")}]`
        : "";
      console.log(`    └─ ${pkg.name} → src/${mount}/${host}`);
      if (hostFiles.length) {
        console.log(`         app supplies inside the mount: ${hostFiles.join(", ")}`);
      }
    }
    console.log();
  }
  return 0;
}

function selectConsumers(names) {
  const consumers = loadConsumers();
  if (names.length === 0) return [...consumers.values()];
  // Naming a CLI project names its nested install directories too: they are
  // consumers of their own (`<app>/src/<anchor>`), and the project's own
  // check deliberately leaves their subtrees to them. Selecting the project
  // alone would report success having looked at none of its installed
  // files. A consumer named twice, or named beside its parent, is taken once.
  // Descendants are the installs inside the named consumer's own `src/`
  // (where `loadConsumers` found them), not every name that shares its
  // prefix: `app/src` and `app/src/library` can be siblings.
  const selected = new Map();
  for (const n of names) {
    const c = consumers.get(n);
    if (!c) die(`${n} has no ${CONSUMER_MANIFEST}`);
    selected.set(c.name, c);
    const ownSrc = join(c.dir, "src");
    for (const other of consumers.values()) {
      if (!other.name.startsWith(`${c.name}/`)) continue;
      if (other.dir === ownSrc || other.dir.startsWith(ownSrc + sep)) selected.set(other.name, other);
    }
  }
  return [...selected.values()];
}

/**
 * `sync [--package <name>]... [consumer...]`.
 *
 * Without `--package`, every selected consumer is rewritten from the working
 * tree: every mount, every lockfile entry. In a shared checkout that also
 * carries another session's uncommitted edits to OTHER packages into every
 * consumer (15 November 2026: a ferrite-sso sync wrote a parallel session's
 * Alloy edits into 39 consumers). `--package` confines the write to the named
 * packages: only their mounts are written or pruned, only their lockfile
 * entries are recomputed (every other entry is kept byte for byte), and only
 * their registry entries are refreshed. The consumers are the ones that mount
 * a named package, narrowed to the named consumers when any are given.
 *
 * Either form refreshes `packages/registry.json` when the workspace has one,
 * so a sync can no longer leave the index stale. A CLI project that mounts a
 * synced package and now differs is not written (its tree belongs to
 * `ferrite add`); sync prints the exact command for it and exits 1, so the
 * leftover cannot pass unnoticed.
 */
function parseSyncArgs(args) {
  const only = [];
  const names = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--package") {
      const name = args[i + 1];
      if (!name || name.startsWith("--")) die("sync --package needs a package name");
      only.push(name);
      i += 1;
    } else if (args[i].startsWith("--package=")) {
      only.push(args[i].slice("--package=".length));
    } else if (args[i].startsWith("--")) {
      die(`sync: unknown option ${args[i]}`);
    } else {
      names.push(args[i]);
    }
  }
  return { only: only.length ? new Set(only) : null, names };
}

function cmdSync(args) {
  const { only, names } = parseSyncArgs(args);
  const packages = loadPackages();
  if (only) {
    for (const name of only) if (!packages.has(name)) die(`sync --package ${name}: no such package under packages/`);
  }
  let wrote = 0;
  const cliLeftovers = [];
  let consumers = selectConsumers(names);
  if (only) {
    consumers = consumers.filter((consumer) =>
      resolveMounts(consumer, packages).some(({ pkg }) => only.has(pkg.name)),
    );
  }
  if (only) {
    // Refuse before writing anything: a scoped sync keeps every other lockfile
    // entry, so it needs the ledger the last full sync wrote.
    for (const consumer of consumers) {
      if (!consumer.cliProject && !existsSync(join(consumer.dir, LOCKFILE))) {
        die(
          `${relative(ROOT, consumer.dir)} has no ${LOCKFILE}, so a scoped sync cannot keep its other entries; ` +
            `run: node tools/ferrite-pkg/ferrite-pkg.mjs sync ${consumer.name}`,
        );
      }
    }
  }
  for (const consumer of consumers) {
    // A CLI project's tree belongs to the developer's `ferrite add`. Writing
    // the in-repo form over it would add the test modules that command
    // strips and a lockfile it never reads.
    if (consumer.cliProject) {
      const { mounts, expected } = expectedTrees(consumer, packages);
      let current = true;
      for (const { pkg, mount } of mounts) {
        if (only && !only.has(pkg.name)) continue;
        const dir = mountDir(consumer, mount);
        const differs = [...expected].some(([target, contents]) =>
          target.startsWith(dir + sep) && !alreadyHolds(target, contents));
        if (!differs) continue;
        current = false;
        cliLeftovers.push(
          `  ! ${relative(ROOT, consumer.dir)}: a CLI project whose ${pkg.name} differs; in that directory run: ` +
            `ferrite add ${pkg.name} --path ${relative(consumer.dir, ROOT) || "."} --force`,
        );
      }
      if (current) console.log(`  = ${relative(ROOT, consumer.dir)}: a CLI project, left as \`ferrite add\` wrote it`);
      continue;
    }
    const all = expectedTrees(consumer, packages);
    const mounts = only ? all.mounts.filter(({ pkg }) => only.has(pkg.name)) : all.mounts;
    const mounted = new Set(mounts.map(({ mount }) => mountDir(consumer, mount)));
    const expected = only
      ? new Map([...all.expected].filter(([target]) => [...mounted].some((dir) => target.startsWith(dir + sep))))
      : all.expected;
    let kept;
    // Undeclared-mount pruning reads and rewrites the whole ledger; it is a
    // full sync's job, and a scoped sync must not touch other packages.
    if (!only) {
      // A mount whose package was UNdeclared since the last sync is invisible
      // to the loops below — no mount entry, no expected files — so it is
      // reconciled first, from the previous lockfile, before that lockfile is
      // rewritten without it.
      const pruned = pruneOrphanedMounts(consumer, mounts, packages);
      wrote += pruned.removed;
      kept = pruned.kept;
    }
    // Remove stale files INSIDE the mounts being synced, so a file deleted
    // from a package does not survive forever in every copy of it.
    // `mountDir` has already proven the directory is beneath <consumer>/src,
    // which is the check that makes this delete safe to perform at all.
    for (const full of strayMountFiles(consumer, mounts, expected)) {
      safeUnlink(srcDirOf(consumer), full);
      console.log(`  - ${relative(ROOT, full)}`);
      wrote += 1;
    }
    for (const [target, contents] of expected) {
      if (alreadyHolds(target, contents)) continue;
      const existed = existsSync(target);
      safeWrite(srcDirOf(consumer), target, contents);
      console.log(`  ${existed ? "~" : "+"} ${relative(ROOT, target)}`);
      wrote += 1;
    }
    if (only) writeScopedLock(consumer, all.mounts, all.expected, only);
    else writeLock(consumer, mounts, expected, kept);
  }
  console.log(wrote === 0 ? "already in sync" : `synced ${wrote} file(s)`);
  if (existsSync(join(PACKAGES_DIR, REGISTRY_FILE))) cmdRegistry(only, packages);
  if (cliLeftovers.length) {
    for (const line of cliLeftovers) console.log(line);
    console.log(`${cliLeftovers.length} CLI project mount(s) still differ; run the command(s) above, then check`);
    return 1;
  }
  return 0;
}

/**
 * Rewrite only the named packages' entries of a consumer's lockfile, keeping
 * every other entry (and the orphan ledger) exactly as the last sync wrote it.
 * Entries stay in mount order, so a scoped sync of an unchanged tree writes
 * the same bytes a full sync would.
 */
function writeScopedLock(consumer, mounts, expected, only) {
  const path = join(consumer.dir, LOCKFILE);
  const previous = readJson(path);
  const lock = { note: "generated by ferrite-pkg; do not edit", packages: {} };
  for (const { pkg, mount } of mounts) {
    if (only.has(pkg.name)) {
      const files = {};
      for (const relPath of pkg.files) files[relPath] = sha256(expected.get(join(mountDir(consumer, mount), relPath)));
      lock.packages[pkg.name] = { version: pkg.version, mount, files };
    } else if (previous.packages && Object.hasOwn(previous.packages, pkg.name)) {
      lock.packages[pkg.name] = previous.packages[pkg.name];
    }
  }
  if (Array.isArray(previous.orphans) && previous.orphans.length > 0) lock.orphans = previous.orphans;
  safeWrite(consumer.dir, path, `${JSON.stringify(lock, null, 2)}\n`);
}

function writeLock(consumer, mounts, expected, orphans = []) {
  const lock = { note: "generated by ferrite-pkg; do not edit", packages: {} };
  for (const { pkg, mount } of mounts) {
    const files = {};
    for (const relPath of pkg.files) {
      const target = join(mountDir(consumer, mount), relPath);
      files[relPath] = sha256(expected.get(target));
    }
    lock.packages[pkg.name] = { version: pkg.version, mount, files };
  }
  // Mounts the tool once wrote but could not prune (a file there no longer
  // matches the ledger). Their ledger is kept, so `check` keeps reporting the
  // directory — an asset-only tree has no provenance header to find it by —
  // and a later sync can still prune it once it matches again.
  if (orphans.length > 0) lock.orphans = orphans;
  // The lock sits BESIDE src/, not beneath it, so the consumer directory is the
  // base here — but it goes through the same guard, because a lockfile replaced
  // by a symlink is exactly as redirectable as a source file.
  safeWrite(
    consumer.dir,
    join(consumer.dir, LOCKFILE),
    `${JSON.stringify(lock, null, 2)}\n`,
  );
}

/**
 * Remove a mount whose package was undeclared — or re-mounted elsewhere —
 * since the last sync.
 *
 * The manifest no longer names this directory, so `resolveMounts` cannot see
 * it — the only record that this tool ever owned it is the PREVIOUS lockfile,
 * which is what a content ledger is for. The deletion rule is strict: every
 * file in the directory must hash-match what the ledger says this tool wrote.
 * One byte of deviation — a hand edit, an undeclared file, a hostFile the app
 * still owns — and NOTHING is deleted; the directory is left standing for
 * `check` to flag, because a prune that guesses is a prune that eats
 * somebody's work.
 */
function pruneOrphanedMounts(consumer, mounts, packages) {
  const lockPath = join(consumer.dir, LOCKFILE);
  if (!existsSync(lockPath)) return { removed: 0, kept: [] };
  const lock = readJson(lockPath);
  // Live ledger entries, then orphans an earlier sync could not prune.
  const candidates = [
    ...Object.entries(lock.packages ?? {}),
    ...(Array.isArray(lock.orphans) ? lock.orphans : []).map((o) => [o?.package, o]),
  ];
  const liveMountOf = new Map(mounts.map(({ pkg, mount }) => [pkg.name, mount]));
  const liveMounts = new Set(mounts.map(({ mount }) => mount));
  for (const { mount } of externalMounts(consumer, packages)) liveMounts.add(mount);
  let removed = 0;
  const kept = [];
  const considered = new Set();
  for (const [name, entry] of candidates) {
    if (typeof name !== "string") continue;
    // Ownership is decided by directory, not by package name: a package
    // re-declared as another tool's at a DIFFERENT mount still leaves this
    // one orphaned. A mount another tool owns now is in `liveMounts` below.
    const mount = entry?.mount;
    if (considered.has(`${name}\u0000${mount}`)) continue;
    considered.add(`${name}\u0000${mount}`);
    // Still mounted where the ledger says: nothing is orphaned. A package that
    // is still declared but MOVED leaves its old directory exactly as orphaned
    // as a package that was removed, so only the (name, mount) pair skips.
    if (mount !== undefined && liveMountOf.get(name) === mount) continue;
    // The recorded mount is about to feed a delete, so it is held to the same
    // shape a declared mount is. But an entry that fails is SKIPPED, not a
    // refusal: sync rewrites this very ledger below, and anything the bad
    // entry was covering is caught by check's marker scan — dying here would
    // wedge sync on a file sync itself owns.
    if (!isModuleIdent(mount)) {
      console.log(
        `  ! ${relative(ROOT, lockPath)}: entry for "${name}" does not name a valid mount; nothing pruned for it`,
      );
      continue;
    }
    // A currently-declared package owns that directory now; its own sync pass
    // writes and prunes it.
    if (liveMounts.has(mount)) continue;
    const dir = mountDir(consumer, mount);
    if (!existsSync(dir)) continue;
    const files = treeFiles(dir); // refuses symlinks: deletes follow this walk
    const ledger = entry.files ?? {};
    const leftovers = files.filter(
      (relPath) =>
        ledger[relPath] === undefined ||
        sha256(readFileSync(join(dir, relPath))) !== ledger[relPath],
    );
    if (leftovers.length > 0) {
      console.log(
        `  ! src/${mount}: "${name}" is no longer declared by ${consumer.name}, but ` +
          `${leftovers.length} file(s) there do not match its lock ledger (e.g. ` +
          `${leftovers[0]}) — leaving the directory; delete it by hand or re-declare the package`,
      );
      kept.push({ package: name, version: entry.version, mount, files: ledger });
      continue;
    }
    for (const relPath of files) {
      const full = join(dir, relPath);
      safeUnlink(srcDirOf(consumer), full);
      console.log(`  - ${relative(ROOT, full)}`);
      removed += 1;
    }
    // Only empty directories can remain: the walk above refused symlinks and
    // every file it found is gone. `rmdirSync` refuses anything non-empty, so
    // this sweep cannot take content the ledger did not prove.
    const sweep = (d) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        if (e.isDirectory()) sweep(join(d, e.name));
      }
      rmdirSync(d);
    };
    sweep(dir);
    console.log(`  - ${relative(ROOT, dir)}/ (unmounted "${name}")`);
  }
  return { removed, kept };
}


/**
 * Whether `text` looks like a copy of `packageText`.
 *
 * A HAND copy carries no provenance header, so the marker scan above cannot
 * see it — which is how thirty-seven applications came to hold their own
 * `src/ferrite_sso/` tree, byte-identical to each other, an entire release
 * behind the package, with nothing in the repository able to say so.
 *
 * Byte-equality is too strict to be the test: a copy that never drifted is
 * the harmless case, and the ones worth catching have. Similarity of the
 * non-trivial lines is the signal. The threshold is deliberately high, so a
 * file that merely shares a name with a package file — `buzz/src/crypto/`
 * holds curve code beside the package's digest, and must not be flagged —
 * stays clean.
 */
function looksLikeCopyOf(text, packageText) {
  const meaningful = (body) =>
    new Set(
      body
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 12 && !line.startsWith("//")),
    );
  const mine = meaningful(text);
  const theirs = meaningful(packageText);
  if (theirs.size < 8) return false;
  let shared = 0;
  for (const line of mine) if (theirs.has(line)) shared += 1;
  return shared / theirs.size >= 0.6;
}

/** Files inside `mounts` that no package produces and no host file claims. */
function* strayMountFiles(consumer, mounts, expected) {
  for (const { mount, hostFiles } of mounts) {
    const dir = mountDir(consumer, mount);
    if (!existsSync(dir)) continue;
    const isHostFile = hostFileMatcher(hostFiles);
    for (const relPath of treeFiles(dir)) {
      const full = join(dir, relPath);
      if (!expected.has(full) && !isHostFile(relPath)) yield full;
    }
  }
}

function checkUndeclaredCopies(consumer, mounts, packages, problems, forks) {
  // A vendored tree whose package was UNdeclared is invisible to everything
  // above: no mount, no expected files, and after a sync the rewritten lock
  // no longer records it either. The provenance header every composed `.rs`
  // carries is the one durable trace, so the whole src tree is scanned for
  // it — outside the live mounts, whose contents the loops above already own.
  const srcDir = srcDirOf(consumer);
  const mountRoots = mounts.map(({ mount }) => mountDir(consumer, mount) + sep);
  // A nested install directory of a CLI project is a consumer of its own
  // ([`loadConsumers`]); its files are judged there, not as strays here.
  // An install at `src/` itself owns only its own `src/` tree; the rest of
  // this project's `src/` is still scanned here.
  if (consumer.cliProject) {
    mountRoots.push(
      ...nestedInstallDirs(srcDir).map((dir) => (dir === srcDir ? join(dir, "src") : dir) + sep),
    );
  }
  // A directory another tool manages is that tool's to judge: it is not
  // even walked. Its path is computed, not passed through `mountDir`: that
  // guard is for directories this tool writes, and a symlinked external
  // install is the other tool's business.
  const externalDirs = externalMounts(consumer, packages).map(({ mount }) => join(srcDir, mount));
  for (const relPath of scanTreeFiles(srcDir, externalDirs)) {
    const full = join(srcDir, relPath);
    if (mountRoots.some((root) => full.startsWith(root))) continue;
    if (!hasGeneratedMarker(full)) continue;
    problems.push(
      `${relative(ROOT, full)}: carries "${GENERATED_MARKER}" but no package declared by ` +
        `${consumer.name} produces it — delete it, or re-declare its package in ` +
        `${consumer.name}/${CONSUMER_MANIFEST} and run sync`,
    );
  }
  // The other half of the same blind spot: a HAND copy of a package,
  // carrying no provenance header at all. The marker scan above cannot see
  // one, and neither can anything else — the copy simply rots.
  for (const relPath of scanTreeFiles(srcDir, externalDirs)) {
    const full = join(srcDir, relPath);
    if (mountRoots.some((root) => full.startsWith(root))) continue;
    if (!relPath.endsWith(".rs")) continue;
    if (hasGeneratedMarker(full)) continue; // reported above
    // scanTreeFiles returns "/"-separated paths on every platform, and a copy may come
    // from any depth of a package, not only its top-level src/.
    const base = relPath.split("/").pop();
    let body;
    let copied = false;
    for (const pkg of packages.values()) {
      if (copied) break;
      for (const pkgRel of pkg.files.filter((f) => f.endsWith(".rs") && f.split("/").pop() === base)) {
        const candidate = join(pkg.srcDir, pkgRel);
        if (!existsSync(candidate)) continue;
        body ??= readFileSync(full, "utf8");
        if (!looksLikeCopyOf(body, readFileSync(candidate, "utf8"))) continue;
        copied = true;
        // A consumer may DECLARE a fork it has not reconciled. That is not
        // the same as an unnoticed copy: it names the file, the package, and
        // why, so the divergence is a decision on the record rather than
        // something nobody knows about. `qjs-engine` was extracted FROM two
        // of these apps and both sides moved on; merging 1600 lines of
        // divergence in a deployed app is engineering, not tidying.
        // Keyed from the CONSUMER's root (`src/wasi.rs`), which is the path
        // a person writing the manifest would name, not the src-relative one
        // this loop happens to iterate.
        const forkKey = relative(consumer.dir, full).split(sep).join("/");
        const declaredFork = (consumer.forks ?? {})[forkKey];
        if (declaredFork) {
          forks.push(
            `${relative(ROOT, full)}: declared fork of packages/${pkg.name} — ${declaredFork}`,
          );
          break;
        }
        problems.push(
          `${relative(ROOT, full)}: a hand copy of packages/${pkg.name}/src/${pkgRel} that no ` +
            `manifest declares, so nothing keeps it in step — declare "${pkg.name}" in ` +
            `${consumer.name}/${CONSUMER_MANIFEST}, delete the copy, and run sync. ` +
            `If the divergence is deliberate, record it under "forks" with the reason.`,
        );
        break;
      }
    }
  }
}

function reportCheck(checked, forks, problems) {
  // Declared forks are printed whether or not anything failed. A divergence
  // that is never mentioned again becomes permanent by silence, and the
  // point of declaring one is that it stays visible.
  if (forks.length > 0) {
    console.log(`ferrite-pkg check: ${forks.length} declared fork(s):`);
    for (const f of forks) console.log(`  ${f}`);
    console.log("");
  }
  if (problems.length === 0) {
    console.log(`ferrite-pkg check: ${checked} vendored file(s) match their packages`);
    return 0;
  }
  console.error(`ferrite-pkg check: ${problems.length} problem(s)\n`);
  for (const p of problems) console.error(`  ${p}`);
  console.error(
    `\nEdit the package under packages/, never the vendored copy, then run:\n` +
      `  node tools/ferrite-pkg/ferrite-pkg.mjs sync\n`,
  );
  return 1;
}

function cmdCheck(names) {
  const packages = loadPackages();
  const problems = [];
  // Divergences a consumer has declared. Not problems — but printed, so a
  // fork cannot quietly become permanent by never being mentioned again.
  const forks = [];
  let checked = 0;
  for (const consumer of selectConsumers(names)) {
    const { mounts, expected } = expectedTrees(consumer, packages);
    for (const [target, contents] of expected) {
      checked += 1;
      const rel = relative(ROOT, target);
      if (!existsSync(target)) {
        problems.push(`${rel}: missing — run sync`);
        continue;
      }
      if (!alreadyHolds(target, contents)) {
        problems.push(
          consumer.cliProject
            ? `${rel}: differs from what \`ferrite add\` writes for its package today — in ${relative(ROOT, consumer.dir)} run: ferrite add <package> --path ${relative(consumer.dir, ROOT) || "."} --force`
            : `${rel}: DRIFTED from its package source`,
        );
      }
    }
    // A file inside a mount that no package produces is drift in the other
    // direction: something was added to the copy instead of to the package.
    for (const full of strayMountFiles(consumer, mounts, expected)) {
      problems.push(`${relative(ROOT, full)}: not produced by any package`);
    }
    checkUndeclaredCopies(consumer, mounts, packages, problems, forks);
    // `ferrite add` keeps no lockfile; the tree comparison above is the
    // whole claim for a CLI project.
    if (!consumer.cliProject) {
      problems.push(...checkLock(consumer, mounts, expected));
      problems.push(...checkOrphans(consumer, mounts, packages));
    }
  }
  // A package publishes the cargo features its source reads.
  problems.push(...checkPackageFeatures(packages));
  // The registry is generated state exactly as a vendored copy is: where one
  // has been written, it must match what the manifests say NOW. A workspace
  // that has not adopted a registry (the scratch trees the test suite builds)
  // simply has no file to defend — `registry` is what creates the claim.
  const registryPath = join(PACKAGES_DIR, REGISTRY_FILE);
  if (existsSync(registryPath)) {
    checked += 1;
    if (!alreadyHolds(registryPath, renderRegistry(packages))) {
      problems.push(
        `packages/${REGISTRY_FILE}: stale — run: node tools/ferrite-pkg/ferrite-pkg.mjs registry`,
      );
    }
  }
  return reportCheck(checked, forks, problems);
}

/**
 * Verify the lockfile actually describes what is on disk.
 *
 * Without this the lock is decorative: it is written by `sync` and, if nothing
 * ever reads it, a deleted or hand-edited lock passes review while claiming to
 * be a content ledger. A ledger nobody audits is worse than no ledger, because
 * it is cited as evidence.
 *
 * The hashes are recomputed from the EXPECTED content rather than from the
 * files on disk, so this is an independent statement: the tree check above says
 * "disk matches package", and this says "the lock records that same package set,
 * at these versions and mounts, with these hashes".
 */
/**
 * A mount sync could not prune stays recorded under the lock's `orphans`
 * until its directory is gone or a declared package owns it again; until
 * then it is a problem, whatever its files are (assets carry no header).
 */
function checkOrphans(consumer, mounts, packages) {
  const lockPath = join(consumer.dir, LOCKFILE);
  if (!existsSync(lockPath)) return [];
  const orphans = readJson(lockPath).orphans;
  if (!Array.isArray(orphans)) return [];
  // A mount a declared package owns now — this tool's or another tool's —
  // is no longer an orphan, whatever the ledger still says.
  const liveMounts = new Set(mounts.map(({ mount }) => mount));
  for (const { mount } of externalMounts(consumer, packages)) liveMounts.add(mount);
  const problems = [];
  for (const o of orphans) {
    if (!isModuleIdent(o?.mount) || liveMounts.has(o.mount)) continue;
    const dir = mountDir(consumer, o.mount);
    if (!existsSync(dir)) continue;
    problems.push(
      `${relative(ROOT, dir)}/: left behind when "${o.package}" was undeclared; files there no longer match ` +
        `what sync wrote, so it was not pruned — delete it by hand (then run sync), or re-declare the package`,
    );
  }
  return problems;
}

function checkLock(consumer, mounts, expected) {
  const problems = [];
  const lockPath = join(consumer.dir, LOCKFILE);
  const where = relative(ROOT, lockPath);
  if (!existsSync(lockPath)) {
    return [`${where}: missing — run sync`];
  }
  const lock = readJson(lockPath);
  const recorded = lock.packages ?? {};
  const live = new Set(mounts.map(({ pkg }) => pkg.name));
  for (const name of Object.keys(recorded)) {
    if (!live.has(name)) {
      problems.push(`${where}: records "${name}", which this app no longer mounts`);
    }
  }
  for (const { pkg, mount } of mounts) {
    const entry = recorded[pkg.name];
    if (!entry) {
      problems.push(`${where}: does not record "${pkg.name}"`);
      continue;
    }
    if (entry.version !== pkg.version) {
      problems.push(
        `${where}: records ${pkg.name} v${entry.version}, package is v${pkg.version}`,
      );
    }
    if (entry.mount !== mount) {
      problems.push(
        `${where}: records ${pkg.name} at "${entry.mount}", resolved mount is "${mount}"`,
      );
    }
    const recordedFiles = entry.files ?? {};
    for (const relPath of Object.keys(recordedFiles)) {
      if (!pkg.files.includes(relPath)) {
        problems.push(`${where}: records ${pkg.name}/${relPath}, which the package no longer has`);
      }
    }
    for (const relPath of pkg.files) {
      const want = sha256(expected.get(join(mountDir(consumer, mount), relPath)));
      const got = recordedFiles[relPath];
      if (!got) {
        problems.push(`${where}: does not record ${pkg.name}/${relPath}`);
      } else if (got !== want) {
        problems.push(`${where}: hash for ${pkg.name}/${relPath} is stale`);
      }
    }
  }
  return problems;
}

/**
 * Similarity of two texts as a multiset Jaccard over non-blank lines.
 *
 * Deliberately not a diff. This is candidate DISCOVERY — the question is "do
 * these two files share a body?", and a cheap order-insensitive measure answers
 * it without a diff implementation. Identical files score 1.
 *
 * Blank lines are dropped because they are the one line every source file has
 * in quantity, and counting them makes unrelated boilerplate look related.
 */
function similarity(a, b) {
  const count = (text) => {
    const m = new Map();
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (line === "") continue;
      m.set(line, (m.get(line) ?? 0) + 1);
    }
    return m;
  };
  const ca = count(a);
  const cb = count(b);
  let shared = 0;
  let total = 0;
  for (const key of new Set([...ca.keys(), ...cb.keys()])) {
    const x = ca.get(key) ?? 0;
    const y = cb.get(key) ?? 0;
    shared += Math.min(x, y);
    total += Math.max(x, y);
  }
  return total === 0 ? 1 : shared / total;
}

/** Every crate directory holding a `src/`, keyed by name. */
function crateDirs() {
  // The same places consumer discovery looks: the root and each category.
  const out = new Map();
  for (const category of CONSUMER_ROOTS) {
    const base = category ? join(ROOT, category) : ROOT;
    if (!existsSync(base) || isSymlink(base)) continue;
    for (const entry of readdirSync(base, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      if (!category && (entry.name === "target" || entry.name === "packages" || CONSUMER_ROOTS.includes(entry.name))) continue;
      const src = join(base, entry.name, "src");
      if (existsSync(src) && lstatSync(src).isDirectory()) {
        out.set(category ? `${category}/${entry.name}` : entry.name, src);
      }
    }
  }
  return out;
}

/**
 * Report cross-crate duplication a package could absorb.
 *
 * Every boundary decision in this workspace began here, and the obvious version
 * of this search is wrong in a specific way: grouping by FILENAME reports
 * `lib.rs` against `lib.rs` for every pair of crates, which share nothing but a
 * name. So candidates are grouped by path below `src/` and then ranked by how
 * much of their CONTENT they share, with anything below the threshold suppressed.
 *
 * Files the packages already produce are excluded. Files inside a mount that a
 * consumer claims via `hostFiles` are NOT excluded — they are genuinely still
 * duplicated, and hiding them to tidy this output would misreport the state.
 */
function cmdScan() {
  const THRESHOLD = 0.6;
  const packages = loadPackages();
  const consumers = loadConsumers();

  const managed = new Set();
  for (const consumer of consumers.values()) {
    for (const target of expectedTrees(consumer, packages).expected.keys()) {
      managed.add(target);
    }
  }

  // path below src/  ->  [{ crate, full }]
  const byRelPath = new Map();
  for (const [crate, src] of crateDirs()) {
    for (const rel of treeFiles(src)) {
      if (!rel.endsWith(RUST_EXT)) continue;
      const full = join(src, rel);
      if (managed.has(full)) continue;
      if (!byRelPath.has(rel)) byRelPath.set(rel, []);
      byRelPath.get(rel).push({ crate, full });
    }
  }

  const findings = [];
  for (const [rel, entries] of byRelPath) {
    if (entries.length < 2) continue;
    for (let i = 0; i < entries.length; i += 1) {
      for (let j = i + 1; j < entries.length; j += 1) {
        const a = entries[i];
        const b = entries[j];
        if (a.crate === b.crate) continue;
        const ta = readFileSync(a.full, "utf8");
        const tb = readFileSync(b.full, "utf8");
        const score = similarity(ta, tb);
        if (score < THRESHOLD) continue;
        findings.push({
          rel,
          a: a.crate,
          b: b.crate,
          score,
          identical: ta === tb,
          lines: Math.max(ta.split("\n").length, tb.split("\n").length),
        });
      }
    }
  }
  findings.sort((x, y) => y.score - x.score || (x.rel < y.rel ? -1 : 1));

  console.log("DUPLICATION CANDIDATES\n");
  if (findings.length === 0) {
    console.log("  none: no file outside a package is shared across crates.\n");
    return 0;
  }
  for (const f of findings) {
    console.log(
      `  ${(f.score * 100).toFixed(0).padStart(3)}%  ${f.identical ? "IDENTICAL" : "similar  "}  ` +
        `${f.rel}  (${f.a} ↔ ${f.b}, up to ${f.lines} lines)`,
    );
  }
  console.log(
    `\n  ${findings.length} candidate(s) at ≥${THRESHOLD * 100}% shared lines.\n` +
      `  Grouped by path below src/ and ranked by CONTENT, because a shared\n` +
      `  filename (every crate has a lib.rs) means nothing on its own.\n` +
      `  Before extracting one, read the source-packages guide (docs.ferrite.cloud), section 9: normalise the\n` +
      `  mount path first, then classify what still differs.\n`,
  );
  return 0;
}

function cmdStatus() {
  const packages = loadPackages();
  const consumers = loadConsumers();
  let mounts = 0;
  for (const consumer of consumers.values()) {
    mounts += resolveMounts(consumer, packages).length;
  }
  console.log(
    `${packages.size} package(s), ${consumers.size} consumer(s), ${mounts} mount(s)`,
  );
  return 0;
}

const [command, ...rest] = process.argv.slice(2);
// No prototype: `ferrite-pkg constructor` (or `toString`, `__proto__`) must be
// an unknown command, not a call into Object.prototype.
const table = Object.assign(Object.create(null), {
  list: () => cmdList(),
  graph: () => cmdGraph(),
  scan: () => cmdScan(),
  sync: () => cmdSync(rest),
  check: () => cmdCheck(rest),
  verify: () => {
    if (rest.length) die("verify checks all consumers and the MCP corpus; no selectors accepted");
    const registry = existsSync(join(PACKAGES_DIR, REGISTRY_FILE)) ? 0 : 1;
    if (registry) console.error("ferrite-pkg verify: packages/registry.json is missing; run registry");
    const consumers = cmdCheck([]);
    const corpus = cmdMcpPackages(["--check"]);
    return registry || consumers || corpus;
  },
  gate: () => cmdGate(rest),
  registry: () => cmdRegistry(),
  "mcp-packages": () => cmdMcpPackages(rest),
  status: () => cmdStatus(),
});
if (!command || !Object.hasOwn(table, command)) {
  console.error(
    "usage: ferrite-pkg <list|graph|scan|sync|check|verify|gate|registry|mcp-packages|status> [app...]\n" +
      "\n" +
      "  list      every package, its size, and who consumes it\n" +
      "  graph     the composition graph, with each package's host imports\n" +
      "  scan      cross-crate duplication a package could absorb\n" +
      "  sync [--package <name>]... [app...]  write vendored copies from packages/ (and prune stale\n" +
      "            files), then refresh packages/registry.json; --package writes only that package's\n" +
      "            files, lockfile entries and registry entry\n" +
      "  check     verify every vendored copy matches (registry included); exit 1 on drift\n" +
      "  verify    read-only check of all consumers, registry and MCP corpus together\n" +
      "  gate [--runner <bin>] [package...]  run the platform's code gate over every package as an app\n" +
      "            receives it (vendored by sync, delivered by ferrite add); exit 1 on a refusal\n" +
      "  registry  write packages/registry.json, the index `ferrite add` installs from\n" +
      "  mcp-packages [--check] [--package <name>]...  write/check mcp-packages.json; optionally preserve unselected entries\n" +
      "  status    one line, for a CI summary\n",
  );
  process.exit(2);
}
process.exit(table[command]());
