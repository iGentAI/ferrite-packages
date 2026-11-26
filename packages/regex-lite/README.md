# regex-lite

A small backtracking regular-expression engine for constrained Ferrite apps,
which do not have the `regex` crate on their dependency surface. Extracted from
`packages/browser-core` (its page-script regex engine) so agent tooling can
share it without carrying a browser.

## Syntax and JavaScript semantics

The engine implements the subset needed by agent tooling (grep, filters, and
validation): literals, `.`, escapes (`\d`, `\w`, `\s` and their negations,
`\b`), character classes with ranges and negation, capturing, named capturing
(`(?<name>...)`), and non-capturing groups, lookahead (`(?=...)`, `(?!...)`)
and lookbehind (`(?<=...)`, `(?<!...)`) assertions, numbered and named
backreferences (`\1`, `\k<name>`), alternation, anchors (`^` and `$`), and the
quantifiers `*`, `+`, `?`, and `{n,m}` in greedy and lazy forms.

Matching follows JavaScript rules:

- Searches return the first match in backtracking order, and captures inside a
  repeated group reset on each iteration.
- `.` stops at JavaScript line terminators (`\n`, `\r`, U+2028, U+2029).
- `\w` and `\b` are ASCII by default, `\s` matches JavaScript white space, and
  character-class escapes (`\x41`, `\b`, `\cJ`, `\012`) follow JavaScript
  behavior.

## Flags

Flags follow JavaScript behavior. Unknown flags, repeated flags, and `v` cause
`compile` to reject the pattern. Captures always slice the original input text
under every flag.

| Flag | Behavior |
| --- | --- |
| `m` | `^` and `$` match at line terminators as well as the start and end of the input |
| `s` | `.` matches line terminators |
| `y` | Anchors matching to the start of the input only (equivalent to JavaScript search from `lastIndex` 0) |
| `g`, `d` | Accepted; no effect on a single search |
| `u` | Enables `\u{...}` escapes, turns lenient escapes into errors, and switches `i` to Unicode simple case folding |
| `i` | Case-insensitive matching using JavaScript's flag-dependent folding rules (see below) |

Under `i` without `u`, two characters match when their uppercase forms match,
counting only uppercase mappings that produce one UTF-16 unit and do not map a
non-ASCII letter to an ASCII one. For example, `σ`, `ς`, and `Σ` match each
other, whereas `ſ` does not match `s`, the Kelvin sign does not match `k`, and
`ẞ` does not match `ß`. Under `i` with `u`, Unicode simple case folding applies
instead, so all of those pairs match, and `\w` and `\b` include `ſ` and the
Kelvin sign as word characters.

## Positions and differences from JavaScript

Match offsets (`Captures::start`, `Captures::end`, and the pair returned by
`find`) count `char`s (Unicode scalar values), not byte offsets and not
JavaScript UTF-16 indices. Those two counts agree only within the Basic
Multilingual Plane, because a character above U+FFFF is one `char` and two
UTF-16 units. No current consumer hands offsets to JavaScript; any consumer
that does must convert them, and slicing `&str` must go through `char_indices`.

Three differences from JavaScript remain:

1. Input is always read as Unicode code points regardless of flags, whereas
   JavaScript does so only under `u` (without `u`, JavaScript splits characters
   above U+FFFF into two units that `.` consumes one at a time and that have no
   case).
2. Positions count `char`s rather than UTF-16 units.
3. Unicode property escapes (`\p{...}`, `\P{...}`) and the `v` flag are
   refused.

## Design and execution limits

Unsupported syntax makes `compile` return `None` rather than panicking, so
callers can degrade to "no match" instead of failing a request.

Patterns compile to a small program executed on an explicit backtracking stack,
so long patterns and long lines never deepen the native call stack (parser
group nesting is capped at 64). A step budget that scales with input length and
a 32 MiB cap on the backtracking stack stop runaway searches before a
pathological pattern can hang a single-threaded app runtime or exhaust memory.

Everyday patterns stay linear in input length. Failed states are memoized
across start positions, preventing exponential backtracking on nested
repetition and avoiding repeated work across starts. A repeated character scans
its run once and skips endings already known to fail together. Patterns
anchored with `^` (without `m`) or marked `y` run only at index 0;
case-sensitive patterns requiring literal text reject lines lacking that
literal immediately; plain-text patterns use substring search. Patterns such as
`.*foo`, `\w+\s+foo`, and `^(a+)+$` finish in linear time on megabyte lines.

When a search hits a limit, the engine has no verdict. `try_is_match`,
`try_find`, and `try_find_captures` return `Err(SearchLimit)`. The plain
`is_match`, `find`, and `find_captures` methods treat a limit-terminated search
as no match, so use them only where a missed match is harmless.

The limits are still reachable in two cases:

- A repeated single character, or a repeated group whose alternatives are
  single characters whether captured or not (`(?:x|y)*`, `(x|y)*`, `([ab])+`),
  leaves a single backtrack point for the whole run, so `(x|y)*foo` completes
  on a 1 MB line. Any other repeated group, such as `(xy|z)*foo` or
  `(?:(x)|y)*foo`, leaves a backtrack point per iteration and fills the stack
  on lines of several hundred thousand characters.
- Repetition with a large upper bound is quadratic because the count is part of
  the memoized state: `(?:ab|cd){1,5000}ef` runs out of steps on a
  40,000-character line.

## Example

```rust
let re = regex_lite::compile(r"fn\s+(\w+)", "").unwrap();
let caps = re.find_captures("pub fn main() {}").unwrap();
assert_eq!(caps.groups[1].as_deref(), Some("main"));
match re.try_is_match(line) {
    Ok(found) => { /* a real answer */ }
    Err(limit) => { /* report `limit`: this line was not searched */ }
}
```

## Status

Active zero-dependency source package compiled into constrained Ferrite apps (mounted directly or transitively through `agent-sdk`). It is not independently deployable.

## Validation

This directory includes a standalone test harness (`Cargo.toml` and `harness/lib.rs`, ignored by `ferrite-pkg` and `ferrite add`) that runs the unit tests and 256 KiB small-stack thread checks:

```bash
cargo test --manifest-path packages/regex-lite/Cargo.toml
node tools/ferrite-pkg/ferrite-pkg.mjs check
```
