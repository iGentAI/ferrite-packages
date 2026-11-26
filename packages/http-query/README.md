# http-query

A total query-string decoder for constrained Ferrite apps. Deployable Ferrite apps read `IngressRequest.path`, which carries `path?query` verbatim, so each app decodes query strings itself. Applications previously accumulated eight hand-rolled decoders that disagreed on `+`, `%2F`, pairs without `=`, and whether parameter names are decoded at all. This package consolidates them into one implementation whose contract is an edge-case table executed row by row by `parse_query_decodes_every_edge`.

## Status

Delivered as a source package and explicitly intended as a stopgap. A recorded platform gap asks for `parse_query` at the `ferrite-app` crate root, backed by a filed platform request. Once it lands, each function here will delegate to it and then be removed, with no changes required in consumers.

## API

One file, `src/mod.rs`, mounted at `http_query`, exposing five public functions:

| Function | Behaviour |
| --- | --- |
| `split_query(target) -> (&str, &str)` | Splits `target` at the first `?`; if `?` is absent, returns an empty query string, never `None` |
| `path_only(target) -> &str` | Path portion of a target for route matching |
| `parse_query(raw) -> Vec<(String, String)>` | Every pair decoded in order, with duplicates preserved |
| `param(raw, name) -> Option<String>` | First value matching `name`, decoding at most one name and one value |
| `target_param(target, name) -> Option<String>` | Runs `param` over a full `path?query` target |

The decoder is total: it cannot fail and cannot panic. `+` decodes to a space, `%XX` decodes in upper or lower hex case, malformed percent-escapes pass through verbatim, pairs without `=` yield `(name, "")`, empty segments are skipped, and non-UTF-8 byte sequences are replaced lossily. Parameter names decode with the same rules as values, fixing the mismatch where looking up `a.b` failed against a caller that sent `a%2Eb`. The module doc contains the full edge-case table and the reason for each row.

## Not claimed

This package does not parse a request target's authority, path segments, or fragment, and it does not encode query strings. It assigns no meaning to decoded values: every decoded value is untrusted input, so any caller placing one into a store-key prefix, filesystem path, or log line must validate its character set first. For example, a gateway's usage report validates the decoded key id before its store query builds `format!("{USAGE_PREFIX}{key_id}\x1f")`, because `%1F` and `%00` can be sent by any client and raw query text used to be the only thing limiting the byte set.

It is also not a second MCP or readiness surface. It exists as a standalone package so applications with their own MCP endpoints can use the decoder without mounting `agent-ready`, whose `mcp_face` would add a second MCP endpoint beside `packages/mcp`.

## Validation

The tests travel with the source and run inside every consumer:

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path <consumer>/Cargo.toml   # for each consumer that mounts it
```

`parse_query_decodes_every_edge` is the executable contract table; change a behaviour row only by changing that test first. `no_input_shape_panics` checks totality across the input shapes a fuzzer reaches first, and `param_and_parse_query_agree_on_encoded_names` verifies that the single-parameter lookup path and the exhaustive parse path agree on encoded names.
