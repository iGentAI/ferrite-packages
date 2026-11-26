# browser-core

A Kitesurf-style, agent-first headless browser engine shipped as an installable Ferrite source package. It has zero external dependencies (`std` only), is infallible by construction, and focuses on the outputs agents consume (extracted text, markdown, links, serialized HTML, and bounded-cost screenshots) rather than pixel-accurate human browsing.

The design draws on Cloudflare's Kitesurf (Agents Week, Aug 2026), which showed that a browser built for AI agents can trade rendering fidelity for a 3 to 7x reduction in CPU and memory compared to Chromium. Inside the Ferrite constrained-app contract, that yields four constraints:

| Property | Behaviour |
| --- | --- |
| Robust over perfect | Any input (truncated, hostile, or binary garbage) produces a best-effort DOM and a valid reply, never a panic or dead session. Consumers deny `clippy::indexing_slicing`, and every stage degrades to an empty box rather than failing. |
| Stateless | A `Page` is a pure value computed from one HTML string. There is no session state, no shared cache, and nothing to reconstruct after a crash. |
| Bounded cost | The rasterizer caps pixel buffers at 64 MiB regardless of page height, and consumers cap fetched documents at 1 MiB. |
| Isolated | The engine does no I/O. Network access belongs to the consuming application through its scoped egress handle. |

## Pipeline

Native tools own their thread creation. In version 0.1.4, the optional `run_on_deep_stack` helper moved out of this source package into the native Agent Browser examples. Deployed applications retain the interpreter's default stack budget and do not create a thread to render a page. A native embedder that controls its own stack may set `RunLimits::stack_budget_bytes` explicitly.

```text
html::parse --> dom::Document --> css + style::compute_styles --> layout::layout_tree
     |                                                                    |
     +--> extract::{text, markdown, links, serialize_html}                v
     +--> api::Page (facade)                                paint::rasterize --> png::encode
```

| Module | Contents |
| --- | --- |
| `dom` | Arena-backed DOM with O(1) append, id lookup, and pre-order iterators. |
| `html` | HTML5 tokenizer and tree constructor supporting doctype, comments, all attribute quoting styles, named and numeric character references, RAWTEXT/RCDATA, void elements, implied `html`/`head`/`body`, and auto-closing (`p`, `li`, `tr`, and others). |
| `css` | Selector parser (compound selectors, combinators, attribute operators, `:nth-child`, and related pseudo-classes), `@media` evaluation, specificity, and color/length parsing. |
| `style` | User-agent stylesheet and cascade producing `ComputedStyle` (box model, typography, display, visibility). |
| `layout` | Block and inline flow with margins, borders, padding, explicit widths, auto-centering, greedy line wrapping, `white-space: pre`, and `text-align`. |
| `paint` | Pure-software rasterizer with an embedded 8x16 bitmap face and CSS canvas background propagation. |
| `image` | Dependency-free PNG, JPEG, GIF, and WebP decoder producing RGBA8 buffers for intrinsic sizing and screenshot compositing. |
| `png` | Dependency-free PNG encoder using fixed-Huffman DEFLATE with distance-4 LZ77 run matching, CRC32, and Adler32. |
| `extract` | Agent views: visible text (with CSS-aware `display:none` exclusion), markdown (headings, emphasis, lists, tables, fences, links, images), links, and HTML serialization. |
| `api` | `Page::load(html)` facade exposing all quick actions. |
| `js` | Panic-free JavaScript interpreter with DOM bindings: DOM event model (target and bubble phases, inline handlers, `stopPropagation`, `stopImmediatePropagation`, cancelable defaults), focus, `click()` activation (checkbox and radio toggles, label forwarding, form submission recorded for the embedder), and a persistent `Realm` a host can carry across runs. |
| `cdp` | Chrome DevTools Protocol facade covering Browser, Schema, Target, Page, Runtime (remote objects), DOM (mutation, box model, hit-testing), Input, CSS, Accessibility, Emulation, and Network domains over an embedder-owned transport; console messages and exceptions surface as events. |

## Consumers

Install the package in any Ferrite application:

```bash
ferrite add browser-core
```

Declare `mod browser_core;` in the crate root, then load HTML bytes that the application received or fetched through one of its declared handles:

```rust
use browser_core::api::{Page, PageOptions};

let page = Page::load_with(
    "<main><h1>Build evidence</h1><a href='/checks'>Checks</a></main>",
    PageOptions { viewport_width: 1280.0, ..PageOptions::default() },
);
let markdown = page.markdown();
let links = page.links();
let png = page.screenshot_png();
```

`agent-browser` (in its own repository, `iGentAI/ferrite-browser`) mounts this package and serves its quick-action and CDP surfaces over queue ingress; its CDP and rendering compliance gates act as the package's conformance suites.

This engine is Rust source compiled directly into the constrained application. It is distinct from the `wasm-runtime` package and is not a host-side search or fetch adapter for external services. `browser-core` owns provider-free in-app rendering, while the consuming application owns network I/O and destination policy.

Installed copies are generated: edit the package source and recompose with `ferrite-pkg`, never by modifying a vendored copy.

## Status

Active source package compiled directly into constrained Ferrite applications and native embedders. It has no external dependencies beyond `std`.

## Not claimed

This package is not independently deployable, performs no network or filesystem I/O, and does not claim Chromium pixel parity. The indicative single-machine benchmark below measures one release build on one host rather than a deployment guarantee.

## Validation

```bash
node tools/ferrite-pkg/ferrite-pkg.mjs check
cargo test --manifest-path <consumer>/Cargo.toml
```

## Indicative single-machine benchmark (release, 460 KB / 2,000-paragraph document)

| Stage | Time |
| --- | --- |
| parse + cascade + layout | ~22 ms |
| text extraction | ~1.2 ms |
| markdown extraction | ~1.4 ms |
| full-page screenshot (64 MiB pixel cap) | ~860 ms |
