//! CSS parsing: stylesheet → rules → selectors + declarations.
//!
//! Implements the subset of CSS that drives agent-relevant rendering:
//! selector lists with descendant/child/adjacent/general-sibling combinators,
//! tag/`#id`/`.class`/`*`/attribute selectors and the common pseudo-classes,
//! specificity per the CSS 2.1/Selectors-3 rules, declaration blocks with
//! `!important`, colors (named/hex/rgb[a]/hsl[a]), lengths (px/em/rem/%/pt),
//! `@media` blocks (evaluated against a fixed screen viewport) and graceful
//! skipping of any other at-rule. Parsing is infallible: unparseable input is
//! skipped per CSS error-recovery rules, never an error.

use crate::browser_core::dom::{Document, NodeId};

/// A parsed stylesheet: a flat list of style rules in source order.
#[derive(Debug, Clone, Default)]
pub struct Stylesheet {
    pub rules: Vec<StyleRule>,
}

/// One style rule: a selector list and its declarations.
#[derive(Debug, Clone)]
pub struct StyleRule {
    pub selectors: Vec<Selector>,
    pub declarations: Vec<Declaration>,
}

/// A single declaration: `name: value [!important]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Declaration {
    pub name: String,
    pub value: String,
    pub important: bool,
}

/// A complex selector: a chain of compound selectors joined by combinators.
/// Stored right-to-left: `parts[0]` is the key (subject) compound.
#[derive(Debug, Clone, PartialEq)]
pub struct Selector {
    /// (compound, combinator-to-the-LEFT-of-this-compound). The first entry's
    /// combinator is `None`; subsequent entries carry how they attach.
    pub parts: Vec<(Compound, Option<Combinator>)>,
}

/// How a compound attaches to the one to its right (in source order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combinator {
    Descendant,
    Child,
    NextSibling,
    SubsequentSibling,
}

/// A compound selector: simple selectors that all apply to one element.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Compound {
    pub tag: Option<String>,
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub attrs: Vec<AttrSelector>,
    pub pseudo_classes: Vec<PseudoClass>,
    pub universal: bool,
}

/// `[name]`, `[name=v]`, `[name~=v]`, `[name^=v]`, `[name$=v]`, `[name*=v]`,
/// `[name|=v]`.
#[derive(Debug, Clone, PartialEq)]
pub struct AttrSelector {
    pub name: String,
    pub op: AttrOp,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrOp {
    Exists,
    Equals,
    Includes,
    Prefix,
    Suffix,
    Substring,
    DashMatch,
}

/// Supported pseudo-classes. Unknown ones make the selector never match
/// (per spec, an unknown pseudo invalidates the complex selector).
#[derive(Debug, Clone, PartialEq)]
pub enum PseudoClass {
    FirstChild,
    LastChild,
    OnlyChild,
    FirstOfType,
    LastOfType,
    NthChild(NthExpr),
    NthOfType(NthExpr),
    Root,
    Empty,
    Not(Box<Compound>),
    /// `:defined`: built-in elements and custom elements whose definition
    /// ran. No script runs in this engine, so a custom element (a tag with
    /// a hyphen) is never defined and `:not(:defined)` — the rule design
    /// systems use to hide a component until it upgrades — matches it, as
    /// it does in a no-script Chrome. 14 of the 512 corpus sites rely on
    /// this to hide fallback or slotted content.
    Defined,
    /// Link-ish and interaction pseudos: statically matched (:link yes for
    /// <a href>, dynamic states never match in a headless snapshot).
    Link,
    /// `:is(<selector-list>)` / `:where(<selector-list>)`: matches when any
    /// complex selector in the list matches. `:is()` takes the specificity
    /// of its most specific argument; `:where()` contributes none. 194 and
    /// 182 of the 512 corpus sites use them (a rule such as
    /// `.nav:is(.x, .y) > ul { display: none }` hid nothing when the
    /// pseudo was simply unmatched).
    Is(Vec<Selector>),
    Where(Vec<Selector>),
    /// `:has(<relative-selector-list>)`: matches when some descendant
    /// matches one of the arguments (the descendant form; `> x`, `+ x`
    /// and `~ x` relative forms are handled by their leading combinator).
    Has(Vec<(Option<Combinator>, Selector)>),
    /// `:scope`: the query root (`el.querySelectorAll(":scope > x")`);
    /// in a stylesheet it is `:root`.
    Scope,
    /// Form-control states read off attributes: `:enabled` / `:disabled`
    /// (form controls without / with `disabled`), `:checked` (checkbox and
    /// radio inputs with `checked`, selected `<option>`s).
    Enabled,
    Disabled,
    Checked,
    /// An unknown or unsupported pseudo-class: the selector never matches
    /// in a stylesheet, and the DOM query API rejects it as a SyntaxError
    /// (`parse_selector_list_strict`), which is what Sizzle's feature
    /// detection relies on to trust `querySelectorAll`.
    Unmatched,
}

/// `an+b` expression for :nth-child/-of-type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NthExpr {
    pub a: i32,
    pub b: i32,
}

impl NthExpr {
    pub fn matches(&self, index_1based: i32) -> bool {
        let n = index_1based - self.b;
        if self.a == 0 {
            n == 0
        } else {
            n % self.a == 0 && n / self.a >= 0
        }
    }
}

/// Specificity: (id, class/attr/pseudo, type) — compared lexicographically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Specificity(pub u32, pub u32, pub u32);

impl Selector {
    pub fn specificity(&self) -> Specificity {
        let mut s = Specificity::default();
        for (c, _) in &self.parts {
            if c.id.is_some() {
                s.0 += 1;
            }
            s.1 += (c.classes.len() + c.attrs.len()) as u32;
            for p in &c.pseudo_classes {
                match p {
                    PseudoClass::Not(inner) => {
                        // `:not(X)` has the specificity of X (Selectors 4
                        // §16): its pseudo-classes count like any other,
                        // so `tag:not(:defined)` outranks a bare `tag`.
                        if inner.id.is_some() {
                            s.0 += 1;
                        }
                        s.1 += (inner.classes.len()
                            + inner.attrs.len()
                            + inner.pseudo_classes.len()) as u32;
                        if inner.tag.is_some() {
                            s.2 += 1;
                        }
                    }
                    PseudoClass::Is(list) => {
                        // The most specific argument (Selectors 4 §16).
                        if let Some(best) = list.iter().map(Selector::specificity).max() {
                            s.0 += best.0;
                            s.1 += best.1;
                            s.2 += best.2;
                        }
                    }
                    PseudoClass::Where(_) => {}
                    _ => s.1 += 1,
                }
            }
            if c.tag.is_some() {
                s.2 += 1;
            }
        }
        s
    }
}

/// Viewport description used to evaluate `@media` queries.
#[derive(Debug, Clone, Copy)]
pub struct MediaEnv {
    pub width: f32,
    pub height: f32,
}

impl Default for MediaEnv {
    fn default() -> Self {
        MediaEnv {
            width: 1280.0,
            height: 800.0,
        }
    }
}

/// Collect the declarations that apply to `el` from `sheets`, in cascade
/// order (apply first-to-last; later entries win).
///
/// Order: normal declarations sorted by (origin, specificity, sheet index,
/// source order), then the element's inline `style="..."` declarations,
/// then `!important` declarations in the same order. Callers pass the UA
/// sheet first and author sheets after; the UA sheet is the only sheet
/// whose POSITION outranks specificity (origin precedence). Among author
/// sheets — the document's `<style>` blocks and the fetched `<link>`
/// sheets alike — a more specific selector wins wherever it was declared,
/// and sheet index only breaks ties as source order (CSS Cascade 4 §6).
/// Sorting author sheets by index first made an external sheet's
/// `tag { display: block }` beat an inline `tag:not(:defined) { display:
/// none }`, which is how ibm.com's hidden web-component fallbacks leaked
/// into the Chrome-referenced corpus render.
pub fn matching_declarations(
    doc: &crate::browser_core::dom::Document,
    el: crate::browser_core::dom::NodeId,
    sheets: &[&Stylesheet],
) -> Vec<(String, String)> {
    // (specificity, sheet_idx, rule_idx) per matched declaration.
    let mut normal: Vec<(usize, Specificity, usize, &Declaration)> = Vec::new();
    let mut important: Vec<(usize, Specificity, usize, &Declaration)> = Vec::new();
    for (si, sheet) in sheets.iter().enumerate() {
        for (ri, rule) in sheet.rules.iter().enumerate() {
            // Highest-specificity matching selector in the list governs.
            let best = rule
                .selectors
                .iter()
                .filter(|s| matches(doc, el, s))
                .map(|s| s.specificity())
                .max();
            let Some(spec) = best else { continue };
            for d in &rule.declarations {
                if d.important {
                    important.push((si, spec, ri, d));
                } else {
                    normal.push((si, spec, ri, d));
                }
            }
        }
    }
    let origin = |si: usize| usize::from(si > 0);
    normal.sort_by_key(|&(si, spec, ri, _)| (origin(si), spec, si, ri));
    important.sort_by_key(|&(si, spec, ri, _)| (origin(si), spec, si, ri));

    let mut out: Vec<(String, String)> = Vec::new();
    for (_, _, _, d) in normal {
        out.push((d.name.clone(), d.value.clone()));
    }
    // Inline style, split by importance: normal inline beats every sheet
    // declaration that is not `!important`; IMPORTANT inline beats sheet
    // `!important` too, so it is emitted last of all (CSS 2.1 §6.4.2 /
    // Cascade L4 origin order).
    let inline_decls: Vec<Declaration> = doc
        .node(el)
        .as_element()
        .and_then(|e| e.attr("style"))
        .map(parse_declarations)
        .unwrap_or_default();
    for d in inline_decls.iter().filter(|d| !d.important) {
        out.push((d.name.clone(), d.value.clone()));
    }
    for (_, _, _, d) in important {
        out.push((d.name.clone(), d.value.clone()));
    }
    for d in inline_decls.iter().filter(|d| d.important) {
        out.push((d.name.clone(), d.value.clone()));
    }
    out
}

/// Parse a stylesheet with the default screen environment.
pub fn parse_stylesheet(input: &str) -> Stylesheet {
    parse_stylesheet_with_env(input, MediaEnv::default())
}

/// Parse a stylesheet, evaluating `@media` against `env`.
pub fn parse_stylesheet_with_env(input: &str, env: MediaEnv) -> Stylesheet {
    let mut sheet = Stylesheet::default();
    let src = strip_comments(input);
    parse_rule_list(&src, env, &mut sheet);
    sheet
}

fn parse_rule_list(src: &str, env: MediaEnv, sheet: &mut Stylesheet) {
    let bytes = src.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'@' {
            i = parse_at_rule(src, i, env, sheet);
            continue;
        }
        // Find the '{' opening this rule's block.
        let Some(open) = find_at_depth(bytes, i, b'{') else {
            break; // no more blocks
        };
        let selector_text = &src[i..open];
        let Some(close) = find_block_end(bytes, open) else {
            break; // unterminated block: drop the rest per error recovery
        };
        let body = &src[open + 1..close];
        let selectors = parse_selector_list(selector_text);
        if !selectors.is_empty() {
            let declarations = parse_declarations(body);
            if !declarations.is_empty() {
                sheet.rules.push(StyleRule {
                    selectors,
                    declarations,
                });
            }
        }
        i = close + 1;
    }
}

/// Handle an at-rule starting at `start` (which points at '@'). Returns the
/// index just past the rule.
fn parse_at_rule(src: &str, start: usize, env: MediaEnv, sheet: &mut Stylesheet) -> usize {
    let bytes = src.as_bytes();
    let mut j = start + 1;
    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-') {
        j += 1;
    }
    let name = src[start + 1..j].to_ascii_lowercase();
    // Find either ';' (statement at-rule) or '{' (block at-rule), whichever
    // comes first at depth 0.
    let mut k = j;
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    while k < bytes.len() {
        let b = bytes[k];
        if let Some(q) = in_str {
            if b == q {
                in_str = None;
            } else if b == b'\\' {
                k += 1;
            }
        } else {
            match b {
                b'"' | b'\'' => in_str = Some(b),
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth == 0 => return k + 1, // statement at-rule: skip
                b'{' if depth == 0 => {
                    let Some(close) = find_block_end(bytes, k) else {
                        return bytes.len();
                    };
                    let prelude = &src[j..k];
                    let body = &src[k + 1..close];
                    if name == "media" && media_matches(prelude, env) {
                        parse_rule_list(body, env, sheet);
                    }
                    // `@supports`: every feature the engine can be asked
                    // about is one Chrome supports (the corpus's 295 uses
                    // are `display: grid`, `gap`, `aspect-ratio`, `selector()`
                    // and `-webkit-` guards); a `not (...)` prelude is the one
                    // that must NOT apply. `@layer`: the block's rules join
                    // the sheet in order (layer ordering beyond source order
                    // is not modelled).
                    if name == "supports" && supports_matches(prelude) {
                        parse_rule_list(body, env, sheet);
                    }
                    if name == "layer" || name == "container" && prelude.trim().is_empty() {
                        parse_rule_list(body, env, sheet);
                    }
                    // Other at-rules are skipped wholesale (@font-face,
                    // @keyframes, @import, @container with a query...).
                    return close + 1;
                }
                _ => {}
            }
        }
        k += 1;
    }
    bytes.len()
}

/// Evaluate an `@supports` condition as Chrome would (CSS Conditional 3
/// §6): `not`, `and` and `or` over parenthesised declaration and
/// `selector()` queries. A declaration is supported unless its property
/// carries a vendor prefix Chrome does not implement (`-moz-`, `-ms-`,
/// `-o-`); a `selector()` query is supported unless it names such a
/// vendor pseudo. Everything Chrome ships (`display: grid`, `gap`,
/// `aspect-ratio`, `:has()`, `-webkit-` properties) is supported, so the
/// 295 corpus uses resolve the way Chrome resolves them, including
/// `(display: grid) and not (-moz-appearance: none)`.
fn supports_matches(prelude: &str) -> bool {
    // A condition the grammar cannot parse is `<general-enclosed>`, which
    // evaluates to false at the top level (CSS Conditional 3 §6.1).
    supports_eval(&prelude.trim().to_ascii_lowercase()).unwrap_or(false)
}

/// Evaluate one `<supports-condition>`; `None` for an unparseable one
/// (`<general-enclosed>`: false at the top level, and it poisons an
/// `and` while an `or` still passes when another operand is true).
fn supports_eval(cond: &str) -> Option<bool> {
    let c = cond.trim();
    if c.is_empty() {
        return None;
    }
    if let Some(rest) = c.strip_prefix("not") {
        if rest.starts_with(|ch: char| ch.is_whitespace() || ch == '(') {
            return supports_eval(rest).map(|v| !v);
        }
    }
    // Split the top-level operands on ` and ` / ` or ` (depth 0).
    let bytes = c.as_bytes();
    let mut depth = 0i32;
    let mut parts: Vec<&str> = Vec::new();
    let mut op: Option<&str> = None;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b' ' | b'\t' | b'\n' if depth == 0 => {
                for word in ["and", "or"] {
                    let end = i + 1 + word.len();
                    if c.get(i + 1..end) == Some(word)
                        && c.get(end..)
                            .and_then(|r| r.chars().next())
                            .map(|ch| ch.is_whitespace() || ch == '(')
                            .unwrap_or(false)
                    {
                        if op.is_some_and(|o| o != word) {
                            return None; // mixing and/or without parens: invalid
                        }
                        op = Some(word);
                        parts.push(c.get(start..i)?);
                        start = end;
                        i = end;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(c.get(start..)?);
    if let Some(op) = op {
        let vals: Vec<Option<bool>> = parts.iter().map(|p| supports_eval(p)).collect();
        return Some(if op == "and" {
            vals.iter().all(|v| v.unwrap_or(false))
        } else {
            vals.iter().any(|v| v.unwrap_or(false))
        });
    }
    // A parenthesised group, a declaration, or a function query.
    if let Some(inner) = c.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
        let inner = inner.trim();
        // `(a and b)`, `(not x)`: a nested condition.
        if inner.starts_with('(') || inner.starts_with("not") {
            return supports_eval(inner);
        }
        // `(property: value)`.
        if let Some((name, value)) = inner.split_once(':') {
            let name = name.trim();
            if value.trim().is_empty() || name.is_empty() {
                return Some(false);
            }
            let unsupported_prefix = ["-moz-", "-ms-", "-o-", "-khtml-"]
                .iter()
                .any(|p| name.starts_with(p) || value.trim().starts_with(p));
            return Some(!unsupported_prefix);
        }
        return supports_eval(inner);
    }
    if let Some(arg) = c.strip_prefix("selector(").and_then(|x| x.strip_suffix(')')) {
        let vendor = [":-moz-", "::-moz-", ":-ms-", "::-ms-", "::-o-"]
            .iter()
            .any(|p| arg.contains(p));
        return Some(!vendor);
    }
    if c.starts_with("font-tech(") || c.starts_with("font-format(") {
        return Some(true);
    }
    None
}

/// Whether a media query list (an `@media` prelude or a `<link media>`
/// attribute) applies in `env`: `screen` / `all` match, `print` never does,
/// and width/height/preference features evaluate against the environment.
pub fn media_query_matches(prelude: &str, env: MediaEnv) -> bool {
    media_matches(prelude, env)
}

/// Evaluate a media query prelude against the environment. Supports
/// `screen`, `all`, `print` (never matches), and `(min-width|max-width|width:
/// <len>)` terms joined by `and` / commas (OR).
fn media_matches(prelude: &str, env: MediaEnv) -> bool {
    let prelude = prelude.trim();
    if prelude.is_empty() {
        return true;
    }
    prelude.split(',').any(|query| {
        let mut ok = true;
        let q = query.trim().to_ascii_lowercase();
        // Split on "and"; evaluate each term.
        for term in q.split(" and ") {
            let t = term.trim().trim_start_matches("only ").trim();
            let matches = if t == "screen" || t == "all" || t.is_empty() {
                true
            } else if t == "print" || t == "not screen" || t == "speech" {
                false
            } else if let Some(inner) = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
                let mut it = inner.splitn(2, ':');
                let feat = it.next().unwrap_or("").trim();
                let val = it.next().unwrap_or("").trim();
                let px = parse_length_px(val).unwrap_or(f32::NAN);
                match feat {
                    "min-width" => env.width >= px,
                    "max-width" => env.width <= px,
                    "width" => (env.width - px).abs() < 0.5,
                    "min-height" => env.height >= px,
                    "max-height" => env.height <= px,
                    "height" => (env.height - px).abs() < 0.5,
                    "orientation" => (val == "landscape") == (env.width >= env.height),
                    // A light-scheme desktop with a mouse, as headless Chrome
                    // reports by default: `prefers-color-scheme: dark` blocks
                    // must NOT apply (35 of the 512 corpus sites rendered
                    // dark when they did), nor the reduced-motion/contrast
                    // and coarse-pointer branches.
                    "prefers-color-scheme" => val == "light",
                    "prefers-reduced-motion" | "prefers-reduced-transparency"
                    | "prefers-contrast" | "prefers-reduced-data" => {
                        val == "no-preference" || val.is_empty()
                    }
                    "hover" | "any-hover" => val == "hover",
                    "pointer" | "any-pointer" => val == "fine",
                    "forced-colors" | "inverted-colors" => val == "none",
                    _ => true, // unknown feature: permissive
                }
            } else {
                true // unknown term: permissive
            };
            if !matches {
                ok = false;
                break;
            }
        }
        ok
    })
}

/// Remove `/* ... */` comments (string-aware).
pub fn strip_comments(input: &str) -> String {
    let b = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let mut in_str: Option<u8> = None;
    while i < b.len() {
        if let Some(q) = in_str {
            if b[i] == b'\\' && i + 1 < b.len() {
                // Escape: the backslash plus the whole escaped char.
                out.push('\\');
                let ch_len = utf8_len(b[i + 1]).min(b.len() - i - 1);
                if let Some(s) = input.get(i + 1..i + 1 + ch_len) {
                    out.push_str(s);
                }
                i += 1 + ch_len;
                continue;
            }
            if b[i] == q {
                in_str = None;
            }
            // String bodies carry multi-byte text (CJK content, curly
            // quotes): copy whole chars, never one byte as a char.
            let ch_len = utf8_len(b[i]).min(b.len() - i);
            if let Some(s) = input.get(i..i + ch_len) {
                out.push_str(s);
            }
            i += ch_len;
        } else if b[i] == b'"' || b[i] == b'\'' {
            in_str = Some(b[i]);
            out.push(b[i] as char);
            i += 1;
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else {
            // Non-ASCII bytes: copy the whole UTF-8 sequence as a str
            // slice. `input` is a valid &str, so the lead byte's length
            // always lands on a char boundary; a truncated tail (a lead
            // byte with too few continuation bytes can only occur at the
            // very end) is dropped rather than pushed as garbage.
            let ch_len = utf8_len(b[i]).min(b.len() - i);
            if let Some(s) = input.get(i..i + ch_len) {
                out.push_str(s);
            }
            i += ch_len;
        }
    }
    out
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

/// Find the next `target` byte at brace/paren/bracket depth 0, string-aware.
fn find_at_depth(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut i = from;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' {
                i += 1;
            } else if b == q {
                in_str = None;
            }
        } else if b == target && depth == 0 {
            return Some(i);
        } else {
            match b {
                b'"' | b'\'' => in_str = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Given `bytes[open] == b'{'`, find the matching `}`.
fn find_block_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' {
                i += 1;
            } else if b == q {
                in_str = None;
            }
        } else {
            match b {
                b'"' | b'\'' => in_str = Some(b),
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Parse a declaration block body (no braces).
pub fn parse_declarations(body: &str) -> Vec<Declaration> {
    let mut out = Vec::new();
    for decl in split_at_depth(body, b';') {
        let decl = decl.trim();
        if decl.is_empty() {
            continue;
        }
        let Some(colon) = find_at_depth(decl.as_bytes(), 0, b':') else {
            continue;
        };
        let name = decl[..colon].trim().to_ascii_lowercase();
        let mut value = decl[colon + 1..].trim().to_string();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        let mut important = false;
        let lower = value.to_ascii_lowercase();
        if let Some(pos) = lower.rfind("!important") {
            if lower[pos + "!important".len()..].trim().is_empty() {
                value.truncate(pos);
                value = value.trim_end().to_string();
                important = true;
            }
        }
        if value.is_empty() {
            continue;
        }
        out.push(Declaration {
            name,
            value,
            important,
        });
    }
    out
}

/// Split on `sep` at depth 0 (string- and paren-aware).
fn split_at_depth(s: &str, sep: u8) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' {
                i += 1;
            } else if b == q {
                in_str = None;
            }
        } else {
            match b {
                b'"' | b'\'' => in_str = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                _ if b == sep && depth == 0 => {
                    parts.push(&s[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    parts.push(&s[start..]);
    parts
}

/// Parse a comma-separated selector list. Invalid selectors are dropped
/// individually (forgiving list, like `:is()`); an empty result means the
/// rule matches nothing.
pub fn parse_selector_list(input: &str) -> Vec<Selector> {
    split_at_depth(input, b',')
        .into_iter()
        .filter_map(|s| parse_selector(s.trim()))
        .collect()
}

/// Parse a selector list the way the DOM query API does (`querySelector`,
/// `matches`, `closest`): the whole list is invalid — `Err` — when ANY
/// complex selector fails to parse or names an unknown pseudo-class, the
/// way Chrome throws `SyntaxError: '*,:x' is not a valid selector`. A
/// stylesheet's forgiving parse (`parse_selector_list`) keeps the valid
/// members instead. jQuery's Sizzle probes exactly this difference to
/// decide whether the native `querySelectorAll` can be trusted.
pub fn parse_selector_list_strict(input: &str) -> Result<Vec<Selector>, String> {
    let mut out = Vec::new();
    for part in split_at_depth(input, b',') {
        let part = part.trim();
        let Some(sel) = parse_selector(part) else {
            return Err(format!("'{input}' is not a valid selector"));
        };
        if selector_has_unknown_pseudo(&sel) {
            return Err(format!("'{input}' is not a valid selector"));
        }
        out.push(sel);
    }
    if out.is_empty() {
        return Err(format!("'{input}' is not a valid selector"));
    }
    Ok(out)
}

/// Whether a parsed selector carries an unknown (`Unmatched`) pseudo-class
/// anywhere, including inside `:not()` / `:is()` / `:has()` arguments.
fn selector_has_unknown_pseudo(sel: &Selector) -> bool {
    sel.parts.iter().any(|(c, _)| compound_has_unknown_pseudo(c))
}

fn compound_has_unknown_pseudo(c: &Compound) -> bool {
    c.pseudo_classes.iter().any(|p| match p {
        PseudoClass::Unmatched => true,
        PseudoClass::Not(inner) => compound_has_unknown_pseudo(inner),
        PseudoClass::Is(list) | PseudoClass::Where(list) => {
            list.iter().any(selector_has_unknown_pseudo)
        }
        PseudoClass::Has(list) => list.iter().any(|(_, s)| selector_has_unknown_pseudo(s)),
        _ => false,
    })
}

/// Parse one complex selector.
pub fn parse_selector(input: &str) -> Option<Selector> {
    if input.is_empty() {
        return None;
    }
    // Tokenize into compounds and combinators, left to right.
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut compounds: Vec<(Compound, Option<Combinator>)> = Vec::new(); // source order
    let mut pending_comb: Option<Combinator> = None;
    while i < bytes.len() {
        // Whitespace: may be a descendant combinator.
        if bytes[i].is_ascii_whitespace() {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && !compounds.is_empty() && pending_comb.is_none() {
                match bytes[j] {
                    b'>' | b'+' | b'~' => {} // explicit combinator follows
                    _ => pending_comb = Some(Combinator::Descendant),
                }
            }
            i = j;
            continue;
        }
        match bytes[i] {
            b'>' => {
                pending_comb = Some(Combinator::Child);
                i += 1;
            }
            b'+' => {
                pending_comb = Some(Combinator::NextSibling);
                i += 1;
            }
            b'~' => {
                pending_comb = Some(Combinator::SubsequentSibling);
                i += 1;
            }
            _ => {
                let (compound, next) = parse_compound(input, i)?;
                if next == i {
                    return None; // no progress: invalid
                }
                let comb = if compounds.is_empty() {
                    None
                } else {
                    Some(pending_comb.unwrap_or(Combinator::Descendant))
                };
                compounds.push((compound, comb));
                pending_comb = None;
                i = next;
            }
        }
    }
    if compounds.is_empty() || pending_comb.is_some() {
        return None;
    }
    // Reverse into right-to-left order; the combinator stored WITH each
    // compound describes how it attaches to the compound to its RIGHT.
    // In source order, compounds[k].1 is the combinator between k-1 and k.
    let mut parts: Vec<(Compound, Option<Combinator>)> = Vec::with_capacity(compounds.len());
    for k in (0..compounds.len()).rev() {
        let comb = if k == compounds.len() - 1 {
            None
        } else {
            compounds[k + 1].1
        };
        parts.push((compounds[k].0.clone(), comb));
    }
    Some(Selector { parts })
}

/// Parse one compound selector starting at `start`. Returns (compound, end).
fn parse_compound(input: &str, start: usize) -> Option<(Compound, usize)> {
    let bytes = input.as_bytes();
    let mut c = Compound::default();
    let mut i = start;
    let mut any = false;
    while i < bytes.len() {
        match bytes[i] {
            b'*' => {
                c.universal = true;
                any = true;
                i += 1;
            }
            b'#' => {
                let (name, next) = read_ident(input, i + 1);
                if name.is_empty() {
                    return None;
                }
                c.id = Some(name);
                any = true;
                i = next;
            }
            b'.' => {
                let (name, next) = read_ident(input, i + 1);
                if name.is_empty() {
                    return None;
                }
                c.classes.push(name);
                any = true;
                i = next;
            }
            b'[' => {
                let close = find_matching(bytes, i, b'[', b']')?;
                let sel = parse_attr_selector(&input[i + 1..close])?;
                c.attrs.push(sel);
                any = true;
                i = close + 1;
            }
            b':' => {
                let mut j = i + 1;
                // ::pseudo-element — treat as unmatched (we don't generate
                // pseudo-element boxes for styling purposes).
                let double = j < bytes.len() && bytes[j] == b':';
                if double {
                    j += 1;
                }
                let (name, next) = read_ident(input, j);
                if name.is_empty() {
                    return None;
                }
                let mut end = next;
                let mut arg = String::new();
                if next < bytes.len() && bytes[next] == b'(' {
                    let close = find_matching(bytes, next, b'(', b')')?;
                    arg = input[next + 1..close].trim().to_string();
                    end = close + 1;
                }
                let pc = if double {
                    PseudoClass::Unmatched
                } else {
                    parse_pseudo_class(&name.to_ascii_lowercase(), &arg)
                };
                c.pseudo_classes.push(pc);
                any = true;
                i = end;
            }
            b if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' => {
                let (name, next) = read_ident(input, i);
                if name.is_empty() {
                    return None;
                }
                c.tag = Some(name.to_ascii_lowercase());
                any = true;
                i = next;
            }
            _ => break,
        }
    }
    if !any {
        return None;
    }
    Some((c, i))
}

fn parse_pseudo_class(name: &str, arg: &str) -> PseudoClass {
    match name {
        "first-child" => PseudoClass::FirstChild,
        "last-child" => PseudoClass::LastChild,
        "only-child" => PseudoClass::OnlyChild,
        "first-of-type" => PseudoClass::FirstOfType,
        "last-of-type" => PseudoClass::LastOfType,
        "root" => PseudoClass::Root,
        "scope" => PseudoClass::Scope,
        "empty" => PseudoClass::Empty,
        "defined" => PseudoClass::Defined,
        "link" | "any-link" => PseudoClass::Link,
        "enabled" => PseudoClass::Enabled,
        "disabled" => PseudoClass::Disabled,
        "checked" => PseudoClass::Checked,
        "has" => {
            // A relative selector list: each argument may start with a
            // combinator (`> a`, `+ a`, `~ a`); without one it is a
            // descendant selector.
            let mut list = Vec::new();
            for raw in split_at_depth(arg, b',') {
                let raw = raw.trim();
                let (comb, rest) = match raw.as_bytes().first() {
                    Some(b'>') => (Some(Combinator::Child), raw.get(1..).unwrap_or("")),
                    Some(b'+') => (Some(Combinator::NextSibling), raw.get(1..).unwrap_or("")),
                    Some(b'~') => (
                        Some(Combinator::SubsequentSibling),
                        raw.get(1..).unwrap_or(""),
                    ),
                    _ => (None, raw),
                };
                match parse_selector(rest.trim()) {
                    Some(s) => list.push((comb, s)),
                    None => return PseudoClass::Unmatched,
                }
            }
            if list.is_empty() {
                PseudoClass::Unmatched
            } else {
                PseudoClass::Has(list)
            }
        }
        "nth-child" => parse_nth(arg)
            .map(PseudoClass::NthChild)
            .unwrap_or(PseudoClass::Unmatched),
        "nth-of-type" => parse_nth(arg)
            .map(PseudoClass::NthOfType)
            .unwrap_or(PseudoClass::Unmatched),
        "not" => {
            // Simple :not(compound) — nested complex selectors unsupported.
            match parse_compound(arg, 0) {
                Some((inner, end)) if end == arg.len() => PseudoClass::Not(Box::new(inner)),
                _ => PseudoClass::Unmatched,
            }
        }
        "is" | "matches" | "-webkit-any" | "where" => {
            // Forgiving selector list: invalid arguments drop out, an empty
            // list matches nothing.
            let list = parse_selector_list(arg);
            if list.is_empty() {
                PseudoClass::Unmatched
            } else if name == "where" {
                PseudoClass::Where(list)
            } else {
                PseudoClass::Is(list)
            }
        }
        // Dynamic states never match in a headless snapshot (:hover and
        // friends), but they ARE valid selectors: a `Not(*)` (never true)
        // keeps the query API from rejecting them. Their functional forms
        // take an argument the grammar requires: `:lang()` with nothing
        // inside, or `:nth-last-child(x)`, is a SyntaxError in Chrome.
        "hover" | "active" | "focus" | "focus-within" | "focus-visible" | "visited" | "target"
        | "indeterminate" | "default" | "valid" | "invalid" | "required" | "optional"
        | "read-only" | "read-write" | "placeholder-shown" | "autofill" | "fullscreen"
        | "modal" | "popover-open" | "playing" | "paused" | "host" => {
            if arg.is_empty() || name == "host" {
                never_matches()
            } else {
                PseudoClass::Unmatched
            }
        }
        "lang" | "dir" | "host-context" => {
            let ok = !arg.is_empty()
                && arg
                    .split(',')
                    .all(|a| {
                        let a = a.trim().trim_matches(|c| c == '"' || c == '\'');
                        !a.is_empty()
                            && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'*' || b == b'_')
                    });
            if ok {
                never_matches()
            } else {
                PseudoClass::Unmatched
            }
        }
        "nth-last-child" | "nth-last-of-type" => {
            if parse_nth(arg).is_some() {
                never_matches()
            } else {
                PseudoClass::Unmatched
            }
        }
        _ => PseudoClass::Unmatched,
    }
}

/// A valid pseudo-class the headless snapshot can never satisfy (`:hover`,
/// `:lang(en)`): `:not(*)`, which matches no element.
fn never_matches() -> PseudoClass {
    PseudoClass::Not(Box::new(Compound {
        universal: true,
        ..Compound::default()
    }))
}

/// Parse an+b: "odd", "even", "3", "2n", "2n+1", "-n+3", "n".
pub fn parse_nth(s: &str) -> Option<NthExpr> {
    let s = s.trim().to_ascii_lowercase().replace(' ', "");
    match s.as_str() {
        "odd" => return Some(NthExpr { a: 2, b: 1 }),
        "even" => return Some(NthExpr { a: 2, b: 0 }),
        _ => {}
    }
    if let Some(npos) = s.find('n') {
        let a_str = &s[..npos];
        let a = match a_str {
            "" | "+" => 1,
            "-" => -1,
            _ => a_str.parse().ok()?,
        };
        let rest = &s[npos + 1..];
        let b = if rest.is_empty() {
            0
        } else {
            rest.parse::<i32>().ok()?
        };
        Some(NthExpr { a, b })
    } else {
        Some(NthExpr {
            a: 0,
            b: s.parse().ok()?,
        })
    }
}

fn parse_attr_selector(body: &str) -> Option<AttrSelector> {
    let body = body.trim();
    // Find operator.
    for (pat, op) in [
        ("~=", AttrOp::Includes),
        ("^=", AttrOp::Prefix),
        ("$=", AttrOp::Suffix),
        ("*=", AttrOp::Substring),
        ("|=", AttrOp::DashMatch),
        ("=", AttrOp::Equals),
    ] {
        if let Some(pos) = body.find(pat) {
            let name = body[..pos].trim().to_ascii_lowercase();
            let mut value = body[pos + pat.len()..].trim();
            // Strip optional case-insensitivity flag (treated as sensitive).
            if value.ends_with(" i") || value.ends_with(" I") || value.ends_with(" s") {
                value = value[..value.len() - 2].trim();
            }
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            if name.is_empty() {
                return None;
            }
            return Some(AttrSelector {
                name,
                op,
                value: value.to_string(),
            });
        }
    }
    let name = body.trim().to_ascii_lowercase();
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(AttrSelector {
        name,
        op: AttrOp::Exists,
        value: String::new(),
    })
}

fn read_ident(input: &str, start: usize) -> (String, usize) {
    let bytes = input.as_bytes();
    let mut i = start;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric()
            || bytes[i] == b'-'
            || bytes[i] == b'_'
            || bytes[i] >= 0x80)
    {
        i += 1;
    }
    (input[start..i].to_string(), i)
}

fn find_matching(bytes: &[u8], open_pos: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut i = open_pos;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' {
                i += 1;
            } else if b == q {
                in_str = None;
            }
        } else if b == b'"' || b == b'\'' {
            in_str = Some(b);
        } else if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Does `sel` match element `el` in `doc`? `:scope` matches the document
/// element here (stylesheet semantics); the query API passes its root
/// through [`matches_scoped`].
pub fn matches(doc: &Document, el: NodeId, sel: &Selector) -> bool {
    match_from(doc, el, sel, 0, None)
}

/// [`matches`] with an explicit `:scope` element (the query root).
pub fn matches_scoped(doc: &Document, el: NodeId, sel: &Selector, scope: Option<NodeId>) -> bool {
    match_from(doc, el, sel, 0, scope)
}

/// All elements under `root` (in document order) matching a selector list.
/// Invalid selectors are dropped individually, per the forgiving-list rule;
/// an empty/unparseable list matches nothing. `:scope` is `root`.
pub fn query_selector_all(doc: &Document, root: NodeId, selector_list: &str) -> Vec<NodeId> {
    let sels = parse_selector_list(selector_list);
    query_with_selectors(doc, root, &sels)
}

/// The DOM query API proper: `Err` for a selector list Chrome would reject
/// (the caller throws a `SyntaxError`), the matching descendants of `root`
/// otherwise. `:scope` is `root`; a document root has no scope element,
/// so `:scope` then matches the document element.
pub fn query_selector_all_strict(
    doc: &Document,
    root: NodeId,
    selector_list: &str,
) -> Result<Vec<NodeId>, String> {
    let sels = parse_selector_list_strict(selector_list)?;
    Ok(query_with_selectors(doc, root, &sels))
}

fn query_with_selectors(doc: &Document, root: NodeId, sels: &[Selector]) -> Vec<NodeId> {
    if sels.is_empty() {
        return Vec::new();
    }
    // The DOM query API returns DESCENDANTS of the root only (DOM §4.2.6
    // "scope-match a selectors string"): `:scope` names the root inside
    // a selector (`:scope > li`) but the root itself is never a result.
    let scope = if root == NodeId::DOCUMENT { None } else { Some(root) };
    doc.descendants(root)
        .filter(|&n| doc.node(n).as_element().is_some())
        .filter(|&n| sels.iter().any(|s| match_from(doc, n, s, 0, scope)))
        .collect()
}

fn match_from(doc: &Document, el: NodeId, sel: &Selector, part: usize, scope: Option<NodeId>) -> bool {
    let Some((compound, _)) = sel.parts.get(part) else {
        return true;
    };
    if !compound_matches(doc, el, compound, scope) {
        return false;
    }
    match_next(doc, el, sel, part, scope)
}

fn match_next(doc: &Document, el: NodeId, sel: &Selector, part: usize, scope: Option<NodeId>) -> bool {
    let Some((_, Some(comb))) = sel.parts.get(part + 1) else {
        // No further parts: matched fully.
        return part + 1 >= sel.parts.len();
    };
    match comb {
        Combinator::Descendant => doc.ancestors(el).any(|a| {
            doc.node(a).as_element().is_some() && match_from(doc, a, sel, part + 1, scope)
        }),
        Combinator::Child => doc
            .node(el)
            .parent
            .filter(|p| doc.node(*p).as_element().is_some())
            .map(|p| match_from(doc, p, sel, part + 1, scope))
            .unwrap_or(false),
        Combinator::NextSibling => prev_element_sibling(doc, el)
            .map(|s| match_from(doc, s, sel, part + 1, scope))
            .unwrap_or(false),
        Combinator::SubsequentSibling => {
            let mut cur = prev_element_sibling(doc, el);
            while let Some(s) = cur {
                if match_from(doc, s, sel, part + 1, scope) {
                    return true;
                }
                cur = prev_element_sibling(doc, s);
            }
            false
        }
    }
}

fn next_element_sibling(doc: &Document, el: NodeId) -> Option<NodeId> {
    let mut cur = doc.node(el).next_sibling;
    while let Some(s) = cur {
        if doc.node(s).as_element().is_some() {
            return Some(s);
        }
        cur = doc.node(s).next_sibling;
    }
    None
}

fn prev_element_sibling(doc: &Document, el: NodeId) -> Option<NodeId> {
    let mut cur = doc.node(el).prev_sibling;
    while let Some(s) = cur {
        if doc.node(s).as_element().is_some() {
            return Some(s);
        }
        cur = doc.node(s).prev_sibling;
    }
    None
}

fn compound_matches(doc: &Document, el: NodeId, c: &Compound, scope: Option<NodeId>) -> bool {
    let Some(e) = doc.node(el).as_element() else {
        return false;
    };
    if let Some(tag) = &c.tag {
        if &e.tag != tag {
            return false;
        }
    }
    if let Some(id) = &c.id {
        if e.id() != Some(id.as_str()) {
            return false;
        }
    }
    for class in &c.classes {
        if !e.has_class(class) {
            return false;
        }
    }
    for a in &c.attrs {
        let Some(v) = e.attr(&a.name) else {
            return false;
        };
        let ok = match a.op {
            AttrOp::Exists => true,
            AttrOp::Equals => v == a.value,
            AttrOp::Includes => v.split_ascii_whitespace().any(|w| w == a.value),
            AttrOp::Prefix => !a.value.is_empty() && v.starts_with(&a.value),
            AttrOp::Suffix => !a.value.is_empty() && v.ends_with(&a.value),
            AttrOp::Substring => !a.value.is_empty() && v.contains(&a.value),
            AttrOp::DashMatch => v == a.value || v.starts_with(&format!("{}-", a.value)),
        };
        if !ok {
            return false;
        }
    }
    for p in &c.pseudo_classes {
        if !pseudo_matches(doc, el, p, scope) {
            return false;
        }
    }
    true
}

fn pseudo_matches(doc: &Document, el: NodeId, p: &PseudoClass, scope: Option<NodeId>) -> bool {
    let elem_children = |parent: NodeId| {
        doc.children(parent)
            .filter(|&k| doc.node(k).as_element().is_some())
            .collect::<Vec<_>>()
    };
    match p {
        PseudoClass::FirstChild => doc
            .node(el)
            .parent
            .map(|par| elem_children(par).first() == Some(&el))
            .unwrap_or(false),
        PseudoClass::LastChild => doc
            .node(el)
            .parent
            .map(|par| elem_children(par).last() == Some(&el))
            .unwrap_or(false),
        PseudoClass::OnlyChild => doc
            .node(el)
            .parent
            .map(|par| elem_children(par) == vec![el])
            .unwrap_or(false),
        PseudoClass::FirstOfType | PseudoClass::LastOfType => {
            let Some(tag) = doc.node(el).as_element().map(|e| e.tag.clone()) else {
                return false;
            };
            let Some(par) = doc.node(el).parent else {
                return false;
            };
            let same: Vec<NodeId> = doc
                .children(par)
                .filter(|&k| doc.node(k).as_element().map(|e| e.tag == tag) == Some(true))
                .collect();
            match p {
                PseudoClass::FirstOfType => same.first() == Some(&el),
                _ => same.last() == Some(&el),
            }
        }
        PseudoClass::NthChild(expr) => doc
            .node(el)
            .parent
            .and_then(|par| {
                elem_children(par)
                    .iter()
                    .position(|&k| k == el)
                    .map(|idx| expr.matches(idx as i32 + 1))
            })
            .unwrap_or(false),
        PseudoClass::NthOfType(expr) => {
            let Some(tag) = doc.node(el).as_element().map(|e| e.tag.clone()) else {
                return false;
            };
            doc.node(el)
                .parent
                .and_then(|par| {
                    doc.children(par)
                        .filter(|&k| doc.node(k).as_element().map(|e| e.tag == tag) == Some(true))
                        .collect::<Vec<_>>()
                        .iter()
                        .position(|&k| k == el)
                        .map(|idx| expr.matches(idx as i32 + 1))
                })
                .unwrap_or(false)
        }
        PseudoClass::Root => doc.document_element() == Some(el),
        PseudoClass::Scope => match scope {
            Some(s) => s == el,
            None => doc.document_element() == Some(el),
        },
        PseudoClass::Enabled | PseudoClass::Disabled => {
            let Some(e) = doc.node(el).as_element() else {
                return false;
            };
            let control = matches!(
                e.tag.as_str(),
                "input" | "button" | "select" | "textarea" | "optgroup" | "option" | "fieldset"
            );
            if !control {
                return false;
            }
            // A disabled <fieldset> disables its descendants, except the
            // controls inside its FIRST <legend> (HTML §4.10.15 "disabled").
            let under_disabled_fieldset = || {
                let mut child = el;
                for a in doc.ancestors(el) {
                    let Some(pe) = doc.node(a).as_element() else {
                        child = a;
                        continue;
                    };
                    if pe.tag == "fieldset" && pe.attr("disabled").is_some() {
                        let first_legend = doc
                            .children(a)
                            .find(|k| doc.node(*k).as_element().map(|e| e.tag == "legend").unwrap_or(false));
                        if first_legend != Some(child) {
                            return true;
                        }
                    }
                    child = a;
                }
                false
            };
            let disabled = e.attr("disabled").is_some() || under_disabled_fieldset();
            (*p == PseudoClass::Disabled) == disabled
        }
        PseudoClass::Checked => doc
            .node(el)
            .as_element()
            .map(|e| {
                (e.tag == "input"
                    && e
                        .attr("type")
                        .map(|t| t.eq_ignore_ascii_case("checkbox") || t.eq_ignore_ascii_case("radio"))
                        .unwrap_or(false)
                    && e.attr("checked").is_some())
                    || (e.tag == "option" && e.attr("selected").is_some())
            })
            .unwrap_or(false),
        PseudoClass::Has(list) => list.iter().any(|(comb, s)| match comb {
            None | Some(Combinator::Descendant) => doc
                .descendants(el)
                .any(|d| doc.node(d).as_element().is_some() && match_from(doc, d, s, 0, Some(el))),
            Some(Combinator::Child) => doc
                .children(el)
                .any(|k| doc.node(k).as_element().is_some() && match_from(doc, k, s, 0, Some(el))),
            Some(Combinator::NextSibling) => next_element_sibling(doc, el)
                .map(|n| match_from(doc, n, s, 0, Some(el)))
                .unwrap_or(false),
            Some(Combinator::SubsequentSibling) => {
                let mut cur = next_element_sibling(doc, el);
                while let Some(n) = cur {
                    if match_from(doc, n, s, 0, Some(el)) {
                        return true;
                    }
                    cur = next_element_sibling(doc, n);
                }
                false
            }
        }),
        PseudoClass::Empty => doc.children(el).next().is_none(),
        PseudoClass::Defined => doc
            .node(el)
            .as_element()
            .map(|e| !e.tag.contains('-'))
            .unwrap_or(false),
        PseudoClass::Not(inner) => !compound_matches(doc, el, inner, scope),
        PseudoClass::Is(list) | PseudoClass::Where(list) => {
            list.iter().any(|s| match_from(doc, el, s, 0, scope))
        }
        PseudoClass::Link => doc
            .node(el)
            .as_element()
            .map(|e| (e.tag == "a" || e.tag == "area") && e.attr("href").is_some())
            .unwrap_or(false),
        PseudoClass::Unmatched => false,
    }
}

/// An sRGB color with alpha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const BLACK: Color = Color::rgb(0, 0, 0);
    pub const WHITE: Color = Color::rgb(255, 255, 255);
    pub const TRANSPARENT: Color = Color {
        r: 0,
        g: 0,
        b: 0,
        a: 0,
    };

    pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color { r, g, b, a: 255 }
    }
}

/// Parse a CSS color value.
pub fn parse_color(v: &str) -> Option<Color> {
    let v = v.trim();
    if let Some(hex) = v.strip_prefix('#') {
        return parse_hex_color(hex);
    }
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("rgb") || lower.starts_with("hsl") {
        return parse_func_color(&lower);
    }
    named_color(&lower)
}

fn parse_hex_color(hex: &str) -> Option<Color> {
    let h = hex.trim();
    let dig = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let b = h.as_bytes();
    match b.len() {
        3 | 4 => {
            let r = dig(b[0])?;
            let g = dig(b[1])?;
            let bl = dig(b[2])?;
            let a = if b.len() == 4 { dig(b[3])? } else { 15 };
            Some(Color {
                r: r * 17,
                g: g * 17,
                b: bl * 17,
                a: a * 17,
            })
        }
        6 | 8 => {
            let r = dig(b[0])? * 16 + dig(b[1])?;
            let g = dig(b[2])? * 16 + dig(b[3])?;
            let bl = dig(b[4])? * 16 + dig(b[5])?;
            let a = if b.len() == 8 {
                dig(b[6])? * 16 + dig(b[7])?
            } else {
                255
            };
            Some(Color { r, g, b: bl, a })
        }
        _ => None,
    }
}

fn parse_func_color(lower: &str) -> Option<Color> {
    let open = lower.find('(')?;
    let close = lower.rfind(')')?;
    let name = &lower[..open];
    let args = &lower[open + 1..close];
    let parts: Vec<&str> = args
        .split([',', '/', ' '])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let num = |s: &str, max: f32| -> Option<f32> {
        if let Some(p) = s.strip_suffix('%') {
            p.parse::<f32>().ok().map(|x| x / 100.0 * max)
        } else {
            s.parse::<f32>().ok()
        }
    };
    match name.trim_end_matches('a') {
        "rgb" => {
            if parts.len() < 3 {
                return None;
            }
            let r = num(parts[0], 255.0)?.clamp(0.0, 255.0) as u8;
            let g = num(parts[1], 255.0)?.clamp(0.0, 255.0) as u8;
            let b = num(parts[2], 255.0)?.clamp(0.0, 255.0) as u8;
            let a = if parts.len() > 3 {
                (num(parts[3], 1.0)?.clamp(0.0, 1.0) * 255.0) as u8
            } else {
                255
            };
            Some(Color { r, g, b, a })
        }
        "hsl" => {
            if parts.len() < 3 {
                return None;
            }
            let h = parts[0]
                .trim_end_matches("deg")
                .parse::<f32>()
                .ok()?
                .rem_euclid(360.0);
            let s = num(parts[1].strip_suffix('%').unwrap_or(parts[1]), 1.0)
                .or_else(|| num(parts[1], 1.0))?
                .clamp(0.0, 1.0);
            let s = if parts[1].ends_with('%') {
                s
            } else {
                s.clamp(0.0, 1.0)
            };
            let l = num(parts[2], 1.0)?.clamp(0.0, 1.0);
            let a = if parts.len() > 3 {
                (num(parts[3], 1.0)?.clamp(0.0, 1.0) * 255.0) as u8
            } else {
                255
            };
            let (r, g, b) = hsl_to_rgb(h, s, l);
            Some(Color { r, g, b, a })
        }
        _ => None,
    }
}

fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let hp = h / 60.0;
    let x = c * (1.0 - (hp % 2.0 - 1.0).abs());
    let (r1, g1, b1) = match hp as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    (
        ((r1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((g1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
        ((b1 + m) * 255.0).round().clamp(0.0, 255.0) as u8,
    )
}

fn named_color(name: &str) -> Option<Color> {
    let c = |r, g, b| Some(Color::rgb(r, g, b));
    match name {
        "black" => c(0, 0, 0),
        "silver" => c(192, 192, 192),
        "gray" | "grey" => c(128, 128, 128),
        "white" => c(255, 255, 255),
        "maroon" => c(128, 0, 0),
        "red" => c(255, 0, 0),
        "purple" => c(128, 0, 128),
        "fuchsia" | "magenta" => c(255, 0, 255),
        "green" => c(0, 128, 0),
        "lime" => c(0, 255, 0),
        "olive" => c(128, 128, 0),
        "yellow" => c(255, 255, 0),
        "navy" => c(0, 0, 128),
        "blue" => c(0, 0, 255),
        "teal" => c(0, 128, 128),
        "aqua" | "cyan" => c(0, 255, 255),
        "orange" => c(255, 165, 0),
        "aliceblue" => c(240, 248, 255),
        "antiquewhite" => c(250, 235, 215),
        "aquamarine" => c(127, 255, 212),
        "azure" => c(240, 255, 255),
        "beige" => c(245, 245, 220),
        "bisque" => c(255, 228, 196),
        "blanchedalmond" => c(255, 235, 205),
        "blueviolet" => c(138, 43, 226),
        "brown" => c(165, 42, 42),
        "burlywood" => c(222, 184, 135),
        "cadetblue" => c(95, 158, 160),
        "chartreuse" => c(127, 255, 0),
        "chocolate" => c(210, 105, 30),
        "coral" => c(255, 127, 80),
        "cornflowerblue" => c(100, 149, 237),
        "cornsilk" => c(255, 248, 220),
        "crimson" => c(220, 20, 60),
        "darkblue" => c(0, 0, 139),
        "darkcyan" => c(0, 139, 139),
        "darkgoldenrod" => c(184, 134, 11),
        "darkgray" | "darkgrey" => c(169, 169, 169),
        "darkgreen" => c(0, 100, 0),
        "darkkhaki" => c(189, 183, 107),
        "darkmagenta" => c(139, 0, 139),
        "darkolivegreen" => c(85, 107, 47),
        "darkorange" => c(255, 140, 0),
        "darkorchid" => c(153, 50, 204),
        "darkred" => c(139, 0, 0),
        "darksalmon" => c(233, 150, 122),
        "darkseagreen" => c(143, 188, 143),
        "darkslateblue" => c(72, 61, 139),
        "darkslategray" | "darkslategrey" => c(47, 79, 79),
        "darkturquoise" => c(0, 206, 209),
        "darkviolet" => c(148, 0, 211),
        "deeppink" => c(255, 20, 147),
        "deepskyblue" => c(0, 191, 255),
        "dimgray" | "dimgrey" => c(105, 105, 105),
        "dodgerblue" => c(30, 144, 255),
        "firebrick" => c(178, 34, 34),
        "floralwhite" => c(255, 250, 240),
        "forestgreen" => c(34, 139, 34),
        "gainsboro" => c(220, 220, 220),
        "ghostwhite" => c(248, 248, 255),
        "gold" => c(255, 215, 0),
        "goldenrod" => c(218, 165, 32),
        "greenyellow" => c(173, 255, 47),
        "honeydew" => c(240, 255, 240),
        "hotpink" => c(255, 105, 180),
        "indianred" => c(205, 92, 92),
        "indigo" => c(75, 0, 130),
        "ivory" => c(255, 255, 240),
        "khaki" => c(240, 230, 140),
        "lavender" => c(230, 230, 250),
        "lavenderblush" => c(255, 240, 245),
        "lawngreen" => c(124, 252, 0),
        "lemonchiffon" => c(255, 250, 205),
        "lightblue" => c(173, 216, 230),
        "lightcoral" => c(240, 128, 128),
        "lightcyan" => c(224, 255, 255),
        "lightgoldenrodyellow" => c(250, 250, 210),
        "lightgray" | "lightgrey" => c(211, 211, 211),
        "lightgreen" => c(144, 238, 144),
        "lightpink" => c(255, 182, 193),
        "lightsalmon" => c(255, 160, 122),
        "lightseagreen" => c(32, 178, 170),
        "lightskyblue" => c(135, 206, 250),
        "lightslategray" | "lightslategrey" => c(119, 136, 153),
        "lightsteelblue" => c(176, 196, 222),
        "lightyellow" => c(255, 255, 224),
        "limegreen" => c(50, 205, 50),
        "linen" => c(250, 240, 230),
        "mediumaquamarine" => c(102, 205, 170),
        "mediumblue" => c(0, 0, 205),
        "mediumorchid" => c(186, 85, 211),
        "mediumpurple" => c(147, 112, 219),
        "mediumseagreen" => c(60, 179, 113),
        "mediumslateblue" => c(123, 104, 238),
        "mediumspringgreen" => c(0, 250, 154),
        "mediumturquoise" => c(72, 209, 204),
        "mediumvioletred" => c(199, 21, 133),
        "midnightblue" => c(25, 25, 112),
        "mintcream" => c(245, 255, 250),
        "mistyrose" => c(255, 228, 225),
        "moccasin" => c(255, 228, 181),
        "navajowhite" => c(255, 222, 173),
        "oldlace" => c(253, 245, 230),
        "olivedrab" => c(107, 142, 35),
        "orangered" => c(255, 69, 0),
        "orchid" => c(218, 112, 214),
        "palegoldenrod" => c(238, 232, 170),
        "palegreen" => c(152, 251, 152),
        "paleturquoise" => c(175, 238, 238),
        "palevioletred" => c(219, 112, 147),
        "papayawhip" => c(255, 239, 213),
        "peachpuff" => c(255, 218, 185),
        "peru" => c(205, 133, 63),
        "pink" => c(255, 192, 203),
        "plum" => c(221, 160, 221),
        "powderblue" => c(176, 224, 230),
        "rebeccapurple" => c(102, 51, 153),
        "rosybrown" => c(188, 143, 143),
        "royalblue" => c(65, 105, 225),
        "saddlebrown" => c(139, 69, 19),
        "salmon" => c(250, 128, 114),
        "sandybrown" => c(244, 164, 96),
        "seagreen" => c(46, 139, 87),
        "seashell" => c(255, 245, 238),
        "sienna" => c(160, 82, 45),
        "skyblue" => c(135, 206, 235),
        "slateblue" => c(106, 90, 205),
        "slategray" | "slategrey" => c(112, 128, 144),
        "snow" => c(255, 250, 250),
        "springgreen" => c(0, 255, 127),
        "steelblue" => c(70, 130, 180),
        "tan" => c(210, 180, 140),
        "thistle" => c(216, 191, 216),
        "tomato" => c(255, 99, 71),
        "turquoise" => c(64, 224, 208),
        "violet" => c(238, 130, 238),
        "wheat" => c(245, 222, 179),
        "whitesmoke" => c(245, 245, 245),
        "yellowgreen" => c(154, 205, 50),
        "transparent" => Some(Color::TRANSPARENT),
        _ => None,
    }
}

/// Parse an absolute length into px (px, pt, pc, in, cm, mm, q; bare number
/// treated as px for attr-style values). `em`/`rem` resolve against the
/// initial 16px font size, which is what a media query's `em` means (Media
/// Queries 4 §2.3: relative to the initial value) — 114 of the 512 corpus
/// sites write their breakpoints as `(min-width: 48rem)`, and treating the
/// unit as unparseable made every such query permissive, so the desktop
/// branch that hides a site's mobile menu never applied.
pub fn parse_length_px(v: &str) -> Option<f32> {
    let v = v.trim().to_ascii_lowercase();
    for (suffix, factor) in [
        ("px", 1.0),
        ("rem", 16.0),
        ("em", 16.0),
        ("pt", 96.0 / 72.0),
        ("pc", 16.0),
        ("in", 96.0),
        ("cm", 96.0 / 2.54),
        ("mm", 96.0 / 25.4),
        ("q", 96.0 / 101.6),
    ] {
        if let Some(n) = v.strip_suffix(suffix) {
            if let Ok(x) = n.trim().parse::<f32>() {
                return Some(x * factor);
            }
        }
    }
    v.parse::<f32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_core::html;

    #[test]
    fn parse_basic_rules() {
        let s = parse_stylesheet("p { color: red; } .a, #b { margin: 0 !important }");
        assert_eq!(s.rules.len(), 2);
        assert_eq!(s.rules[0].declarations[0].name, "color");
        assert!(!s.rules[0].declarations[0].important);
        assert_eq!(s.rules[1].selectors.len(), 2);
        assert!(s.rules[1].declarations[0].important);
    }

    #[test]
    fn comments_and_recovery() {
        let s = parse_stylesheet(
            "/* x */ p { color: /* inline */ blue } bad { } q { ; color:green;; }",
        );
        assert_eq!(s.rules.len(), 2);
        assert_eq!(s.rules[0].declarations[0].value, "blue");
        assert_eq!(s.rules[1].declarations[0].value, "green");
    }

    #[test]
    fn comments_beside_multibyte_text_do_not_split_a_char() {
        // Found by the Chrome-referenced site corpus: ja/zh/ko Wikipedia,
        // apple.com and nginx.com stylesheets carry CJK and curly-quote
        // text next to comments; the old byte walker truncated a String
        // inside a multi-byte char and panicked.
        let src = "/* 日本語 */ p::before { content: \"→ “quoted”\"; } /* ✓ */ q { color: red }";
        let stripped = strip_comments(src);
        assert!(stripped.contains("“quoted”"));
        assert!(!stripped.contains("日本語"));
        let s = parse_stylesheet(src);
        assert_eq!(s.rules.len(), 2);
        assert_eq!(s.rules[1].declarations[0].value, "red");
        // A lead byte with no continuation (truncated tail) is dropped.
        let truncated = String::from_utf8_lossy(&[b'a', 0xE6]).into_owned();
        let _ = strip_comments(&truncated);
    }

    #[test]
    fn specificity_order() {
        let a = parse_selector("#x").unwrap().specificity();
        let b = parse_selector(".x.y").unwrap().specificity();
        let c = parse_selector("div p").unwrap().specificity();
        assert!(a > b && b > c);
        assert_eq!(c, Specificity(0, 0, 2));
    }

    #[test]
    fn colors() {
        assert_eq!(parse_color("#fff"), Some(Color::WHITE));
        assert_eq!(parse_color("#000000"), Some(Color::BLACK));
        assert_eq!(parse_color("#00ff00"), Some(Color::rgb(0, 255, 0)));
        assert_eq!(parse_color("rgb(1, 2, 3)"), Some(Color::rgb(1, 2, 3)));
        assert_eq!(
            parse_color("rgba(0,0,0,0.5)"),
            Some(Color {
                r: 0,
                g: 0,
                b: 0,
                a: 127
            })
        );
        assert_eq!(
            parse_color("hsl(0, 100%, 50%)"),
            Some(Color::rgb(255, 0, 0))
        );
        assert_eq!(parse_color("red"), Some(Color::rgb(255, 0, 0)));
        assert_eq!(parse_color("rebeccapurple"), Some(Color::rgb(102, 51, 153)));
        assert_eq!(parse_color("TRANSPARENT"), Some(Color::TRANSPARENT));
        assert_eq!(parse_color("#12345"), None);
        assert_eq!(parse_color("bogus"), None);
    }

    #[test]
    fn selector_matching() {
        let doc = html::parse(
            "<div id=x class='a b'><p>1</p><p class=c>2</p><span data-k='u v'>3</span></div>",
        );
        let mut d = doc.clone();
        let x = d.get_element_by_id("x").unwrap();
        let p2 = d
            .find_tag("p")
            .map(|p| d.node(p).next_sibling.unwrap())
            .unwrap();
        let span = d.find_tag("span").unwrap();

        let m = |sel: &str, el| matches(&doc, el, &parse_selector(sel).unwrap());
        assert!(m("#x", x));
        assert!(m("div.a.b", x));
        assert!(m("div p.c", p2));
        assert!(m("div > p:last-of-type", p2));
        assert!(m("p + p", p2));
        assert!(m("p ~ span", span));
        assert!(m("[data-k~=v]", span));
        assert!(m("p:nth-child(2)", p2));
        assert!(!m("p:first-child", p2));
        assert!(m("span:last-child", span));
        assert!(!m("#nope", x));
        assert!(m(":not(.c)", x));
    }

    #[test]
    fn specificity_wins_across_author_sheets() {
        // An inline <style> with a more specific selector must beat a LATER
        // external sheet's plain tag rule: sheet position is source order,
        // not origin (ibm.com's `:not(:defined)` fallback hiding).
        let doc = html::parse("<style>x-el:not(:defined) { display: none }</style><x-el id=e>x</x-el>");
        let inline_sheets = crate::browser_core::style::document_stylesheets(&doc);
        let external = parse_stylesheet("x-el { display: block; color: red }");
        let mut sheets = inline_sheets;
        sheets.push(external);
        let styles = crate::browser_core::style::compute_styles(&doc, &sheets);
        let mut d = doc.clone();
        let e = d.get_element_by_id("e").unwrap();
        assert_eq!(styles[&e].display, crate::browser_core::style::Display::None);
        // The unrelated, unopposed declaration still applies.
        assert_eq!(styles[&e].color, Color::rgb(255, 0, 0));
        // And equal specificity still resolves by sheet order (later wins).
        let doc = html::parse("<style>p { color: blue }</style><p id=p>x</p>");
        let mut sheets = crate::browser_core::style::document_stylesheets(&doc);
        sheets.push(parse_stylesheet("p { color: green }"));
        let styles = crate::browser_core::style::compute_styles(&doc, &sheets);
        let mut d = doc.clone();
        let p = d.get_element_by_id("p").unwrap();
        assert_eq!(styles[&p].color, Color::rgb(0, 128, 0));
    }

    #[test]
    fn custom_elements_are_never_defined_without_script() {
        // ibm.com (corpus) hides its web components with
        // `c4d-table-of-contents:not(:defined) { display: none }` until the
        // component script upgrades them; with scripting off Chrome keeps
        // them hidden, and so must the engine.
        let doc = html::parse("<div id=d><c4d-toc id=c>slot</c4d-toc></div>");
        let mut d = doc.clone();
        let div = d.get_element_by_id("d").unwrap();
        let ce = d.get_element_by_id("c").unwrap();
        let m = |sel: &str, el| matches(&doc, el, &parse_selector(sel).unwrap());
        assert!(m(":defined", div));
        assert!(!m(":defined", ce));
        assert!(m("c4d-toc:not(:defined)", ce));
        assert!(!m("div:not(:defined)", div));
    }

    #[test]
    fn is_where_and_supports() {
        let doc = html::parse(
            "<nav class=nav><ul class=sub><li id=a>x</li></ul></nav><p class='w x' id=b>y</p><p id=c>z</p>",
        );
        let mut d = doc.clone();
        let a = d.get_element_by_id("a").unwrap();
        let b = d.get_element_by_id("b").unwrap();
        let c = d.get_element_by_id("c").unwrap();
        let m = |sel: &str, el| matches(&doc, el, &parse_selector(sel).unwrap());
        assert!(m(":is(.nav, .other) li", a));
        assert!(m("p:is(.w.x)", b));
        assert!(!m("p:is(.w.x)", c));
        assert!(m(".w:where(.x)", b));
        assert!(m(":is(nav > ul) > li", a));
        // :is() takes its most specific argument; :where() adds nothing.
        assert_eq!(parse_selector("p:is(#q, .r)").unwrap().specificity(), Specificity(1, 0, 1));
        assert_eq!(parse_selector("p:where(#q, .r)").unwrap().specificity(), Specificity(0, 0, 1));
        // @supports applies unless negated; @layer blocks join the sheet.
        let s = parse_stylesheet(
            "@supports (display: grid) { p { color: red } } @supports not (display: grid) { p { color: blue } } @layer base { p { margin: 0 } } @supports selector(:has(a)) { q { color: green } }",
        );
        assert_eq!(s.rules.len(), 3);
        assert_eq!(s.rules[0].declarations[0].value, "red");
        assert_eq!(s.rules[1].declarations[0].name, "margin");
        assert_eq!(s.rules[2].declarations[0].value, "green");
        // Boolean conditions evaluate the way Chrome does: a Firefox-only
        // property is unsupported, so `not` of it is TRUE (the
        // "everything but Firefox" guard sites write); a Firefox-only
        // pseudo in selector() is unsupported.
        assert_eq!(supports_eval("(-moz-appearance: none)"), Some(false));
        assert_eq!(supports_eval("not (-moz-appearance: none)"), Some(true));
        assert_eq!(supports_eval("not (display: grid)"), Some(false));
        assert_eq!(supports_eval("(display: grid) and not (-moz-appearance: none)"), Some(true));
        assert_eq!(supports_eval("(display: grid) and (-moz-appearance: none)"), Some(false));
        assert_eq!(supports_eval("(display: grid) and (gap: 1px)"), Some(true));
        assert_eq!(supports_eval("(-moz-appearance: none) or (-webkit-appearance: none)"), Some(true));
        assert_eq!(supports_eval("not ((display: grid) and (gap: 1px))"), Some(false));
        assert_eq!(supports_eval("selector(::-moz-placeholder)"), Some(false));
        assert_eq!(supports_eval("selector(:is(a, b))"), Some(true));
        // Unparseable conditions are <general-enclosed>: false.
        assert!(!supports_matches("garbage"));
        assert!(!supports_matches("(display: grid) and garbage"));
        assert!(supports_matches("(display: grid) or garbage"));
    }

    #[test]
    fn media_queries() {
        let env = MediaEnv {
            width: 1280.0,
            height: 800.0,
        };
        let s = parse_stylesheet_with_env(
            "@media (max-width: 600px) { p { color: red } } @media screen and (min-width: 1000px) { p { color: blue } } @font-face { font-family: x; }",
            env,
        );
        assert_eq!(s.rules.len(), 1);
        assert_eq!(s.rules[0].declarations[0].value, "blue");
        // em/rem breakpoints resolve at 16px: 48rem = 768px (matches at
        // 1280), 100em = 1600px (does not). An unparseable length must
        // NOT fall through as permissive.
        let s = parse_stylesheet_with_env(
            "@media (min-width: 48rem) { a { color: red } } @media (min-width: 100em) { a { color: blue } } @media (max-width: 47.9375em) { a { color: green } }",
            env,
        );
        assert_eq!(s.rules.len(), 1);
        assert_eq!(s.rules[0].declarations[0].value, "red");
    }

    #[test]
    fn nth_expr() {
        let odd = parse_nth("odd").unwrap();
        assert!(odd.matches(1) && !odd.matches(2) && odd.matches(3));
        let e = parse_nth("-n+3").unwrap();
        assert!(e.matches(1) && e.matches(3) && !e.matches(4));
        let n2 = parse_nth("2n").unwrap();
        assert!(!n2.matches(1) && n2.matches(2) && n2.matches(4));
    }
}
