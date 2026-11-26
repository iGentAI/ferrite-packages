//! Computed style: applies the CSS cascade to each element and resolves the
//! properties the layout and paint stages consume.
//!
//! Follows the Kitesurf philosophy: resolve what agents need (box model,
//! display, typography, colors, visibility), skip what only matters for
//! pixel-perfect human browsing. Unknown properties are carried through the
//! cascade untouched and simply unused; invalid values fall back to defaults
//! rather than erroring.

use std::collections::HashMap;
use std::rc::Rc;

use crate::browser_core::css::{self, Stylesheet};
use crate::browser_core::dom::{Document, NodeId};

// The canonical color type and parser live in `css`; re-exported here so the
// computed-style surface is self-contained for consumers.
pub use crate::browser_core::css::Color;

/// CSS display values we distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Display {
    Inline,
    Block,
    InlineBlock,
    ListItem,
    Table,
    TableRow,
    TableCell,
    None,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for Display {
    fn default() -> Self {
        Display::Inline
    }
}

/// A resolved length. `Auto` survives to layout; percentages resolve against
/// the containing block during layout.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Length {
    Auto,
    Px(f32),
    Percent(f32),
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for Length {
    fn default() -> Self {
        Length::Auto
    }
}

impl Length {
    /// Resolve against a containing dimension; `Auto` yields `fallback`.
    pub fn resolve(self, containing: f32, fallback: f32) -> f32 {
        match self {
            Length::Auto => fallback,
            Length::Px(v) => v,
            Length::Percent(p) => containing * p / 100.0,
        }
    }

    pub fn is_auto(self) -> bool {
        matches!(self, Length::Auto)
    }
}

/// Font weight (only the normal/bold axis matters to our rasterizer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontWeight {
    Normal,
    Bold,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for FontWeight {
    fn default() -> Self {
        FontWeight::Normal
    }
}

/// Font style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontStyle {
    Normal,
    Italic,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for FontStyle {
    fn default() -> Self {
        FontStyle::Normal
    }
}

/// Text alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign {
    Left,
    Center,
    Right,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for TextAlign {
    fn default() -> Self {
        TextAlign::Left
    }
}

/// Whitespace handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhiteSpace {
    Normal,
    Pre,
    NoWrap,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for WhiteSpace {
    fn default() -> Self {
        WhiteSpace::Normal
    }
}

/// CSS positioning scheme, reduced to what layout needs: whether the box
/// takes part in normal flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Static,
    Relative,
    Absolute,
    Fixed,
    Sticky,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for Position {
    fn default() -> Self {
        Position::Static
    }
}

impl Position {
    /// Absolutely positioned boxes leave normal flow: they take no space in
    /// their parent and do not push later siblings down.
    pub fn out_of_flow(self) -> bool {
        matches!(self, Position::Absolute | Position::Fixed)
    }
}

/// CSS `float`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Float {
    None,
    Left,
    Right,
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for Float {
    fn default() -> Self {
        Float::None
    }
}

/// The column structure of a grid container, as far as layout models it:
/// a fixed track count, or `repeat(auto-fill|auto-fit, minmax(<px>, ..))`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GridColumns {
    None,
    Count(u32),
    AutoFill(f32),
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for GridColumns {
    fn default() -> Self {
        GridColumns::None
    }
}

/// Per-side box values (margin, padding, border widths).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Edges {
    pub top: Length,
    pub right: Length,
    pub bottom: Length,
    pub left: Length,
}

/// Per-side box values resolved to concrete pixels (`Auto` resolves to 0).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ResolvedEdges {
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
    pub left: f32,
}

impl Edges {
    /// Resolve every side against the containing block width (per CSS 2.1,
    /// vertical margins/padding also resolve against the *width*). `Auto`
    /// resolves to 0 here; auto-margin centering is handled in layout, which
    /// checks `Length::is_auto` before resolving.
    pub fn resolve(&self, containing: f32) -> ResolvedEdges {
        ResolvedEdges {
            top: self.top.resolve(containing, 0.0),
            right: self.right.resolve(containing, 0.0),
            bottom: self.bottom.resolve(containing, 0.0),
            left: self.left.resolve(containing, 0.0),
        }
    }
}

/// The computed style for one element.
#[derive(Debug, Clone, PartialEq)]
pub struct ComputedStyle {
    pub display: Display,
    pub color: Color,
    pub background: Color,
    pub font_size: f32,
    pub font_weight: FontWeight,
    pub font_style: FontStyle,
    pub monospace: bool,
    pub text_align: TextAlign,
    pub white_space: WhiteSpace,
    pub line_height: f32,
    pub width: Length,
    pub height: Length,
    pub margin: Edges,
    pub padding: Edges,
    pub border_width: Edges,
    pub border_color: Color,
    pub visible: bool,
    /// `max-width` / `min-width` / `min-height` (`Auto` = none).
    pub max_width: Length,
    pub min_width: Length,
    pub min_height: Length,
    pub position: Position,
    pub float: Float,
    /// `display: flex | inline-flex`: children are flex items.
    pub flex_container: bool,
    /// `flex-direction: column` (items stack like blocks).
    pub flex_column: bool,
    /// `flex-wrap: wrap`.
    pub flex_wrap: bool,
    /// `flex-grow` (the first number of `flex:` counts too).
    pub flex_grow: f32,
    /// `display: grid | inline-grid` with its column structure.
    pub grid_columns: GridColumns,
    /// `box-sizing: border-box`: an explicit width/height is the border box.
    pub box_sizing_border: bool,
    /// `overflow-x` / `overflow-y` is `hidden`/`clip`/`auto`/`scroll`:
    /// content past the box's explicit size on that axis is clipped, so a
    /// `height: 0; overflow: hidden` container hides its text (the
    /// collapsed-menu idiom on 258 of the corpus sites). Two flags because
    /// the longhands cascade independently (`overflow-x: hidden` then
    /// `overflow-x: visible` must end up not clipping).
    pub overflow_x_clips: bool,
    pub overflow_y_clips: bool,
    /// `max-height` (`Auto` = none).
    pub max_height: Length,
    /// CSS custom properties (`--name: value`) in scope for this element:
    /// inherited from the parent and overridden by the element's own
    /// declarations. Shared by `Rc` so a root with hundreds of tokens
    /// costs one clone per element that REDEFINES something, not per
    /// element. 373 of the 510 sites in the Chrome-referenced corpus drive
    /// their widths, colours and display values through `var()`.
    pub custom: Rc<HashMap<String, String>>,
}

impl FontWeight {
    /// Whether this weight rasterizes with the bold face.
    pub fn is_bold(self) -> bool {
        matches!(self, FontWeight::Bold)
    }
}

impl ComputedStyle {
    /// Whether the computed font style is italic.
    pub fn font_style_italic(&self) -> bool {
        self.font_style == FontStyle::Italic
    }

    /// Whether both horizontal margins are `auto` (block centering).
    pub fn margin_x_auto(&self) -> bool {
        self.margin.left.is_auto() && self.margin.right.is_auto()
    }
}

impl Default for ComputedStyle {
    fn default() -> Self {
        ComputedStyle {
            display: Display::Inline,
            color: Color::BLACK,
            background: Color::TRANSPARENT,
            font_size: 16.0,
            font_weight: FontWeight::Normal,
            font_style: FontStyle::Normal,
            monospace: false,
            text_align: TextAlign::Left,
            white_space: WhiteSpace::Normal,
            line_height: 1.2,
            width: Length::Auto,
            height: Length::Auto,
            margin: Edges::default(),
            padding: Edges::default(),
            border_width: Edges::default(),
            border_color: Color::BLACK,
            visible: true,
            max_width: Length::Auto,
            min_width: Length::Auto,
            min_height: Length::Auto,
            position: Position::Static,
            float: Float::None,
            flex_container: false,
            flex_column: false,
            flex_wrap: false,
            flex_grow: 0.0,
            grid_columns: GridColumns::None,
            box_sizing_border: false,
            overflow_x_clips: false,
            overflow_y_clips: false,
            max_height: Length::Auto,
            custom: Rc::new(HashMap::new()),
        }
    }
}

/// The user-agent stylesheet: HTML element defaults per WHATWG rendering
/// section, reduced to the properties we implement.
pub const UA_STYLESHEET: &str = r#"
html, body { display: block; }
body { margin: 8px; }
div, p, h1, h2, h3, h4, h5, h6, ul, ol, li, dl, dt, dd, blockquote, pre,
form, fieldset, legend, details, summary, address, article, aside, footer,
header, hgroup, main, nav, section, figure, figcaption, table, hr,
noscript, center, search, dialog, menu, dir, frameset, optgroup { display: block; }
li { display: list-item; }
table { display: table; }
tr { display: table-row; }
td, th { display: table-cell; padding: 1px; }
th { font-weight: bold; text-align: center; }
head, style, script, meta, link, title, base, template { display: none; }
[hidden] { display: none; }
h1 { font-size: 32px; font-weight: bold; margin: 21px 0; }
h2 { font-size: 24px; font-weight: bold; margin: 20px 0; }
h3 { font-size: 19px; font-weight: bold; margin: 18px 0; }
h4 { font-size: 16px; font-weight: bold; margin: 21px 0; }
h5 { font-size: 13px; font-weight: bold; margin: 22px 0; }
h6 { font-size: 11px; font-weight: bold; margin: 25px 0; }
p, blockquote, ul, ol, dl, pre { margin: 16px 0; }
blockquote { margin-left: 40px; margin-right: 40px; }
ul, ol { padding-left: 40px; }
dd { margin-left: 40px; }
b, strong { font-weight: bold; }
i, em, cite, var, dfn { font-style: italic; }
pre, code, kbd, samp, tt { font-family: monospace; }
pre { white-space: pre; }
a { color: #0000ee; }
mark { background: #ffff00; }
hr { border-width: 1px; margin: 8px 0; }
center { text-align: center; }
big { font-size: 19px; }
small { font-size: 13px; }
"#;

/// Collect the document's own stylesheets: every `<style>` block's text,
/// parsed in document order. (`<link rel=stylesheet>` requires network I/O
/// and is the embedding app's responsibility.)
pub fn document_stylesheets(doc: &Document) -> Vec<Stylesheet> {
    let mut sheets = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        if doc.node(n).as_element().map(|e| e.tag.as_str()) == Some("style") {
            sheets.push(css::parse_stylesheet(&doc.text_content(n)));
        }
    }
    sheets
}

/// Cascade + compute styles for every element in the document.
///
/// `author_sheets` are the document's stylesheets in source order. Inline
/// `style="..."` attributes are honored with the highest specificity, per the
/// cascade.
pub fn compute_styles(
    doc: &Document,
    author_sheets: &[Stylesheet],
) -> HashMap<NodeId, ComputedStyle> {
    let ua = css::parse_stylesheet(UA_STYLESHEET);
    let mut sheets: Vec<&Stylesheet> = Vec::with_capacity(author_sheets.len() + 1);
    sheets.push(&ua);
    sheets.extend(author_sheets.iter());

    let mut out: HashMap<NodeId, ComputedStyle> = HashMap::new();
    // Document order guarantees parents are computed before children, so
    // inheritance can read the parent's finished style.
    let root_style = ComputedStyle::default();
    for node in doc.descendants(NodeId::DOCUMENT) {
        let Some(_el) = doc.node(node).as_element() else {
            continue;
        };
        let parent_style = doc
            .node(node)
            .parent
            .and_then(|p| out.get(&p))
            .unwrap_or(&root_style);
        let decls = css::matching_declarations(doc, node, &sheets);
        let style = compute_one(parent_style, &decls);
        out.insert(node, style);
    }
    out
}

/// Inheritable properties copy from the parent; boxes reset per element.
fn inherit_from(parent: &ComputedStyle) -> ComputedStyle {
    ComputedStyle {
        display: Display::Inline,
        color: parent.color,
        background: Color::TRANSPARENT,
        font_size: parent.font_size,
        font_weight: parent.font_weight,
        font_style: parent.font_style,
        monospace: parent.monospace,
        text_align: parent.text_align,
        white_space: parent.white_space,
        line_height: parent.line_height,
        width: Length::Auto,
        height: Length::Auto,
        margin: Edges::default(),
        padding: Edges::default(),
        border_width: Edges::default(),
        border_color: parent.color,
        visible: parent.visible,
        max_width: Length::Auto,
        min_width: Length::Auto,
        min_height: Length::Auto,
        position: Position::Static,
        float: Float::None,
        flex_container: false,
        flex_column: false,
        flex_wrap: false,
        flex_grow: 0.0,
        grid_columns: GridColumns::None,
        box_sizing_border: false,
        overflow_x_clips: false,
        overflow_y_clips: false,
        max_height: Length::Auto,
        custom: parent.custom.clone(),
    }
}

fn compute_one(parent: &ComputedStyle, decls: &[(String, String)]) -> ComputedStyle {
    let mut s = inherit_from(parent);
    // Custom properties first (CSS Variables §2): they cascade like any
    // other property, inherit, and are substituted into the element's
    // other declarations. The element's own tokens are collected RAW and
    // then resolved against the complete map (inherited tokens plus every
    // own one), so `--a: var(--b); --b: 10px` works regardless of order. A
    // token whose reference cannot be substituted (undefined, or a cycle)
    // is invalid at computed-value time and is REMOVED, so a later
    // `var(--a, 10px)` takes its fallback exactly as the spec says (§3).
    let mut own_names: Vec<String> = Vec::new();
    for (name, value) in decls {
        if name.starts_with("--") {
            own_names.push(name.clone());
            let _ = value;
        }
    }
    if !own_names.is_empty() {
        let mut raw: HashMap<String, String> = (*parent.custom).clone();
        for (name, value) in decls {
            if name.starts_with("--") {
                raw.insert(name.clone(), value.trim().to_string());
            }
        }
        let mut resolved = raw.clone();
        for name in &own_names {
            let value = raw.get(name).cloned().unwrap_or_default();
            match substitute_vars(&value, &raw, 0) {
                Some(v) => {
                    resolved.insert(name.clone(), v);
                }
                None => {
                    resolved.remove(name);
                }
            }
        }
        s.custom = Rc::new(resolved);
    }
    for (name, value) in decls {
        if name.starts_with("--") {
            continue;
        }
        if value.contains("var(") {
            // A declaration whose `var()` cannot be substituted is invalid
            // at computed-value time (§3): the property computes to `unset`
            // — inherited for inherited properties, initial otherwise — so
            // an earlier UA or author declaration does NOT survive it, and
            // the raw `var(...)` text is never applied.
            match substitute_vars(value, &s.custom, 0) {
                Some(v) => apply_declaration(&mut s, parent, name, &v),
                None => apply_unset(&mut s, parent, name),
            }
        } else {
            apply_declaration(&mut s, parent, name, value);
        }
    }
    s
}

/// Apply `unset` to one property: inherited properties take the parent's
/// value, non-inherited ones their initial value. The template is the
/// freshly inherited style, which is exactly that split.
fn apply_unset(s: &mut ComputedStyle, parent: &ComputedStyle, name: &str) {
    let r = inherit_from(parent);
    match name {
        "display" => {
            s.display = r.display;
            s.flex_container = false;
            s.grid_columns = GridColumns::None;
        }
        "position" => s.position = r.position,
        "float" => s.float = r.float,
        "flex-direction" => s.flex_column = false,
        "flex-wrap" => s.flex_wrap = false,
        "flex-flow" => {
            s.flex_column = false;
            s.flex_wrap = false;
        }
        "flex" | "flex-grow" => s.flex_grow = 0.0,
        "grid-template-columns" => {
            if s.grid_columns != GridColumns::None {
                s.grid_columns = GridColumns::Count(1);
            }
        }
        "box-sizing" => s.box_sizing_border = false,
        "overflow" => {
            s.overflow_x_clips = false;
            s.overflow_y_clips = false;
        }
        "overflow-x" => s.overflow_x_clips = false,
        "overflow-y" => s.overflow_y_clips = false,
        "max-width" => s.max_width = r.max_width,
        "max-height" => s.max_height = r.max_height,
        "min-width" => s.min_width = r.min_width,
        "min-height" => s.min_height = r.min_height,
        "color" => s.color = r.color,
        "background" | "background-color" => s.background = r.background,
        "font-size" => s.font_size = r.font_size,
        "font-weight" => s.font_weight = r.font_weight,
        "font-style" => s.font_style = r.font_style,
        "font-family" => s.monospace = r.monospace,
        "text-align" => s.text_align = r.text_align,
        "white-space" => s.white_space = r.white_space,
        "line-height" => s.line_height = r.line_height,
        "width" => s.width = r.width,
        "height" => s.height = r.height,
        "margin" => s.margin = r.margin,
        "margin-top" => s.margin.top = r.margin.top,
        "margin-right" => s.margin.right = r.margin.right,
        "margin-bottom" => s.margin.bottom = r.margin.bottom,
        "margin-left" => s.margin.left = r.margin.left,
        "padding" => s.padding = r.padding,
        "padding-top" => s.padding.top = r.padding.top,
        "padding-right" => s.padding.right = r.padding.right,
        "padding-bottom" => s.padding.bottom = r.padding.bottom,
        "padding-left" => s.padding.left = r.padding.left,
        "border" | "border-width" => {
            s.border_width = r.border_width;
            s.border_color = r.border_color;
        }
        "border-top" => s.border_width.top = r.border_width.top,
        "border-right" => s.border_width.right = r.border_width.right,
        "border-bottom" => s.border_width.bottom = r.border_width.bottom,
        "border-left" => s.border_width.left = r.border_width.left,
        "border-color" => s.border_color = r.border_color,
        "visibility" => s.visible = r.visible,
        _ => {}
    }
}

/// The longest value `var()` substitution may produce, in bytes.
const MAX_VAR_EXPANDED_BYTES: usize = 16 * 1024;

/// How many `var()` references one substitution may resolve, counting
/// every reference met inside custom property values and fallbacks.
const MAX_VAR_REFERENCES: usize = 1024;

/// Replace every `var(--name[, fallback])` in `value` with the custom
/// property's value (or the fallback), repeating until none remain.
/// `None` when a reference has neither a value nor a fallback, or when
/// substitution does not terminate within a bounded depth (a cycle).
///
/// Also `None` when the substitution would exceed
/// [`MAX_VAR_EXPANDED_BYTES`] or resolve more than [`MAX_VAR_REFERENCES`]
/// references. Custom properties that each reference the previous one
/// several times expand exponentially inside the depth bound, in size
/// when they carry text and in work even when they expand to nothing; the
/// value is then treated as invalid at computed-value time, like a cycle.
pub fn substitute_vars(value: &str, custom: &HashMap<String, String>, depth: usize) -> Option<String> {
    let mut budget = MAX_VAR_REFERENCES;
    substitute_vars_within(value, custom, depth, &mut budget)
}

fn substitute_vars_within(
    value: &str,
    custom: &HashMap<String, String>,
    depth: usize,
    budget: &mut usize,
) -> Option<String> {
    if depth > 16 || value.len() > MAX_VAR_EXPANDED_BYTES {
        return None;
    }
    let Some(start) = value.find("var(") else {
        return Some(value.to_string());
    };
    *budget = budget.checked_sub(1)?;
    // The matching close paren, honoring nested functions in the fallback.
    let bytes = value.as_bytes();
    let mut level = 0i32;
    let mut end: Option<usize> = None;
    let mut i = start.checked_add(3)?;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'(' => level += 1,
            b')' => {
                level -= 1;
                if level == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let end = end?;
    let inner = value.get(start.checked_add(4)?..end)?;
    // `--name` then an optional fallback after the first depth-0 comma.
    let mut split: Option<usize> = None;
    let mut level = 0i32;
    for (j, b) in inner.bytes().enumerate() {
        match b {
            b'(' => level += 1,
            b')' => level -= 1,
            b',' if level == 0 => {
                split = Some(j);
                break;
            }
            _ => {}
        }
    }
    let (name, fallback) = match split {
        Some(j) => (inner.get(..j)?, inner.get(j.checked_add(1)?..)),
        None => (inner, None),
    };
    // Names are looked up as the declaration parser stores them
    // (lowercased), so `--Foo` and `--foo` meet the same key on both sides.
    let key = name.trim().to_ascii_lowercase();
    // The token's value may itself reference tokens: resolve it first (the
    // depth bound turns a cycle into `None`), and fall back when it cannot
    // be resolved — an invalid token is treated as absent (§3).
    let referenced = custom
        .get(&key)
        .and_then(|v| substitute_vars_within(v, custom, depth.saturating_add(1), budget));
    let replacement = match referenced {
        Some(v) => v,
        None => substitute_vars_within(fallback?.trim(), custom, depth.saturating_add(1), budget)?,
    };
    // Sibling references in the rest of the value do not deepen the chain.
    let tail = substitute_vars_within(value.get(end.checked_add(1)?..)?, custom, depth, budget)?;
    let prefix = value.get(..start)?;
    let len = prefix
        .len()
        .saturating_add(replacement.len())
        .saturating_add(tail.len());
    if len > MAX_VAR_EXPANDED_BYTES {
        return None;
    }
    Some(format!("{prefix}{replacement}{tail}"))
}

fn apply_declaration(s: &mut ComputedStyle, parent: &ComputedStyle, name: &str, value: &str) {
    let v = value.trim();
    match name {
        "display" => {
            // Flex and grid containers are block-level boxes whose CHILDREN
            // are laid out side by side; the container flag drives that in
            // layout while the display value stays a block.
            s.flex_container = matches!(v, "flex" | "inline-flex");
            if !matches!(v, "grid" | "inline-grid") {
                s.grid_columns = GridColumns::None;
            } else if s.grid_columns == GridColumns::None {
                // A grid with no template yet: one column until a
                // `grid-template-columns` declaration says otherwise.
                s.grid_columns = GridColumns::Count(1);
            }
            s.display = match v {
                "none" => Display::None,
                "block" | "flex" | "grid" | "flow-root" => Display::Block,
                "inline-block" | "inline-flex" | "inline-grid" => Display::InlineBlock,
                "list-item" => Display::ListItem,
                "table" => Display::Table,
                "table-row" => Display::TableRow,
                "table-cell" => Display::TableCell,
                "inline" => Display::Inline,
                _ => s.display,
            };
        }
        "position" => {
            s.position = match v {
                "absolute" => Position::Absolute,
                "fixed" => Position::Fixed,
                "relative" => Position::Relative,
                "sticky" => Position::Sticky,
                "static" => Position::Static,
                _ => s.position,
            };
        }
        "float" => {
            s.float = match v {
                "left" | "inline-start" => Float::Left,
                "right" | "inline-end" => Float::Right,
                "none" => Float::None,
                _ => s.float,
            };
        }
        "flex-direction" => {
            s.flex_column = v.starts_with("column");
        }
        "flex-wrap" => {
            s.flex_wrap = v.starts_with("wrap");
        }
        "flex-flow" => {
            for tok in v.split_whitespace() {
                if tok.starts_with("column") {
                    s.flex_column = true;
                } else if tok.starts_with("row") {
                    s.flex_column = false;
                } else if tok.starts_with("wrap") {
                    s.flex_wrap = true;
                } else if tok == "nowrap" {
                    s.flex_wrap = false;
                }
            }
        }
        "flex-grow" => {
            if let Ok(g) = v.parse::<f32>() {
                if g.is_finite() && g >= 0.0 {
                    s.flex_grow = g;
                }
            }
        }
        "flex" => {
            // `flex: <grow> [<shrink>] [<basis>]` | `auto` | `none` | `<basis>`.
            let first = v.split_whitespace().next().unwrap_or("");
            s.flex_grow = match first {
                "auto" => 1.0,
                "none" | "initial" => 0.0,
                _ => first
                    .parse::<f32>()
                    .ok()
                    .filter(|g| g.is_finite() && *g >= 0.0)
                    .unwrap_or(s.flex_grow),
            };
        }
        "grid-template-columns" => {
            s.grid_columns = parse_grid_columns(v);
        }
        "box-sizing" => {
            s.box_sizing_border = v == "border-box";
        }
        "overflow" => {
            // `overflow: <x> [<y>]`; one value sets both axes.
            let clips = |t: &str| matches!(t, "hidden" | "clip" | "auto" | "scroll");
            let mut it = v.split_whitespace();
            let x = it.next().unwrap_or("visible");
            let y = it.next().unwrap_or(x);
            s.overflow_x_clips = clips(x);
            s.overflow_y_clips = clips(y);
        }
        "overflow-x" => {
            s.overflow_x_clips = matches!(v, "hidden" | "clip" | "auto" | "scroll");
        }
        "overflow-y" => {
            s.overflow_y_clips = matches!(v, "hidden" | "clip" | "auto" | "scroll");
        }
        "max-height" => {
            if v == "none" {
                s.max_height = Length::Auto;
            } else if let Some(l) = parse_length(v) {
                s.max_height = l;
            }
        }
        "max-width" => {
            if v == "none" {
                s.max_width = Length::Auto;
            } else if let Some(l) = parse_length(v) {
                s.max_width = l;
            }
        }
        "min-width" => {
            if let Some(l) = parse_length(v) {
                s.min_width = l;
            }
        }
        "min-height" => {
            if let Some(l) = parse_length(v) {
                s.min_height = l;
            }
        }
        "color" => {
            if let Some(c) = parse_color(v) {
                s.color = c;
            }
        }
        "background" | "background-color" => {
            // Whole value first (handles `rgb(1, 2, 3)` with spaces), then the
            // first color-looking token of a shorthand list.
            if let Some(c) = parse_color(v) {
                s.background = c;
            } else if let Some(c) = v.split_whitespace().find_map(parse_color) {
                s.background = c;
            } else if v == "none" || v == "transparent" {
                s.background = Color::TRANSPARENT;
            }
        }
        "font-size" => {
            if let Some(px) = parse_font_size(v, parent.font_size) {
                // `font-size: 0` is a real value (the accessible-label
                // hiding idiom): it computes to 0 and the text takes no
                // space and paints nothing, as in Chrome.
                s.font_size = px.clamp(0.0, 512.0);
            }
        }
        "font-weight" => {
            s.font_weight = match v {
                "bold" | "bolder" => FontWeight::Bold,
                "normal" | "lighter" => FontWeight::Normal,
                _ => match v.parse::<u32>() {
                    Ok(n) if n >= 600 => FontWeight::Bold,
                    Ok(_) => FontWeight::Normal,
                    Err(_) => s.font_weight,
                },
            };
        }
        "font-style" => {
            s.font_style = match v {
                "italic" | "oblique" => FontStyle::Italic,
                "normal" => FontStyle::Normal,
                _ => s.font_style,
            };
        }
        "font-family" => {
            s.monospace = v.to_ascii_lowercase().contains("monospace")
                || v.to_ascii_lowercase().contains("courier");
        }
        "text-align" => {
            s.text_align = match v {
                "center" => TextAlign::Center,
                "right" | "end" => TextAlign::Right,
                "left" | "start" | "justify" => TextAlign::Left,
                _ => s.text_align,
            };
        }
        "white-space" => {
            s.white_space = match v {
                "pre" | "pre-wrap" => WhiteSpace::Pre,
                "nowrap" => WhiteSpace::NoWrap,
                "normal" | "pre-line" => WhiteSpace::Normal,
                _ => s.white_space,
            };
        }
        "line-height" => {
            if v == "normal" {
                s.line_height = 1.2;
            } else if let Ok(mult) = v.parse::<f32>() {
                if mult.is_finite() && mult > 0.0 {
                    s.line_height = mult.min(10.0);
                }
            } else if let Some(px) = parse_px(v) {
                if s.font_size > 0.0 {
                    s.line_height = (px / s.font_size).clamp(0.1, 10.0);
                }
            }
        }
        "width" => {
            if let Some(l) = parse_length(v) {
                s.width = l;
            }
        }
        "height" => {
            if let Some(l) = parse_length(v) {
                s.height = l;
            }
        }
        "margin" => apply_shorthand(v, &mut s.margin),
        "margin-top" => apply_side(v, &mut s.margin.top),
        "margin-right" => apply_side(v, &mut s.margin.right),
        "margin-bottom" => apply_side(v, &mut s.margin.bottom),
        "margin-left" => apply_side(v, &mut s.margin.left),
        "padding" => apply_shorthand(v, &mut s.padding),
        "padding-top" => apply_side(v, &mut s.padding.top),
        "padding-right" => apply_side(v, &mut s.padding.right),
        "padding-bottom" => apply_side(v, &mut s.padding.bottom),
        "padding-left" => apply_side(v, &mut s.padding.left),
        "border" | "border-top" | "border-right" | "border-bottom" | "border-left" => {
            // Shorthand: width style color, any order. "none" clears.
            let mut width: Option<Length> = None;
            let mut color: Option<Color> = None;
            let mut none = false;
            for tok in v.split_whitespace() {
                if tok == "none" || tok == "hidden" {
                    none = true;
                } else if let Some(px) = parse_px(tok) {
                    width = Some(Length::Px(px));
                } else if tok == "thin" {
                    width = Some(Length::Px(1.0));
                } else if tok == "medium" {
                    width = Some(Length::Px(3.0));
                } else if tok == "thick" {
                    width = Some(Length::Px(5.0));
                } else if let Some(c) = parse_color(tok) {
                    color = Some(c);
                }
            }
            let w = if none {
                Length::Px(0.0)
            } else {
                width.unwrap_or(Length::Px(3.0))
            };
            let apply_to: &mut [&mut Length] = &mut match name {
                "border-top" => vec![&mut s.border_width.top],
                "border-right" => vec![&mut s.border_width.right],
                "border-bottom" => vec![&mut s.border_width.bottom],
                "border-left" => vec![&mut s.border_width.left],
                _ => vec![
                    &mut s.border_width.top,
                    &mut s.border_width.right,
                    &mut s.border_width.bottom,
                    &mut s.border_width.left,
                ],
            };
            for slot in apply_to.iter_mut() {
                **slot = w;
            }
            if let Some(c) = color {
                s.border_color = c;
            }
        }
        "border-width" => apply_shorthand(v, &mut s.border_width),
        "border-color" => {
            if let Some(c) = parse_color(v) {
                s.border_color = c;
            }
        }
        "visibility" => {
            s.visible = v != "hidden" && v != "collapse";
        }
        _ => {}
    }
}

/// The column count of a `grid-template-columns` value: `repeat(N, …)`,
/// `repeat(auto-fill|auto-fit, minmax(<px>, …))`, or the number of track
/// tokens (line names in brackets skipped). Unparseable values keep one
/// column, which is what an unknown template degrades to.
fn parse_grid_columns(v: &str) -> GridColumns {
    let lower = v.to_ascii_lowercase();
    if lower == "none" {
        return GridColumns::Count(1);
    }
    if let Some(rest) = lower.strip_prefix("repeat(") {
        let args = rest.strip_suffix(')').unwrap_or(rest);
        let mut it = args.splitn(2, ',');
        let count = it.next().unwrap_or("").trim();
        let tracks = it.next().unwrap_or("").trim();
        if count == "auto-fill" || count == "auto-fit" {
            // minmax(<min>, …): the min track size decides how many fit.
            let min = tracks
                .strip_prefix("minmax(")
                .and_then(|m| m.split(',').next())
                .and_then(parse_px)
                .or_else(|| parse_px(tracks))
                .unwrap_or(0.0);
            return if min > 0.0 {
                GridColumns::AutoFill(min)
            } else {
                GridColumns::Count(1)
            };
        }
        return match count.parse::<u32>() {
            Ok(n) if n >= 1 => GridColumns::Count(n.min(64)),
            _ => GridColumns::Count(1),
        };
    }
    // Count depth-0 whitespace-separated tracks, skipping `[line-names]`.
    let mut n = 0u32;
    let mut depth = 0i32;
    let mut in_name = false;
    let mut in_token = false;
    for c in lower.chars() {
        match c {
            '[' => in_name = true,
            ']' => in_name = false,
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c.is_whitespace() && depth == 0 && !in_name => in_token = false,
            _ if !in_name => {
                if !in_token {
                    in_token = true;
                    n += 1;
                }
            }
            _ => {}
        }
    }
    GridColumns::Count(n.clamp(1, 64))
}

fn apply_side(v: &str, slot: &mut Length) {
    if let Some(l) = parse_length(v) {
        *slot = l;
    }
}

/// CSS 1-4 value shorthand expansion (top right bottom left).
fn apply_shorthand(v: &str, edges: &mut Edges) {
    let vals: Vec<Length> = v.split_whitespace().filter_map(parse_length).collect();
    match vals.len() {
        1 => {
            edges.top = vals[0];
            edges.right = vals[0];
            edges.bottom = vals[0];
            edges.left = vals[0];
        }
        2 => {
            edges.top = vals[0];
            edges.bottom = vals[0];
            edges.right = vals[1];
            edges.left = vals[1];
        }
        3 => {
            edges.top = vals[0];
            edges.right = vals[1];
            edges.left = vals[1];
            edges.bottom = vals[2];
        }
        4 => {
            edges.top = vals[0];
            edges.right = vals[1];
            edges.bottom = vals[2];
            edges.left = vals[3];
        }
        _ => {}
    }
}

/// Parse a CSS length: px/em/rem/pt/%/auto/0.
pub fn parse_length(v: &str) -> Option<Length> {
    let v = v.trim();
    if v == "auto" {
        return Some(Length::Auto);
    }
    if v == "0" {
        return Some(Length::Px(0.0));
    }
    if let Some(p) = v.strip_suffix('%') {
        return p
            .trim()
            .parse::<f32>()
            .ok()
            .filter(|f| f.is_finite())
            .map(Length::Percent);
    }
    parse_px(v).map(Length::Px)
}

/// Parse an absolute length to px. em/rem use the 16px root default (element
/// font-relative units are resolved separately where the context is known).
fn parse_px(v: &str) -> Option<f32> {
    let v = v.trim();
    let (num, unit) = split_unit(v)?;
    let n: f32 = num.parse().ok()?;
    if !n.is_finite() {
        return None;
    }
    let px = match unit.as_str() {
        "px" | "" => n,
        "em" | "rem" => n * 16.0,
        "pt" => n * 96.0 / 72.0,
        "pc" => n * 16.0,
        "in" => n * 96.0,
        "cm" => n * 96.0 / 2.54,
        "mm" => n * 96.0 / 25.4,
        "q" => n * 96.0 / 101.6,
        "ch" | "ex" => n * 8.0,
        // The layout viewport the corpus and the service render at:
        // 1280 x 720. `100vh` heroes are a page's first screen in Chrome.
        "vw" | "vmax" => n * 1280.0 / 100.0,
        "vh" | "vmin" | "svh" | "lvh" | "dvh" => n * 720.0 / 100.0,
        _ => return None,
    };
    Some(px)
}

fn parse_font_size(v: &str, parent_px: f32) -> Option<f32> {
    match v {
        "xx-small" => return Some(9.0),
        "x-small" => return Some(10.0),
        "small" => return Some(13.0),
        "medium" => return Some(16.0),
        "large" => return Some(18.0),
        "x-large" => return Some(24.0),
        "xx-large" => return Some(32.0),
        "smaller" => return Some(parent_px / 1.2),
        "larger" => return Some(parent_px * 1.2),
        _ => {}
    }
    let (num, unit) = split_unit(v)?;
    let n: f32 = num.parse().ok()?;
    if !n.is_finite() {
        return None;
    }
    match unit.as_str() {
        "em" => Some(n * parent_px),
        "rem" => Some(n * 16.0),
        "%" => Some(n / 100.0 * parent_px),
        _ => parse_px(v),
    }
}

fn split_unit(v: &str) -> Option<(&str, String)> {
    let idx = v
        .find(|c: char| c.is_ascii_alphabetic() || c == '%')
        .unwrap_or(v.len());
    let (num, unit) = v.split_at(idx);
    if num.is_empty() {
        return None;
    }
    Some((num, unit.to_ascii_lowercase()))
}

/// Parse a CSS color: named, #rgb, #rrggbb, #rrggbbaa, rgb()/rgba().
pub fn parse_color(v: &str) -> Option<Color> {
    let v = v.trim();
    if let Some(hex) = v.strip_prefix('#') {
        return parse_hex_color(hex);
    }
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("rgb") {
        let inner = lower
            .trim_start_matches("rgba")
            .trim_start_matches("rgb")
            .trim()
            .strip_prefix('(')?
            .strip_suffix(')')?;
        let parts: Vec<&str> = inner
            .split([',', '/', ' '])
            .filter(|s| !s.trim().is_empty())
            .collect();
        if parts.len() < 3 {
            return None;
        }
        let chan = |s: &str| -> Option<u8> {
            let s = s.trim();
            if let Some(p) = s.strip_suffix('%') {
                let f: f32 = p.parse().ok()?;
                Some((f.clamp(0.0, 100.0) * 2.55) as u8)
            } else {
                let f: f32 = s.parse().ok()?;
                Some(f.clamp(0.0, 255.0) as u8)
            }
        };
        let r = chan(parts[0])?;
        let g = chan(parts[1])?;
        let b = chan(parts[2])?;
        let a = if parts.len() > 3 {
            let s = parts[3].trim();
            if let Some(p) = s.strip_suffix('%') {
                let f: f32 = p.parse().ok()?;
                (f.clamp(0.0, 100.0) * 2.55) as u8
            } else {
                let f: f32 = s.parse().ok()?;
                (f.clamp(0.0, 1.0) * 255.0) as u8
            }
        } else {
            255
        };
        return Some(Color { r, g, b, a });
    }
    named_color(&lower)
}

fn parse_hex_color(hex: &str) -> Option<Color> {
    let h = hex.trim();
    let hv = |c: u8| -> Option<u8> {
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
            let r = hv(b[0])?;
            let g = hv(b[1])?;
            let bl = hv(b[2])?;
            let a = if b.len() == 4 { hv(b[3])? } else { 15 };
            Some(Color {
                r: r * 17,
                g: g * 17,
                b: bl * 17,
                a: a * 17,
            })
        }
        6 | 8 => {
            let r = hv(b[0])? * 16 + hv(b[1])?;
            let g = hv(b[2])? * 16 + hv(b[3])?;
            let bl = hv(b[4])? * 16 + hv(b[5])?;
            let a = if b.len() == 8 {
                hv(b[6])? * 16 + hv(b[7])?
            } else {
                255
            };
            Some(Color { r, g, b: bl, a })
        }
        _ => None,
    }
}

fn named_color(name: &str) -> Option<Color> {
    let c = match name {
        "black" => Color::rgb(0, 0, 0),
        "white" => Color::rgb(255, 255, 255),
        "red" => Color::rgb(255, 0, 0),
        "green" => Color::rgb(0, 128, 0),
        "blue" => Color::rgb(0, 0, 255),
        "yellow" => Color::rgb(255, 255, 0),
        "cyan" | "aqua" => Color::rgb(0, 255, 255),
        "magenta" | "fuchsia" => Color::rgb(255, 0, 255),
        "gray" | "grey" => Color::rgb(128, 128, 128),
        "silver" => Color::rgb(192, 192, 192),
        "maroon" => Color::rgb(128, 0, 0),
        "olive" => Color::rgb(128, 128, 0),
        "lime" => Color::rgb(0, 255, 0),
        "teal" => Color::rgb(0, 128, 128),
        "navy" => Color::rgb(0, 0, 128),
        "purple" => Color::rgb(128, 0, 128),
        "orange" => Color::rgb(255, 165, 0),
        "pink" => Color::rgb(255, 192, 203),
        "brown" => Color::rgb(165, 42, 42),
        "gold" => Color::rgb(255, 215, 0),
        "indigo" => Color::rgb(75, 0, 130),
        "violet" => Color::rgb(238, 130, 238),
        "khaki" => Color::rgb(240, 230, 140),
        "coral" => Color::rgb(255, 127, 80),
        "salmon" => Color::rgb(250, 128, 114),
        "turquoise" => Color::rgb(64, 224, 208),
        "beige" => Color::rgb(245, 245, 220),
        "ivory" => Color::rgb(255, 255, 240),
        "lavender" => Color::rgb(230, 230, 250),
        "crimson" => Color::rgb(220, 20, 60),
        "tomato" => Color::rgb(255, 99, 71),
        "orchid" => Color::rgb(218, 112, 214),
        "plum" => Color::rgb(221, 160, 221),
        "tan" => Color::rgb(210, 180, 140),
        "wheat" => Color::rgb(245, 222, 179),
        "snow" => Color::rgb(255, 250, 250),
        "seashell" => Color::rgb(255, 245, 238),
        "azure" => Color::rgb(240, 255, 255),
        "honeydew" => Color::rgb(240, 255, 240),
        "aliceblue" => Color::rgb(240, 248, 255),
        "ghostwhite" => Color::rgb(248, 248, 255),
        "whitesmoke" => Color::rgb(245, 245, 245),
        "gainsboro" => Color::rgb(220, 220, 220),
        "lightgray" | "lightgrey" => Color::rgb(211, 211, 211),
        "darkgray" | "darkgrey" => Color::rgb(169, 169, 169),
        "dimgray" | "dimgrey" => Color::rgb(105, 105, 105),
        "slategray" | "slategrey" => Color::rgb(112, 128, 144),
        "lightslategray" | "lightslategrey" => Color::rgb(119, 136, 153),
        "darkred" => Color::rgb(139, 0, 0),
        "darkgreen" => Color::rgb(0, 100, 0),
        "darkblue" => Color::rgb(0, 0, 139),
        "darkorange" => Color::rgb(255, 140, 0),
        "darkviolet" => Color::rgb(148, 0, 211),
        "deeppink" => Color::rgb(255, 20, 147),
        "deepskyblue" => Color::rgb(0, 191, 255),
        "dodgerblue" => Color::rgb(30, 144, 255),
        "firebrick" => Color::rgb(178, 34, 34),
        "forestgreen" => Color::rgb(34, 139, 34),
        "goldenrod" => Color::rgb(218, 165, 32),
        "hotpink" => Color::rgb(255, 105, 180),
        "indianred" => Color::rgb(205, 92, 92),
        "lawngreen" => Color::rgb(124, 252, 0),
        "lightblue" => Color::rgb(173, 216, 230),
        "lightcoral" => Color::rgb(240, 128, 128),
        "lightcyan" => Color::rgb(224, 255, 255),
        "lightgreen" => Color::rgb(144, 238, 144),
        "lightpink" => Color::rgb(255, 182, 193),
        "lightsalmon" => Color::rgb(255, 160, 122),
        "lightseagreen" => Color::rgb(32, 178, 170),
        "lightskyblue" => Color::rgb(135, 206, 250),
        "lightsteelblue" => Color::rgb(176, 196, 222),
        "lightyellow" => Color::rgb(255, 255, 224),
        "limegreen" => Color::rgb(50, 205, 50),
        "mediumblue" => Color::rgb(0, 0, 205),
        "mediumorchid" => Color::rgb(186, 85, 211),
        "mediumpurple" => Color::rgb(147, 112, 219),
        "mediumseagreen" => Color::rgb(60, 179, 113),
        "mediumslateblue" => Color::rgb(123, 104, 238),
        "mediumspringgreen" => Color::rgb(0, 250, 154),
        "mediumturquoise" => Color::rgb(72, 209, 204),
        "mediumvioletred" => Color::rgb(199, 21, 133),
        "midnightblue" => Color::rgb(25, 25, 112),
        "mintcream" => Color::rgb(245, 255, 250),
        "mistyrose" => Color::rgb(255, 228, 225),
        "moccasin" => Color::rgb(255, 228, 181),
        "navajowhite" => Color::rgb(255, 222, 173),
        "oldlace" => Color::rgb(253, 245, 230),
        "olivedrab" => Color::rgb(107, 142, 35),
        "orangered" => Color::rgb(255, 69, 0),
        "palegoldenrod" => Color::rgb(238, 232, 170),
        "palegreen" => Color::rgb(152, 251, 152),
        "paleturquoise" => Color::rgb(175, 238, 238),
        "palevioletred" => Color::rgb(219, 112, 147),
        "papayawhip" => Color::rgb(255, 239, 213),
        "peachpuff" => Color::rgb(255, 218, 185),
        "peru" => Color::rgb(205, 133, 63),
        "powderblue" => Color::rgb(176, 224, 230),
        "rosybrown" => Color::rgb(188, 143, 143),
        "royalblue" => Color::rgb(65, 105, 225),
        "saddlebrown" => Color::rgb(139, 69, 19),
        "sandybrown" => Color::rgb(244, 164, 96),
        "seagreen" => Color::rgb(46, 139, 87),
        "sienna" => Color::rgb(160, 82, 45),
        "skyblue" => Color::rgb(135, 206, 235),
        "slateblue" => Color::rgb(106, 90, 205),
        "springgreen" => Color::rgb(0, 255, 127),
        "steelblue" => Color::rgb(70, 130, 180),
        "thistle" => Color::rgb(216, 191, 216),
        "yellowgreen" => Color::rgb(154, 205, 50),
        "rebeccapurple" => Color::rgb(102, 51, 153),
        "transparent" => Color::TRANSPARENT,
        "currentcolor" | "inherit" | "initial" | "unset" => return None,
        _ => return None,
    };
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Custom properties that each reference the previous one several
    /// times ("billion laughs", PR #609). The chain stays inside the
    /// depth bound (16), so only a bound on the expanded size stops it.
    #[test]
    fn var_expansion_is_bounded_in_size() {
        let mut m = HashMap::new();
        m.insert("--v0".to_string(), "x".repeat(64));
        for n in 1..=15 {
            m.insert(format!("--v{n}"), format!("var(--v{p}) var(--v{p})", p = n - 1));
        }
        // Called directly: the vendored source may not spawn a thread (the
        // code gate refuses threads), and the reference budget bounds
        // the work, so a regression shows as a wrong answer or a slow test.
        let out = substitute_vars("var(--v15)", &m, 0).map(|v| v.len());
        assert_eq!(out, None, "a 2^15-fold expansion was produced instead of refused");
    }

    /// The same shape with values that expand to nothing: the output
    /// stays empty, so a size bound alone never trips, yet the naive
    /// substitution resolves 4^14 references. It must give up quickly.
    #[test]
    fn var_expansion_is_bounded_in_work() {
        let mut m = HashMap::new();
        m.insert("--v0".to_string(), "var(--none,)".to_string());
        for n in 1..=14 {
            let p = n - 1;
            m.insert(
                format!("--v{n}"),
                format!("var(--v{p})var(--v{p})var(--v{p})var(--v{p})"),
            );
        }
        let out = substitute_vars("var(--v14)", &m, 0);
        assert_eq!(out, None, "4^14 var() references were not refused");
    }

    /// The style module's own color parser, which the cascade uses for
    /// every color property (css.rs has a separate one with its own test).
    #[test]
    fn colors() {
        assert_eq!(parse_color("#fff"), Some(Color::WHITE));
        assert_eq!(parse_color("#000000"), Some(Color::BLACK));
        assert_eq!(parse_color("red"), Some(Color::rgb(255, 0, 0)));
        assert_eq!(parse_color("rgb(1, 2, 3)"), Some(Color::rgb(1, 2, 3)));
        assert_eq!(
            parse_color("rgba(255, 0, 0, 0.5)"),
            Some(Color {
                r: 255,
                g: 0,
                b: 0,
                a: 127
            })
        );
        assert_eq!(parse_color("#12345"), None);
        assert_eq!(parse_color("notacolor"), None);
    }

    #[test]
    fn lengths() {
        assert_eq!(parse_length("10px"), Some(Length::Px(10.0)));
        assert_eq!(parse_length("50%"), Some(Length::Percent(50.0)));
        assert_eq!(parse_length("auto"), Some(Length::Auto));
        assert_eq!(parse_length("2em"), Some(Length::Px(32.0)));
        assert_eq!(parse_length("junk"), None);
    }

    #[test]
    fn custom_properties_cascade_inherit_and_substitute() {
        use crate::browser_core::html;
        let doc = html::parse(
            r#"<style>
              :root { --w: 300px; --c: #ff0000; --pad: 4px; --box: var(--pad) calc(1px) }
              .col { width: var(--w); color: var(--c); --w: 120px; }
              .inner { width: var(--w); background: var(--missing, #00ff00); margin: var(--nope) }
              .dead { width: var(--undefined); }
            </style>
            <div class=col><p class=inner id=i>x</p></div><div class=dead id=d>y</div>"#,
        );
        let sheets = document_stylesheets(&doc);
        let styles = compute_styles(&doc, &sheets);
        let mut d = doc.clone();
        let col = d.find_tag("div").unwrap();
        let inner = d.get_element_by_id("i").unwrap();
        let dead = d.get_element_by_id("d").unwrap();
        // The element's own --w override wins for its own width…
        assert_eq!(styles[&col].width, Length::Px(120.0));
        assert_eq!(styles[&col].color, Color::rgb(255, 0, 0));
        // …and is what the child inherits.
        assert_eq!(styles[&inner].width, Length::Px(120.0));
        // Fallback when the token is undefined; no fallback → declaration dropped.
        assert_eq!(styles[&inner].background, Color::rgb(0, 255, 0));
        assert_eq!(styles[&inner].margin, Edges::default());
        assert_eq!(styles[&dead].width, Length::Auto);
        // Tokens are substituted inside other tokens.
        assert_eq!(styles[&col].custom.get("--box").map(String::as_str), Some("4px calc(1px)"));
        // A cycle terminates without resolving; with a fallback, the
        // fallback is used (the cyclic token is invalid, so absent).
        let mut m = HashMap::new();
        m.insert("--a".to_string(), "var(--b)".to_string());
        m.insert("--b".to_string(), "var(--a)".to_string());
        assert_eq!(substitute_vars("var(--a)", &m, 0), None);
        assert_eq!(
            substitute_vars("var(--a, 10px) var(--b, 2px)", &m, 0).as_deref(),
            Some("10px 2px")
        );
        // Declaration order does not matter: a token may reference one
        // declared later in the same rule.
        let doc = html::parse(
            "<style>#o { --x: var(--y); --y: 7px; --cyc: var(--cyc); width: var(--x); height: var(--cyc, 3px) }</style><div id=o>z</div>",
        );
        let sheets = document_stylesheets(&doc);
        let styles = compute_styles(&doc, &sheets);
        let mut d = doc.clone();
        let o = d.get_element_by_id("o").unwrap();
        assert_eq!(styles[&o].width, Length::Px(7.0));
        assert_eq!(styles[&o].height, Length::Px(3.0));
        assert!(styles[&o].custom.get("--cyc").is_none(), "cyclic token is invalid");
    }

    #[test]
    fn shorthand_expansion() {
        let mut e = Edges::default();
        apply_shorthand("1px 2px 3px 4px", &mut e);
        assert_eq!(e.top, Length::Px(1.0));
        assert_eq!(e.right, Length::Px(2.0));
        assert_eq!(e.bottom, Length::Px(3.0));
        assert_eq!(e.left, Length::Px(4.0));
        apply_shorthand("5px", &mut e);
        assert_eq!(e.top, Length::Px(5.0));
        assert_eq!(e.left, Length::Px(5.0));
    }
}
