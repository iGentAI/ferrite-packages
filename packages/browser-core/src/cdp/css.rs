//! The CSS domain: computed and matched styles, sheet edits and coverage.

use super::super::dom::NodeId;
use super::{CdpBrowser, CdpCommand, CdpError, JsonValue, Session, cdp_to_node, invalid, method_not_found};

impl CdpBrowser {
    pub(super) fn css_command(
        &mut self,
        cmd: &CdpCommand,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "CSS.enable" | "CSS.disable" => Ok(JsonValue::obj(vec![])),
            "CSS.getComputedStyleForNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let page = self.page_for(cmd)?;
                let s = page.style_of(cdp_to_node(node_id));
                let display = match s.display {
                    super::super::style::Display::Inline => "inline",
                    super::super::style::Display::Block => "block",
                    super::super::style::Display::InlineBlock => "inline-block",
                    super::super::style::Display::ListItem => "list-item",
                    super::super::style::Display::Table => "table",
                    super::super::style::Display::TableRow => "table-row",
                    super::super::style::Display::TableCell => "table-cell",
                    super::super::style::Display::None => "none",
                };
                let props: Vec<(&str, String)> = vec![
                    ("display", display.to_string()),
                    ("color", css_color(&s.color)),
                    ("background-color", css_color(&s.background)),
                    ("font-size", format!("{}px", s.font_size)),
                    (
                        "font-weight",
                        if matches!(s.font_weight, super::super::style::FontWeight::Bold) {
                            "700".to_string()
                        } else {
                            "400".to_string()
                        },
                    ),
                    (
                        "font-style",
                        if matches!(s.font_style, super::super::style::FontStyle::Normal) {
                            "normal".to_string()
                        } else {
                            "italic".to_string()
                        },
                    ),
                    (
                        "text-align",
                        match s.text_align {
                            super::super::style::TextAlign::Left => "left".to_string(),
                            super::super::style::TextAlign::Center => "center".to_string(),
                            super::super::style::TextAlign::Right => "right".to_string(),
                        },
                    ),
                    (
                        "white-space",
                        match s.white_space {
                            super::super::style::WhiteSpace::Normal => "normal".to_string(),
                            super::super::style::WhiteSpace::Pre => "pre".to_string(),
                            super::super::style::WhiteSpace::NoWrap => "nowrap".to_string(),
                        },
                    ),
                    ("line-height", format!("{}", s.line_height)),
                    (
                        "visibility",
                        if s.visible {
                            "visible".to_string()
                        } else {
                            "hidden".to_string()
                        },
                    ),
                ];
                Ok(JsonValue::obj(vec![(
                    "computedStyle",
                    JsonValue::Arr(
                        props
                            .into_iter()
                            .map(|(name, value)| {
                                JsonValue::obj(vec![
                                    ("name", JsonValue::str(name)),
                                    ("value", JsonValue::str(value)),
                                ])
                            })
                            .collect(),
                    ),
                )]))
            }
            "CSS.getMatchedStylesForNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let page = self.page_for(cmd)?;
                let node = cdp_to_node(node_id);
                let mut matched: Vec<JsonValue> = Vec::new();
                for sheet in &page.stylesheets {
                    for rule in &sheet.rules {
                        for sel in &rule.selectors {
                            if super::super::css::matches(&page.doc, node, sel) {
                                let props: Vec<JsonValue> = rule
                                    .declarations
                                    .iter()
                                    .map(|d| {
                                        JsonValue::obj(vec![
                                            ("name", JsonValue::str(d.name.clone())),
                                            ("value", JsonValue::str(d.value.clone())),
                                            ("important", JsonValue::Bool(d.important)),
                                        ])
                                    })
                                    .collect();
                                let text = selector_text(sel);
                                matched.push(JsonValue::obj(vec![
                                    (
                                        "matchingSelectors",
                                        JsonValue::Arr(vec![JsonValue::Num(0.0)]),
                                    ),
                                    (
                                        "rule",
                                        JsonValue::obj(vec![
                                            (
                                                "selectorList",
                                                JsonValue::obj(vec![
                                                    (
                                                        "selectors",
                                                        JsonValue::Arr(vec![JsonValue::obj(
                                                            vec![(
                                                                "text",
                                                                JsonValue::str(text.clone()),
                                                            )],
                                                        )]),
                                                    ),
                                                    ("text", JsonValue::str(text)),
                                                ]),
                                            ),
                                            ("origin", JsonValue::str("regular")),
                                            (
                                                "style",
                                                JsonValue::obj(vec![
                                                    (
                                                        "cssProperties",
                                                        JsonValue::Arr(props),
                                                    ),
                                                    (
                                                        "shorthandEntries",
                                                        JsonValue::Arr(vec![]),
                                                    ),
                                                ]),
                                            ),
                                        ]),
                                    ),
                                ]));
                                break;
                            }
                        }
                    }
                }
                // The element's inline style attribute, parsed as declarations.
                let inline_props: Vec<JsonValue> = page
                    .doc
                    .get(node)
                    .and_then(|n| n.as_element())
                    .and_then(|e| e.attr("style"))
                    .map(|style| {
                        style
                            .split(';')
                            .filter_map(|decl| decl.split_once(':'))
                            .map(|(k, v)| {
                                JsonValue::obj(vec![
                                    ("name", JsonValue::str(k.trim())),
                                    ("value", JsonValue::str(v.trim())),
                                    ("important", JsonValue::Bool(false)),
                                ])
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(JsonValue::obj(vec![
                    ("matchedCSSRules", JsonValue::Arr(matched)),
                    (
                        "inlineStyle",
                        JsonValue::obj(vec![
                            ("cssProperties", JsonValue::Arr(inline_props)),
                            ("shorthandEntries", JsonValue::Arr(vec![])),
                        ]),
                    ),
                ]))
            }
            "CSS.createStyleSheet" => {
                let frame_id = cmd
                    .params
                    .get("frameId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("frameId required"))?;
                let session = self.session_for(cmd)?;
                if frame_id != session.target_id {
                    return Err(invalid("no such frame"));
                }
                let id = format!("sheet-{}", session.next_sheet_id);
                session.next_sheet_id = session.next_sheet_id.wrapping_add(1);
                session.created_sheets.push((id.clone(), String::new()));
                Ok(JsonValue::obj(vec![("styleSheetId", JsonValue::str(id))]))
            }
            "CSS.setStyleSheetText" => {
                let id = cmd
                    .params
                    .get("styleSheetId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("styleSheetId required"))?
                    .to_string();
                let text = cmd
                    .params
                    .get("text")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("text required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let Some(slot) = session.created_sheets.iter_mut().find(|(i, _)| i == &id) else {
                    return Err(invalid("no such style sheet"));
                };
                slot.1 = text;
                Ok(JsonValue::obj(vec![]))
            }
            "CSS.getStyleSheetText" => {
                let id = cmd
                    .params
                    .get("styleSheetId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("styleSheetId required"))?;
                let session = self.session_for(cmd)?;
                let text = sheet_text(session, id).ok_or_else(|| invalid("no such style sheet"))?;
                Ok(JsonValue::obj(vec![("text", JsonValue::str(text))]))
            }
            "CSS.addRule" => {
                let id = cmd
                    .params
                    .get("styleSheetId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("styleSheetId required"))?
                    .to_string();
                let rule_text = cmd
                    .params
                    .get("ruleText")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("ruleText required"))?
                    .to_string();
                if cmd.params.get("location").is_none() {
                    return Err(invalid("location required"));
                }
                let session = self.session_for(cmd)?;
                let Some(slot) = session.created_sheets.iter_mut().find(|(i, _)| i == &id) else {
                    return Err(invalid("only client-created style sheets are editable"));
                };
                if !slot.1.is_empty() && !slot.1.ends_with('\n') {
                    slot.1.push('\n');
                }
                slot.1.push_str(&rule_text);
                let parsed = super::super::css::parse_stylesheet(&rule_text);
                let Some(rule) = parsed.rules.first() else {
                    return Err(invalid("ruleText is not a style rule"));
                };
                Ok(JsonValue::obj(vec![("rule", css_rule_json(rule, Some(&id)))]))
            }
            "CSS.setStyleTexts" => {
                let edits = match cmd.params.get("edits") {
                    Some(JsonValue::Arr(a)) => a.clone(),
                    _ => return Err(invalid("edits required")),
                };
                let session = self.session_for(cmd)?;
                let mut styles: Vec<JsonValue> = Vec::new();
                for edit in &edits {
                    let id = edit
                        .get("styleSheetId")
                        .and_then(JsonValue::as_str)
                        .ok_or_else(|| invalid("styleSheetId required"))?;
                    let text = edit
                        .get("text")
                        .and_then(JsonValue::as_str)
                        .ok_or_else(|| invalid("text required"))?;
                    // Inline styles are addressed as `inline-<nodeId>`: the edit
                    // rewrites the element's style attribute.
                    if let Some(node) = id.strip_prefix("inline-") {
                        let node_id: f64 = node.parse().map_err(|_| invalid("bad inline style id"))?;
                        session
                            .doc
                            .borrow_mut()
                            .set_attr(cdp_to_node(node_id), "style", text);
                        styles.push(inline_style_json(text, Some(id)));
                        continue;
                    }
                    let Some(slot) = session.created_sheets.iter_mut().find(|(i, _)| i == id)
                    else {
                        return Err(invalid("no such style sheet"));
                    };
                    slot.1 = text.to_string();
                    styles.push(inline_style_json(text, Some(id)));
                }
                Ok(JsonValue::obj(vec![("styles", JsonValue::Arr(styles))]))
            }
            "CSS.getInlineStylesForNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow();
                let Some(el) = doc.get(cdp_to_node(node_id)).and_then(|n| n.as_element()) else {
                    return Err(invalid("no such element"));
                };
                let style = el.attr("style").unwrap_or("");
                let id = format!("inline-{}", node_id as u64);
                Ok(JsonValue::obj(vec![
                    ("inlineStyle", inline_style_json(style, Some(&id))),
                    (
                        "attributesStyle",
                        JsonValue::obj(vec![
                            ("cssProperties", JsonValue::Arr(vec![])),
                            ("shorthandEntries", JsonValue::Arr(vec![])),
                        ]),
                    ),
                ]))
            }
            "CSS.setEffectivePropertyValueForNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let name = cmd
                    .params
                    .get("propertyName")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("propertyName required"))?
                    .trim()
                    .to_ascii_lowercase();
                let value = cmd
                    .params
                    .get("value")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("value required"))?
                    .trim()
                    .to_string();
                let session = self.session_for(cmd)?;
                let mut doc = session.doc.borrow_mut();
                let id = cdp_to_node(node_id);
                let Some(existing) = doc
                    .get(id)
                    .and_then(|n| n.as_element())
                    .map(|e| e.attr("style").unwrap_or("").to_string())
                else {
                    return Err(invalid("no such element"));
                };
                // The inline declaration is the most specific author rule an
                // element can carry, so setting it there makes the value
                // effective in the cascade.
                let mut decls: Vec<(String, String)> = existing
                    .split(';')
                    .filter_map(|d| d.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .filter(|(k, _)| !k.is_empty())
                    .collect();
                decls.retain(|(k, _)| k != &name);
                decls.push((name, value));
                let joined = decls
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                doc.set_attr(id, "style", &joined);
                Ok(JsonValue::obj(vec![]))
            }
            "CSS.collectClassNames" => {
                let id = cmd
                    .params
                    .get("styleSheetId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("styleSheetId required"))?;
                let session = self.session_for(cmd)?;
                let text = sheet_text(session, id).ok_or_else(|| invalid("no such style sheet"))?;
                let parsed = super::super::css::parse_stylesheet(&text);
                let mut names: Vec<String> = Vec::new();
                for rule in &parsed.rules {
                    for sel in &rule.selectors {
                        for (compound, _) in &sel.parts {
                            for c in &compound.classes {
                                if !names.iter().any(|n| n == c) {
                                    names.push(c.clone());
                                }
                            }
                        }
                    }
                }
                Ok(JsonValue::obj(vec![(
                    "classNames",
                    JsonValue::Arr(names.into_iter().map(JsonValue::str).collect()),
                )]))
            }
            "CSS.getMediaQueries" => {
                let session = self.session_for(cmd)?;
                let width = session.viewport_width as f64;
                let height = session.viewport_height;
                let mut medias: Vec<JsonValue> = Vec::new();
                for (id, text) in sheet_sources(session) {
                    for query in media_query_texts(&text) {
                        medias.push(JsonValue::obj(vec![
                            ("text", JsonValue::str(query.clone())),
                            ("source", JsonValue::str("mediaRule")),
                            ("styleSheetId", JsonValue::str(id.clone())),
                            (
                                "mediaList",
                                JsonValue::Arr(vec![JsonValue::obj(vec![
                                    ("expressions", JsonValue::Arr(vec![])),
                                    (
                                        "active",
                                        JsonValue::Bool(
                                            !super::super::css::parse_stylesheet_with_env(
                                                &format!("@media {query} {{ x {{ y: z }} }}"),
                                                super::super::css::MediaEnv {
                                                    width: width as f32,
                                                    height,
                                                },
                                            )
                                            .rules
                                            .is_empty(),
                                        ),
                                    ),
                                ])]),
                            ),
                        ]));
                    }
                }
                Ok(JsonValue::obj(vec![("medias", JsonValue::Arr(medias))]))
            }
            "CSS.setMediaText" | "CSS.setRuleSelector" | "CSS.setKeyframeKey"
            | "CSS.setPropertyRulePropertyName" => {
                // Rule-level edits address rules by source range inside a
                // sheet; the engine keeps parsed rules without source
                // positions, so these edits cannot be applied.
                self.session_for(cmd)?;
                Err(CdpError {
                    code: -32000,
                    message: "source-range rule edits are not supported; edit the sheet text with CSS.setStyleSheetText".to_string(),
                })
            }
            "CSS.getBackgroundColors" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let page = self.page_for(cmd)?;
                let node = cdp_to_node(node_id);
                // Walk up to the first ancestor with an opaque background —
                // that is the color the node's text is drawn over.
                let mut cur = Some(node);
                let mut colors: Vec<JsonValue> = Vec::new();
                while let Some(n) = cur {
                    let s = page.style_of(n);
                    if s.background.a > 0 {
                        colors.push(JsonValue::str(css_color(&s.background)));
                        break;
                    }
                    cur = page.doc.get(n).and_then(|x| x.parent);
                }
                if colors.is_empty() {
                    let canvas = page
                        .layout
                        .canvas_background
                        .unwrap_or(super::super::css::Color::WHITE);
                    colors.push(JsonValue::str(css_color(&canvas)));
                }
                let s = page.style_of(node);
                Ok(JsonValue::obj(vec![
                    ("backgroundColors", JsonValue::Arr(colors)),
                    ("computedFontSize", JsonValue::str(format!("{}px", s.font_size))),
                    (
                        "computedFontWeight",
                        JsonValue::str(if matches!(s.font_weight, super::super::style::FontWeight::Bold) {
                            "700"
                        } else {
                            "400"
                        }),
                    ),
                ]))
            }
            "CSS.getPlatformFontsForNode" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let page = self.page_for(cmd)?;
                let node = cdp_to_node(node_id);
                let glyphs: usize = page
                    .layout
                    .boxes
                    .iter()
                    .filter(|b| b.node == Some(node))
                    .filter_map(|b| match &b.content {
                        super::super::layout::BoxContent::Text { text, .. } => Some(text.chars().count()),
                        _ => None,
                    })
                    .sum();
                let s = page.style_of(node);
                // One embedded bitmap face paints everything; monospace is a
                // metric variant of it.
                let family = if s.monospace { "browser-core mono" } else { "browser-core sans" };
                Ok(JsonValue::obj(vec![(
                    "fonts",
                    JsonValue::Arr(vec![JsonValue::obj(vec![
                        ("familyName", JsonValue::str(family)),
                        ("postScriptName", JsonValue::str(family.replace(' ', "-"))),
                        ("isCustomFont", JsonValue::Bool(false)),
                        ("glyphCount", JsonValue::Num(glyphs as f64)),
                    ])]),
                )]))
            }
            "CSS.forcePseudoState" => {
                let node_id = cmd
                    .params
                    .get("nodeId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("nodeId required"))?;
                let classes: Vec<String> = match cmd.params.get("forcedPseudoClasses") {
                    Some(JsonValue::Arr(a)) => a
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_string)
                        .collect(),
                    _ => return Err(invalid("forcedPseudoClasses required")),
                };
                let session = self.session_for(cmd)?;
                let handle = cdp_to_node(node_id).index();
                session.forced_pseudo.retain(|(h, _)| *h != handle);
                if !classes.is_empty() {
                    session.forced_pseudo.push((handle, classes));
                }
                Ok(JsonValue::obj(vec![]))
            }
            "CSS.forceStartingStyle" => {
                if cmd.params.get("nodeId").and_then(JsonValue::as_f64).is_none()
                    || cmd.params.get("forced").and_then(JsonValue::as_bool).is_none()
                {
                    return Err(invalid("nodeId and forced required"));
                }
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "CSS.startRuleUsageTracking" => {
                let session = self.session_for(cmd)?;
                session.rule_tracking = true;
                Ok(JsonValue::obj(vec![]))
            }
            "CSS.takeCoverageDelta" | "CSS.stopRuleUsageTracking" => {
                let stop = cmd.method == "CSS.stopRuleUsageTracking";
                let page = self.page_for(cmd)?;
                let session = self.session_for(cmd)?;
                if !session.rule_tracking {
                    return Err(CdpError {
                        code: -32000,
                        message: "rule usage tracking is not active".to_string(),
                    });
                }
                if stop {
                    session.rule_tracking = false;
                }
                // A rule is "used" when some element matches one of its
                // selectors in the current document.
                let mut used: Vec<JsonValue> = Vec::new();
                for (sheet_id, text) in sheet_sources(session) {
                    let parsed = super::super::css::parse_stylesheet(&text);
                    let mut offset = 0usize;
                    for rule in &parsed.rules {
                        let hit = page.doc.descendants(NodeId::DOCUMENT).any(|n| {
                            rule.selectors.iter().any(|sel| super::super::css::matches(&page.doc, n, sel))
                        });
                        let span = rule.declarations.len().max(1);
                        used.push(JsonValue::obj(vec![
                            ("styleSheetId", JsonValue::str(sheet_id.clone())),
                            ("startOffset", JsonValue::Num(offset as f64)),
                            ("endOffset", JsonValue::Num((offset + span) as f64)),
                            ("used", JsonValue::Bool(hit)),
                        ]));
                        offset += span;
                    }
                }
                let key = if stop { "ruleUsage" } else { "coverage" };
                Ok(JsonValue::obj(vec![
                    (key, JsonValue::Arr(used)),
                    ("timestamp", JsonValue::Num(0.0)),
                ]))
            }
            other => Err(method_not_found(other)),
        }
    }
}

/// Reconstruct a selector's text from its parsed parts (best-effort: tag,
/// #id, .classes, [attrs]; pseudo-classes are elided).
fn selector_text(sel: &super::super::css::Selector) -> String {
    let mut out = String::new();
    for (compound, comb) in &sel.parts {
        match comb {
            Some(super::super::css::Combinator::Descendant) => out.push(' '),
            Some(super::super::css::Combinator::Child) => out.push_str(" > "),
            Some(super::super::css::Combinator::NextSibling) => out.push_str(" + "),
            Some(super::super::css::Combinator::SubsequentSibling) => out.push_str(" ~ "),
            None => {}
        }
        if compound.universal {
            out.push('*');
        }
        if let Some(t) = &compound.tag {
            out.push_str(t);
        }
        if let Some(i) = &compound.id {
            out.push('#');
            out.push_str(i);
        }
        for c in &compound.classes {
            out.push('.');
            out.push_str(c);
        }
        for a in &compound.attrs {
            out.push('[');
            out.push_str(&a.name);
            out.push(']');
        }
    }
    out
}

/// The text of a stylesheet by CDP id: `doc-N` is the document's N-th
/// `<style>` block, `link-N` the N-th fetched `<link rel=stylesheet>`, and
/// `sheet-N` a client-created sheet.
fn sheet_text(session: &Session, id: &str) -> Option<String> {
    sheet_sources(session)
        .into_iter()
        .find(|(i, _)| i == id)
        .map(|(_, t)| t)
}

/// Every stylesheet the session cascades, with its CDP id, in cascade order.
fn sheet_sources(session: &Session) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let doc = session.doc.borrow();
    let mut n = 0usize;
    for node in doc.descendants(NodeId::DOCUMENT) {
        if doc.get(node).and_then(|x| x.as_element()).map(|e| e.tag == "style").unwrap_or(false) {
            n = n.saturating_add(1);
            out.push((format!("doc-{n}"), doc.text_content(node)));
        }
    }
    for (i, css) in session.stylesheets.iter().enumerate() {
        out.push((format!("link-{}", i + 1), css.clone()));
    }
    for (id, css) in &session.created_sheets {
        out.push((id.clone(), css.clone()));
    }
    out
}

/// The `@media` query texts in a stylesheet source, in order.
fn media_query_texts(css: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = css;
    while let Some(i) = rest.find("@media") {
        let after = rest.get(i + 6..).unwrap_or("");
        let end = after.find('{').unwrap_or(after.len());
        let q = after.get(..end).unwrap_or("").trim();
        if !q.is_empty() {
            out.push(q.to_string());
        }
        rest = after.get(end..).unwrap_or("");
    }
    out
}

/// A CDP `CSS.CSSRule` for one parsed style rule.
fn css_rule_json(rule: &super::super::css::StyleRule, sheet_id: Option<&str>) -> JsonValue {
    let texts: Vec<String> = rule.selectors.iter().map(selector_text).collect();
    let props: Vec<JsonValue> = rule
        .declarations
        .iter()
        .map(|d| {
            JsonValue::obj(vec![
                ("name", JsonValue::str(d.name.clone())),
                ("value", JsonValue::str(d.value.clone())),
                ("important", JsonValue::Bool(d.important)),
            ])
        })
        .collect();
    let mut entries = vec![
        (
            "selectorList",
            JsonValue::obj(vec![
                (
                    "selectors",
                    JsonValue::Arr(
                        texts
                            .iter()
                            .map(|t| JsonValue::obj(vec![("text", JsonValue::str(t.clone()))]))
                            .collect(),
                    ),
                ),
                ("text", JsonValue::str(texts.join(", "))),
            ]),
        ),
        ("origin", JsonValue::str("regular")),
        (
            "style",
            JsonValue::obj(vec![
                ("cssProperties", JsonValue::Arr(props)),
                ("shorthandEntries", JsonValue::Arr(vec![])),
            ]),
        ),
    ];
    if let Some(id) = sheet_id {
        entries.insert(0, ("styleSheetId", JsonValue::str(id)));
    }
    JsonValue::obj(entries)
}

/// A CDP `CSS.CSSStyle` for an inline declaration list.
fn inline_style_json(style: &str, sheet_id: Option<&str>) -> JsonValue {
    let props: Vec<JsonValue> = style
        .split(';')
        .filter_map(|decl| decl.split_once(':'))
        .map(|(k, v)| {
            JsonValue::obj(vec![
                ("name", JsonValue::str(k.trim())),
                ("value", JsonValue::str(v.trim())),
                ("important", JsonValue::Bool(false)),
            ])
        })
        .collect();
    let mut entries = vec![
        ("cssProperties", JsonValue::Arr(props)),
        ("shorthandEntries", JsonValue::Arr(vec![])),
        ("cssText", JsonValue::str(style)),
    ];
    if let Some(id) = sheet_id {
        entries.insert(0, ("styleSheetId", JsonValue::str(id)));
    }
    JsonValue::obj(entries)
}

/// A CSS color string the computed-style surface reports.
fn css_color(c: &super::super::css::Color) -> String {
    if c.a == 255 {
        format!("rgb({}, {}, {})", c.r, c.g, c.b)
    } else {
        format!("rgba({}, {}, {}, {})", c.r, c.g, c.b, (c.a as f32) / 255.0)
    }
}
