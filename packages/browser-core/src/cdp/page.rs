//! The Page domain: navigation, history, screenshots, extraction and dialogs.

use std::collections::HashMap;
use std::rc::Rc;
use super::super::api::Page;
use super::super::api::PageOptions;
use super::super::dom::Document;
use super::super::dom::NodeId;
use super::{CdpBrowser, CdpCommand, CdpError, CdpEvent, CdpHost, JsonValue, all_sheets, b64, invalid, method_not_found, resolve_url};

impl CdpBrowser {
    pub(super) fn page_command(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Page.enable" | "Page.disable" => Ok(JsonValue::obj(vec![])),
            "Page.getFrameTree" => {
                let session = self.session_for(cmd)?;
                let frame = JsonValue::obj(vec![
                    ("id", JsonValue::str(session.target_id.clone())),
                    ("loaderId", JsonValue::str("loader-1")),
                    ("url", JsonValue::str(session.url.clone())),
                    ("domainAndRegistry", JsonValue::str("")),
                    ("securityOrigin", JsonValue::str("")),
                    ("mimeType", JsonValue::str("text/html")),
                ]);
                Ok(JsonValue::obj(vec![(
                    "frameTree",
                    JsonValue::obj(vec![
                        ("frame", frame),
                        ("childFrames", JsonValue::Arr(vec![])),
                    ]),
                )]))
            }
            "Page.navigate" => {
                let url = cmd
                    .params
                    .get("url")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("url required"))?
                    .to_string();
                self.navigate_session(cmd, host, url, None, "GET", None, true, true)
            }
            "Page.reload" => {
                let url = {
                    let session = self.session_for(cmd)?;
                    session.url.clone()
                };
                self.navigate_session(cmd, host, url, None, "GET", None, false, true)
            }
            "Page.captureScreenshot" => {
                // Parameter surface: `format` — png is native; jpeg/webp
                // answer a typed unsupported error rather than silently
                // substituting. `clip` scales via its `scale` member and
                // bounds the capture height. `captureBeyondViewport` is
                // accepted (full-page capture is this engine's default; the
                // raster height cap still applies).
                let format = cmd
                    .params
                    .get("format")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("png");
                if format != "png" {
                    return Err(CdpError {
                        code: -32000,
                        message: format!(
                            "unsupported format '{format}': this engine encodes png only"
                        ),
                    });
                }
                let clip = cmd.params.get("clip").cloned();
                let clip_scale = clip
                    .as_ref()
                    .and_then(|c| c.get("scale"))
                    .and_then(JsonValue::as_f64)
                    .map(|v| (v as f32).clamp(0.1, 3.0))
                    .unwrap_or(1.0);
                let clip_height = clip
                    .as_ref()
                    .and_then(|c| c.get("height"))
                    .and_then(JsonValue::as_f64)
                    .map(|v| v as f32)
                    .filter(|v| *v > 0.0);
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow().clone();
                let width = session.viewport_width;
                let height = session.viewport_height;
                let sheets = all_sheets(session);
                let backdrop = session.background_override;
                // Decode images for the capture, resolving relative srcs
                // against the page URL (never a synthetic string).
                let mut images: HashMap<String, Rc<super::super::image::DecodedImage>> = HashMap::new();
                let srcs: Vec<String> = doc_img_srcs(&doc);
                let base = session.url.clone();
                let fetchable = srcs
                    .into_iter()
                    .filter_map(|src| resolve_url(&base, &src).map(|abs| (src, abs)))
                    .take(20);
                for (src, abs) in fetchable {
                    if let Ok(bytes) = host.fetch_bytes(&abs) {
                        if let Some(decoded) = super::super::image::decode(&bytes) {
                            images.insert(src, Rc::new(decoded));
                        }
                    }
                }
                let sheet_refs: Vec<&str> = sheets.iter().map(String::as_str).collect();
                let default_cap = PageOptions::default().max_screenshot_height;
                let capture_opts = PageOptions {
                    viewport_width: width,
                    viewport_height: height,
                    scale: clip_scale,
                    max_screenshot_height: clip_height
                        .map(|h| h.min(default_cap))
                        .unwrap_or(default_cap),
                };
                let mut page = Page::from_document(doc, capture_opts, &sheet_refs, &images);
                // Emulation.setDefaultBackgroundColorOverride paints the
                // canvas when the page itself sets no background.
                if page.layout.canvas_background.is_none() {
                    if let Some((r, g, b, a)) = backdrop {
                        page.layout.canvas_background = Some(super::super::css::Color { r, g, b, a });
                    }
                }
                // Projected-cost gate BEFORE any pixel allocation — the same
                // poison-pill defence the host's render action carries: an
                // oversized allocation under a hard process memory cap kills
                // the app mid-command and the queue redelivers the message.
                let gate_scale = page.options.scale.max(0.1);
                let w = (page.layout.page_width * gate_scale).ceil().max(1.0) as u32;
                let h = (page
                    .layout
                    .page_height
                    .min(page.options.max_screenshot_height)
                    * gate_scale)
                    .ceil()
                    .max(1.0) as u32;
                let projected = super::super::png::projected_encode_cost(w, h);
                let budget = host.screenshot_cost_budget();
                if projected > budget {
                    return Err(CdpError {
                        code: -32000,
                        message: format!(
                            "screenshot of {w}x{h} px needs ~{} MiB (budget {} MiB); reduce the viewport or clip",
                            projected / (1024 * 1024),
                            budget / (1024 * 1024)
                        ),
                    });
                }
                let png = page.screenshot_png();
                Ok(JsonValue::obj(vec![("data", JsonValue::str(b64(&png)))]))
            }
            // Vendor extension (agent-first surface): markdown extraction
            // over the live session DOM. `params.clean` (default true here —
            // this method exists for agents) resolves URLs against the
            // session URL, filters CSS-hidden subtrees and prepends
            // front-matter; `params.mainContent` isolates <main>/<article>.
            "Page.extractMarkdown" => {
                let clean = cmd
                    .params
                    .get("clean")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(true);
                let main_content = cmd
                    .params
                    .get("mainContent")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                let session = self.session_for(cmd)?;
                let doc = session.doc.borrow().clone();
                let width = session.viewport_width;
                let height = session.viewport_height;
                let sheets = all_sheets(session);
                let url = session.url.clone();
                let sheet_refs: Vec<&str> = sheets.iter().map(String::as_str).collect();
                let page = Page::from_document(
                    doc,
                    PageOptions {
                        viewport_width: width,
                        viewport_height: height,
                        ..PageOptions::default()
                    },
                    &sheet_refs,
                    &HashMap::new(),
                );
                let md = if clean {
                    let base = (url != "about:blank" && !url.is_empty()).then_some(url.as_str());
                    page.markdown_clean(base, main_content)
                } else {
                    page.markdown()
                };
                Ok(JsonValue::obj(vec![
                    ("markdown", JsonValue::str(md)),
                    ("title", JsonValue::str(page.title())),
                ]))
            }
            "Page.setDocumentContent" => {
                let html_src = cmd
                    .params
                    .get("html")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("html required"))?
                    .to_string();
                let url = {
                    let session = self.session_for(cmd)?;
                    session.url.clone()
                };
                self.navigate_session(cmd, host, url, Some(html_src), "GET", None, false, false)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Page.getNavigationHistory" => {
                let session = self.session_for(cmd)?;
                let entries: Vec<JsonValue> = session
                    .history
                    .iter()
                    .enumerate()
                    .map(|(i, u)| {
                        JsonValue::obj(vec![
                            ("id", JsonValue::Num(i as f64)),
                            ("url", JsonValue::str(u.clone())),
                            ("userTypedURL", JsonValue::str(u.clone())),
                            ("title", JsonValue::str("")),
                            ("transitionType", JsonValue::str("typed")),
                        ])
                    })
                    .collect();
                Ok(JsonValue::obj(vec![
                    (
                        "currentIndex",
                        JsonValue::Num(session.history_index as f64),
                    ),
                    ("entries", JsonValue::Arr(entries)),
                ]))
            }
            "Page.navigateToHistoryEntry" => {
                let entry = cmd
                    .params
                    .get("entryId")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("entryId required"))? as usize;
                let url = {
                    let session = self.session_for(cmd)?;
                    session
                        .history
                        .get(entry)
                        .cloned()
                        .ok_or_else(|| invalid("no such history entry"))?
                };
                self.navigate_session(cmd, host, url, None, "GET", None, false, true)?;
                let session = self.session_for(cmd)?;
                session.history_index = entry;
                Ok(JsonValue::obj(vec![]))
            }
            "Page.addScriptToEvaluateOnNewDocument" => {
                let source = cmd
                    .params
                    .get("source")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("source required"))?
                    .to_string();
                let session = self.session_for(cmd)?;
                let id = format!("script-{}", session.next_script_id);
                session.next_script_id = session.next_script_id.wrapping_add(1);
                session.new_doc_scripts.push((id.clone(), source));
                Ok(JsonValue::obj(vec![("identifier", JsonValue::str(id))]))
            }
            "Page.removeScriptToEvaluateOnNewDocument" => {
                let id = cmd
                    .params
                    .get("identifier")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let session = self.session_for(cmd)?;
                session.new_doc_scripts.retain(|(i, _)| i != &id);
                Ok(JsonValue::obj(vec![]))
            }
            "Page.getLayoutMetrics" => {
                let page = self.page_for(cmd)?;
                let (pw, ph) = (
                    page.layout.page_width as f64,
                    page.layout.page_height as f64,
                );
                let (vw, vh) = {
                    let session = self.session_for(cmd)?;
                    (
                        session.viewport_width as f64,
                        session.viewport_height as f64,
                    )
                };
                let content = JsonValue::obj(vec![
                    ("x", JsonValue::Num(0.0)),
                    ("y", JsonValue::Num(0.0)),
                    ("width", JsonValue::Num(pw)),
                    ("height", JsonValue::Num(ph)),
                ]);
                let layout_viewport = JsonValue::obj(vec![
                    ("pageX", JsonValue::Num(0.0)),
                    ("pageY", JsonValue::Num(0.0)),
                    ("clientWidth", JsonValue::Num(vw)),
                    ("clientHeight", JsonValue::Num(vh)),
                ]);
                let visual_viewport = JsonValue::obj(vec![
                    ("offsetX", JsonValue::Num(0.0)),
                    ("offsetY", JsonValue::Num(0.0)),
                    ("pageX", JsonValue::Num(0.0)),
                    ("pageY", JsonValue::Num(0.0)),
                    ("clientWidth", JsonValue::Num(vw)),
                    ("clientHeight", JsonValue::Num(vh)),
                    ("scale", JsonValue::Num(1.0)),
                    ("zoom", JsonValue::Num(1.0)),
                ]);
                Ok(JsonValue::obj(vec![
                    ("contentSize", content.clone()),
                    ("cssContentSize", content),
                    ("layoutViewport", layout_viewport.clone()),
                    ("cssLayoutViewport", layout_viewport),
                    ("visualViewport", visual_viewport.clone()),
                    ("cssVisualViewport", visual_viewport),
                ]))
            }
            "Page.stopLoading" | "Page.bringToFront" | "Page.setLifecycleEventsEnabled" => {
                Ok(JsonValue::obj(vec![]))
            }
            "Page.resetNavigationHistory" => {
                let session = self.session_for(cmd)?;
                let current = session.url.clone();
                session.history = vec![current];
                session.history_index = 0;
                Ok(JsonValue::obj(vec![]))
            }
            "Page.close" => {
                let tid = {
                    let session = self.session_for(cmd)?;
                    session.target_id.clone()
                };
                self.targets.remove(&tid);
                self.target_contexts.remove(&tid);
                self.sessions.retain(|_, s| s.target_id != tid);
                self.events.push(CdpEvent {
                    method: "Target.targetDestroyed".to_string(),
                    params: JsonValue::obj(vec![("targetId", JsonValue::str(tid))]),
                    session_id: None,
                });
                Ok(JsonValue::obj(vec![]))
            }
            "Page.handleJavaScriptDialog" => {
                let accept = cmd
                    .params
                    .get("accept")
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| invalid("accept required"))?;
                let prompt_text = cmd
                    .params
                    .get("promptText")
                    .and_then(JsonValue::as_str)
                    .map(str::to_string);
                {
                    let session = self.session_for(cmd)?;
                    session.dialog_accept = accept;
                    session.dialog_prompt = prompt_text;
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Page.setBypassCSP" => {
                let enabled = cmd
                    .params
                    .get("enabled")
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| invalid("enabled required"))?;
                let session = self.session_for(cmd)?;
                session.bypass_csp = enabled;
                Ok(JsonValue::obj(vec![]))
            }
            "Page.setInterceptFileChooserDialog" => {
                let enabled = cmd
                    .params
                    .get("enabled")
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| invalid("enabled required"))?;
                let session = self.session_for(cmd)?;
                session.intercept_file_chooser = enabled;
                Ok(JsonValue::obj(vec![]))
            }
            "Page.createIsolatedWorld" => {
                let frame_id = cmd
                    .params
                    .get("frameId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("frameId required"))?;
                let session = self.session_for(cmd)?;
                if frame_id != session.target_id {
                    return Err(invalid("no such frame"));
                }
                // One realm per page: the engine has no isolated worlds, so
                // the "world" is the page's own execution context.
                Ok(JsonValue::obj(vec![(
                    "executionContextId",
                    JsonValue::Num(1.0),
                )]))
            }
            "Page.getAppManifest" => {
                let session = self.session_for(cmd)?;
                let href = {
                    let doc = session.doc.borrow();
                    doc.descendants(NodeId::DOCUMENT)
                        .filter_map(|n| doc.get(n).and_then(|x| x.as_element()))
                        .find(|e| {
                            e.tag == "link"
                                && e.attr("rel")
                                    .map(|r| r.split_whitespace().any(|w| w == "manifest"))
                                    .unwrap_or(false)
                        })
                        .and_then(|e| e.attr("href").map(str::to_string))
                };
                let base = session.url.clone();
                match href.and_then(|h| resolve_url(&base, &h)) {
                    Some(url) => match host.fetch_document(&url) {
                        Ok(data) => Ok(JsonValue::obj(vec![
                            ("url", JsonValue::str(url)),
                            ("errors", JsonValue::Arr(vec![])),
                            ("data", JsonValue::str(data)),
                        ])),
                        Err(e) => Ok(JsonValue::obj(vec![
                            ("url", JsonValue::str(url)),
                            (
                                "errors",
                                JsonValue::Arr(vec![JsonValue::obj(vec![
                                    ("message", JsonValue::str(e)),
                                    ("critical", JsonValue::Num(1.0)),
                                    ("line", JsonValue::Num(0.0)),
                                    ("column", JsonValue::Num(0.0)),
                                ])]),
                            ),
                        ])),
                    },
                    None => Ok(JsonValue::obj(vec![
                        ("url", JsonValue::str("")),
                        ("errors", JsonValue::Arr(vec![])),
                    ])),
                }
            }
            "Page.printToPDF" => {
                let page = self.page_for(cmd)?;
                let lines = wrap_lines(&page.text(), 80);
                let pdf = text_pdf(&lines);
                Ok(JsonValue::obj(vec![("data", JsonValue::str(b64(&pdf)))]))
            }
            other => Err(method_not_found(other)),
        }
    }
}

/// A minimal, valid PDF 1.4 document laying `lines` out in 12pt Helvetica on
/// US Letter pages (the `Page.printToPDF` body: the engine has no vector
/// backend, so the print is the page's text flow rather than its raster).
fn text_pdf(lines: &[String]) -> Vec<u8> {
    let per_page = 48usize;
    let empty: [String; 0] = [];
    let pages: Vec<&[String]> = if lines.is_empty() {
        vec![&empty[..]]
    } else {
        lines.chunks(per_page).collect()
    };
    let mut objs: Vec<Vec<u8>> = Vec::new();
    let mut kids = String::new();
    for i in 0..pages.len() {
        kids.push_str(&format!("{} 0 R ", 4 + i * 2));
    }
    objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objs.push(
        format!(
            "<< /Type /Pages /Kids [{kids}] /Count {} >>",
            pages.len()
        )
        .into_bytes(),
    );
    objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());
    for (i, chunk) in pages.iter().enumerate() {
        let content_id = 5 + i * 2;
        objs.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                 /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );
        let mut stream = String::from("BT /F1 12 Tf 14 TL 72 720 Td\n");
        for line in chunk.iter() {
            stream.push('(');
            for ch in line.chars() {
                match ch {
                    '(' | ')' | '\\' => {
                        stream.push('\\');
                        stream.push(ch);
                    }
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => stream.push('?'),
                    c => stream.push(c),
                }
            }
            stream.push_str(") Tj T*\n");
        }
        stream.push_str("ET");
        objs.push(
            format!(
                "<< /Length {} >>\nstream\n{stream}\nendstream",
                stream.len()
            )
            .into_bytes(),
        );
    }
    let mut out: Vec<u8> = b"%PDF-1.4\n".to_vec();
    let mut offsets: Vec<usize> = Vec::new();
    for (i, body) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
    );
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Wrap extracted page text into print lines of at most `width` characters.
fn wrap_lines(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let mut cur = String::new();
        for word in raw.split_whitespace() {
            if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
                out.push(core::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        out.push(cur);
    }
    out
}

fn doc_img_srcs(doc: &Document) -> Vec<String> {
    let mut out = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        if let Some(el) = doc.node(n).as_element() {
            if el.tag == "img" {
                if let Some(src) = el.attr("src") {
                    out.push(src.to_string());
                }
            }
        }
    }
    out
}
