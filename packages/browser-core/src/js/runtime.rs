//! runtime — the top-level page-script driver: build a realm, install the
//! globals (`window`, `document`, `console`, timers, `fetch`/XHR), execute
//! every `<script>` in document order against the shared arena DOM, then
//! drain the microtask queue and virtual-clock timers.
//!
//! The consumer supplies a [`HostHooks`] implementation for network and
//! console sinks; the engine itself performs no I/O. Script errors are
//! collected per script, never panics, and never abort the page.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::super::dom::{Document, NodeData, NodeId};
use super::dom_bindings;
use super::interp::{to_display, HostHooks, Interp, Scope};
use super::parser;

/// The outcome of running a page's scripts.
#[derive(Debug, Default)]
pub struct ScriptRunReport {
    /// Scripts found (external scripts without fetched source are skipped).
    pub scripts_found: usize,
    /// Scripts that ran to completion.
    pub scripts_ok: usize,
    /// (script index, error message) for scripts that threw or failed to parse.
    pub errors: Vec<(usize, String)>,
    /// console.* lines captured during the run, as (level, message).
    pub console: Vec<(String, String)>,
    /// Number of timer callbacks fired during the virtual event loop.
    pub timers_fired: u32,
    /// Interpreter steps charged across every script, the event loop and
    /// the load events (the sum of what each budget window consumed), so a
    /// budget exhaustion can be read as a cost, not only as an error.
    pub steps_used: u64,
}

/// Limits for one script run.
#[derive(Clone)]
pub struct RunLimits {
    /// Interpreter step budget PER SCRIPT (and for each event-loop phase).
    /// Sized for real bundles, not toy pages: DevDocs' Prism build walks
    /// 84 language grammars through `insertBefore`/DFS at page load and
    /// legitimately costs 5.5M steps (Node needs the same 23,000 DFS frames
    /// for it), so 5M cut a correct program short. The wall-clock budget is
    /// the bound on real time; this one stops a single runaway loop.
    pub step_budget: u64,
    /// Virtual-clock horizon for timers (ms): setTimeout beyond this never
    /// fires. 10s of virtual time covers real pages' startup work.
    pub max_virtual_ms: f64,
    /// The page URL `location` reports (`about:blank` when absent). Scripts
    /// branch on `location.hostname` / `.pathname` constantly, so a render
    /// of a fetched page passes its URL here.
    pub page_url: Option<String>,
    /// Wall-clock budget for the WHOLE run (every script, the event loop
    /// and the load events), in milliseconds. The step budget bounds one
    /// script; a page with seventy scripts still needs a bound on the sum,
    /// or a heavy bundle holds the render for minutes. Scripts that have
    /// not started when the clock runs out are skipped and reported.
    pub max_wall_ms: u64,
    /// The native stack the script run may consume on the CALLING thread
    /// before a deep recursion throws its RangeError. The default is safe
    /// on a 2 MiB thread; an embedder that runs the page through
    /// A native embedder can pass `interp::DEEP_STACK_BUDGET_BYTES`
    /// so minified recursive helpers reach Chrome-like depths.
    pub stack_budget_bytes: usize,
    /// The embedder's monotonic-milliseconds clock. Every wall-clock budget
    /// here runs on it; without one the wall budgets are not enforced and
    /// `step_budget` / `max_virtual_ms` are the only bounds — which is the
    /// constrained-platform reality, where the app hands its injected
    /// context clock through and nothing else may read time.
    pub monotonic: Option<super::interp::MonotonicMs>,
}

impl std::fmt::Debug for RunLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunLimits")
            .field("step_budget", &self.step_budget)
            .field("max_virtual_ms", &self.max_virtual_ms)
            .field("page_url", &self.page_url)
            .field("max_wall_ms", &self.max_wall_ms)
            .field("stack_budget_bytes", &self.stack_budget_bytes)
            .field("monotonic", &self.monotonic.is_some())
            .finish()
    }
}

impl Default for RunLimits {
    fn default() -> Self {
        RunLimits {
            step_budget: 20_000_000,
            max_virtual_ms: 10_000.0,
            page_url: None,
            max_wall_ms: 20_000,
            stack_budget_bytes: super::interp::DEFAULT_STACK_BUDGET_BYTES,
            monotonic: None,
        }
    }
}

/// The persistent state of a page's JS realm after its scripts ran: the
/// global scope chain and global object (where `var`s, functions and
/// `window.x` live), the registered event listeners, and focus. A CDP
/// session keeps one of these per page so `Runtime.evaluate`, `Input`
/// events and later script runs all see the same world — prototypes travel
/// with the objects themselves (`Rc`), so values created under an earlier
/// interpreter instance keep working under a later one.
///
/// Both listener tables persist: `node_listeners` (element and document
/// targets, keyed by node handle) and `window_listeners` (the window
/// target), so a `window.addEventListener("resize", …)` registered by one
/// script run still fires when a later `Runtime.evaluate` or `Input`
/// command dispatches the event. The timer table and the virtual clock
/// persist too: a `setTimeout` armed by one `Runtime.evaluate` is what a
/// later `Runtime.awaitPromise` drives to completion, and timer ids stay
/// unique across commands so a `clearTimeout` from a later command finds
/// the timer an earlier one armed. Pending microtasks persist for the same
/// reason: a promise reaction queued by one command (an `await` inside a
/// `Runtime.evaluate` that hands the promise back) is what the next
/// command's drain runs, not something a fresh interpreter may drop.
#[derive(Clone, Default)]
pub struct Realm {
    pub scope: Option<super::interp::ScopeRef>,
    pub global: Option<super::value::ObjRef>,
    pub node_listeners: HashMap<(usize, String), Vec<super::value::JsValue>>,
    pub window_listeners: HashMap<String, Vec<super::value::JsValue>>,
    pub focused: Option<usize>,
    /// The node-wrapper identity table (see `Interp::node_wrappers`).
    pub node_wrappers: HashMap<usize, super::value::ObjRef>,
    /// Live timers (`Interp::timers`, fired and cleared ones dropped).
    pub timers: Vec<super::interp::Timer>,
    /// The next timer id (`Interp::next_timer_id_pub`); 0 means "fresh".
    pub next_timer_id: u32,
    /// The virtual clock (`Interp::now_ms`).
    pub now_ms: f64,
    /// Microtasks queued and not yet run (`Interp::microtasks`).
    pub microtasks: std::collections::VecDeque<super::interp::Job>,
}

impl Realm {
    /// Adopt this realm into a fresh interpreter (intrinsics are rebuilt; the
    /// scope chain, global object, listeners, focus, timers and clock are
    /// the realm's own).
    pub fn adopt_into(&self, interp: &mut Interp) {
        if let (Some(scope), Some(global)) = (&self.scope, &self.global) {
            interp.global_scope = scope.clone();
            interp.global_object = global.clone();
        }
        interp.node_listeners = self.node_listeners.clone();
        interp.listeners = self.window_listeners.clone();
        interp.focused = self.focused;
        interp.node_wrappers = self.node_wrappers.clone();
        interp.timers = self.timers.clone();
        if self.next_timer_id > 0 {
            interp.next_timer_id_pub = self.next_timer_id;
        }
        interp.now_ms = interp.now_ms.max(self.now_ms);
        interp.microtasks.extend(self.microtasks.iter().cloned());
    }

    /// Capture the interpreter's realm state after a run.
    pub fn capture_from(interp: &Interp) -> Realm {
        Realm {
            scope: Some(interp.global_scope.clone()),
            global: Some(interp.global_object.clone()),
            node_listeners: interp.node_listeners.clone(),
            window_listeners: interp.listeners.clone(),
            focused: interp.focused,
            node_wrappers: interp.node_wrappers.clone(),
            timers: interp.timers.iter().filter(|t| !t.cancelled).cloned().collect(),
            next_timer_id: interp.next_timer_id_pub,
            now_ms: interp.now_ms,
            microtasks: interp.microtasks.clone(),
        }
    }

    /// Whether the realm has been created (a page ran, or an evaluate ran).
    pub fn is_live(&self) -> bool {
        self.scope.is_some() && self.global.is_some()
    }
}

/// The most console lines a run keeps, and the longest message kept per
/// line. A page whose timer logs on every tick (ad loaders retrying a
/// blocked endpoint do exactly this) would otherwise grow the report until
/// allocation failed: the render died with "memory allocation of N bytes
/// failed" on three corpus sites. Past the cap one final line records how
/// many were dropped.
pub const MAX_CONSOLE_LINES: usize = 2_000;
pub const MAX_CONSOLE_MESSAGE_CHARS: usize = 4_096;

/// Collected console sink so the report owns the lines after the run.
struct ConsoleCapture<'h> {
    inner: &'h mut dyn HostHooks,
    lines: Rc<RefCell<Vec<(String, String)>>>,
    dropped: usize,
}

impl<'h> HostHooks for ConsoleCapture<'h> {
    fn fetch(
        &mut self,
        url: &str,
        method: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        self.inner.fetch(url, method, headers, body)
    }
    fn console(&mut self, level: &str, message: &str) {
        let msg: String = message.chars().take(MAX_CONSOLE_MESSAGE_CHARS).collect();
        {
            let mut lines = self.lines.borrow_mut();
            if lines.len() < MAX_CONSOLE_LINES {
                lines.push((level.to_string(), msg.clone()));
            } else {
                self.dropped = self.dropped.saturating_add(1);
                if let Some(last) = lines.last_mut() {
                    if last.0 == "engine" {
                        last.1 = format!("{} further console line(s) dropped (cap {MAX_CONSOLE_LINES})", self.dropped);
                    } else {
                        lines.push(("engine".to_string(), format!("1 further console line(s) dropped (cap {MAX_CONSOLE_LINES})")));
                    }
                }
            }
        }
        // The embedder's own sink still sees every line, truncated to the
        // same length; it decides its own retention.
        self.inner.console(level, &msg);
    }
    fn random_fill(&mut self, dest: &mut [u8]) -> Result<(), String> {
        self.inner.random_fill(dest)
    }
}

/// Only classic scripts run: JSON, module and template payloads do not.
fn is_classic_script(el: &super::super::dom::ElementData) -> bool {
    let stype = el.attr("type").unwrap_or("").trim().to_ascii_lowercase();
    el.tag == "script"
        && (stype.is_empty() || stype == "text/javascript" || stype == "application/javascript")
}

/// Extract inline scripts (and external ones whose source the embedder has
/// pre-fetched into `external`) in document order.
pub fn collect_scripts(doc: &Document, external: &HashMap<String, String>) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        let Some(el) = doc.node(n).as_element() else {
            continue;
        };
        if !is_classic_script(el) {
            continue;
        }
        if let Some(src) = el.attr("src") {
            if let Some(fetched) = external.get(src) {
                out.push((n.index(), fetched.clone()));
            }
            continue;
        }
        let mut source = String::new();
        for c in doc.children(n) {
            if let NodeData::Text(t) = &doc.node(c).data {
                source.push_str(t);
            }
        }
        if !source.trim().is_empty() {
            out.push((n.index(), source));
        }
    }
    out
}

/// The `src` attribute values of external classic `<script>` tags in
/// document order, parsed from raw HTML. The embedder fetches these through
/// its scoped egress and passes them to [`run_page_scripts`] as `external`.
pub fn external_script_srcs(html_src: &str) -> Vec<String> {
    let doc = super::super::html::parse(html_src);
    let mut out = Vec::new();
    for n in doc.descendants(NodeId::DOCUMENT) {
        let Some(el) = doc.node(n).as_element() else {
            continue;
        };
        if !is_classic_script(el) {
            continue;
        }
        if let Some(src) = el.attr("src") {
            if !src.is_empty() {
                out.push(src.to_string());
            }
        }
    }
    out
}

/// Run every page script against `doc`, mutating it in place.
///
/// `external` maps `<script src>` values to pre-fetched source (the embedder
/// owns network access). Returns the run report; the mutated DOM is the
/// caller's `doc`, which layout/extraction/screenshots then consume.
pub fn run_page_scripts(
    doc: Rc<RefCell<Document>>,
    external: &HashMap<String, String>,
    hooks: &mut dyn HostHooks,
    limits: RunLimits,
) -> ScriptRunReport {
    let mut realm = Realm::default();
    run_page_scripts_in_realm(doc, external, hooks, limits, &mut realm)
}

/// Run every page script against `doc` INSIDE `realm`: a live realm (one a
/// CDP `Page.addScriptToEvaluateOnNewDocument` script already populated) is
/// adopted, a fresh one is created, and the realm is captured back after
/// the run so later `Runtime.evaluate` / `Input` commands see the page's
/// globals, listeners and focus. The scripts are skipped when there are
/// none, and the realm is then left untouched.
pub fn run_page_scripts_in_realm(
    doc: Rc<RefCell<Document>>,
    external: &HashMap<String, String>,
    hooks: &mut dyn HostHooks,
    limits: RunLimits,
    realm: &mut Realm,
) -> ScriptRunReport {
    let mut report = ScriptRunReport::default();
    let scripts = collect_scripts(&doc.borrow(), external);
    report.scripts_found = scripts.len();
    if scripts.is_empty() {
        return report;
    }

    let lines: Rc<RefCell<Vec<(String, String)>>> = Rc::new(RefCell::new(Vec::new()));
    let mut capture = ConsoleCapture {
        inner: hooks,
        lines: lines.clone(),
        dropped: 0,
    };

    let mut interp = Interp::new(&mut capture);
    interp.step_budget = limits.step_budget;
    interp.stack_base = super::interp::stack_mark();
    interp.stack_budget_bytes = limits.stack_budget_bytes;
    if realm.is_live() {
        realm.adopt_into(&mut interp);
    }
    interp.dom = Some(doc.clone());
    dom_bindings::install_document(&mut interp);
    if let Some(url) = &limits.page_url {
        interp.set_location(url);
    }
    // The document's own scripts are "already started": a loader that
    // re-inserts one (jQuery's `domManip` moves scripts it finds in
    // markup) must not run it again. Dynamically inserted scripts fetch
    // through the hooks, or from the embedder's pre-fetched map when the
    // URL is there (the replay harness captures them by URL).
    for (node, _) in &scripts {
        interp.started_scripts.insert(*node);
    }
    interp.external_scripts = external.clone();
    interp.script_step_budget = limits.step_budget;

    let clock = limits.monotonic.clone();
    let started_ms = clock.as_ref().map(|c| c());
    let wall_ms = limits.max_wall_ms;
    // Elapsed wall milliseconds — `None` when the embedder gave no clock,
    // which disables every wall check below (the step and virtual budgets
    // still bound the run).
    let wall_spent_ms = |clock: &Option<super::interp::MonotonicMs>| match (started_ms, clock) {
        (Some(s), Some(c)) => Some(c().saturating_sub(s)),
        _ => None,
    };
    interp.monotonic = clock.clone();
    interp.deadline = started_ms.map(|s| s.saturating_add(wall_ms));
    for (i, (node, source)) in scripts.iter().enumerate() {
        // `document.currentScript` is the <script> element whose source is
        // running (null between scripts and inside callbacks). Bundlers
        // read its `src` to locate their chunk directory; Turbopack throws
        // "chunk path empty but not in a worker" without it.
        let current = dom_bindings::wrap_node(&mut interp, *node);
        set_current_script(&mut interp, current);
        if wall_spent_ms(&clock).is_some_and(|spent| spent >= wall_ms) {
            report.errors.push((
                i,
                format!("RangeError: page script wall-clock budget ({} ms) exhausted; script skipped", limits.max_wall_ms),
            ));
            continue;
        }
        // Each script gets a fresh step budget: one hostile script must not
        // starve the scripts after it (they are separate error domains).
        interp.step_budget = limits.step_budget;
        let prog = match parser::parse(source) {
            Ok(p) => p,
            Err(e) => {
                report
                    .errors
                    .push((i, format!("SyntaxError: {} at {}", e.message, e.pos)));
                continue;
            }
        };
        interp.error_trace.clear();
        let budget_before = interp.step_budget;
        match interp.run_program(&prog) {
            Ok(_) => report.scripts_ok += 1,
            Err(e) => {
                let mut msg = to_display(&e);
                if !interp.error_trace.is_empty() {
                    msg.push_str(" [at ");
                    msg.push_str(&interp.error_trace.join(" < "));
                    msg.push(']');
                }
                report.errors.push((i, msg));
            }
        }
        // Microtasks drain between scripts (spec: checkpoint after each).
        if let Err(e) = interp.drain_microtasks() {
            report.errors.push((i, to_display(&e)));
        }
        report.steps_used = report
            .steps_used
            .saturating_add(budget_before.saturating_sub(interp.step_budget));
    }
    set_current_script(&mut interp, super::value::JsValue::Null);

    // Event loop: timers on the virtual clock, microtasks between them.
    // The remaining wall-clock budget caps it too: a fast-firing interval
    // across ten virtual seconds is the common way a page burns real time.
    interp.step_budget = limits.step_budget;
    let fired_before = interp.timers_fired();
    // The virtual horizon is ONE budget for the whole run: the settle pass
    // after `load` gets whatever this pass did not consume.
    let virtual_deadline = interp.now_ms + limits.max_virtual_ms;
    let spent = wall_spent_ms(&clock);
    if spent.is_some_and(|s| s >= wall_ms) {
        report.errors.push((
            usize::MAX,
            "RangeError: page script wall-clock budget exhausted before the event loop".to_string(),
        ));
    } else {
        let remaining =
            std::time::Duration::from_millis(wall_ms.saturating_sub(spent.unwrap_or(0)));
        if let Err(e) = interp.run_event_loop_until(limits.max_virtual_ms, remaining) {
            report.errors.push((usize::MAX, to_display(&e)));
        }
    }
    report.timers_fired = interp.timers_fired().saturating_sub(fired_before);
    report.steps_used = report
        .steps_used
        .saturating_add(limits.step_budget.saturating_sub(interp.step_budget));

    // DOMContentLoaded / load listeners registered via addEventListener.
    interp.step_budget = limits.step_budget;
    // `document.readyState` advances with them, the way a browser's parser
    // end-of-file steps do (jQuery's ready and many loaders read it).
    for (event, state) in [("DOMContentLoaded", "interactive"), ("load", "complete")] {
        set_ready_state(&mut interp, state);
        if let Err(e) = interp.dispatch_simple_event(event) {
            report.errors.push((usize::MAX, to_display(&e)));
        }
        if let Err(e) = interp.drain_microtasks() {
            report.errors.push((usize::MAX, to_display(&e)));
        }
    }
    // The load listeners schedule work of their own (jQuery resolves its
    // ready Deferred through setTimeout; analytics loaders defer to the
    // next tick), so the event loop settles once more on what is left of
    // the budget — a browser keeps running timers after `load`.
    report.steps_used = report
        .steps_used
        .saturating_add(limits.step_budget.saturating_sub(interp.step_budget));
    interp.step_budget = limits.step_budget;
    let virtual_left = (virtual_deadline - interp.now_ms).max(0.0);
    let spent = wall_spent_ms(&clock);
    if spent.is_none_or(|s| s < wall_ms) {
        let remaining =
            std::time::Duration::from_millis(wall_ms.saturating_sub(spent.unwrap_or(0)));
        if let Err(e) = interp.run_event_loop_until(virtual_left, remaining) {
            report.errors.push((usize::MAX, to_display(&e)));
        }
    } else if interp.timers.iter().any(|t| !t.cancelled) || !interp.microtasks.is_empty() {
        // The load listeners scheduled work the budget no longer covers:
        // say so, rather than reporting a clean run with timers abandoned.
        report.errors.push((
            usize::MAX,
            "RangeError: page script wall-clock budget exhausted after the load event (pending timers abandoned)".to_string(),
        ));
    }
    report.timers_fired = interp.timers_fired().saturating_sub(fired_before);
    report.steps_used = report
        .steps_used
        .saturating_add(limits.step_budget.saturating_sub(interp.step_budget))
        .saturating_add(interp.dynamic_steps);
    report.scripts_found = report.scripts_found.saturating_add(interp.dynamic_scripts);
    report.scripts_ok = report.scripts_ok.saturating_add(interp.dynamic_scripts_ok);

    report.console = lines.borrow().clone();
    *realm = Realm::capture_from(&interp);
    report
}

impl<'h> Interp<'h> {
    /// Run the source of a dynamically inserted `<script>` (see
    /// `dom_bindings::script_inserted`) as a classic script in the global
    /// scope, under its own per-script step budget (the embedder's
    /// `RunLimits::step_budget`), with `document.currentScript` naming the
    /// element while it runs. The steps it consumes are charged to
    /// `dynamic_steps`; the caller's budget (the event-loop phase that fired
    /// the task) is restored afterwards. Returns whether the script ran to
    /// completion; a parse or runtime error is reported on the console with
    /// the unwind trace, the way the page's own script errors are, and
    /// never aborts the task that ran it.
    pub fn run_dynamic_script(&mut self, handle: usize, source: &str) -> bool {
        let saved_budget = self.step_budget;
        self.step_budget = self.script_step_budget;
        // A dynamic script can start another one synchronously (a loader
        // that appends a chunk from inside a chunk): the enclosing
        // script's `currentScript` comes back once the nested run ends.
        let previous = self
            .node_wrappers
            .get(&0)
            .and_then(|d| d.borrow().get_prop("currentScript"))
            .unwrap_or(super::value::JsValue::Null);
        let current = dom_bindings::wrap_node(self, handle);
        set_current_script(self, current);
        let ok = match parser::parse(source) {
            Ok(prog) => {
                self.error_trace.clear();
                match self.run_program(&prog) {
                    Ok(_) => true,
                    Err(e) => {
                        let mut msg = to_display(&e);
                        if !self.error_trace.is_empty() {
                            msg.push_str(" [at ");
                            msg.push_str(&self.error_trace.join(" < "));
                            msg.push(']');
                        }
                        self.hooks
                            .console("error", &format!("uncaught (in dynamic script): {msg}"));
                        false
                    }
                }
            }
            Err(e) => {
                self.hooks.console(
                    "error",
                    &format!("SyntaxError in dynamic script: {} at {}", e.message, e.pos),
                );
                false
            }
        };
        set_current_script(self, previous);
        self.dynamic_steps = self
            .dynamic_steps
            .saturating_add(self.script_step_budget.saturating_sub(self.step_budget));
        self.step_budget = saved_budget;
        ok
    }
}

/// Set `document.readyState` on the document wrapper (handle 0).
fn set_ready_state(interp: &mut Interp, state: &str) {
    if let Some(doc_obj) = interp.node_wrappers.get(&0).cloned() {
        doc_obj
            .borrow_mut()
            .set_prop("readyState", super::value::JsValue::str(state), true);
    }
}

/// Set `document.currentScript` on the document wrapper (handle 0).
fn set_current_script(interp: &mut Interp, script: super::value::JsValue) {
    if let Some(doc_obj) = interp.node_wrappers.get(&0).cloned() {
        doc_obj.borrow_mut().set_prop("currentScript", script, true);
    }
}

/// Convenience: get a global binding's display value after a run (used by
/// tests and the capability probe).
pub fn global_display(interp: &Interp, name: &str) -> Option<String> {
    Scope::get(&interp.global_scope, name).map(|v| v.to_js_string())
}
