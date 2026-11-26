//! interp — the tree-walking interpreter: scopes, evaluation, the microtask
//! queue, and virtual-clock timers.
//!
//! Design notes:
//!
//! * **Panic-free**: no indexing, no unwrap; every internal error becomes a
//!   thrown `JsValue` the page script can catch (or that surfaces as a
//!   script error on the page, never a dead render).
//! * **Bounded**: `step_budget` caps total evaluation steps so hostile
//!   `while(true){}` terminates the SCRIPT, not the service.
//! * **Suspension**: generator and async bodies run on the explicit frame
//!   stack in `coroutine.rs`, so `yield` hands a value out and `await`
//!   parks the body until its promise settles, each resumed from exactly
//!   that point by a microtask. A suspension in an expression position
//!   (`f(await a, yield b)`) is lowered by `desugar.rs` into statements
//!   the frame stack can suspend on, so evaluation order is preserved.
//!   `await_promise` (the eager drain) remains for the host-side callers
//!   that await outside any async body (`Promise.all`).
//! * **No I/O**: network access is delegated to the consumer through
//!   [`HostHooks`]; the engine itself never opens a socket.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::rc::Rc;

use super::ast::{ClassDef, DeclKind, Expr, FnDef, MemberKind, Pattern, Program, PropKey, SpreadElem, Stmt};
use super::coroutine::{Coroutine, Mode, Step};
use super::value::{GeneratorState, JsObject, JsValue, NativeFn, ObjKind, ObjRef, PromiseState, Prop, Reaction, SymbolData, WELL_KNOWN_SYMBOLS, is_symbol_key, iterator_key, well_known_symbol};

/// How a generator is resumed (`next(v)`, `throw(e)`, `return(v)`).
pub enum GenResume {
    Next(JsValue),
    Throw(JsValue),
    Return(JsValue),
}

/// Shared mutable scope.
pub type ScopeRef = Rc<RefCell<Scope>>;

/// Native recursion guard for script calls. Chrome allows roughly ten
/// thousand frames; minified recursive helpers (a tree walk over a 2,000
/// node DOM, a recursive `merge`) routinely pass a few thousand, so a
/// shallow guard surfaces as a spurious "Maximum call stack size exceeded"
/// that Chrome never throws. Each interpreted frame costs the host roughly
/// 20-30 KiB of native stack (the tree-walker recurses through `eval` /
/// `exec_stmt` / `call`). Reaching this depth needs at least
/// `REQUIRED_STACK_BYTES`, arranged by a native embedder. The default stack
/// budget stops scripts earlier so a constrained app need not allocate a
/// native thread or exhaust its smaller stack.
pub const MAX_CALL_DEPTH: u32 = 3_000;

/// The native stack a thread needs to run page scripts to `MAX_CALL_DEPTH`
/// with margin: 3,000 frames × ~48 KiB worst case (a frame holding a wide
/// `match` plus the parser's recursion for `eval`) plus headroom for the
/// layout / paint stages that follow.
pub const REQUIRED_STACK_BYTES: usize = 256 * 1024 * 1024;

/// The native stack a script run may consume when the embedder says
/// nothing: safe on a 2 MiB thread (the test harness default, tokio's
/// worker default) with headroom for the layout stage that follows. An
/// embedder on a deeper stack raises `RunLimits::stack_budget_bytes`.
pub const DEFAULT_STACK_BUDGET_BYTES: usize = 1_200_000;

/// The stack budget a native deep-stack embedder affords: the thread minus
/// headroom for layout and paint.
pub const DEEP_STACK_BUDGET_BYTES: usize = REQUIRED_STACK_BYTES - 32 * 1024 * 1024;

/// The address of a stack local, as the interpreter's yardstick for how
/// deep the native stack currently is. Safe code: a pointer-to-integer
/// cast is not dereferenced, only subtracted.
#[inline(never)]
pub fn stack_mark() -> usize {
    let marker = 0u8;
    std::ptr::from_ref(&marker) as usize
}

/// The embedder's monotonic-milliseconds clock. The engine never reads an
/// ambient clock — on the constrained platform an app's only time source is
/// the injected context seam — so every wall-clock budget runs on this and
/// is simply not enforced when the embedder supplies none; the step and
/// virtual-clock budgets remain the unconditional bounds.
pub type MonotonicMs = std::rc::Rc<dyn Fn() -> u64>;

/// One lexical scope: bindings + parent link.
pub struct Scope {
    pub vars: HashMap<String, JsValue>,
    /// Names declared `const` (assignment throws TypeError).
    pub consts: Vec<String>,
    pub parent: Option<ScopeRef>,
    /// A function (or the global) environment: `var` declarations from
    /// any nested block hoist up to the nearest scope with this flag.
    pub function_scope: bool,
    /// On a function environment: the function is strict code.
    pub strict: bool,
}

impl Scope {
    pub fn new(parent: Option<ScopeRef>) -> ScopeRef {
        let function_scope = parent.is_none();
        Rc::new(RefCell::new(Scope {
            vars: HashMap::new(),
            consts: Vec::new(),
            parent,
            function_scope,
            strict: false,
        }))
    }

    /// A function body's environment (the `var` hoisting target).
    pub fn new_function(parent: Option<ScopeRef>) -> ScopeRef {
        Rc::new(RefCell::new(Scope {
            vars: HashMap::new(),
            consts: Vec::new(),
            parent,
            function_scope: true,
            strict: false,
        }))
    }

    /// The nearest enclosing function/global scope of `scope`.
    pub fn var_scope(scope: &ScopeRef) -> ScopeRef {
        let mut cur = scope.clone();
        loop {
            let next = {
                let b = cur.borrow();
                if b.function_scope {
                    return cur.clone();
                }
                b.parent.clone()
            };
            match next {
                Some(p) => cur = p,
                None => return cur,
            }
        }
    }

    /// Look a name up the scope chain.
    pub fn get(scope: &ScopeRef, name: &str) -> Option<JsValue> {
        let mut cur = Some(scope.clone());
        while let Some(s) = cur {
            if let Some(v) = s.borrow().vars.get(name) {
                return Some(v.clone());
            }
            cur = s.borrow().parent.clone();
        }
        None
    }

    /// Assign to the nearest binding; returns false when unbound (caller
    /// creates an implicit global, matching sloppy-mode pages).
    pub fn set(scope: &ScopeRef, name: &str, value: JsValue) -> Result<bool, JsValue> {
        let mut cur = Some(scope.clone());
        while let Some(s) = cur {
            let mut b = s.borrow_mut();
            if b.vars.contains_key(name) {
                if b.consts.iter().any(|c| c == name) {
                    drop(b);
                    return Err(JsValue::str(format!(
                        "TypeError: assignment to constant '{name}'"
                    )));
                }
                b.vars.insert(name.to_string(), value);
                return Ok(true);
            }
            let parent = b.parent.clone();
            drop(b);
            cur = parent;
        }
        Ok(false)
    }

    pub fn declare(scope: &ScopeRef, name: &str, value: JsValue, constant: bool) {
        let mut b = scope.borrow_mut();
        b.vars.insert(name.to_string(), value);
        if constant {
            b.consts.push(name.to_string());
        }
    }
}

/// Statement/loop completion.
pub enum Completion {
    Normal(JsValue),
    Return(JsValue),
    Break(Option<String>),
    Continue(Option<String>),
}

/// A queued microtask.
#[derive(Clone)]
pub enum Job {
    /// Call `handler(arg)` and settle `derived` with the result.
    Reaction {
        handler: Option<ObjRef>,
        arg: JsValue,
        fulfilled: bool,
        derived: ObjRef,
    },
}

/// A pending timer.
#[derive(Clone)]
pub struct Timer {
    pub id: u32,
    pub due_ms: f64,
    pub callback: JsValue,
    pub args: Vec<JsValue>,
    pub interval_ms: Option<f64>,
    pub cancelled: bool,
}

/// HTTP response returned by a [`HostHooks`] implementation.
pub type FetchResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// Host-provided capabilities the engine itself must not own.
pub trait HostHooks {
    /// Perform an HTTP request. Synchronous from the engine's view; the
    /// consumer decides how it is actually transported (scoped egress in the
    /// deployed app, a stub in tests). Returns (status, headers, body).
    fn fetch(
        &mut self,
        url: &str,
        method: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<FetchResponse, String>;

    /// console.* sink (captured per render for diagnostics).
    fn console(&mut self, level: &str, message: &str);

    /// Fill `dest` from a cryptographically secure generator: the bytes
    /// behind `crypto.getRandomValues` and `crypto.randomUUID`, which pages
    /// use for session identifiers, CSRF tokens and keys. The engine is
    /// std-only and reaches no entropy source of its own, so the default
    /// has none and fails; the script call then throws instead of receiving
    /// predictable bytes. Embedders supply their platform's generator.
    fn random_fill(&mut self, _dest: &mut [u8]) -> Result<(), String> {
        Err("no secure random source: the embedder supplies none".to_string())
    }
}

/// A no-network hooks impl: every fetch fails with a typed error.
pub struct NoNetwork;
impl HostHooks for NoNetwork {
    fn fetch(
        &mut self,
        _url: &str,
        _method: &str,
        _headers: &[(String, String)],
        _body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        Err("no_egress: network is not available in this context".to_string())
    }
    fn console(&mut self, _level: &str, _message: &str) {}
}

/// The interpreter: one realm per rendered page.
pub struct Interp<'h> {
    pub global_scope: ScopeRef,
    pub global_object: ObjRef,
    /// Intrinsic prototypes.
    pub object_proto: ObjRef,
    pub function_proto: ObjRef,
    pub array_proto: ObjRef,
    pub string_proto: ObjRef,
    pub number_proto: ObjRef,
    pub boolean_proto: ObjRef,
    pub promise_proto: ObjRef,
    pub error_proto: ObjRef,
    pub regexp_proto: ObjRef,
    pub date_proto: ObjRef,
    pub symbol_proto: ObjRef,
    pub map_proto: ObjRef,
    pub set_proto: ObjRef,
    pub iterator_proto: ObjRef,
    pub generator_proto: ObjRef,
    /// Next id for `Symbol()` (well-known ids are below `WELL_KNOWN_SYMBOLS`).
    pub next_symbol_id: u64,
    /// `Symbol.for` registry: description → symbol.
    pub symbol_registry: HashMap<String, JsValue>,
    /// Every non-registry symbol that has been used as a property key, by
    /// id, so reflection (`getOwnPropertySymbols`, `Reflect.ownKeys`)
    /// returns the original value.
    pub known_symbols: HashMap<u64, JsValue>,
    pub microtasks: VecDeque<Job>,
    pub timers: Vec<Timer>,
    /// Next timer id (public so the globals bootstrap can seed it).
    pub next_timer_id_pub: u32,
    /// Virtual clock (ms). Timers fire against this, not the wall clock.
    pub now_ms: f64,
    /// Remaining evaluation steps before the script is terminated.
    pub step_budget: u64,
    pub hooks: &'h mut dyn HostHooks,
    /// Documents arena shared with DOM bindings (set by the dom module).
    /// Relative path: the package mounts as a module inside its consumer
    /// (`agent_browser::browser_core`), so `crate::` paths must not be used.
    pub dom: Option<Rc<RefCell<super::super::dom::Document>>>,
    /// Window-level event listeners registered via addEventListener
    /// (event → callbacks).
    pub listeners: HashMap<String, Vec<JsValue>>,
    /// Node-scoped listeners registered by `element.addEventListener` and
    /// `element.onX = fn`: (node handle, event) → callbacks. Events dispatched
    /// through [`Interp::dispatch_node_event`] walk the target's ancestor
    /// chain (bubbling) and then the window-level `listeners`.
    pub node_listeners: HashMap<(usize, String), Vec<JsValue>>,
    /// The focused element handle (`document.activeElement`), if any.
    pub focused: Option<usize>,
    /// One JS wrapper per DOM node handle, so `a.parentNode === b` holds
    /// and expando properties frameworks hang on elements (React's
    /// `__reactFiber$…`, jQuery's data cache) survive between lookups.
    pub node_wrappers: HashMap<usize, ObjRef>,
    /// Total timer callbacks fired (for run reports).
    pub timers_fired_count: u32,
    /// `new.target` for the call `construct` is about to make (consumed by
    /// the callee's scope setup).
    pub new_target: Option<JsValue>,
    /// Recursion depth guard for `call` (hostile deep recursion must throw
    /// a RangeError, not overflow the native stack).
    pub call_depth: u32,
    /// Function names on the unwind path of the error currently
    /// propagating (innermost first), for diagnostics: the run report
    /// appends it to uncaught errors so a failing bundle names its call
    /// site. Cleared when a `catch` takes the error.
    pub error_trace: Vec<String>,
    /// Wall-clock deadline for the current run, in [`MonotonicMs`]
    /// milliseconds. Checked every few thousand steps by `charge`, so a
    /// script whose steps are individually expensive (regex over a
    /// megabyte, a `delete` storm) still stops on time; the step budget
    /// alone only bounds the NUMBER of steps. Enforced only when
    /// `monotonic` carries the embedder's clock.
    pub deadline: Option<u64>,
    /// The embedder's clock that `deadline` is measured on.
    pub monotonic: Option<MonotonicMs>,
    /// The native stack address where this interpreter started running
    /// (see [`stack_mark`]); `call` measures the distance from it.
    pub stack_base: usize,
    /// How far below `stack_base` a script call may reach before it throws
    /// `RangeError: Maximum call stack size exceeded`. The frame-count
    /// guard (`MAX_CALL_DEPTH`) is the ceiling; this is what keeps a deep
    /// recursion from overflowing a thread whose stack the embedder did
    /// not size for it.
    pub stack_budget_bytes: usize,
    /// `<script>` node handles whose source has already been started (the
    /// document's own scripts, and every dynamically inserted one), so a
    /// script element moved around the tree never runs twice (HTML §4.12.1
    /// "already started").
    pub started_scripts: HashSet<usize>,
    /// How many dynamically inserted scripts this realm has started;
    /// bounded by [`super::dom_bindings::MAX_DYNAMIC_SCRIPTS`].
    pub dynamic_scripts: usize,
    /// How many of those ran to completion without throwing.
    pub dynamic_scripts_ok: usize,
    /// Pre-fetched external script sources by raw `src` and by absolute
    /// URL (the embedder's `external` map), consulted before the host's
    /// `fetch` when a dynamically inserted script names one of them.
    pub external_scripts: HashMap<String, String>,
    /// The per-script step budget a dynamically inserted script runs
    /// under (the embedder's `RunLimits::step_budget`); the event-loop
    /// phase that fires it keeps its own budget.
    pub script_step_budget: u64,
    /// Whether the script `run_program` is executing is strict code: the
    /// strictness of top-level code, which runs in the shared global
    /// scope (a function's comes from its own scope, see `is_strict`).
    pub script_strict: bool,
    /// Steps charged to dynamically inserted scripts, reported separately
    /// so the run report's total stays a sum of what actually ran.
    pub dynamic_steps: u64,
    /// The realm's own `[Symbol.iterator]` functions, recorded once the
    /// globals are installed. A `for...of` over a dense shape takes the
    /// snapshot fast path only while the iterator it RESOLVES is still the
    /// intrinsic for THAT shape; a script that replaced
    /// `Array.prototype[Symbol.iterator]` (with its own function, or with
    /// another intrinsic such as the Set iterator) is called like any other
    /// iterable.
    pub intrinsic_iterators: IntrinsicIterators,
    /// `NodeList.prototype` once the DOM interfaces are installed: every
    /// live list the bindings hand out sits on it, so a method a bundle
    /// adds to `NodeList.prototype` is visible on every list and
    /// `list instanceof NodeList` holds.
    pub dom_list_proto: Option<ObjRef>,
    /// The object a base constructor handed back to `super(...)` in place
    /// of the allocated `this` (an `HTMLElement` subclass receives the
    /// element under construction). `construct_with_target` returns it
    /// as the instance.
    pub super_this: Option<ObjRef>,
    /// The empty string, shared as the `name` of every anonymous function
    /// so creating a closure allocates no string for it.
    pub empty_string: JsValue,
    /// Objects `name_builtins` has already walked (by address), so the
    /// walk after the DOM bindings are installed only visits what they
    /// added.
    pub named_builtins: HashSet<usize>,
    /// The realm's `Array` constructor and its `@@species` getter as
    /// installed: ArraySpeciesCreate skips the lookups for an Array whose
    /// constructor is still these (see `array_species_create`).
    pub array_species: Option<(ObjRef, ObjRef)>,
    /// The DOM event interfaces' prototypes (`Event`, `MouseEvent`, …)
    /// once the DOM bindings are installed (see `events.rs`); the
    /// dispatcher makes each event an instance of its interface.
    pub event_protos: Vec<(&'static str, ObjRef)>,
}

/// The realm's intrinsic `[Symbol.iterator]` functions, by the shape whose
/// snapshot stands in for them (see [`LoopSource::open`]).
#[derive(Default, Clone)]
pub struct IntrinsicIterators {
    /// `Array.prototype[Symbol.iterator]` (arrays and DOM lists).
    pub array: Option<ObjRef>,
    /// `%TypedArray%.prototype[Symbol.iterator]`.
    pub typed: Option<ObjRef>,
    /// `Map.prototype[Symbol.iterator]`.
    pub map: Option<ObjRef>,
    /// `Set.prototype[Symbol.iterator]`.
    pub set: Option<ObjRef>,
}

impl<'h> Interp<'h> {
    /// Throw helper: build an Error-like string value.
    pub fn throw(msg: impl Into<String>) -> JsValue {
        JsValue::str(msg.into())
    }

    /// Public charge wrapper for the eval.rs impl half.
    pub fn charge_pub(&mut self) -> Result<(), JsValue> {
        self.charge()
    }

    /// Public hoisting wrapper for the coroutine executor (a block it
    /// enters needs the same function/`var` hoisting `exec_stmt` does).
    pub fn hoist_pub(&mut self, body: &[Stmt], scope: &ScopeRef) -> Result<(), JsValue> {
        self.hoist(body, scope)
    }

    /// A `catch` took the propagating error: its unwind trace is over.
    pub fn clear_error_trace(&mut self) {
        self.error_trace.clear();
    }

    /// Public class-construction wrapper for the eval.rs impl half.
    pub fn make_class_pub(
        &mut self,
        def: &Rc<ClassDef>,
        scope: &ScopeRef,
    ) -> Result<JsValue, JsValue> {
        self.make_class(def, scope)
    }

    /// Charge one step; errs when the budget is exhausted or (every 4096
    /// steps) when the wall-clock deadline has passed.
    fn charge(&mut self) -> Result<(), JsValue> {
        if self.step_budget == 0 {
            return Err(Self::throw("RangeError: script step budget exhausted"));
        }
        self.step_budget = self.step_budget.saturating_sub(1);
        if self.step_budget & 0xfff == 0 {
            if let (Some(d), Some(clock)) = (self.deadline, self.monotonic.as_ref()) {
                if clock() >= d {
                    self.step_budget = 0;
                    return Err(Self::throw(
                        "RangeError: script wall-clock budget exhausted",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Execute a whole program in the global scope.
    pub fn run_program(&mut self, prog: &Program) -> Result<JsValue, JsValue> {
        // Top-level `this` is the global object (the HTML global
        // environment); installed once per realm.
        if !self.global_scope.borrow().vars.contains_key("this") {
            let g = JsValue::Object(self.global_object.clone());
            Scope::declare(&self.global_scope.clone(), "this", g, false);
        }
        let outer_strict = core::mem::replace(&mut self.script_strict, prog.strict);
        let out = self.run_program_body(prog);
        self.script_strict = outer_strict;
        out
    }

    fn run_program_body(&mut self, prog: &Program) -> Result<JsValue, JsValue> {
        self.hoist(&prog.body, &self.global_scope.clone())?;
        let mut last = JsValue::Undefined;
        for stmt in &prog.body {
            match self.exec_stmt(stmt, &self.global_scope.clone())? {
                Completion::Normal(v) => last = v,
                Completion::Return(v) => return Ok(v),
                _ => {}
            }
        }
        Ok(last)
    }

    /// Whether the code running in `scope` is strict: its function's
    /// strictness, or, at the top level, the running script's.
    pub fn is_strict(&self, scope: &ScopeRef) -> bool {
        let env = Scope::var_scope(scope);
        if Rc::ptr_eq(&env, &self.global_scope) {
            return self.script_strict;
        }
        let strict = env.borrow().strict;
        strict
    }

    /// Hoist function declarations and `var` bindings. In the GLOBAL scope
    /// these are also properties of the global object (the HTML global
    /// environment: `var x` makes `window.x`), which is what `typeof x`
    /// after a binding removal and CDP's lexical-vs-var split observe.
    fn hoist(&mut self, body: &[Stmt], scope: &ScopeRef) -> Result<(), JsValue> {
        let is_global = Rc::ptr_eq(scope, &self.global_scope);
        for stmt in body {
            if let Stmt::Function(def) = stmt {
                let f = self.make_function(def.clone(), scope.clone(), None);
                if let Some(name) = &def.name {
                    Scope::declare(scope, name, f.clone(), false);
                    if is_global {
                        self.global_object.borrow_mut().set_prop(name, f, true);
                    }
                }
            }
        }
        // `var` binds in the nearest FUNCTION scope, wherever the
        // declaration sits (a nested block, a `for` head, a `try` body), so
        // an outer binding of the same name is shadowed, never assigned
        // through, and a loop variable never leaks into the global object.
        // A function-scope hoist collects the whole body; a block hoist is
        // a no-op for vars because its function already collected them.
        if scope.borrow().function_scope {
            let mut names: Vec<String> = Vec::new();
            for stmt in body {
                collect_var_names(stmt, &mut names);
            }
            for name in names {
                if !scope.borrow().vars.contains_key(&name) {
                    Scope::declare(scope, &name, JsValue::Undefined, false);
                }
                if is_global && self.global_object.borrow().own(&name).is_none() {
                    self.global_object
                        .borrow_mut()
                        .set_prop(&name, JsValue::Undefined, true);
                }
            }
        }
        Ok(())
    }

    pub fn exec_stmt(&mut self, stmt: &Stmt, scope: &ScopeRef) -> Result<Completion, JsValue> {
        self.charge()?;
        match stmt {
            Stmt::Empty => Ok(Completion::Normal(JsValue::Undefined)),
            Stmt::Expr(e) => Ok(Completion::Normal(self.eval(e, scope)?)),
            Stmt::VarDecl { kind, decls } => {
                for (pat, init) in decls {
                    let value = match (init, pat) {
                        (Some(e), Pattern::Ident(name)) => self.eval_named(e, scope, name)?,
                        (Some(e), _) => self.eval(e, scope)?,
                        (None, _) => JsValue::Undefined,
                    };
                    match kind {
                        // `var`: the name was hoisted; assign through the
                        // binding (and onto the global object at top level).
                        DeclKind::Var => self.bind_pattern(pat, value, scope, false, false)?,
                        DeclKind::Let => self.bind_pattern(pat, value, scope, true, false)?,
                        DeclKind::Const => self.bind_pattern(pat, value, scope, true, true)?,
                    }
                }
                Ok(Completion::Normal(JsValue::Undefined))
            }
            Stmt::Function(_) => Ok(Completion::Normal(JsValue::Undefined)), // hoisted
            Stmt::Return(e) => {
                let v = match e {
                    Some(e) => self.eval(e, scope)?,
                    None => JsValue::Undefined,
                };
                Ok(Completion::Return(v))
            }
            Stmt::If { cond, then, alt } => {
                if self.eval(cond, scope)?.truthy() {
                    self.exec_stmt(then, scope)
                } else if let Some(alt) = alt {
                    self.exec_stmt(alt, scope)
                } else {
                    Ok(Completion::Normal(JsValue::Undefined))
                }
            }
            Stmt::Block(body) => {
                let inner = Scope::new(Some(scope.clone()));
                self.hoist(body, &inner)?;
                self.exec_block(body, &inner)
            }
            Stmt::While { cond, body } => {
                loop {
                    self.charge()?;
                    if !self.eval(cond, scope)?.truthy() {
                        break;
                    }
                    match self.exec_stmt(body, scope)? {
                        Completion::Break(None) => break,
                        Completion::Break(l) => return Ok(Completion::Break(l)),
                        Completion::Continue(None) => continue,
                        Completion::Continue(l) => return Ok(Completion::Continue(l)),
                        Completion::Return(v) => return Ok(Completion::Return(v)),
                        Completion::Normal(_) => {}
                    }
                }
                Ok(Completion::Normal(JsValue::Undefined))
            }
            Stmt::DoWhile { body, cond } => {
                loop {
                    self.charge()?;
                    match self.exec_stmt(body, scope)? {
                        Completion::Break(None) => break,
                        Completion::Break(l) => return Ok(Completion::Break(l)),
                        Completion::Continue(None) => {}
                        Completion::Continue(l) => return Ok(Completion::Continue(l)),
                        Completion::Return(v) => return Ok(Completion::Return(v)),
                        Completion::Normal(_) => {}
                    }
                    if !self.eval(cond, scope)?.truthy() {
                        break;
                    }
                }
                Ok(Completion::Normal(JsValue::Undefined))
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let loop_scope = Scope::new(Some(scope.clone()));
                if let Some(init) = init {
                    self.exec_stmt(init, &loop_scope)?;
                }
                loop {
                    self.charge()?;
                    if let Some(c) = cond {
                        if !self.eval(c, &loop_scope)?.truthy() {
                            break;
                        }
                    }
                    match self.exec_stmt(body, &loop_scope)? {
                        Completion::Break(None) => break,
                        Completion::Break(l) => return Ok(Completion::Break(l)),
                        Completion::Continue(None) => {}
                        Completion::Continue(l) => return Ok(Completion::Continue(l)),
                        Completion::Return(v) => return Ok(Completion::Return(v)),
                        Completion::Normal(_) => {}
                    }
                    if let Some(u) = update {
                        self.eval(u, &loop_scope)?;
                    }
                }
                Ok(Completion::Normal(JsValue::Undefined))
            }
            Stmt::ForIn {
                decl_kind,
                pat,
                object,
                body,
                of,
            } => {
                let obj = self.eval(object, scope)?;
                // `for...of` PULLS from a live iterator: a generator runs
                // only as far as the loop consumes, and an early exit
                // (`break`, `return`, a throw) closes it so its `finally`
                // blocks run (ES §14.7.5.7 IteratorClose). `for...in`
                // snapshots the keys, as the spec allows.
                let mut source = if *of {
                    LoopSource::open(self, &obj)?
                } else {
                    self.for_in_source(&obj)?
                };
                let outcome: Result<Completion, JsValue> = (|| loop {
                    self.charge()?;
                    let Some(item) = source.next(self)? else {
                        return Ok(Completion::Normal(JsValue::Undefined));
                    };
                    let iter_scope = Scope::new(Some(scope.clone()));
                    let target = if decl_kind.is_some() {
                        &iter_scope
                    } else {
                        scope
                    };
                    self.bind_pattern(
                        pat,
                        item,
                        target,
                        decl_kind.is_some(),
                        *decl_kind == Some(DeclKind::Const),
                    )?;
                    match self.exec_stmt(body, &iter_scope)? {
                        Completion::Break(None) => {
                            return Ok(Completion::Normal(JsValue::Undefined))
                        }
                        Completion::Break(l) => return Ok(Completion::Break(l)),
                        Completion::Continue(None) => continue,
                        Completion::Continue(l) => return Ok(Completion::Continue(l)),
                        Completion::Return(v) => return Ok(Completion::Return(v)),
                        Completion::Normal(_) => {}
                    }
                })();
                // Any exit before exhaustion closes the iterator; an error
                // from `return()` is masked by the loop's own throw.
                if !source.exhausted() {
                    let close = source.close(self);
                    if outcome.is_ok() {
                        close?;
                    }
                }
                outcome
            }
            Stmt::Break(l) => Ok(Completion::Break(l.clone())),
            Stmt::Continue(l) => Ok(Completion::Continue(l.clone())),
            Stmt::Throw(e) => {
                let v = self.eval(e, scope)?;
                Err(v)
            }
            Stmt::Try {
                block,
                catch,
                finally,
            } => {
                let result = (|| {
                    let inner = Scope::new(Some(scope.clone()));
                    self.hoist(block, &inner)?;
                    self.exec_block(block, &inner)
                })();
                let after_catch = match result {
                    Err(thrown) => {
                        if let Some((param, cbody)) = catch {
                            self.error_trace.clear();
                            let cscope = Scope::new(Some(scope.clone()));
                            if let Some(pat) = param {
                                self.bind_pattern(pat, thrown, &cscope, true, false)?;
                            }
                            self.hoist(cbody, &cscope)?;
                            self.exec_block(cbody, &cscope)
                        } else {
                            Err(thrown)
                        }
                    }
                    ok => ok,
                };
                if let Some(fbody) = finally {
                    let fscope = Scope::new(Some(scope.clone()));
                    self.hoist(fbody, &fscope)?;
                    match self.exec_block(fbody, &fscope)? {
                        Completion::Normal(_) => {}
                        abrupt => return Ok(abrupt), // finally overrides
                    }
                }
                after_catch
            }
            Stmt::Switch { disc, cases } => {
                let d = self.eval(disc, scope)?;
                let sscope = Scope::new(Some(scope.clone()));
                let mut matched = false;
                // Two passes: cases in order, then default when nothing hit.
                for pass in 0..2 {
                    for (test, body) in cases {
                        if !matched {
                            match (pass, test) {
                                (0, Some(t)) => {
                                    let tv = self.eval(t, &sscope)?;
                                    if strict_eq(&d, &tv) {
                                        matched = true;
                                    }
                                }
                                (1, None) => matched = true,
                                _ => {}
                            }
                        }
                        if matched {
                            for stmt in body {
                                match self.exec_stmt(stmt, &sscope)? {
                                    Completion::Break(None) => {
                                        return Ok(Completion::Normal(JsValue::Undefined))
                                    }
                                    Completion::Break(l) => return Ok(Completion::Break(l)),
                                    Completion::Continue(l) => return Ok(Completion::Continue(l)),
                                    Completion::Return(v) => return Ok(Completion::Return(v)),
                                    Completion::Normal(_) => {}
                                }
                            }
                        }
                    }
                    if matched {
                        break;
                    }
                }
                Ok(Completion::Normal(JsValue::Undefined))
            }
            Stmt::Labeled { label, body } => match self.exec_stmt(body, scope)? {
                Completion::Break(Some(l)) if l == *label => {
                    Ok(Completion::Normal(JsValue::Undefined))
                }
                Completion::Continue(Some(l)) if l == *label => {
                    Ok(Completion::Normal(JsValue::Undefined))
                }
                other => Ok(other),
            },
            Stmt::ClassDecl(def) => {
                let cls = self.make_class(def, scope)?;
                if let Some(name) = &def.name {
                    Scope::declare(scope, name, cls, false);
                }
                Ok(Completion::Normal(JsValue::Undefined))
            }
        }
    }

    fn exec_block(&mut self, body: &[Stmt], scope: &ScopeRef) -> Result<Completion, JsValue> {
        let mut last = JsValue::Undefined;
        for stmt in body {
            match self.exec_stmt(stmt, scope)? {
                Completion::Normal(v) => last = v,
                abrupt => return Ok(abrupt),
            }
        }
        Ok(Completion::Normal(last))
    }

    /// Drain microtasks, then fire due timers, advancing the virtual clock,
    /// until both queues are empty or `max_virtual_ms` is exceeded.
    pub fn run_event_loop(&mut self, max_virtual_ms: f64) -> Result<(), JsValue> {
        self.run_event_loop_until(max_virtual_ms, std::time::Duration::from_secs(3600))
    }

    /// [`Interp::run_event_loop`] with a wall-clock bound as well: once
    /// `wall` has elapsed the loop stops and reports the truncation as an
    /// error (pending timers and microtasks were abandoned), so a render
    /// cut short by the budget is never mistaken for a quiescent page.
    pub fn run_event_loop_until(
        &mut self,
        max_virtual_ms: f64,
        wall: std::time::Duration,
    ) -> Result<(), JsValue> {
        let wall_ms = u64::try_from(wall.as_millis()).unwrap_or(u64::MAX);
        let started = self.monotonic.as_ref().map(|clock| clock());
        let deadline = self.now_ms + max_virtual_ms;
        loop {
            let wall_exhausted = match (started, self.monotonic.as_ref()) {
                (Some(s), Some(clock)) => clock().saturating_sub(s) >= wall_ms,
                _ => false,
            };
            if wall_exhausted {
                let pending = self.timers.iter().filter(|t| !t.cancelled).count();
                return Err(Self::throw(format!(
                    "RangeError: event loop wall-clock budget exhausted ({pending} timer(s), {} microtask(s) abandoned)",
                    self.microtasks.len()
                )));
            }
            self.drain_microtasks()?;
            // Earliest live timer.
            let next = self
                .timers
                .iter()
                .filter(|t| !t.cancelled)
                .map(|t| t.due_ms)
                .fold(f64::INFINITY, f64::min);
            if !next.is_finite() || next > deadline {
                return Ok(());
            }
            self.now_ms = self.now_ms.max(next);
            self.fire_due_timers()?;
        }
    }

    pub fn drain_microtasks(&mut self) -> Result<(), JsValue> {
        while let Some(job) = self.microtasks.pop_front() {
            self.charge()?;
            match job {
                Job::Reaction {
                    handler,
                    arg,
                    fulfilled,
                    derived,
                } => {
                    match handler {
                        Some(h) => {
                            let f = JsValue::Object(h);
                            match self.call(f, JsValue::Undefined, &[arg]) {
                                Ok(v) => self.resolve_promise(&derived, v, true),
                                Err(e) => self.resolve_promise(&derived, e, false),
                            }
                        }
                        None => {
                            // Pass-through reaction.
                            self.resolve_promise(&derived, arg, fulfilled);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn fire_due_timers(&mut self) -> Result<(), JsValue> {
        let now = self.now_ms;
        // Collect due timer indices first (callbacks may add timers).
        let due: Vec<u32> = self
            .timers
            .iter()
            .filter(|t| !t.cancelled && t.due_ms <= now)
            .map(|t| t.id)
            .collect();
        for id in due {
            let (cb, args, interval) = {
                let Some(t) = self.timers.iter_mut().find(|t| t.id == id && !t.cancelled) else {
                    continue;
                };
                let out = (t.callback.clone(), t.args.clone(), t.interval_ms);
                match t.interval_ms {
                    Some(iv) => t.due_ms = now + iv.max(1.0),
                    None => t.cancelled = true,
                }
                out
            };
            let _ = interval;
            self.timers_fired_count = self.timers_fired_count.saturating_add(1);
            let r = self.call(cb, JsValue::Undefined, &args);
            if let Err(e) = r {
                self.hooks
                    .console("error", &format!("uncaught (in timer): {}", to_display(&e)));
            }
            self.drain_microtasks()?;
        }
        // Fired one-shot timers and cleared ones are dead entries: drop
        // them so the table (and every scan of it) stays proportional to
        // the LIVE timers, not to every timer the page ever scheduled.
        if self.timers.len() > 64 {
            self.timers.retain(|t| !t.cancelled);
        }
        Ok(())
    }

    /// The most live timers a page may hold at once. Past it `setTimeout`
    /// still hands out an id but schedules nothing; a page that arms a
    /// million timers is not going to render differently for the extra
    /// ones, and the table must stay bounded.
    pub const MAX_LIVE_TIMERS: usize = 100_000;

    pub fn set_timer(
        &mut self,
        callback: JsValue,
        delay_ms: f64,
        args: Vec<JsValue>,
        interval: bool,
    ) -> u32 {
        let id = self.next_timer_id_pub;
        self.next_timer_id_pub = self.next_timer_id_pub.wrapping_add(1);
        let delay = if delay_ms.is_finite() {
            delay_ms.max(0.0)
        } else {
            0.0
        };
        if self.timers.len() >= Self::MAX_LIVE_TIMERS {
            self.timers.retain(|t| !t.cancelled);
            if self.timers.len() >= Self::MAX_LIVE_TIMERS {
                return id;
            }
        }
        self.timers.push(Timer {
            id,
            due_ms: self.now_ms + delay,
            callback,
            args,
            interval_ms: if interval { Some(delay.max(1.0)) } else { None },
            cancelled: false,
        });
        id
    }

    pub fn clear_timer(&mut self, id: u32) {
        if let Some(t) = self.timers.iter_mut().find(|t| t.id == id) {
            t.cancelled = true;
        }
    }

    /// An already-fulfilled promise (`Promise.resolve(v)`).
    pub fn resolved_promise(&mut self, value: JsValue) -> JsValue {
        let p = self.new_promise();
        self.resolve_promise(&p, value, true);
        JsValue::Object(p)
    }

    /// An already-rejected promise (`Promise.reject(e)`).
    pub fn rejected_promise(&mut self, error: JsValue) -> JsValue {
        let p = self.new_promise();
        self.resolve_promise(&p, error, false);
        JsValue::Object(p)
    }

    /// `Promise.withResolvers()`: a pending promise and the two functions
    /// that settle it, for host surfaces that resolve later
    /// (`customElements.whenDefined`, a fetch that completes on a task).
    pub fn new_promise_with_resolvers(&mut self) -> (JsValue, JsValue, JsValue) {
        let p = self.new_promise();
        let settle = |promise: ObjRef, fulfill: bool| -> NativeFn {
            Rc::new(move |interp, _this, args| {
                let v = args.first().cloned().unwrap_or(JsValue::Undefined);
                interp.resolve_promise(&promise, v, fulfill);
                Ok(JsValue::Undefined)
            })
        };
        let resolve = self.native(settle(p.clone(), true));
        let reject = self.native(settle(p.clone(), false));
        (JsValue::Object(p), resolve, reject)
    }

    pub fn new_promise(&mut self) -> ObjRef {
        JsObject::new(
            ObjKind::Promise(PromiseState::Pending {
                on_fulfilled: Vec::new(),
                on_rejected: Vec::new(),
            }),
            Some(self.promise_proto.clone()),
        )
    }

    /// Settle a promise, scheduling its queued reactions as microtasks.
    pub fn resolve_promise(&mut self, promise: &ObjRef, value: JsValue, fulfill: bool) {
        // Chained thenable adoption: resolving with a promise adopts its state.
        if fulfill {
            if let JsValue::Object(inner) = &value {
                let is_promise = matches!(inner.borrow().kind, ObjKind::Promise(_));
                if is_promise && !Rc::ptr_eq(inner, promise) {
                    let derived = promise.clone();
                    self.add_reactions(inner, None, None, derived);
                    return;
                }
            }
        }
        let reactions = {
            let mut b = promise.borrow_mut();
            match &mut b.kind {
                ObjKind::Promise(state @ PromiseState::Pending { .. }) => {
                    let taken = core::mem::replace(
                        state,
                        if fulfill {
                            PromiseState::Fulfilled(Box::new(value.clone()))
                        } else {
                            PromiseState::Rejected(Box::new(value.clone()))
                        },
                    );
                    match taken {
                        PromiseState::Pending {
                            on_fulfilled,
                            on_rejected,
                        } => Some(if fulfill { on_fulfilled } else { on_rejected }),
                        _ => None,
                    }
                }
                _ => None,
            }
        };
        if let Some(rs) = reactions {
            for r in rs {
                self.microtasks.push_back(Job::Reaction {
                    handler: r.handler,
                    arg: value.clone(),
                    fulfilled: fulfill,
                    derived: r.derived,
                });
            }
        }
    }

    /// Attach fulfill/reject handlers, returning nothing; `derived` receives
    /// the handler result. Passing `None,None` adopts state pass-through.
    pub fn add_reactions(
        &mut self,
        promise: &ObjRef,
        on_fulfilled: Option<ObjRef>,
        on_rejected: Option<ObjRef>,
        derived: ObjRef,
    ) {
        let immediate = {
            let mut b = promise.borrow_mut();
            match &mut b.kind {
                ObjKind::Promise(PromiseState::Pending {
                    on_fulfilled: f,
                    on_rejected: r,
                }) => {
                    f.push(Reaction {
                        handler: on_fulfilled.clone(),
                        derived: derived.clone(),
                    });
                    r.push(Reaction {
                        handler: on_rejected.clone(),
                        derived: derived.clone(),
                    });
                    None
                }
                ObjKind::Promise(PromiseState::Fulfilled(v)) => Some((true, (**v).clone())),
                ObjKind::Promise(PromiseState::Rejected(v)) => Some((false, (**v).clone())),
                _ => None,
            }
        };
        if let Some((fulfilled, value)) = immediate {
            let handler = if fulfilled { on_fulfilled } else { on_rejected };
            self.microtasks.push_back(Job::Reaction {
                handler,
                arg: value,
                fulfilled,
                derived,
            });
        }
    }

    /// `await` support: drain queues until the promise settles. Every
    /// iteration charges the step budget (and so the wall-clock deadline):
    /// an `await` on a promise that an interval keeps alive would otherwise
    /// spin the virtual clock forever — a corpus site did exactly that,
    /// logging on every tick until allocation failed.
    pub fn await_promise(&mut self, promise: &ObjRef) -> Result<JsValue, JsValue> {
        loop {
            self.charge()?;
            {
                let b = promise.borrow();
                match &b.kind {
                    ObjKind::Promise(PromiseState::Fulfilled(v)) => return Ok((**v).clone()),
                    ObjKind::Promise(PromiseState::Rejected(v)) => return Err((**v).clone()),
                    ObjKind::Promise(PromiseState::Pending { .. }) => {}
                    _ => return Ok(JsValue::Object(promise.clone())),
                }
            }
            let had_micro = !self.microtasks.is_empty();
            let next_timer = self
                .timers
                .iter()
                .filter(|t| !t.cancelled)
                .map(|t| t.due_ms)
                .fold(f64::INFINITY, f64::min);
            if had_micro {
                self.drain_microtasks()?;
            } else if next_timer.is_finite() {
                self.now_ms = self.now_ms.max(next_timer);
                self.fire_due_timers()?;
            } else {
                return Err(Self::throw(
                    "Error: await deadlock — promise can never settle",
                ));
            }
        }
    }

    /// A function object for `def` closing over `scope`. An ordinary
    /// function or generator is a constructor and gets a `prototype`
    /// (ES 10.2.5 MakeConstructor); an arrow or an async function does
    /// not.
    pub fn make_function(
        &mut self,
        def: Rc<FnDef>,
        scope: ScopeRef,
        captured_this: Option<JsValue>,
    ) -> JsValue {
        let constructor = !def.arrow && (!def.is_async || def.is_generator);
        self.make_function_object(def, scope, captured_this, constructor)
    }

    /// A method, accessor or class element function: not a constructor,
    /// so no `prototype`, unless it is a generator method, whose
    /// `prototype` its generator objects inherit from.
    pub fn make_method(&mut self, def: Rc<FnDef>, scope: ScopeRef) -> JsValue {
        let generator = def.is_generator;
        self.make_function_object(def, scope, None, generator)
    }

    fn make_function_object(
        &mut self,
        def: Rc<FnDef>,
        scope: ScopeRef,
        captured_this: Option<JsValue>,
        constructor: bool,
    ) -> JsValue {
        let length = super::function_meta::expected_argument_count(&def) as f64;
        let name = match &def.name {
            Some(n) => JsValue::str(n.clone()),
            None => self.empty_string.clone(),
        };
        let obj = JsObject::new(
            ObjKind::Function {
                def,
                scope,
                captured_this: captured_this.map(Box::new),
            },
            Some(self.function_proto.clone()),
        );
        obj.borrow_mut().define_function_meta(length, name);
        if !constructor {
            return JsValue::Object(obj);
        }
        let proto = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        proto
            .borrow_mut()
            .set_prop("constructor", JsValue::Object(obj.clone()), false);
        obj.borrow_mut()
            .set_prop("prototype", JsValue::Object(proto), false);
        JsValue::Object(obj)
    }

    pub fn call(
        &mut self,
        callee: JsValue,
        this: JsValue,
        args: &[JsValue],
    ) -> Result<JsValue, JsValue> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(Self::throw("RangeError: Maximum call stack size exceeded"));
        }
        // The stack grows downward on every supported target, but the
        // distance is taken both ways so the check is direction-agnostic.
        if self.stack_base.abs_diff(stack_mark()) > self.stack_budget_bytes {
            return Err(Self::throw("RangeError: Maximum call stack size exceeded"));
        }
        self.call_depth = self.call_depth.saturating_add(1);
        let name = match &callee {
            JsValue::Object(o) => match &o.borrow().kind {
                ObjKind::Function { def, .. } => Some(def.name.clone().unwrap_or_default()),
                _ => None,
            },
            _ => None,
        };
        let r = self.call_inner(callee, this, args);
        self.call_depth = self.call_depth.saturating_sub(1);
        if r.is_err() {
            if let Some(n) = name {
                if self.error_trace.len() < 24 {
                    self.error_trace.push(if n.is_empty() {
                        "<anonymous>".to_string()
                    } else {
                        n
                    });
                }
            }
        }
        r
    }

    fn call_inner(
        &mut self,
        callee: JsValue,
        this: JsValue,
        args: &[JsValue],
    ) -> Result<JsValue, JsValue> {
        self.charge()?;
        let JsValue::Object(fobj) = &callee else {
            return Err(Self::throw(format!(
                "TypeError: {} is not a function",
                to_display(&callee)
            )));
        };
        // Proxy apply trap / pass-through.
        let proxy = match &fobj.borrow().kind {
            ObjKind::Proxy { target, handler } => Some((target.clone(), handler.clone())),
            _ => None,
        };
        if let Some((target, handler)) = proxy {
            // GetMethod: the trap is read through [[Get]] (a getter runs),
            // and a value that is neither nullish nor callable throws.
            if let Some(trap) = self.proxy_trap(&handler, "apply")? {
                let arr = self.new_array(args.to_vec());
                return self.call(trap, JsValue::Object(handler), &[JsValue::Object(target), this, arr]);
            }
            return self.call(JsValue::Object(target), this, args);
        }
        // A class constructor has no [[Call]]: every invocation path
        // (direct, `.call`, reflective) throws unless it came via `new`,
        // which `construct_with_target` signals through `new_target`.
        if fobj.borrow().is_class && self.new_target.is_none() {
            return Err(Self::throw(
                "TypeError: Class constructor cannot be invoked without 'new'",
            ));
        }
        // Clone what we need out of the borrow before running.
        enum Plan {
            Interp {
                def: Rc<FnDef>,
                scope: ScopeRef,
                captured_this: Option<JsValue>,
            },
            Native(NativeFn),
            Bound {
                target: ObjRef,
                this_arg: JsValue,
                bound_args: Vec<JsValue>,
            },
        }
        let plan = {
            let b = fobj.borrow();
            match &b.kind {
                ObjKind::Function {
                    def,
                    scope,
                    captured_this,
                } => Plan::Interp {
                    def: def.clone(),
                    scope: scope.clone(),
                    captured_this: captured_this.as_deref().cloned(),
                },
                ObjKind::Native(f) => Plan::Native(f.clone()),
                ObjKind::Bound {
                    target,
                    this_arg,
                    bound_args,
                } => Plan::Bound {
                    target: target.clone(),
                    this_arg: (**this_arg).clone(),
                    bound_args: bound_args.clone(),
                },
                _ => {
                    return Err(Self::throw(format!(
                        "TypeError: value is not callable ({} object)",
                        b.class_name
                    )))
                }
            }
        };
        match plan {
            Plan::Native(f) => f(self, this, args),
            Plan::Bound {
                target,
                this_arg,
                bound_args,
            } => {
                let mut all = bound_args;
                all.extend_from_slice(args);
                self.call(JsValue::Object(target), this_arg, &all)
            }
            Plan::Interp {
                def,
                scope,
                captured_this,
            } => {
                let fscope = Scope::new_function(Some(scope));
                fscope.borrow_mut().strict = def.strict;
                // Sloppy-mode pages: a plain call's `this` is the global
                // object (ES §10.2.1.2 OrdinaryCallBindThis). UMD wrappers
                // (`(function(){...})(this)`, `...(e=e||self).React={}`) rely
                // on it to find the global. Strict functions keep the
                // `this` they were given: `undefined` for a plain call,
                // `null` for `.call(null)`.
                let effective_this = if def.arrow {
                    captured_this.unwrap_or(JsValue::Undefined)
                } else if this.is_nullish() && !def.strict {
                    JsValue::Object(self.global_object.clone())
                } else {
                    this
                };
                Scope::declare(&fscope, "this", effective_this.clone(), false);
                // `new.target`: set by `construct` for the duration of the
                // call; arrows inherit the enclosing binding lexically.
                if !def.arrow {
                    let nt = self.new_target.take().unwrap_or(JsValue::Undefined);
                    Scope::declare(&fscope, "new.target", nt, false);
                }
                // arguments object (array-ish).
                if !def.arrow {
                    let args_arr = self.new_array(args.to_vec());
                    Scope::declare(&fscope, "arguments", args_arr, false);
                }
                // Bind parameters (with defaults and rest).
                let mut i = 0usize;
                for p in &def.params {
                    if p.rest {
                        let rest: Vec<JsValue> =
                            args.get(i..).map(|s| s.to_vec()).unwrap_or_default();
                        let arr = self.new_array(rest);
                        self.bind_pattern(&p.pat, arr, &fscope, true, false)?;
                        break;
                    }
                    let mut v = args.get(i).cloned().unwrap_or(JsValue::Undefined);
                    if matches!(v, JsValue::Undefined) {
                        if let Some(d) = &p.default {
                            v = self.eval_default(d, &p.pat, &fscope)?;
                        }
                    }
                    self.bind_pattern(&p.pat, v, &fscope, true, false)?;
                    i = i.saturating_add(1);
                }
                self.hoist(&def.body, &fscope)?;
                if def.is_generator {
                    // A generator object: the body is a coroutine that the
                    // first `next()` starts and every later one resumes at
                    // its `yield`, so values come out lazily and an
                    // infinite generator costs only what is consumed.
                    let def2 = def.clone();
                    let scope2 = fscope.clone();
                    return Ok(self.make_generator(def2, scope2));
                }
                if def.is_async {
                    // The body runs until its first `await`, then parks; the
                    // awaited promise's reaction (a microtask) resumes it.
                    // The call returns the promise before any of that runs
                    // further, as the spec's ordering requires.
                    let promise = self.new_promise();
                    let co = Rc::new(RefCell::new(Coroutine::new(
                        Mode::Async,
                        Rc::new(def.body.clone()),
                        fscope,
                    )));
                    let step = match co.try_borrow_mut() {
                        Ok(mut c) => c.resume(self, JsValue::Undefined),
                        Err(_) => Step::Threw(Self::throw(
                            "TypeError: async function body is already running",
                        )),
                    };
                    self.async_settle(&co, &promise, step);
                    return Ok(JsValue::Object(promise));
                }
                match self.exec_block(&def.body, &fscope)? {
                    Completion::Return(v) => Ok(v),
                    _ => Ok(JsValue::Undefined),
                }
            }
        }
    }

    pub fn construct(&mut self, callee: JsValue, args: &[JsValue]) -> Result<JsValue, JsValue> {
        self.construct_with_target(callee.clone(), args, callee)
    }

    /// `new callee(...args)` with an explicit `new.target` (the derived
    /// class when a `super(...)` call reaches a base constructor, so the
    /// instance's prototype is the DERIVED class's).
    pub fn construct_with_target(
        &mut self,
        callee: JsValue,
        args: &[JsValue],
        new_target: JsValue,
    ) -> Result<JsValue, JsValue> {
        let JsValue::Object(fobj) = &callee else {
            return Err(Self::throw("TypeError: not a constructor"));
        };
        if fobj.borrow().is_arrow() {
            return Err(Self::throw("TypeError: arrow function is not a constructor"));
        }
        // Proxy construct trap.
        let proxy = match &fobj.borrow().kind {
            ObjKind::Proxy { target, handler } => Some((target.clone(), handler.clone())),
            _ => None,
        };
        if let Some((target, handler)) = proxy {
            if let Some(trap) = self.proxy_trap(&handler, "construct")? {
                let arr = self.new_array(args.to_vec());
                let out = self.call(
                    trap,
                    JsValue::Object(handler),
                    &[JsValue::Object(target), arr, new_target],
                )?;
                if !matches!(out, JsValue::Object(_)) {
                    return Err(Self::throw(
                        "TypeError: proxy [[Construct]] must return an object",
                    ));
                }
                return Ok(out);
            }
            return self.construct_with_target(JsValue::Object(target), args, new_target);
        }
        // Bound functions construct their target with the bound args.
        let bound = match &fobj.borrow().kind {
            ObjKind::Bound {
                target, bound_args, ..
            } => Some((target.clone(), bound_args.clone())),
            _ => None,
        };
        if let Some((target, mut all)) = bound {
            all.extend_from_slice(args);
            let nt = if matches!(&new_target, JsValue::Object(o) if Rc::ptr_eq(o, fobj)) {
                JsValue::Object(target.clone())
            } else {
                new_target
            };
            return self.construct_with_target(JsValue::Object(target), &all, nt);
        }
        // The instance prototype comes from new.target's `prototype`.
        let proto_src = match &new_target {
            JsValue::Object(t) => t.clone(),
            _ => fobj.clone(),
        };
        let proto = match self.get_property(&JsValue::Object(proto_src), "prototype") {
            Ok(JsValue::Object(p)) => Some(p),
            _ => Some(self.object_proto.clone()),
        };
        // A derived class constructor does not allocate: `this` is created
        // by the base constructor reached through `super(...)`. The derived
        // body runs with an uninitialised `this` until then.
        let is_derived = fobj.borrow().get_prop("__super__").is_some();
        let this_obj = JsObject::new(ObjKind::Plain, proto);
        let this = JsValue::Object(this_obj.clone());
        if !is_derived {
            // Instance fields of a BASE class initialise before the body.
            self.init_fields(fobj, &this)?;
        }
        // `new_target` is consumed by the callee's scope setup; a throwing
        // constructor must not leave it armed for the next plain call.
        let saved = self.new_target.replace(new_target);
        let outer_super_this = self.super_this.take();
        let r = self.call(callee, this.clone(), args);
        self.new_target = saved;
        let rebound = self.super_this.take();
        self.super_this = outer_super_this;
        let r = r?;
        match r {
            JsValue::Object(_) => Ok(r),
            // A `super()` that rebound `this` (the HTMLElement base handing
            // back the element under construction) makes THAT object the
            // instance.
            _ => Ok(rebound.map(JsValue::Object).unwrap_or(this)),
        }
    }

    /// Run a class's instance field initialisers against `this`, in
    /// declaration order. Fields live on the constructor as the hidden
    /// `__fields__` list of (key, initializer function).
    pub fn init_fields(&mut self, ctor: &ObjRef, this: &JsValue) -> Result<(), JsValue> {
        let fields = ctor.borrow().get_prop("__fields__");
        let Some(JsValue::Object(list)) = fields else {
            return Ok(());
        };
        let items = list.borrow().array_values();
        for item in items {
            let JsValue::Object(pair) = item else { continue };
            let (key, init) = {
                let b = pair.borrow();
                (
                    b.elem(0).cloned().unwrap_or(JsValue::Undefined),
                    b.elem(1).cloned().unwrap_or(JsValue::Undefined),
                )
            };
            let k = key.to_property_key();
            let v = match &init {
                JsValue::Object(f) if f.borrow().is_callable() => {
                    self.call(init.clone(), this.clone(), &[])?
                }
                _ => JsValue::Undefined,
            };
            if super::function_meta::field_initializer_is_anonymous(&init) {
                let name = self.function_name_for_key(&k, None);
                self.name_anonymous_function(&v, &name);
            }
            if let JsValue::Object(o) = this {
                o.borrow_mut().set_prop(&k, v, !k.starts_with('#'));
            }
        }
        Ok(())
    }

    /// Settle an async function's promise from one coroutine step: a
    /// finished body resolves or rejects it; an `await` attaches reactions
    /// to the awaited value (a non-promise is wrapped in a resolved one, so
    /// the continuation still runs as a microtask, per spec) that resume
    /// the body with the settled value or throw the rejection into it.
    pub fn async_settle(&mut self, co: &Rc<RefCell<Coroutine>>, promise: &ObjRef, step: Step) {
        match step {
            Step::Done(v) | Step::Yielded(v) => self.resolve_promise(promise, v, true),
            Step::Threw(e) => self.resolve_promise(promise, e, false),
            Step::Awaited(v) => {
                let awaited = match &v {
                    JsValue::Object(o) if matches!(o.borrow().kind, ObjKind::Promise(_)) => {
                        o.clone()
                    }
                    _ => {
                        let p = self.new_promise();
                        self.resolve_promise(&p, v, true);
                        p
                    }
                };
                let (c1, p1) = (co.clone(), promise.clone());
                let on_fulfilled: NativeFn = Rc::new(move |interp, _t, args| {
                    let v = args.first().cloned().unwrap_or(JsValue::Undefined);
                    let step = match c1.try_borrow_mut() {
                        Ok(mut c) => c.resume(interp, v),
                        Err(_) => Step::Threw(Interp::throw(
                            "TypeError: async function body is already running",
                        )),
                    };
                    interp.async_settle(&c1, &p1, step);
                    Ok(JsValue::Undefined)
                });
                let (c2, p2) = (co.clone(), promise.clone());
                let on_rejected: NativeFn = Rc::new(move |interp, _t, args| {
                    let e = args.first().cloned().unwrap_or(JsValue::Undefined);
                    let step = match c2.try_borrow_mut() {
                        Ok(mut c) => c.resume_throw(interp, e),
                        Err(_) => Step::Threw(Interp::throw(
                            "TypeError: async function body is already running",
                        )),
                    };
                    interp.async_settle(&c2, &p2, step);
                    Ok(JsValue::Undefined)
                });
                let f = self.native(on_fulfilled);
                let r = self.native(on_rejected);
                let derived = self.new_promise();
                if let (JsValue::Object(f), JsValue::Object(r)) = (f, r) {
                    self.add_reactions(&awaited, Some(f), Some(r), derived);
                }
            }
        }
    }

    /// Build a generator object for `def` over its (already parameter-bound)
    /// call scope: a suspended coroutine that `next()` starts and resumes.
    fn make_generator(&mut self, def: Rc<FnDef>, scope: ScopeRef) -> JsValue {
        let co = Coroutine::new(Mode::Generator, Rc::new(def.body.clone()), scope);
        let gen = JsObject::new(
            ObjKind::Generator(GeneratorState {
                co: Some(Box::new(co)),
                running: false,
                buffer: Vec::new(),
                pos: 0,
                done: false,
                return_value: Box::new(JsValue::Undefined),
            }),
            Some(self.generator_proto.clone()),
        );
        JsValue::Object(gen)
    }

    /// Resume a generator: `next(v)` delivers `v` as the value of the
    /// suspended `yield`, `throw(e)` throws `e` there (so the body's own
    /// `catch` / `finally` run), `return(v)` completes the body from there
    /// (running its `finally` blocks, which may yield again). A generator
    /// that is already running (a body resuming itself) is a TypeError; a
    /// finished one answers `{ undefined, true }`, rethrows, or returns
    /// `{ v, true }` respectively.
    pub fn generator_resume(&mut self, gen: &ObjRef, how: GenResume) -> Result<JsValue, JsValue> {
        enum Plan {
            Done,
            Running,
            List,
            Body(Box<Coroutine>),
        }
        let plan = {
            let mut b = gen.borrow_mut();
            match &mut b.kind {
                ObjKind::Generator(g) => {
                    if g.done {
                        Plan::Done
                    } else if g.running {
                        Plan::Running
                    } else {
                        match g.co.take() {
                            Some(co) => {
                                g.running = true;
                                Plan::Body(co)
                            }
                            None => Plan::List,
                        }
                    }
                }
                _ => return Err(Self::throw("TypeError: next on non-generator")),
            }
        };
        match plan {
            Plan::Running => Err(Self::throw("TypeError: Generator is already running")),
            Plan::Done => match how {
                GenResume::Next(_) => Ok(self.iter_result(JsValue::Undefined, true)),
                GenResume::Return(v) => Ok(self.iter_result(v, true)),
                GenResume::Throw(e) => Err(e),
            },
            Plan::List => {
                // The engine's own list iterators: a snapshot of items.
                let (value, done) = {
                    let mut b = gen.borrow_mut();
                    let ObjKind::Generator(g) = &mut b.kind else {
                        return Ok(JsValue::Undefined);
                    };
                    match how {
                        GenResume::Next(_) => {
                            if g.pos >= g.buffer.len() {
                                g.done = true;
                                g.buffer.clear();
                                let rv = core::mem::replace(
                                    &mut g.return_value,
                                    Box::new(JsValue::Undefined),
                                );
                                (*rv, true)
                            } else {
                                let v = g.buffer.get(g.pos).cloned().unwrap_or(JsValue::Undefined);
                                g.pos = g.pos.saturating_add(1);
                                (v, false)
                            }
                        }
                        GenResume::Return(v) => {
                            g.done = true;
                            g.buffer.clear();
                            (v, true)
                        }
                        GenResume::Throw(e) => {
                            g.done = true;
                            g.buffer.clear();
                            drop(b);
                            return Err(e);
                        }
                    }
                };
                Ok(self.iter_result(value, done))
            }
            Plan::Body(mut co) => {
                let step = match how {
                    GenResume::Next(v) => co.resume(self, v),
                    GenResume::Throw(e) => co.resume_throw(self, e),
                    GenResume::Return(v) => co.resume_return(self, v),
                };
                let finished = co.is_done();
                {
                    let mut b = gen.borrow_mut();
                    if let ObjKind::Generator(g) = &mut b.kind {
                        g.running = false;
                        if finished {
                            g.done = true;
                        } else {
                            g.co = Some(co);
                        }
                    }
                }
                match step {
                    Step::Yielded(v) | Step::Awaited(v) => Ok(self.iter_result(v, false)),
                    Step::Done(v) => Ok(self.iter_result(v, true)),
                    Step::Threw(e) => Err(e),
                }
            }
        }
    }

    /// `{ value, done }` iterator result record.
    pub fn iter_result(&mut self, value: JsValue, done: bool) -> JsValue {
        let o = JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
        o.borrow_mut().set_prop("value", value, true);
        o.borrow_mut().set_prop("done", JsValue::Bool(done), true);
        JsValue::Object(o)
    }

    pub fn new_array(&mut self, elems: Vec<JsValue>) -> JsValue {
        self.new_array_with_holes(elems.into_iter().map(Some).collect())
    }

    /// A new Array whose elements are `elems`, `None` leaving a hole.
    pub fn new_array_with_holes(&mut self, elems: Vec<Option<JsValue>>) -> JsValue {
        let arr = JsObject::new(ObjKind::Array, Some(self.array_proto.clone()));
        arr.borrow_mut().elems = elems;
        JsValue::Object(arr)
    }

    fn make_class(&mut self, def: &Rc<ClassDef>, scope: &ScopeRef) -> Result<JsValue, JsValue> {
        let parent = match &def.parent {
            Some(e) => Some(self.eval(e, scope)?),
            None => None,
        };
        // `class X extends null` / a non-constructor parent is a TypeError.
        if let Some(p) = &parent {
            let ok = match p {
                JsValue::Object(o) => o.borrow().is_callable(),
                JsValue::Null => true,
                _ => false,
            };
            if !ok {
                return Err(Self::throw(
                    "TypeError: Class extends value is not a constructor or null",
                ));
            }
        }
        let parent_proto = match &parent {
            Some(JsValue::Object(p)) => match self.get_property(&JsValue::Object(p.clone()), "prototype") {
                Ok(JsValue::Object(pp)) => Some(pp),
                _ => Some(self.object_proto.clone()),
            },
            Some(JsValue::Null) => None,
            _ => Some(self.object_proto.clone()),
        };
        // The constructor function. A derived class without an explicit
        // constructor gets `constructor(...args) { super(...args); }`.
        let ctor_def = def.constructor.clone().unwrap_or_else(|| {
            let body = if parent.is_some() {
                vec![Stmt::Expr(Expr::Call {
                    callee: Box::new(Expr::Ident("super".to_string())),
                    args: vec![SpreadElem {
                        expr: Expr::Ident("arguments".to_string()),
                        spread: true,
                    }],
                    optional: false,
                })]
            } else {
                Vec::new()
            };
            Rc::new(FnDef {
                name: def.name.clone(),
                params: Vec::new(),
                body,
                arrow: false,
                is_async: false,
                is_expr_body: false,
                is_generator: false,
                strict: true,
            })
        });
        // Methods and the constructor close over a scope that knows the
        // parent: `super.x` and `super(...)` resolve through these bindings.
        let class_scope = Scope::new(Some(scope.clone()));
        if let Some(JsValue::Object(parent_obj)) = &parent {
            Scope::declare(
                &class_scope,
                "__super_ctor__",
                JsValue::Object(parent_obj.clone()),
                false,
            );
        }
        // The class binding is visible inside its own body (methods refer
        // to the class by name, `static` initialisers read statics).
        let ctor = self.make_function(ctor_def, class_scope.clone(), None);
        let JsValue::Object(ctor_obj) = &ctor else {
            return Err(Self::throw("internal: class constructor"));
        };
        ctor_obj.borrow_mut().is_class = true;
        // The constructor's `name` is the class's (its definition may be
        // an explicit `constructor(...)` method); `length` is its own.
        ctor_obj
            .borrow_mut()
            .set_prop("name", JsValue::str(def.name.clone().unwrap_or_default()), false);
        if let Some(name) = &def.name {
            Scope::declare(&class_scope, name, ctor.clone(), false);
        }
        // `super(...)` initialises THIS class's fields once the parent
        // returns; it finds the class through this hidden binding.
        Scope::declare(&class_scope, "__class_ctor__", ctor.clone(), false);
        // Wire prototype chain and methods.
        let proto = match ctor_obj.borrow().get_prop("prototype") {
            Some(JsValue::Object(p)) => p,
            _ => JsObject::new(ObjKind::Plain, Some(self.object_proto.clone())),
        };
        proto.borrow_mut().proto = parent_proto;
        if let Some(JsValue::Object(parent_obj)) = &parent {
            // Static inheritance + super() support via __super__.
            ctor_obj.borrow_mut().proto = Some(parent_obj.clone());
            ctor_obj
                .borrow_mut()
                .set_prop("__super__", JsValue::Object(parent_obj.clone()), false);
        }
        // Parent prototype for super.method lookups inside methods.
        if let Some(JsValue::Object(parent_obj)) = &parent {
            if let Some(JsValue::Object(pp)) = parent_obj.borrow().get_prop("prototype") {
                Scope::declare(&class_scope, "__super_proto__", JsValue::Object(pp), false);
            }
        }
        // Instance field initialisers, in order, for `construct`.
        let mut instance_fields: Vec<JsValue> = Vec::new();
        // Static fields and blocks run after the methods are installed, in
        // declaration order, with `this` = the constructor.
        let mut static_inits: Vec<(Option<String>, JsValue)> = Vec::new();
        for m in &def.members {
            let key = match &m.key {
                PropKey::Static(s) => JsValue::str(s.clone()),
                PropKey::Computed(e) => {
                    let v = self.eval(e, scope)?;
                    if matches!(v, JsValue::Symbol(_)) {
                        self.note_symbol(&v);
                        v
                    } else {
                        JsValue::str(v.to_js_string())
                    }
                }
            };
            let k = key.to_property_key();
            // Methods and accessors see `super` through the class scope and
            // their `this` at call time; the method's `.name` is its key
            // (`get k` / `set k` for an accessor, `[desc]` for a symbol).
            let f = self.make_method(m.def.clone(), class_scope.clone());
            if let JsValue::Object(fo) = &f {
                let prefix = match m.kind {
                    MemberKind::Get => Some("get"),
                    MemberKind::Set => Some("set"),
                    _ => None,
                };
                if !matches!(m.kind, MemberKind::Field | MemberKind::StaticBlock) {
                    let name = self.function_name_for_key(&k, prefix);
                    fo.borrow_mut().set_prop("name", JsValue::str(name), false);
                }
            }
            // A static member named `name` or `length` replaces the
            // constructor's own property, writable as members are.
            if m.is_static && matches!(k.as_str(), "name" | "length") {
                ctor_obj.borrow_mut().set_writable(&k, true);
            }
            let target = if m.is_static { ctor_obj } else { &proto };
            match m.kind {
                MemberKind::Method => target.borrow_mut().set_prop(&k, f, false),
                MemberKind::Get => {
                    if let JsValue::Object(fo) = f {
                        target.borrow_mut().set_accessor(&k, Some(fo), None, false);
                    }
                }
                MemberKind::Set => {
                    if let JsValue::Object(fo) = f {
                        target.borrow_mut().set_accessor(&k, None, Some(fo), false);
                    }
                }
                MemberKind::Field => {
                    if m.is_static {
                        static_inits.push((Some(k), f));
                    } else {
                        let pair = self.new_array(vec![key, f]);
                        instance_fields.push(pair);
                    }
                }
                MemberKind::StaticBlock => static_inits.push((None, f)),
            }
        }
        if !instance_fields.is_empty() {
            // Derived classes chain: the parent's fields initialise first
            // (when `super()` returns), then this class's own.
            let list = self.new_array(instance_fields);
            ctor_obj.borrow_mut().set_prop("__fields__", list, false);
        }
        for (key, init) in static_inits {
            let anonymous = super::function_meta::field_initializer_is_anonymous(&init);
            let v = self.call(init, ctor.clone(), &[])?;
            if let Some(k) = key {
                if anonymous {
                    let name = self.function_name_for_key(&k, None);
                    self.name_anonymous_function(&v, &name);
                }
                ctor_obj.borrow_mut().set_prop(&k, v, !k.starts_with('#'));
            }
        }
        Ok(ctor)
    }

    /// Collect an iterable into a Vec: strings by code point, arrays and
    /// DOM lists directly, Map/Set in insertion order, generators by running
    /// them, and any other object through its `[Symbol.iterator]()` protocol
    /// (bounded by the step budget and a hard element cap).
    pub fn iterate(&mut self, v: &JsValue) -> Result<Vec<JsValue>, JsValue> {
        match v {
            JsValue::Str(s) => Ok(s.chars().map(|c| JsValue::str(c.to_string())).collect()),
            JsValue::Object(o) => {
                enum Fast {
                    Elems(Vec<JsValue>),
                    Dom(Vec<usize>),
                    MapItems(Vec<(JsValue, JsValue)>, bool),
                    Generator,
                    /// A Proxy over an array: walk `length` and the indices
                    /// through the traps (calling its `Symbol.iterator`
                    /// would land back here through the prototype).
                    ArrayLike,
                    Protocol,
                }
                let fast = {
                    let b = o.borrow();
                    match &b.kind {
                        // An array with a user-overridden iterator is rare
                        // enough that the dense fast path stays
                        // (array_like_items reads the store directly unless
                        // an index is an accessor).
                        ObjKind::Array => Fast::ArrayLike,
                        ObjKind::TypedArray(t) => {
                            Fast::Elems(t.values().into_iter().map(JsValue::Num).collect())
                        }
                        ObjKind::DomList(handles) => Fast::Dom(handles.clone()),
                        ObjKind::Map(m) => Fast::MapItems(m.items(), false),
                        ObjKind::Set(m) => Fast::MapItems(m.items(), true),
                        ObjKind::Generator(_) => Fast::Generator,
                        ObjKind::Proxy { target, .. }
                            if matches!(target.borrow().kind, ObjKind::Array) =>
                        {
                            Fast::ArrayLike
                        }
                        _ => Fast::Protocol,
                    }
                };
                match fast {
                    Fast::Elems(e) => Ok(e),
                    Fast::Dom(hs) => Ok(hs.iter().map(|h| self.wrap_dom_node(*h)).collect()),
                    Fast::MapItems(items, is_set) => Ok(items
                        .into_iter()
                        .map(|(k, val)| {
                            if is_set {
                                k
                            } else {
                                self.new_array(vec![k, val])
                            }
                        })
                        .collect()),
                    Fast::Generator => self.drain_iterator(v.clone()),
                    Fast::ArrayLike => self.array_like_items(v),
                    Fast::Protocol => {
                        let key = iterator_key();
                        let method = self.get_property(v, &key)?;
                        match &method {
                            JsValue::Object(f) if f.borrow().is_callable() => {
                                let it = self.call(method.clone(), v.clone(), &[])?;
                                self.drain_iterator(it)
                            }
                            _ => {
                                // Array-likes (`arguments`, NodeList shims
                                // from bundles): walk `length`.
                                let len = self.get_property(v, "length")?;
                                if let JsValue::Num(n) = len {
                                    if n.is_finite() && n >= 0.0 {
                                        let n = (n as usize).min(1_000_000);
                                        let mut out = Vec::with_capacity(n);
                                        for i in 0..n {
                                            out.push(self.get_property(v, &i.to_string())?);
                                        }
                                        return Ok(out);
                                    }
                                }
                                Err(Self::throw(format!(
                                    "TypeError: {} is not iterable",
                                    to_display(v)
                                )))
                            }
                        }
                    }
                }
            }
            _ => Err(Self::throw(format!(
                "TypeError: {} is not iterable",
                to_display(v)
            ))),
        }
    }

    /// Pull every value out of an iterator object by calling `next()` until
    /// `done`. Bounded by the step budget (each call charges) and a hard cap
    /// so an infinite iterator terminates the script, not the service.
    pub fn drain_iterator(&mut self, it: JsValue) -> Result<Vec<JsValue>, JsValue> {
        let mut out = Vec::new();
        let next = self.get_property(&it, "next")?;
        loop {
            self.charge()?;
            let r = self.call(next.clone(), it.clone(), &[])?;
            if self.get_property(&r, "done")?.truthy() {
                return Ok(out);
            }
            out.push(self.get_property(&r, "value")?);
            if out.len() >= 1_000_000 {
                return Err(Self::throw("RangeError: iterator produced too many values"));
            }
        }
    }

    /// An iterator object over a fixed list of values (`Array.prototype
    /// .values()`, `Map.prototype.entries()` and friends): `next()` walks
    /// the list, and the object is itself iterable.
    pub fn make_list_iterator(&mut self, items: Vec<JsValue>) -> JsValue {
        let it = JsObject::new(
            ObjKind::Generator(GeneratorState {
                co: None,
                running: false,
                buffer: items,
                pos: 0,
                done: false,
                return_value: Box::new(JsValue::Undefined),
            }),
            Some(self.generator_proto.clone()),
        );
        it.borrow_mut().class_name = "Array Iterator";
        JsValue::Object(it)
    }

    /// The symbol value a property-table key stands for: well-known symbols
    /// by id, registry symbols by identity, and any other live symbol the
    /// realm has seen (recorded when it was used as a key) so reflection
    /// returns the SAME symbol the script created, description included.
    pub fn symbol_for_key(&mut self, key: &str) -> JsValue {
        let id = key
            .strip_prefix("@@sym:")
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        if id < WELL_KNOWN_SYMBOLS {
            return well_known_symbol(id);
        }
        if let Some(v) = self.symbol_registry.values().find(|v| matches!(v, JsValue::Symbol(s) if s.id == id)) {
            return v.clone();
        }
        if let Some(v) = self.known_symbols.get(&id) {
            return v.clone();
        }
        JsValue::Symbol(Rc::new(SymbolData { id, description: None }))
    }

    /// Remember a symbol that is about to become a property key so
    /// [`Interp::symbol_for_key`] can hand back the identical value.
    pub fn note_symbol(&mut self, v: &JsValue) {
        if let JsValue::Symbol(s) = v {
            if s.id >= WELL_KNOWN_SYMBOLS && !self.known_symbols.contains_key(&s.id) {
                self.known_symbols.insert(s.id, v.clone());
            }
        }
    }

    /// ToObject: box a primitive in its wrapper object (objects pass through).
    pub fn to_object(&mut self, v: &JsValue) -> JsValue {
        let proto = match v {
            JsValue::Object(_) => return v.clone(),
            JsValue::Str(_) => self.string_proto.clone(),
            JsValue::Num(_) => self.number_proto.clone(),
            JsValue::Bool(_) => self.boolean_proto.clone(),
            JsValue::Symbol(_) => self.symbol_proto.clone(),
            JsValue::Undefined | JsValue::Null => self.object_proto.clone(),
        };
        let o = JsObject::new(ObjKind::Primitive(Box::new(v.clone())), Some(proto));
        JsValue::Object(o)
    }

    /// The source a `for (k in v)` loop pulls from (ES §14.7.5.6
    /// ForIn/OfHeadEvaluation): nothing for null and undefined, otherwise
    /// EnumerateObjectProperties over ToObject(v) (see `ForInState`).
    pub fn for_in_source(&mut self, v: &JsValue) -> Result<LoopSource, JsValue> {
        if v.is_nullish() {
            return Ok(LoopSource::Items(Vec::new().into_iter()));
        }
        let JsValue::Object(o) = self.to_object(v) else {
            return Ok(LoopSource::Items(Vec::new().into_iter()));
        };
        let mut state = ForInState {
            level: None,
            level_is_proxy: false,
            keys: Vec::new().into_iter(),
            host_keys: HashSet::new(),
            earlier: Vec::new(),
            visited: HashSet::new(),
        };
        state.enter(self, Some(o))?;
        Ok(LoopSource::Keys(Box::new(state)))
    }

    /// One level's keys for a `for-in` walk, in [[OwnPropertyKeys]] order:
    /// a Proxy's every string key (its `ownKeys` trap's answer), an
    /// ordinary object's enumerable string keys, and before them the keys
    /// a host object answers for itself (a DOM list's indices, a style or
    /// dataset facet's names).
    fn for_in_level_keys(&mut self, o: &ObjRef) -> Result<(Vec<String>, HashSet<String>), JsValue> {
        if Self::proxy_parts(o).is_some() {
            let keys = self.own_property_keys(o)?.into_iter().filter(|k| !is_symbol_key(k)).collect();
            return Ok((keys, HashSet::new()));
        }
        let facet = match &o.borrow().kind {
            ObjKind::DomFacet { handle, facet } => Some((*handle, *facet)),
            _ => None,
        };
        let b = o.borrow();
        let host: Vec<String> = match (&b.kind, facet) {
            (ObjKind::DomList(h), _) => (0..h.len()).map(|i| i.to_string()).collect(),
            (_, Some((h, f))) => super::dom_bindings::facet_keys(self, h, f),
            _ => Vec::new(),
        };
        let host_keys: HashSet<String> = host.iter().cloned().collect();
        let mut keys = host;
        keys.extend(b.own_keys().into_iter().filter(|k| !host_keys.contains(k)));
        Ok((keys, host_keys))
    }

    /// [[GetOwnProperty]] of a key at its turn in a `for-in` walk:
    /// `None` when `o` no longer has it, else whether it is enumerable.
    fn for_in_key_state(&mut self, o: &ObjRef, key: &str, host_keys: &HashSet<String>) -> Result<Option<bool>, JsValue> {
        if Self::proxy_parts(o).is_some() {
            return Ok(self
                .own_property_descriptor(o, key)?
                .map(|d| d.borrow().get_prop("enumerable").is_some_and(|e| e.truthy())));
        }
        let b = o.borrow();
        if let Some(Prop::Value { enumerable, .. } | Prop::Accessor { enumerable, .. }) = b.own_slot(key) {
            return Ok(Some(*enumerable));
        }
        if !host_keys.is_empty() && host_keys.contains(key) {
            return Ok(Some(true));
        }
        if !b.has_own_key(key) {
            return Ok(None);
        }
        Ok(Some(super::builtins_es::own_enumerable(&b, key)))
    }

    /// A binding pattern's default value: NamedEvaluation when the
    /// pattern is a plain identifier (`{ cb = () => {} }` names `cb`).
    fn eval_default(&mut self, d: &Expr, pat: &Pattern, scope: &ScopeRef) -> Result<JsValue, JsValue> {
        match pat {
            Pattern::Ident(name) => self.eval_named(d, scope, name),
            _ => self.eval(d, scope),
        }
    }

    pub fn bind_pattern(
        &mut self,
        pat: &Pattern,
        value: JsValue,
        scope: &ScopeRef,
        declare: bool,
        constant: bool,
    ) -> Result<(), JsValue> {
        match pat {
            Pattern::Ident(name) => {
                if declare {
                    // `let` / `const` / parameters: a lexical binding that
                    // never reaches the global object.
                    Scope::declare(scope, name, value, constant);
                } else {
                    self.set_binding(scope, name, value)?;
                }
                Ok(())
            }
            Pattern::Array(elems) => {
                let items = self.iterate(&value).unwrap_or_default();
                let mut idx = 0usize;
                for elem in elems {
                    let Some(elem) = elem else {
                        idx = idx.saturating_add(1);
                        continue;
                    };
                    if elem.rest {
                        let rest: Vec<JsValue> =
                            items.get(idx..).map(|s| s.to_vec()).unwrap_or_default();
                        let arr = self.new_array(rest);
                        self.bind_pattern(&elem.pat, arr, scope, declare, constant)?;
                        break;
                    }
                    let mut v = items.get(idx).cloned().unwrap_or(JsValue::Undefined);
                    if matches!(v, JsValue::Undefined) {
                        if let Some(d) = &elem.default {
                            v = self.eval_default(d, &elem.pat, scope)?;
                        }
                    }
                    self.bind_pattern(&elem.pat, v, scope, declare, constant)?;
                    idx = idx.saturating_add(1);
                }
                Ok(())
            }
            Pattern::Object(props) => {
                let mut taken: Vec<String> = Vec::new();
                for p in props {
                    if p.rest {
                        // { ...rest } — copy remaining own enumerable props.
                        let rest_obj =
                            JsObject::new(ObjKind::Plain, Some(self.object_proto.clone()));
                        if let JsValue::Object(src) = &value {
                            for (k, prop) in &src.borrow().props {
                                if let Prop::Value {
                                    value: v,
                                    enumerable: true,
                                } = prop
                                {
                                    if !taken.iter().any(|t| t == k) {
                                        rest_obj.borrow_mut().set_prop(k, v.clone(), true);
                                    }
                                }
                            }
                        }
                        self.bind_pattern(
                            &p.pat,
                            JsValue::Object(rest_obj),
                            scope,
                            declare,
                            constant,
                        )?;
                        continue;
                    }
                    let key = match &p.computed {
                        Some(e) => {
                            let k = self.eval(e, scope)?;
                            self.to_property_key(&k)?
                        }
                        None => p.key.clone(),
                    };
                    taken.push(key.clone());
                    let mut v = self.get_property(&value, &key)?;
                    if matches!(v, JsValue::Undefined) {
                        if let Some(d) = &p.default {
                            v = self.eval_default(d, &p.pat, scope)?;
                        }
                    }
                    self.bind_pattern(&p.pat, v, scope, declare, constant)?;
                }
                Ok(())
            }
        }
    }

    pub fn wrap_dom_node(&mut self, handle: usize) -> JsValue {
        super::dom_bindings::wrap_node(self, handle)
    }

    /// Assign to the nearest binding of `name`; an unbound name becomes an
    /// implicit global. A write that lands in the GLOBAL scope also lands on
    /// the global object when the name is a `var`/function/implicit global
    /// there, so `window.x` and `x` stay one binding.
    pub fn set_binding(
        &mut self,
        scope: &ScopeRef,
        name: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        if !Scope::set(scope, name, value.clone())? {
            // Implicit global (sloppy mode pages do this constantly).
            Scope::declare(&self.global_scope.clone(), name, value.clone(), false);
            self.mirror_global(name, &value);
            return Ok(());
        }
        // The binding exists somewhere on the chain; when it is the global
        // scope's own and the global object already carries it, update it.
        let on_global = self.global_scope.borrow().vars.contains_key(name)
            && !inner_scopes_bind(scope, &self.global_scope, name);
        if on_global && self.global_object.borrow().own(name).is_some() {
            self.mirror_global(name, &value);
        }
        Ok(())
    }

    fn mirror_global(&mut self, name: &str, value: &JsValue) {
        self.global_object
            .borrow_mut()
            .set_prop(name, value.clone(), true);
    }
}

/// Where a `for...of` / `for...in` loop takes its items from: a
/// pre-materialised list (arrays, strings, Map/Set snapshots, `for...in`
/// keys) or a live iterator object pulled one `next()` at a time, so a
/// generator body runs only as far as the loop consumes it.
/// EnumerateObjectProperties (ES §14.7.5.9) as the spec's informative
/// generator runs it: the own string keys of the object, then of each
/// object on its prototype chain (read through [[GetPrototypeOf]] when the
/// previous level is done), each key's [[GetOwnProperty]] asked when its
/// turn comes, so a key deleted by then is skipped and a Proxy's
/// `ownKeys`, `getOwnPropertyDescriptor` and `getPrototypeOf` traps run in
/// the spec's order. A key is visited at most once, and never when an
/// object nearer the start owns it, enumerable or not.
///
/// An ordinary level offers only its enumerable keys (no script can see
/// it asked about the others), and a key it owns shadows a later level's
/// by asking it again when that key comes up, so a prototype of
/// non-enumerable methods costs nothing to walk past.
pub struct ForInState {
    /// The object whose keys are being walked; `None` once done.
    level: Option<ObjRef>,
    level_is_proxy: bool,
    keys: std::vec::IntoIter<String>,
    /// The level's keys a host object answers for itself.
    host_keys: HashSet<String>,
    /// Ordinary levels already walked: their own keys shadow later ones.
    earlier: Vec<ObjRef>,
    /// Keys a Proxy or host level already walked reported present.
    visited: HashSet<String>,
}

impl ForInState {
    /// Leave the current level for `next`, taking its keys.
    fn enter(&mut self, interp: &mut Interp, next: Option<ObjRef>) -> Result<(), JsValue> {
        if let Some(done) = self.level.take() {
            if !self.level_is_proxy {
                self.earlier.push(done);
            }
            self.visited.extend(self.host_keys.drain());
        }
        if let Some(o) = &next {
            self.level_is_proxy = Interp::proxy_parts(o).is_some();
            let (keys, host_keys) = interp.for_in_level_keys(o)?;
            self.keys = keys.into_iter();
            self.host_keys = host_keys;
        }
        self.level = next;
        Ok(())
    }

    fn next(&mut self, interp: &mut Interp) -> Result<Option<String>, JsValue> {
        loop {
            let Some(o) = self.level.clone() else {
                return Ok(None);
            };
            let Some(k) = self.keys.next() else {
                interp.charge()?;
                let parent = interp.get_prototype_of(&o)?;
                self.enter(interp, parent)?;
                continue;
            };
            let Some(enumerable) = interp.for_in_key_state(&o, &k, &self.host_keys)? else {
                continue;
            };
            let shadowed = (!self.visited.is_empty() && self.visited.contains(&k))
                || self.earlier.iter().any(|e| e.borrow().has_own_key(&k));
            if self.level_is_proxy {
                self.visited.insert(k.clone());
            }
            if enumerable && !shadowed {
                return Ok(Some(k));
            }
        }
    }
}

pub enum LoopSource {
    Items(std::vec::IntoIter<JsValue>),
    /// A `for-in` loop's walk (see `ForInState`).
    Keys(Box<ForInState>),
    Iter {
        it: JsValue,
        next: JsValue,
        done: bool,
        /// The `value` of the `{ done: true }` result that ended the
        /// iteration: what `yield* it` evaluates to (ES §14.4.14).
        result: JsValue,
    },
}

impl LoopSource {
    /// Open `v` for iteration. Generators and protocol iterables (anything
    /// with a callable `[Symbol.iterator]` that is not one of the engine's
    /// own fast-path shapes) are pulled live; the rest are snapshotted.
    pub fn open(interp: &mut Interp, v: &JsValue) -> Result<LoopSource, JsValue> {
        if let JsValue::Object(o) = v {
            enum Shape {
                /// The engine's list iterators are a snapshot already.
                Snapshot,
                /// A dense shape whose snapshot stands in for ONE intrinsic
                /// iterator: the realm's own for that shape.
                FastIfIntrinsic(Option<ObjRef>),
                Protocol,
            }
            let ii = &interp.intrinsic_iterators;
            let shape = match &o.borrow().kind {
                ObjKind::Generator(g) if g.co.is_some() || g.running => Shape::Protocol,
                ObjKind::Generator(_) => Shape::Snapshot,
                ObjKind::Array | ObjKind::DomList(_) => Shape::FastIfIntrinsic(ii.array.clone()),
                ObjKind::TypedArray(_) => Shape::FastIfIntrinsic(ii.typed.clone()),
                ObjKind::Map(_) => Shape::FastIfIntrinsic(ii.map.clone()),
                ObjKind::Set(_) => Shape::FastIfIntrinsic(ii.set.clone()),
                // A Proxy over an array snapshots through its traps (the
                // `iterate` fast path); any other Proxy is a protocol
                // iterable.
                ObjKind::Proxy { target, .. } if matches!(target.borrow().kind, ObjKind::Array) => {
                    Shape::FastIfIntrinsic(ii.array.clone())
                }
                _ => Shape::Protocol,
            };
            let live = match shape {
                Shape::Snapshot => false,
                Shape::Protocol => true,
                Shape::FastIfIntrinsic(expected) => {
                    // Resolve the iterator the way the spec does (through
                    // the prototype chain, through a Proxy's `get` trap);
                    // the snapshot is only valid for the realm's own one
                    // for this shape. Anything non-callable is not
                    // iterable (ES §7.4.2 GetIterator).
                    let method = interp.get_property(v, &iterator_key())?;
                    match &method {
                        JsValue::Object(f) if f.borrow().is_callable() => {
                            !matches!(&expected, Some(i) if Rc::ptr_eq(i, f))
                        }
                        _ => {
                            return Err(Interp::throw(format!(
                                "TypeError: {} is not iterable",
                                to_display(v)
                            )))
                        }
                    }
                }
            };
            if live {
                let key = iterator_key();
                let method = interp.get_property(v, &key)?;
                if matches!(&method, JsValue::Object(f) if f.borrow().is_callable()) {
                    let it = interp.call(method, v.clone(), &[])?;
                    if !matches!(it, JsValue::Object(_)) {
                        return Err(Interp::throw(
                            "TypeError: Result of the Symbol.iterator method is not an object",
                        ));
                    }
                    let next = interp.get_property(&it, "next")?;
                    return Ok(LoopSource::Iter {
                        it,
                        next,
                        done: false,
                        result: JsValue::Undefined,
                    });
                }
            }
        }
        Ok(LoopSource::Items(interp.iterate(v)?.into_iter()))
    }

    /// The next item, or `None` once the source is exhausted.
    pub fn next(&mut self, interp: &mut Interp) -> Result<Option<JsValue>, JsValue> {
        self.next_with(interp, None)
    }

    /// [`LoopSource::next`] passing `sent` to the iterator's `next()`: a
    /// `yield*` forwards the value its own `next(v)` received (ES §14.4.14),
    /// so `var x = yield` inside the delegate sees it. `None` is the
    /// argumentless first pull; `Some(v)` is always ONE argument, even when
    /// `v` is undefined (a delegate may observe `arguments.length`).
    pub fn next_with(
        &mut self,
        interp: &mut Interp,
        sent: Option<JsValue>,
    ) -> Result<Option<JsValue>, JsValue> {
        match self {
            LoopSource::Items(items) => Ok(items.next()),
            LoopSource::Keys(state) => Ok(state.next(interp)?.map(JsValue::str)),
            LoopSource::Iter {
                it,
                next,
                done,
                result,
            } => {
                if *done {
                    return Ok(None);
                }
                let args: Vec<JsValue> = match sent {
                    Some(v) => vec![v],
                    None => Vec::new(),
                };
                let r = match interp.call(next.clone(), it.clone(), &args) {
                    Ok(r) => r,
                    Err(e) => {
                        // A throwing `next()` leaves nothing to close.
                        *done = true;
                        return Err(e);
                    }
                };
                if !matches!(r, JsValue::Object(_)) {
                    *done = true;
                    return Err(Interp::throw(format!(
                        "TypeError: Iterator result {} is not an object",
                        to_display(&r)
                    )));
                }
                if interp.get_property(&r, "done")?.truthy() {
                    *done = true;
                    *result = interp.get_property(&r, "value")?;
                    return Ok(None);
                }
                Ok(Some(interp.get_property(&r, "value")?))
            }
        }
    }

    /// The value the finished iterator returned with `done: true`
    /// (undefined for a snapshot source or before exhaustion).
    pub fn return_value(&self) -> JsValue {
        match self {
            LoopSource::Items(_) | LoopSource::Keys(_) => JsValue::Undefined,
            LoopSource::Iter { result, .. } => result.clone(),
        }
    }

    /// Whether the source ran to its end (nothing left to close).
    pub fn exhausted(&self) -> bool {
        match self {
            LoopSource::Items(items) => items.len() == 0,
            LoopSource::Keys(state) => state.level.is_none(),
            LoopSource::Iter { done, .. } => *done,
        }
    }

    /// IteratorClose: call the iterator's `return()` when it has one.
    pub fn close(&mut self, interp: &mut Interp) -> Result<(), JsValue> {
        let LoopSource::Iter { it, done, .. } = self else {
            return Ok(());
        };
        if *done {
            return Ok(());
        }
        *done = true;
        let ret = interp.get_property(it, "return")?;
        if matches!(&ret, JsValue::Object(f) if f.borrow().is_callable()) {
            let r = interp.call(ret, it.clone(), &[])?;
            if !matches!(r, JsValue::Object(_)) {
                return Err(Interp::throw(
                    "TypeError: Iterator result is not an object",
                ));
            }
        }
        Ok(())
    }
}

/// Whether a scope between `scope` (inclusive) and `global` (exclusive)
/// binds `name` — in which case a write shadows the global, not updates it.
fn inner_scopes_bind(scope: &ScopeRef, global: &ScopeRef, name: &str) -> bool {
    let mut cur = Some(scope.clone());
    while let Some(s) = cur {
        if Rc::ptr_eq(&s, global) {
            return false;
        }
        if s.borrow().vars.contains_key(name) {
            return true;
        }
        cur = s.borrow().parent.clone();
    }
    false
}

/// Every `var`-declared name inside `stmt`, descending into nested
/// statements but never into nested functions (they hoist their own).
fn collect_var_names(stmt: &Stmt, out: &mut Vec<String>) {
    match stmt {
        Stmt::VarDecl {
            kind: DeclKind::Var,
            decls,
        } => {
            for (pat, _) in decls {
                for n in pattern_names(pat) {
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
        }
        Stmt::Block(body) => {
            for s in body {
                collect_var_names(s, out);
            }
        }
        Stmt::If { then, alt, .. } => {
            collect_var_names(then, out);
            if let Some(a) = alt {
                collect_var_names(a, out);
            }
        }
        Stmt::For { init, body, .. } => {
            if let Some(i) = init {
                collect_var_names(i, out);
            }
            collect_var_names(body, out);
        }
        Stmt::ForIn {
            decl_kind: Some(DeclKind::Var),
            pat,
            body,
            ..
        } => {
            for n in pattern_names(pat) {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
            collect_var_names(body, out);
        }
        Stmt::ForIn { body, .. } => collect_var_names(body, out),
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::Labeled { body, .. } => {
            collect_var_names(body, out)
        }
        Stmt::Try {
            block,
            catch,
            finally,
        } => {
            for s in block {
                collect_var_names(s, out);
            }
            if let Some((_, cbody)) = catch {
                for s in cbody {
                    collect_var_names(s, out);
                }
            }
            if let Some(fbody) = finally {
                for s in fbody {
                    collect_var_names(s, out);
                }
            }
        }
        Stmt::Switch { cases, .. } => {
            for (_, body) in cases {
                for s in body {
                    collect_var_names(s, out);
                }
            }
        }
        _ => {}
    }
}

/// Collect the names a pattern binds (for var hoisting).
pub fn pattern_names(pat: &Pattern) -> Vec<String> {
    let mut out = Vec::new();
    collect_pattern_names(pat, &mut out);
    out
}

fn collect_pattern_names(pat: &Pattern, out: &mut Vec<String>) {
    match pat {
        Pattern::Ident(n) => out.push(n.clone()),
        Pattern::Array(elems) => {
            for e in elems.iter().flatten() {
                collect_pattern_names(&e.pat, out);
            }
        }
        Pattern::Object(props) => {
            for p in props {
                collect_pattern_names(&p.pat, out);
            }
        }
    }
}

/// Strict equality (===).
pub fn strict_eq(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
        (JsValue::Bool(x), JsValue::Bool(y)) => x == y,
        (JsValue::Num(x), JsValue::Num(y)) => x == y,
        (JsValue::Str(x), JsValue::Str(y)) => x == y,
        (JsValue::Symbol(x), JsValue::Symbol(y)) => x.id == y.id,
        (JsValue::Object(x), JsValue::Object(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

/// Human-readable display for errors/console.
pub fn to_display(v: &JsValue) -> String {
    v.to_js_string()
}

/// Shared by the engine's unit tests: run a script in a fresh realm with
/// no network and render its completion value, or `uncaught <error>`.
#[cfg(test)]
pub(super) mod test_support {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use super::super::super::html;
    use super::super::parser;
    use super::super::runtime::{run_page_scripts, RunLimits};
    use super::{to_display, Interp, NoNetwork};

    pub(in super::super) fn eval_js(src: &str) -> String {
        let prog = match parser::parse(src) {
            Ok(p) => p,
            Err(e) => return format!("syntax error: {}", e.message),
        };
        let mut host = NoNetwork;
        let mut interp = Interp::new(&mut host);
        match interp.run_program(&prog) {
            Ok(v) => v.to_js_string(),
            Err(e) => format!("uncaught {}", to_display(&e)),
        }
    }

    /// Run `src` as a function body in a page holding `body_html`, with the
    /// DOM bindings installed, and render what it returns (or
    /// `uncaught <error>`).
    pub(in super::super) fn eval_in_page(body_html: &str, src: &str) -> String {
        let page = format!(
            "<body>{body_html}<script>let r; try {{ r = String((() => {{ {src} }})()); }} \
             catch (e) {{ r = 'uncaught ' + String(e); }} console.log(r);</script></body>"
        );
        let doc = Rc::new(RefCell::new(html::parse(&page)));
        let report = run_page_scripts(doc, &HashMap::new(), &mut NoNetwork, RunLimits::default());
        match report.console.last() {
            Some((_, line)) => line.clone(),
            None => format!("no output: {:?}", report.errors),
        }
    }
}

#[cfg(test)]
mod for_in_tests {
    use super::test_support::{eval_in_page, eval_js};

    fn keys(setup: &str, obj: &str) -> String {
        eval_js(&format!(
            "let r; try {{ {setup} const ks = []; for (const k in {obj}) ks.push(k); r = ks.join(); }} catch (e) {{ r = String(e).split(':')[0]; }} r"
        ))
    }

    #[test]
    fn for_in_visits_inherited_enumerable_keys_once() {
        assert_eq!(keys("const o = Object.create({ a: 1, b: 2 }); o.c = 3;", "o"), "c,a,b");
        // An own property shadows an inherited one of the same name, even
        // when the own one is not enumerable.
        assert_eq!(keys("const o = Object.create({ a: 1, b: 2 }); o.a = 5;", "o"), "a,b");
        assert_eq!(keys("const o = Object.create({ a: 1, b: 2 }); Object.defineProperty(o, 'a', { value: 3 });", "o"), "b");
        assert_eq!(keys("const p = Object.create({ z: 1 }); Object.defineProperty(p, 'z', { value: 2 }); const o = Object.create(p);", "o"), "");
        // Assigned prototype members are enumerable; class methods are not.
        assert_eq!(keys("function F() { this.x = 1; } F.prototype.m = function () {}; class C { y = 2; n() {} }", "new F()"), "x,m");
        assert_eq!(keys("class C { y = 2; n() {} }", "new C()"), "y");
        assert_eq!(keys("Array.prototype.extra = 1;", "[7, 8]"), "0,1,extra");
        // Symbols are never visited; primitives are converted, null and
        // undefined visit nothing.
        assert_eq!(keys("const o = { [Symbol('s')]: 1, k: 2 };", "o"), "k");
        assert_eq!(keys("", "'ab'"), "0,1");
        assert_eq!(keys("", "null") + "|" + &keys("", "undefined") + "|" + &keys("", "5"), "||");
    }

    #[test]
    fn for_in_goes_through_proxy_traps_on_the_object_and_its_chain() {
        let proxy = "const log = []; const p = new Proxy({ t: 1 }, { \
                       ownKeys(t) { log.push('ownKeys'); return ['a', 'b', 'c']; }, \
                       getOwnPropertyDescriptor(t, k) { log.push('gopd ' + k); return k === 'b' ? undefined : { value: 1, enumerable: k !== 'c', configurable: true }; }, \
                       getPrototypeOf(t) { log.push('proto'); return { inherited: 1 }; } });";
        assert_eq!(keys(proxy, "p"), "a,inherited");
        assert_eq!(
            eval_js(&format!("{proxy} for (const k in p) {{}} log.join()")),
            "ownKeys,gopd a,gopd b,gopd c,proto"
        );
        assert_eq!(keys(proxy, "Object.create(p)"), "a,inherited");
    }

    #[test]
    fn a_key_deleted_before_its_turn_is_skipped() {
        assert_eq!(
            eval_js("const o = { a: 1, b: 2, c: 3 }; const seen = []; for (const k in o) { seen.push(k); delete o.c; o.d = 4; } seen.join()"),
            "a,b"
        );
        // Deleting an own key that shadows an inherited one leaves the
        // inherited key, which is still a property.
        assert_eq!(
            eval_js("const o = Object.create({ b: 'p' }); o.a = 1; o.b = 2; const seen = []; for (const k in o) { seen.push(k + o[k]); delete o.b; } seen.join()"),
            "a1,bp"
        );
    }

    #[test]
    fn a_suspending_body_and_host_objects_enumerate_the_same_way() {
        assert_eq!(
            eval_js("function* g(o) { for (const k in o) yield k; } const o = Object.create({ a: 1 }); o.b = 2; [...g(o)].join()"),
            "b,a"
        );
        assert_eq!(
            eval_in_page("<p>x</p><p>y</p>", "const ks = []; for (const k in document.querySelectorAll('p')) if (/^[0-9]+$/.test(k)) ks.push(k); return ks.join()"),
            "0,1"
        );
    }
}
