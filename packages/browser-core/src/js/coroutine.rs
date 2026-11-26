//! coroutine — resumable execution of generator and async-function bodies.
//!
//! A tree-walking interpreter cannot suspend a native stack frame without
//! unsafe code or threads (the realm is `Rc`-based, so it is not `Send`),
//! so a generator that ran its body to completion and buffered its yields
//! was the engine's original answer. That is observably wrong for the
//! shapes real bundles use: an infinite generator hung on the step budget
//! instead of producing values lazily, `next(v)` could not send a value in,
//! side effects between two yields all happened at the first `next()`, and
//! breaking out of a `for...of` still ran the whole body.
//!
//! This module executes a function body against an EXPLICIT frame stack
//! instead of the host stack, so the body can stop at a `yield` / `await`
//! and continue later from exactly that point. Statements that contain no
//! suspension run atomically through the ordinary [`Interp::exec_stmt`], so
//! only the control flow that actually surrounds a suspension is modelled
//! here: blocks, `if`, `while` / `do` / `for` / `for...of`, `try`, labels,
//! and the statement-level positions a suspension appears in directly
//! (`yield x;`, `t = yield x`, `let t = yield x`, `return yield x`).
//!
//! A statement whose suspension sits anywhere else in an expression (a
//! call argument, an operand, an object literal, a condition) is LOWERED
//! by `desugar.rs` into a sequence of statements whose suspensions are
//! statements of their own, with every sub-expression evaluated before
//! the suspension captured into a temporary first, so source evaluation
//! order and the value sent back in are both preserved.
//! `Coroutine::lowered` records that it happened (diagnostics only).
//!
//! Panic-free like the rest of the engine: no indexing, no unwrap, and a
//! re-entrant resume (a body that resumes itself) is a thrown TypeError
//! rather than a `RefCell` double borrow.

use std::rc::Rc;

use super::ast::{AssignOp, DeclKind, Expr, MemberKey, ObjectProp, Pattern, PropKey, Stmt, TemplateElem};
use super::interp::{strict_eq, Completion, Interp, LoopSource, Scope, ScopeRef};
use super::value::JsValue;

/// The deepest frame stack one coroutine may build. Hostile input nests
/// blocks; the body still terminates, with a RangeError.
pub const MAX_FRAMES: usize = 512;


/// What suspends this body.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `yield` suspends; `await` is not a suspension here (a generator
    /// body is not async, so the parser never produces one).
    Generator,
    /// `await` suspends; `yield` is a syntax error the parser rejected.
    Async,
}

/// One step of a coroutine.
pub enum Step {
    /// A generator `yield`: the value handed to the consumer.
    Yielded(JsValue),
    /// An async `await`: the value being awaited (usually a promise).
    Awaited(JsValue),
    /// The body returned (or ran off the end).
    Done(JsValue),
    /// The body threw.
    Threw(JsValue),
}

/// How a statement's execution ended.
enum Outcome {
    Normal,
    Return(JsValue),
    Throw(JsValue),
    Break(Option<String>),
    Continue(Option<String>),
}

/// What to do with the value sent back in when the body resumes.
#[derive(Clone)]
enum After {
    /// `yield x;` — the sent value is discarded.
    Discard,
    /// `t = yield x` / `t.k = await x` — assign the sent value, in the
    /// scope the statement ran in.
    Assign(Expr, ScopeRef),
    /// `let t = yield x` — bind the sent value.
    Declare {
        pat: Pattern,
        declare: bool,
        constant: bool,
        scope: ScopeRef,
    },
    /// `return yield x` — return the sent value.
    Return,
}

/// A `while` / `do…while` / `for` frame.
struct LoopFrame {
    cond: Option<Expr>,
    update: Option<Expr>,
    body: Rc<Vec<Stmt>>,
    /// The body is a block (each iteration gets a fresh child scope).
    body_is_block: bool,
    /// The scope the head runs in (a `for` head's own scope).
    scope: ScopeRef,
    label: Option<String>,
    /// `do…while`: the first iteration runs before the condition.
    check_cond: bool,
    /// The update runs before the next condition check.
    run_update: bool,
}

/// A `for…of` frame pulling from a live [`LoopSource`] (a generator runs
/// only as far as this loop consumes it; an early exit closes it).
struct ForOfFrame {
    source: LoopSource,
    pat: Pattern,
    decl_kind: Option<DeclKind>,
    body: Rc<Vec<Stmt>>,
    body_is_block: bool,
    scope: ScopeRef,
    label: Option<String>,
}

/// A `try` frame: which part is running, and the outcome a `finally`
/// must re-raise once it completes.
struct TryFrame {
    block: Rc<Vec<Stmt>>,
    catch: Option<(Option<Pattern>, Rc<Vec<Stmt>>)>,
    finally: Option<Rc<Vec<Stmt>>>,
    scope: ScopeRef,
    /// 0 = the try block, 1 = the catch block, 2 = the finally block.
    phase: u8,
    saved: Option<Box<Outcome>>,
}

enum Frame {
    Block {
        stmts: Rc<Vec<Stmt>>,
        pc: usize,
        scope: ScopeRef,
        label: Option<String>,
        /// The block absorbs an unlabelled `break` (a `switch` body).
        breaks: bool,
    },
    Loop(LoopFrame),
    ForOf(ForOfFrame),
    Try(TryFrame),
    /// `yield* iterable`: the inner iterator, pulled one value at a time
    /// (so delegating to an infinite generator stays lazy). `started` is
    /// false until the first pull, which is argumentless; every later pull
    /// forwards the value our own `next(v)` received as one argument.
    Delegate {
        source: LoopSource,
        after: After,
        started: bool,
    },
}

/// A suspended function body.
pub struct Coroutine {
    pub mode: Mode,
    frames: Vec<Frame>,
    /// The value the next resume delivers (`next(v)`, an awaited result).
    sent: JsValue,
    /// An exception injected at the suspension point (`gen.throw(e)`, a
    /// rejected awaited promise).
    thrown_in: Option<JsValue>,
    /// A return injected at the suspension point (`gen.return(v)`): the
    /// body unwinds from there, running its `finally` blocks.
    return_in: Option<JsValue>,
    /// What the pending suspension does with the sent value.
    after: Option<After>,
    pub done: bool,
    /// The body is currently running (guards a re-entrant resume).
    running: bool,
    /// Counter for the temporaries the expression lowering introduces
    /// (`desugar::TEMP_PREFIX` + N, names no source text can spell),
    /// unique across the whole body.
    temps: usize,
    /// A statement needed lowering (a `yield` / `await` in an expression
    /// position) on this body: diagnostics only.
    pub lowered: bool,
}

impl Coroutine {
    /// A coroutine over `body`, running in `scope` (parameters already
    /// bound and the body already hoisted by the caller).
    pub fn new(mode: Mode, body: Rc<Vec<Stmt>>, scope: ScopeRef) -> Coroutine {
        Coroutine {
            mode,
            frames: vec![Frame::Block {
                stmts: body,
                pc: 0,
                scope,
                label: None,
                breaks: false,
            }],
            sent: JsValue::Undefined,
            thrown_in: None,
            return_in: None,
            after: None,
            done: false,
            running: false,
            temps: 0,
            lowered: false,
        }
    }

    /// Deliver `value` at the suspension point and run to the next one.
    pub fn resume(&mut self, interp: &mut Interp, value: JsValue) -> Step {
        self.sent = value;
        self.run(interp)
    }

    /// Throw `error` at the suspension point and run to the next one.
    pub fn resume_throw(&mut self, interp: &mut Interp, error: JsValue) -> Step {
        self.thrown_in = Some(error);
        self.run(interp)
    }

    /// Finish the body early (`gen.return(v)`, an iterator close): a
    /// `return v` completion is injected at the suspension point, so every
    /// `finally` block between it and the function boundary runs (and may
    /// itself yield, or override the return). A body that never started
    /// completes at once with `v`.
    pub fn resume_return(&mut self, interp: &mut Interp, value: JsValue) -> Step {
        self.return_in = Some(value);
        self.run(interp)
    }

    /// Pop the innermost frame, closing a `for…of` loop's live iterator
    /// when the loop is left before exhaustion (IteratorClose). Every
    /// unwinding pop goes through here so a `break`, `return` or throw out
    /// of a `for…of` over a generator runs that generator's `finally`.
    /// Returns the error a throwing `return()` raised, when the source had
    /// one to close; the caller decides whether it replaces the completion
    /// being unwound (it does for `break` / `continue` / `return`, not for
    /// a throw already in flight — ES §7.4.8 IteratorClose).
    fn pop_frame(&mut self, interp: &mut Interp) -> Option<JsValue> {
        let source = match self.frames.pop() {
            Some(Frame::ForOf(f)) => Some(f.source),
            Some(Frame::Delegate { source, .. }) => Some(source),
            _ => None,
        };
        let mut source = source?;
        if source.exhausted() {
            return None;
        }
        source.close(interp).err()
    }

    /// Abandon the body without running anything further (the realm is
    /// being torn down).
    pub fn close(&mut self) {
        self.frames.clear();
        self.after = None;
        self.done = true;
    }

    /// Whether the body has started (any statement ran).
    pub fn is_done(&self) -> bool {
        self.done
    }

    fn run(&mut self, interp: &mut Interp) -> Step {
        if self.done {
            return Step::Done(JsValue::Undefined);
        }
        if self.running {
            // The outer activation is still live: it keeps its state and
            // may yield or complete later; only this call fails.
            return Step::Threw(Interp::throw(
                "TypeError: Generator is already running",
            ));
        }
        self.running = true;
        let step = self.run_inner(interp);
        self.running = false;
        if matches!(step, Step::Done(_) | Step::Threw(_)) {
            self.done = true;
        }
        step
    }

    fn run_inner(&mut self, interp: &mut Interp) -> Step {
        let mut outcome: Option<Outcome> = None;
        if let Some(e) = self.thrown_in.take() {
            // An injected throw replaces whatever the suspension point was
            // about to do: it propagates from that point, through `finally`.
            self.after = None;
            outcome = Some(Outcome::Throw(e));
        } else if let Some(v) = self.return_in.take() {
            self.after = None;
            outcome = Some(Outcome::Return(v));
        } else if let Some(after) = self.after.take() {
            // Apply whatever the suspension was waiting to do with the
            // sent value.
            let sent = core::mem::replace(&mut self.sent, JsValue::Undefined);
            if let Err(e) = self.apply_after(interp, after, sent, &mut outcome) {
                outcome = Some(Outcome::Throw(e));
            }
        }

        loop {
            if let Err(e) = interp.charge_pub() {
                return Step::Threw(e);
            }
            // An abrupt completion unwinds frames until something handles it.
            if let Some(o) = outcome.take() {
                match self.unwind(interp, o) {
                    Unwound::Settled(step) => return step,
                    Unwound::Continue => continue,
                    Unwound::Resume(o) => {
                        outcome = Some(o);
                        continue;
                    }
                }
            }
            let Some(top) = self.frames.len().checked_sub(1) else {
                return Step::Done(JsValue::Undefined);
            };
            match self.step_frame(interp, top) {
                Ok(Progress::Ran) => {}
                Ok(Progress::Suspended(step)) => return step,
                Ok(Progress::Completed(o)) => outcome = Some(o),
                Err(e) => outcome = Some(Outcome::Throw(e)),
            }
        }
    }

    /// Deliver the sent value where the suspended statement wanted it.
    fn apply_after(
        &mut self,
        interp: &mut Interp,
        after: After,
        sent: JsValue,
        outcome: &mut Option<Outcome>,
    ) -> Result<(), JsValue> {
        match after {
            After::Discard => Ok(()),
            After::Assign(target, scope) => interp.assign_to(&target, sent, &scope),
            After::Declare {
                pat,
                declare,
                constant,
                scope,
            } => interp.bind_pattern(&pat, sent, &scope, declare, constant),
            After::Return => {
                *outcome = Some(Outcome::Return(sent));
                Ok(())
            }
        }
    }

    /// The scope the innermost frame runs statements in.
    fn current_scope(&self) -> ScopeRef {
        for f in self.frames.iter().rev() {
            match f {
                Frame::Block { scope, .. } => return scope.clone(),
                Frame::Loop(l) => return l.scope.clone(),
                Frame::ForOf(f) => return f.scope.clone(),
                Frame::Try(t) => return t.scope.clone(),
                Frame::Delegate { .. } => {}
            }
        }
        // Unreachable while a frame exists; a detached coroutine uses the
        // global scope rather than failing.
        Scope::new(None)
    }

    fn step_frame(&mut self, interp: &mut Interp, top: usize) -> Result<Progress, JsValue> {
        // Everything the step needs is cloned out first: `interp` is
        // borrowed mutably while a statement runs, so no frame reference
        // may be held across it.
        enum Plan {
            Stmt(Stmt, ScopeRef),
            BlockDone,
            LoopCond(Option<Expr>, ScopeRef),
            LoopUpdate(Option<Expr>, ScopeRef),
            LoopBody,
            ForOfNext,
            TryEnter,
            DelegateNext,
        }
        let plan = match self.frames.get_mut(top) {
            Some(Frame::Block { stmts, pc, scope, .. }) => {
                let stmts = stmts.clone();
                match stmts.get(*pc) {
                    Some(s) => {
                        *pc = pc.saturating_add(1);
                        Plan::Stmt(s.clone(), scope.clone())
                    }
                    None => Plan::BlockDone,
                }
            }
            Some(Frame::Loop(l)) => {
                if l.check_cond {
                    if l.run_update {
                        l.run_update = false;
                        Plan::LoopUpdate(l.update.clone(), l.scope.clone())
                    } else {
                        l.check_cond = false;
                        Plan::LoopCond(l.cond.clone(), l.scope.clone())
                    }
                } else {
                    Plan::LoopBody
                }
            }
            Some(Frame::ForOf(_)) => Plan::ForOfNext,
            Some(Frame::Try(t)) if t.phase == 0 => Plan::TryEnter,
            // An entered try frame on top means the part above it already
            // completed: resolve it as a normal completion.
            Some(Frame::Try(_)) => return Ok(Progress::Completed(Outcome::Normal)),
            Some(Frame::Delegate { .. }) => Plan::DelegateNext,
            None => return Ok(Progress::Completed(Outcome::Normal)),
        };
        match plan {
            Plan::BlockDone => {
                // The block's normal completion travels to the frame below
                // it: a `try` frame advances to its `finally` (or finishes),
                // any other frame is unaffected.
                self.frames.pop();
                Ok(Progress::Completed(Outcome::Normal))
            }
            Plan::Stmt(stmt, scope) => self.exec_one(interp, &stmt, &scope),
            Plan::LoopCond(cond, scope) => {
                let keep = match &cond {
                    Some(c) => interp.eval(c, &scope)?.truthy(),
                    None => true,
                };
                if keep {
                    Ok(Progress::Ran)
                } else {
                    self.frames.pop();
                    Ok(Progress::Ran)
                }
            }
            Plan::LoopUpdate(update, scope) => {
                if let Some(u) = &update {
                    interp.eval(u, &scope)?;
                }
                Ok(Progress::Ran)
            }
            Plan::LoopBody => {
                let (body, is_block, scope) = match self.frames.get_mut(top) {
                    Some(Frame::Loop(l)) => {
                        l.check_cond = true;
                        l.run_update = true;
                        (l.body.clone(), l.body_is_block, l.scope.clone())
                    }
                    _ => return Ok(Progress::Ran),
                };
                self.push_body(interp, body, is_block, &scope, None)?;
                Ok(Progress::Ran)
            }
            Plan::ForOfNext => {
                let next = match self.frames.get_mut(top) {
                    Some(Frame::ForOf(f)) => {
                        let item = f.source.next(interp)?;
                        item.map(|item| {
                            (
                                item,
                                f.pat.clone(),
                                f.decl_kind,
                                f.body.clone(),
                                f.body_is_block,
                                f.scope.clone(),
                            )
                        })
                    }
                    _ => None,
                };
                let Some((item, pat, decl_kind, body, is_block, scope)) = next else {
                    self.frames.pop();
                    return Ok(Progress::Ran);
                };
                let iter_scope = Scope::new(Some(scope.clone()));
                let target = if decl_kind.is_some() { &iter_scope } else { &scope };
                interp.bind_pattern(
                    &pat,
                    item,
                    target,
                    decl_kind.is_some(),
                    decl_kind == Some(DeclKind::Const),
                )?;
                self.push_body(interp, body, is_block, &iter_scope, None)?;
                Ok(Progress::Ran)
            }
            Plan::TryEnter => {
                let (stmts, scope) = match self.frames.get_mut(top) {
                    Some(Frame::Try(t)) => {
                        let stmts = match t.phase {
                            0 => t.block.clone(),
                            1 => match &t.catch {
                                Some((_, body)) => body.clone(),
                                None => Rc::new(Vec::new()),
                            },
                            _ => match &t.finally {
                                Some(body) => body.clone(),
                                None => Rc::new(Vec::new()),
                            },
                        };
                        // The next visit to this frame resolves the phase's
                        // completion, so mark it as entered.
                        t.phase = t.phase.saturating_add(3);
                        (stmts, t.scope.clone())
                    }
                    _ => return Ok(Progress::Ran),
                };
                let inner = Scope::new(Some(scope));
                interp.hoist_pub(&stmts, &inner)?;
                self.push_frame(Frame::Block {
                    stmts,
                    pc: 0,
                    scope: inner,
                    label: None,
                    breaks: false,
                })?;
                Ok(Progress::Ran)
            }
            Plan::DelegateNext => {
                // The value our own `next(v)` delivered travels into the
                // delegate's `next(v)`; the first pull sends undefined.
                let sent = core::mem::replace(&mut self.sent, JsValue::Undefined);
                let next = match self.frames.get_mut(top) {
                    Some(Frame::Delegate {
                        source,
                        after,
                        started,
                    }) => {
                        let arg = if *started { Some(sent) } else { None };
                        *started = true;
                        match source.next_with(interp, arg)? {
                            Some(v) => Some(Ok(v)),
                            None => Some(Err((after.clone(), source.return_value()))),
                        }
                    }
                    _ => None,
                };
                match next {
                    Some(Ok(v)) => Ok(Progress::Suspended(Step::Yielded(v))),
                    Some(Err((after, value))) => {
                        self.frames.pop();
                        // A finished `yield*` evaluates to the inner
                        // iterator's return value (ES §14.4.14).
                        self.after = Some(after);
                        self.sent = value;
                        let mut outcome = None;
                        if let Some(a) = self.after.take() {
                            let sent = core::mem::replace(&mut self.sent, JsValue::Undefined);
                            self.apply_after(interp, a, sent, &mut outcome)?;
                        }
                        Ok(match outcome {
                            Some(o) => Progress::Completed(o),
                            None => Progress::Ran,
                        })
                    }
                    None => Ok(Progress::Ran),
                }
            }
        }
    }

    /// Execute one statement: structurally when it contains a suspension,
    /// atomically when it does not.
    fn exec_one(
        &mut self,
        interp: &mut Interp,
        stmt: &Stmt,
        scope: &ScopeRef,
    ) -> Result<Progress, JsValue> {
        if !stmt_suspends(stmt, self.mode) {
            return Ok(match interp.exec_stmt(stmt, scope)? {
                Completion::Normal(_) => Progress::Ran,
                Completion::Return(v) => Progress::Completed(Outcome::Return(v)),
                Completion::Break(l) => Progress::Completed(Outcome::Break(l)),
                Completion::Continue(l) => Progress::Completed(Outcome::Continue(l)),
            });
        }
        match stmt {
            // `yield x;` / `await x;`
            Stmt::Expr(e) if is_simple_suspend(e, self.mode) => {
                self.suspend(interp, e, After::Discard, scope)
            }
            // `t = yield x` (and every compound target form).
            Stmt::Expr(Expr::Assign {
                op: AssignOp::Assign,
                target,
                value,
            }) if is_simple_suspend(value, self.mode) && !expr_suspends(target, self.mode) => {
                let after = After::Assign((**target).clone(), scope.clone());
                self.suspend(interp, value, after, scope)
            }
            // `let t = yield x`
            Stmt::VarDecl { kind, decls }
                if decls.len() == 1
                    && matches!(decls.first(), Some((_, Some(init))) if is_simple_suspend(init, self.mode)) =>
            {
                let Some((pat, Some(init))) = decls.first() else {
                    return self.lower(interp, stmt, scope);
                };
                let after = After::Declare {
                    pat: pat.clone(),
                    declare: *kind != DeclKind::Var,
                    constant: *kind == DeclKind::Const,
                    scope: scope.clone(),
                };
                self.suspend(interp, init, after, scope)
            }
            Stmt::Return(Some(e)) if is_simple_suspend(e, self.mode) => {
                self.suspend(interp, e, After::Return, scope)
            }
            Stmt::Block(body) => {
                let stmts = Rc::new(body.clone());
                let inner = Scope::new(Some(scope.clone()));
                interp.hoist_pub(&stmts, &inner)?;
                self.push_frame(Frame::Block {
                    stmts,
                    pc: 0,
                    scope: inner,
                    label: None,
                    breaks: false,
                })?;
                Ok(Progress::Ran)
            }
            Stmt::If { cond, then, alt } => {
                if expr_suspends(cond, self.mode) {
                    return self.lower(interp, stmt, scope);
                }
                let take_then = interp.eval(cond, scope)?.truthy();
                let branch = if take_then {
                    Some(then.as_ref())
                } else {
                    alt.as_deref()
                };
                if let Some(b) = branch {
                    let (stmts, is_block) = body_statements(b);
                    self.push_body(interp, stmts, is_block, scope, None)?;
                }
                Ok(Progress::Ran)
            }
            Stmt::While { cond, body } => {
                if expr_suspends(cond, self.mode) {
                    return self.lower(interp, stmt, scope);
                }
                let (stmts, is_block) = body_statements(body);
                self.push_frame(Frame::Loop(LoopFrame {
                    cond: Some(cond.clone()),
                    update: None,
                    body: stmts,
                    body_is_block: is_block,
                    scope: scope.clone(),
                    label: None,
                    check_cond: true,
                    run_update: false,
                }))?;
                Ok(Progress::Ran)
            }
            Stmt::DoWhile { body, cond } => {
                if expr_suspends(cond, self.mode) {
                    return self.lower(interp, stmt, scope);
                }
                let (stmts, is_block) = body_statements(body);
                self.push_frame(Frame::Loop(LoopFrame {
                    cond: Some(cond.clone()),
                    update: None,
                    body: stmts,
                    body_is_block: is_block,
                    scope: scope.clone(),
                    label: None,
                    // The body runs before the first condition check.
                    check_cond: false,
                    run_update: false,
                }))?;
                Ok(Progress::Ran)
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => {
                let head_suspends = cond.as_ref().map(|c| expr_suspends(c, self.mode)) == Some(true)
                    || update.as_ref().map(|u| expr_suspends(u, self.mode)) == Some(true)
                    || init.as_ref().map(|i| stmt_suspends(i, self.mode)) == Some(true);
                if head_suspends {
                    return self.lower(interp, stmt, scope);
                }
                let loop_scope = Scope::new(Some(scope.clone()));
                if let Some(i) = init {
                    interp.exec_stmt(i, &loop_scope)?;
                }
                let (stmts, is_block) = body_statements(body);
                self.push_frame(Frame::Loop(LoopFrame {
                    cond: cond.clone(),
                    update: update.clone(),
                    body: stmts,
                    body_is_block: is_block,
                    scope: loop_scope,
                    label: None,
                    check_cond: true,
                    run_update: false,
                }))?;
                Ok(Progress::Ran)
            }
            Stmt::ForIn {
                decl_kind,
                pat,
                object,
                body,
                of: true,
            } => {
                if expr_suspends(object, self.mode) {
                    return self.lower(interp, stmt, scope);
                }
                let obj = interp.eval(object, scope)?;
                let source = LoopSource::open(interp, &obj)?;
                let (stmts, is_block) = body_statements(body);
                self.push_frame(Frame::ForOf(ForOfFrame {
                    source,
                    pat: pat.clone(),
                    decl_kind: *decl_kind,
                    body: stmts,
                    body_is_block: is_block,
                    scope: scope.clone(),
                    label: None,
                }))?;
                Ok(Progress::Ran)
            }
            Stmt::Try {
                block,
                catch,
                finally,
            } => {
                self.push_frame(Frame::Try(TryFrame {
                    block: Rc::new(block.clone()),
                    catch: catch
                        .as_ref()
                        .map(|(p, b)| (p.clone(), Rc::new(b.clone()))),
                    finally: finally.as_ref().map(|b| Rc::new(b.clone())),
                    scope: scope.clone(),
                    phase: 0,
                    saved: None,
                }))?;
                Ok(Progress::Ran)
            }
            Stmt::Labeled { label, body } => {
                let (stmts, is_block) = body_statements(body);
                // A labelled loop keeps the label on the LOOP frame so
                // `continue label` finds it.
                match body.as_ref() {
                    Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } | Stmt::ForIn { .. } => {
                        let before = self.frames.len();
                        let progress = self.exec_one(interp, body, scope)?;
                        if self.frames.len() > before {
                            if let Some(f) = self.frames.last_mut() {
                                set_label(f, label.clone());
                            }
                        }
                        Ok(progress)
                    }
                    _ => {
                        self.push_body(interp, stmts, is_block, scope, Some(label.clone()))?;
                        Ok(Progress::Ran)
                    }
                }
            }
            // `for (k in obj)` whose BODY suspends: the keys are a snapshot
            // (as the spec allows), pulled by the same frame a `for…of`
            // uses. A suspending OBJECT expression is lowered first.
            Stmt::ForIn {
                decl_kind,
                pat,
                object,
                body,
                of: false,
            } => {
                if expr_suspends(object, self.mode) {
                    return self.lower(interp, stmt, scope);
                }
                let obj = interp.eval(object, scope)?;
                let source = interp.for_in_source(&obj)?;
                let (stmts, is_block) = body_statements(body);
                self.push_frame(Frame::ForOf(ForOfFrame {
                    source,
                    pat: pat.clone(),
                    decl_kind: *decl_kind,
                    body: stmts,
                    body_is_block: is_block,
                    scope: scope.clone(),
                    label: None,
                }))?;
                Ok(Progress::Ran)
            }
            // `switch` whose case BODIES suspend: the discriminant and the
            // tests (which do not suspend here; a suspending one is lowered
            // into an if-chain first) pick the entry case, and the bodies
            // from there on run as ONE block so fall-through works and an
            // unlabelled `break` ends the switch.
            Stmt::Switch { disc, cases } => {
                let head_suspends = expr_suspends(disc, self.mode)
                    || cases
                        .iter()
                        .any(|(t, _)| t.as_ref().map(|e| expr_suspends(e, self.mode)).unwrap_or(false));
                if head_suspends {
                    return self.lower(interp, stmt, scope);
                }
                let d = interp.eval(disc, scope)?;
                let sscope = Scope::new(Some(scope.clone()));
                let mut matched: Option<usize> = None;
                for (i, (test, _)) in cases.iter().enumerate() {
                    if let Some(t) = test {
                        let tv = interp.eval(t, &sscope)?;
                        if strict_eq(&d, &tv) {
                            matched = Some(i);
                            break;
                        }
                    }
                }
                if matched.is_none() {
                    matched = cases.iter().position(|(t, _)| t.is_none());
                }
                let Some(start) = matched else {
                    return Ok(Progress::Ran);
                };
                // The case block is ONE lexical scope (ES §14.12.4): its
                // function declarations hoist over every case, not only
                // the ones control reaches, so the hoist runs over the
                // whole block while execution starts at the matched case.
                let whole: Vec<Stmt> = cases
                    .iter()
                    .flat_map(|(_, body)| body.iter().cloned())
                    .collect();
                interp.hoist_pub(&whole, &sscope)?;
                let stmts: Vec<Stmt> = cases
                    .iter()
                    .skip(start)
                    .flat_map(|(_, body)| body.iter().cloned())
                    .collect();
                let stmts = Rc::new(stmts);
                self.push_frame(Frame::Block {
                    stmts,
                    pc: 0,
                    scope: sscope,
                    label: None,
                    breaks: true,
                })?;
                Ok(Progress::Ran)
            }
            // `throw await e`,
            // `f(await a)`, `x = 1 + (yield y)`, `return g(yield)`: the
            // suspension sits inside an expression. Lower the statement
            // into a sequence whose suspensions are statements of their own
            // and run THAT, in a block frame over the same scope (the
            // temporaries are block-scoped `let`s of that frame).
            _ => self.lower(interp, stmt, scope),
        }
    }

    /// Suspend on `expr` (a `yield` / `yield*` / `await`).
    fn suspend(
        &mut self,
        interp: &mut Interp,
        expr: &Expr,
        after: After,
        scope: &ScopeRef,
    ) -> Result<Progress, JsValue> {
        match expr {
            Expr::Yield { arg, delegate } => {
                let v = match arg {
                    Some(e) => interp.eval(e, scope)?,
                    None => JsValue::Undefined,
                };
                if *delegate {
                    let source = LoopSource::open(interp, &v)?;
                    self.push_frame(Frame::Delegate {
                        source,
                        after,
                        started: false,
                    })?;
                    return Ok(Progress::Ran);
                }
                self.after = Some(after);
                Ok(Progress::Suspended(Step::Yielded(v)))
            }
            Expr::Await(e) => {
                let v = interp.eval(e, scope)?;
                self.after = Some(after);
                Ok(Progress::Suspended(Step::Awaited(v)))
            }
            _ => Ok(Progress::Ran),
        }
    }

    /// Lower a statement whose suspension sits in an expression position
    /// (see `desugar`) and push the result as a block frame. The block's
    /// scope is a child of `scope` so the lowering's temporaries do not
    /// leak, while every name the statement itself binds with `var` was
    /// already hoisted to the function scope; a `let`/`const` the original
    /// statement declared is re-declared in the enclosing scope by the
    /// lowered `VarDecl`, which the block frame runs against `scope`
    /// itself for that reason (temporaries start with a NUL byte the lexer
    /// never admits into an identifier, so sharing the scope is safe).
    fn lower(
        &mut self,
        interp: &mut Interp,
        stmt: &Stmt,
        scope: &ScopeRef,
    ) -> Result<Progress, JsValue> {
        self.lowered = true;
        let Some(stmts) = super::desugar::lower_statement(stmt, self.mode, &mut self.temps) else {
            return Err(Interp::throw(
                "RangeError: too many suspension points in one statement",
            ));
        };
        let stmts = Rc::new(stmts);
        // A `let`/`const` declared by the statement must land in the
        // statement's own scope (the next statement reads it), so the
        // lowered sequence runs in `scope`, not a child. Temporaries are
        // `let`s too; their names cannot be spelled in source, so they
        // cannot shadow or be shadowed.
        interp.hoist_pub(&stmts, scope)?;
        self.push_frame(Frame::Block {
            stmts,
            pc: 0,
            scope: scope.clone(),
            label: None,
            breaks: false,
        })?;
        Ok(Progress::Ran)
    }

    /// Push a statement list as the body of a loop / branch: a block body
    /// gets a fresh child scope and hoisting, a bare statement does not.
    fn push_body(
        &mut self,
        interp: &mut Interp,
        stmts: Rc<Vec<Stmt>>,
        is_block: bool,
        parent: &ScopeRef,
        label: Option<String>,
    ) -> Result<(), JsValue> {
        let scope = if is_block {
            let inner = Scope::new(Some(parent.clone()));
            interp.hoist_pub(&stmts, &inner)?;
            inner
        } else {
            parent.clone()
        };
        self.push_frame(Frame::Block {
            stmts,
            pc: 0,
            scope,
            label,
            breaks: false,
        })
    }

    fn push_frame(&mut self, frame: Frame) -> Result<(), JsValue> {
        if self.frames.len() >= MAX_FRAMES {
            return Err(Interp::throw(
                "RangeError: generator control flow nested too deeply",
            ));
        }
        self.frames.push(frame);
        Ok(())
    }

    /// Propagate an abrupt completion through the frame stack.
    fn unwind(&mut self, interp: &mut Interp, outcome: Outcome) -> Unwound {
        let Some(top) = self.frames.len().checked_sub(1) else {
            return Unwound::Settled(match outcome {
                Outcome::Return(v) => Step::Done(v),
                Outcome::Throw(e) => Step::Threw(e),
                _ => Step::Done(JsValue::Undefined),
            });
        };
        // A `try` frame handles throws and defers other completions past a
        // `finally`.
        let is_try = matches!(self.frames.get(top), Some(Frame::Try(_)));
        if is_try {
            return self.unwind_try(interp, top, outcome);
        }
        match &outcome {
            // A normal completion arriving at a non-try frame (a block that
            // ended inside a loop body) needs nothing: the frame resumes.
            Outcome::Normal => Unwound::Continue,
            Outcome::Break(label) => {
                let matches_here = frame_takes_break(self.frames.get(top), label.as_deref());
                if let Some(e) = self.pop_frame(interp) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                if matches_here {
                    return Unwound::Continue;
                }
                Unwound::Resume(outcome)
            }
            Outcome::Continue(label) => {
                let is_loop = matches!(
                    self.frames.get(top),
                    Some(Frame::Loop(_)) | Some(Frame::ForOf(_))
                );
                let named = frame_label(self.frames.get(top));
                if is_loop && (label.is_none() || label.as_deref() == named.as_deref()) {
                    // The loop frame itself continues: nothing to pop.
                    return Unwound::Continue;
                }
                if let Some(e) = self.pop_frame(interp) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                Unwound::Resume(outcome)
            }
            Outcome::Return(_) => {
                if let Some(e) = self.pop_frame(interp) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                Unwound::Resume(outcome)
            }
            Outcome::Throw(_) => {
                // The throw in flight wins over a throwing `return()`.
                let _ = self.pop_frame(interp);
                Unwound::Resume(outcome)
            }
        }
    }

    /// Unwinding into a `try` frame: run the catch or the finally.
    fn unwind_try(&mut self, interp: &mut Interp, top: usize, outcome: Outcome) -> Unwound {
        enum Act {
            Catch(Option<Pattern>, Rc<Vec<Stmt>>, ScopeRef, JsValue),
            Finally,
            Pop(Outcome),
        }
        let act = match self.frames.get_mut(top) {
            Some(Frame::Try(t)) => {
                // Phases 3/4/5 mean "that part has been entered"; the block
                // frame above it has just completed.
                let entered = t.phase;
                match (entered, &outcome) {
                    // The try block threw and a catch exists.
                    (3, Outcome::Throw(e)) if t.catch.is_some() => {
                        let (pat, body) = match &t.catch {
                            Some((p, b)) => (p.clone(), b.clone()),
                            None => (None, Rc::new(Vec::new())),
                        };
                        t.phase = 1;
                        Act::Catch(pat, body, t.scope.clone(), e.clone())
                    }
                    // Anything else with a finally still to run.
                    (3 | 4, _) if t.finally.is_some() => {
                        t.phase = 2;
                        t.saved = Some(Box::new(clone_outcome(&outcome)));
                        Act::Finally
                    }
                    // The finally completed: re-raise what it interrupted,
                    // unless the finally itself completed abruptly.
                    (5, Outcome::Normal) => {
                        let saved = t.saved.take().map(|b| *b).unwrap_or(Outcome::Normal);
                        Act::Pop(saved)
                    }
                    _ => Act::Pop(clone_outcome(&outcome)),
                }
            }
            _ => Act::Pop(clone_outcome(&outcome)),
        };
        match act {
            Act::Catch(pat, body, scope, err) => {
                interp.clear_error_trace();
                let cscope = Scope::new(Some(scope));
                if let Some(p) = &pat {
                    if let Err(e) = interp.bind_pattern(p, err, &cscope, true, false) {
                        return Unwound::Resume(Outcome::Throw(e));
                    }
                }
                if let Err(e) = interp.hoist_pub(&body, &cscope) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                if let Some(Frame::Try(t)) = self.frames.get_mut(top) {
                    t.phase = 4;
                }
                if let Err(e) = self.push_frame(Frame::Block {
                    stmts: body,
                    pc: 0,
                    scope: cscope,
                    label: None,
                    breaks: false,
                }) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                Unwound::Continue
            }
            Act::Finally => {
                let (body, scope) = match self.frames.get(top) {
                    Some(Frame::Try(t)) => (
                        t.finally.clone().unwrap_or_else(|| Rc::new(Vec::new())),
                        t.scope.clone(),
                    ),
                    _ => (Rc::new(Vec::new()), self.current_scope()),
                };
                let fscope = Scope::new(Some(scope));
                if let Err(e) = interp.hoist_pub(&body, &fscope) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                if let Some(Frame::Try(t)) = self.frames.get_mut(top) {
                    t.phase = 5;
                }
                if let Err(e) = self.push_frame(Frame::Block {
                    stmts: body,
                    pc: 0,
                    scope: fscope,
                    label: None,
                    breaks: false,
                }) {
                    return Unwound::Resume(Outcome::Throw(e));
                }
                Unwound::Continue
            }
            Act::Pop(o) => {
                self.frames.pop();
                match o {
                    Outcome::Normal => Unwound::Continue,
                    other => Unwound::Resume(other),
                }
            }
        }
    }
}

/// What one frame step produced.
enum Progress {
    /// Work happened; keep going.
    Ran,
    /// The body suspended or finished.
    Suspended(Step),
    /// The frame completed abruptly.
    Completed(Outcome),
}

/// What unwinding one frame produced.
enum Unwound {
    /// The completion was handled; keep running.
    Continue,
    /// The completion must keep unwinding.
    Resume(Outcome),
    /// The coroutine is finished.
    Settled(Step),
}

fn clone_outcome(o: &Outcome) -> Outcome {
    match o {
        Outcome::Normal => Outcome::Normal,
        Outcome::Return(v) => Outcome::Return(v.clone()),
        Outcome::Throw(v) => Outcome::Throw(v.clone()),
        Outcome::Break(l) => Outcome::Break(l.clone()),
        Outcome::Continue(l) => Outcome::Continue(l.clone()),
    }
}

/// Whether a frame absorbs `break` (optionally labelled).
fn frame_takes_break(frame: Option<&Frame>, label: Option<&str>) -> bool {
    match label {
        None => matches!(
            frame,
            Some(Frame::Loop(_)) | Some(Frame::ForOf(_)) | Some(Frame::Block { breaks: true, .. })
        ),
        Some(l) => frame_label(frame).as_deref() == Some(l),
    }
}

fn frame_label(frame: Option<&Frame>) -> Option<String> {
    match frame {
        Some(Frame::Block { label, .. }) => label.clone(),
        Some(Frame::Loop(l)) => l.label.clone(),
        Some(Frame::ForOf(f)) => f.label.clone(),
        _ => None,
    }
}

fn set_label(frame: &mut Frame, label: String) {
    match frame {
        Frame::Block { label: l, .. } => *l = Some(label),
        Frame::Loop(f) => f.label = Some(label),
        Frame::ForOf(f) => f.label = Some(label),
        Frame::Try(_) | Frame::Delegate { .. } => {}
    }
}

/// The statements of a loop/branch body, and whether it was a block (which
/// needs its own scope).
fn body_statements(stmt: &Stmt) -> (Rc<Vec<Stmt>>, bool) {
    match stmt {
        Stmt::Block(body) => (Rc::new(body.clone()), true),
        other => (Rc::new(vec![other.clone()]), false),
    }
}

/// Whether `e` is the suspension operator for `mode` AND its operand
/// holds no further suspension (`yield f(yield x)` is a nested shape that
/// goes through the lowering instead).
fn is_simple_suspend(e: &Expr, mode: Mode) -> bool {
    match (mode, e) {
        (Mode::Generator, Expr::Yield { arg, .. }) => {
            !arg.as_ref().map(|a| expr_suspends(a, mode)).unwrap_or(false)
        }
        (Mode::Async, Expr::Await(inner)) => !expr_suspends(inner, mode),
        _ => false,
    }
}

/// Whether the statement contains a suspension anywhere outside a nested
/// function body.
pub fn stmt_suspends(stmt: &Stmt, mode: Mode) -> bool {
    match stmt {
        Stmt::Expr(e) | Stmt::Throw(e) => expr_suspends(e, mode),
        Stmt::Return(e) => e.as_ref().map(|e| expr_suspends(e, mode)).unwrap_or(false),
        Stmt::VarDecl { decls, .. } => decls
            .iter()
            .any(|(_, init)| init.as_ref().map(|e| expr_suspends(e, mode)).unwrap_or(false)),
        Stmt::If { cond, then, alt } => {
            expr_suspends(cond, mode)
                || stmt_suspends(then, mode)
                || alt.as_ref().map(|a| stmt_suspends(a, mode)).unwrap_or(false)
        }
        Stmt::Block(body) => body.iter().any(|s| stmt_suspends(s, mode)),
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            expr_suspends(cond, mode) || stmt_suspends(body, mode)
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            init.as_ref().map(|s| stmt_suspends(s, mode)).unwrap_or(false)
                || cond.as_ref().map(|e| expr_suspends(e, mode)).unwrap_or(false)
                || update.as_ref().map(|e| expr_suspends(e, mode)).unwrap_or(false)
                || stmt_suspends(body, mode)
        }
        Stmt::ForIn { object, body, .. } => {
            expr_suspends(object, mode) || stmt_suspends(body, mode)
        }
        Stmt::Try {
            block,
            catch,
            finally,
        } => {
            block.iter().any(|s| stmt_suspends(s, mode))
                || catch
                    .as_ref()
                    .map(|(_, b)| b.iter().any(|s| stmt_suspends(s, mode)))
                    .unwrap_or(false)
                || finally
                    .as_ref()
                    .map(|b| b.iter().any(|s| stmt_suspends(s, mode)))
                    .unwrap_or(false)
        }
        Stmt::Switch { disc, cases } => {
            expr_suspends(disc, mode)
                || cases.iter().any(|(t, body)| {
                    t.as_ref().map(|e| expr_suspends(e, mode)).unwrap_or(false)
                        || body.iter().any(|s| stmt_suspends(s, mode))
                })
        }
        Stmt::Labeled { body, .. } => stmt_suspends(body, mode),
        _ => false,
    }
}

/// Whether the expression contains a suspension outside a nested function.
pub fn expr_suspends(e: &Expr, mode: Mode) -> bool {
    let sub = |e: &Expr| expr_suspends(e, mode);
    match e {
        Expr::Yield { arg, .. } => {
            mode == Mode::Generator
                || arg.as_ref().map(|a| sub(a)).unwrap_or(false)
        }
        Expr::Await(inner) => mode == Mode::Async || sub(inner),
        Expr::Unary { expr, .. } | Expr::Update { target: expr, .. } | Expr::Spread(expr) => {
            sub(expr)
        }
        Expr::Binary { left, right, .. } | Expr::Logical { left, right, .. } => {
            sub(left) || sub(right)
        }
        Expr::Assign { target, value, .. } => sub(target) || sub(value),
        Expr::Cond { cond, then, alt } => sub(cond) || sub(then) || sub(alt),
        Expr::Call { callee, args, .. } | Expr::New { callee, args } => {
            sub(callee) || args.iter().any(|a| sub(&a.expr))
        }
        Expr::Member {
            object, property, ..
        } => {
            sub(object)
                || match property {
                    MemberKey::Computed(k) => sub(k),
                    MemberKey::Static(_) => false,
                }
        }
        Expr::Sequence(items) => items.iter().any(sub),
        Expr::Array(items) => items.iter().flatten().any(|s| sub(&s.expr)),
        Expr::Object(props) => props.iter().any(|p| match p {
            ObjectProp::KeyValue(k, v) => key_suspends(k, mode) || sub(v),
            ObjectProp::ShorthandDefault(_, v) => sub(v),
            ObjectProp::Spread(v) => sub(v),
            ObjectProp::Method(k, _, _) => key_suspends(k, mode),
            ObjectProp::Shorthand(_) => false,
        }),
        Expr::Template(parts) => parts.iter().any(|p| match p {
            TemplateElem::Expr(e) => sub(e),
            TemplateElem::Str(_) => false,
        }),
        // A nested function body has its own suspension context.
        Expr::Function(_) | Expr::Class(_) => false,
        _ => false,
    }
}

fn key_suspends(k: &PropKey, mode: Mode) -> bool {
    match k {
        PropKey::Computed(e) => expr_suspends(e, mode),
        PropKey::Static(_) => false,
    }
}
