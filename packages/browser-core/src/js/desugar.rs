//! desugar — lower a statement whose `yield` / `await` sits in an
//! EXPRESSION position (`f(await a, await b)`, `x = 1 + (yield y)`,
//! `if (await p) …`, `return g(yield)`) into a sequence of statements the
//! coroutine frame machine can suspend on: every suspension becomes its
//! own `let $tN = yield …;` / `let $tN = await …;` statement, and every
//! sub-expression evaluated BEFORE it in source order is hoisted into its
//! own temporary first, so evaluation order, short-circuiting and the
//! value sent back in are all preserved.
//!
//! The output is ordinary AST the interpreter already executes; the only
//! new thing is the temporaries. Their names start with a NUL character
//! (`"\0co0"`), which the lexer never admits into an identifier, so no
//! script can declare, read or shadow one: they are unforgeable by
//! construction, not by convention. Short-circuit operators,
//! conditionals and optional chains whose RIGHT side suspends lower into
//! `if` statements so the suspension only happens when the operand would
//! have been evaluated. Anything without a suspension is left exactly as
//! written (and evaluated atomically by the interpreter), so the lowering
//! is the identity on code that never suspends.
//!
//! Std-only, panic-free: no indexing, no unwrap.

use std::rc::Rc;

use super::ast::{AssignOp, BinaryOp, DeclKind, Expr, LogicalOp, MemberKey, ObjectProp, Pattern, PropKey, SpreadElem, Stmt, TemplateElem, UnaryOp};
use super::coroutine::{expr_suspends, stmt_suspends, Mode};

/// A lowering pass over one statement.
struct Lower {
    mode: Mode,
    next: usize,
    /// The statements emitted so far for the current statement.
    out: Vec<Stmt>,
}

/// The most temporaries one statement may introduce: a hostile expression
/// with a million `await`s still terminates (the step budget bounds the
/// run; this bounds the rewrite).
const MAX_TEMPS: usize = 100_000;

/// The prefix of every lowering temporary. A NUL byte is not an
/// identifier character (the lexer emits `TokenKind::Error` for it), so
/// no source text can name one of these bindings.
pub const TEMP_PREFIX: &str = "\0co";

impl Lower {
    fn temp(&mut self) -> Option<String> {
        if self.next >= MAX_TEMPS {
            return None;
        }
        let n = self.next;
        self.next = self.next.saturating_add(1);
        Some(format!("{TEMP_PREFIX}{n}"))
    }

    /// Emit `let name = value;`.
    fn declare(&mut self, name: &str, value: Expr) {
        self.out.push(Stmt::VarDecl {
            kind: DeclKind::Let,
            decls: vec![(Pattern::Ident(name.to_string()), Some(value))],
        });
    }

    /// Emit `name = value;`.
    fn assign(&mut self, name: &str, value: Expr) {
        self.out.push(Stmt::Expr(Expr::Assign {
            op: AssignOp::Assign,
            target: Box::new(Expr::Ident(name.to_string())),
            value: Box::new(value),
        }));
    }

    /// Hoist `e` into a fresh temporary when `force` (it is evaluated
    /// before a suspension and must be captured first), else leave it in
    /// place. The returned expression is what the caller substitutes.
    fn capture(&mut self, e: Expr, force: bool) -> Option<Expr> {
        let e = self.lower_expr(e)?;
        if !force || is_pure_leaf(&e) {
            return Some(e);
        }
        let t = self.temp()?;
        self.declare(&t, e);
        Some(Expr::Ident(t))
    }

    /// Lower an expression: every suspension inside it is emitted as a
    /// statement onto `out`, and the returned expression reads the
    /// temporaries instead. An expression without a suspension is
    /// returned unchanged.
    fn lower_expr(&mut self, e: Expr) -> Option<Expr> {
        if !expr_suspends(&e, self.mode) {
            return Some(e);
        }
        let mode = self.mode;
        Some(match e {
            // The suspension itself: evaluate its operand (which may itself
            // suspend), then suspend as a statement whose result lands in
            // a temporary.
            Expr::Yield { arg, delegate } => {
                let arg = match arg {
                    Some(a) => Some(Box::new(self.lower_expr(*a)?)),
                    None => None,
                };
                let t = self.temp()?;
                self.declare(&t, Expr::Yield { arg, delegate });
                Expr::Ident(t)
            }
            Expr::Await(inner) => {
                let inner = self.lower_expr(*inner)?;
                let t = self.temp()?;
                self.declare(&t, Expr::Await(Box::new(inner)));
                Expr::Ident(t)
            }
            Expr::Unary { op, expr } => Expr::Unary {
                op,
                expr: Box::new(self.lower_expr(*expr)?),
            },
            Expr::Update { op, prefix, target } => Expr::Update {
                op,
                prefix,
                target: Box::new(self.lower_expr(*target)?),
            },
            Expr::Spread(inner) => Expr::Spread(Box::new(self.lower_expr(*inner)?)),
            Expr::Binary { op, left, right } => {
                // The left operand is evaluated before the right suspends.
                let right_suspends = expr_suspends(&right, mode);
                let left = self.capture(*left, right_suspends)?;
                let right = self.lower_expr(*right)?;
                Expr::Binary {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                }
            }
            Expr::Logical { op, left, right } => {
                if !expr_suspends(&right, mode) {
                    return Some(Expr::Logical {
                        op,
                        left: Box::new(self.lower_expr(*left)?),
                        right,
                    });
                }
                // `a && (await b)`: the right side is evaluated only when
                // the short-circuit does not take, so the suspension goes
                // inside an `if`.
                let left = self.lower_expr(*left)?;
                let t = self.temp()?;
                self.declare(&t, left);
                let cond = match op {
                    LogicalOp::And => Expr::Ident(t.clone()),
                    LogicalOp::Or => Expr::Unary {
                        op: UnaryOp::Not,
                        expr: Box::new(Expr::Ident(t.clone())),
                    },
                    LogicalOp::Nullish => Expr::Binary {
                        op: BinaryOp::Eq,
                        left: Box::new(Expr::Ident(t.clone())),
                        right: Box::new(Expr::Null),
                    },
                };
                let body = self.lower_branch(*right, &t)?;
                self.out.push(Stmt::If {
                    cond,
                    then: Box::new(Stmt::Block(body)),
                    alt: None,
                });
                Expr::Ident(t)
            }
            Expr::Cond { cond, then, alt } => {
                let cond = self.lower_expr(*cond)?;
                let t = self.temp()?;
                self.declare(&t, Expr::Undefined);
                let then_body = self.lower_branch(*then, &t)?;
                let alt_body = self.lower_branch(*alt, &t)?;
                self.out.push(Stmt::If {
                    cond,
                    then: Box::new(Stmt::Block(then_body)),
                    alt: Some(Box::new(Stmt::Block(alt_body))),
                });
                Expr::Ident(t)
            }
            Expr::Assign { op, target, value } => {
                // A compound / logical assignment reads the target first;
                // the target's own sub-expressions (`a[await k] = v`) are
                // lowered, then the value.
                let value_suspends = expr_suspends(&value, mode);
                let target = self.lower_target(*target, value_suspends)?;
                if matches!(op, AssignOp::And | AssignOp::Or | AssignOp::Nullish) && value_suspends {
                    // `a ||= await b`: the value is evaluated only when the
                    // short-circuit does not take.
                    let cond = match op {
                        AssignOp::And => target.clone(),
                        AssignOp::Or => Expr::Unary {
                            op: UnaryOp::Not,
                            expr: Box::new(target.clone()),
                        },
                        _ => Expr::Binary {
                            op: BinaryOp::Eq,
                            left: Box::new(target.clone()),
                            right: Box::new(Expr::Null),
                        },
                    };
                    let saved = core::mem::take(&mut self.out);
                    let value = self.lower_expr(*value)?;
                    let mut body = core::mem::replace(&mut self.out, saved);
                    body.push(Stmt::Expr(Expr::Assign {
                        op: AssignOp::Assign,
                        target: Box::new(target.clone()),
                        value: Box::new(value),
                    }));
                    self.out.push(Stmt::If {
                        cond,
                        then: Box::new(Stmt::Block(body)),
                        alt: None,
                    });
                    return Some(target);
                }
                if value_suspends && !matches!(op, AssignOp::Assign | AssignOp::And | AssignOp::Or | AssignOp::Nullish) {
                    // `o.x += await v`: the target is read (its getter runs)
                    // before the value suspends, then written with the
                    // combined result (ES §13.15.2).
                    let current = self.temp()?;
                    self.declare(&current, target.clone());
                    let value = self.lower_expr(*value)?;
                    return Some(Expr::Assign {
                        op: AssignOp::Assign,
                        target: Box::new(target),
                        value: Box::new(Expr::Binary {
                            op: super::eval::compound_binary_op(op),
                            left: Box::new(Expr::Ident(current)),
                            right: Box::new(value),
                        }),
                    });
                }
                let value = self.lower_expr(*value)?;
                Expr::Assign {
                    op,
                    target: Box::new(target),
                    value: Box::new(value),
                }
            }
            Expr::Call {
                callee,
                args,
                optional,
            } => {
                // `obj.m(await x)` keeps its `this`: the member callee is
                // left as a member expression over a captured object.
                let later_suspends = args.iter().any(|a| expr_suspends(&a.expr, mode));
                let callee = match *callee {
                    Expr::Member {
                        object,
                        property,
                        optional: m_opt,
                    } => {
                        let prop_suspends = match &property {
                            MemberKey::Computed(k) => expr_suspends(k, mode),
                            MemberKey::Static(_) => false,
                        };
                        let object = self.capture(*object, later_suspends || prop_suspends)?;
                        let property = match property {
                            MemberKey::Computed(k) => {
                                MemberKey::Computed(Box::new(self.capture(*k, later_suspends)?))
                            }
                            s => s,
                        };
                        Expr::Member {
                            object: Box::new(object),
                            property,
                            optional: m_opt,
                        }
                    }
                    other => self.capture(other, later_suspends)?,
                };
                let args = self.lower_args(args)?;
                Expr::Call {
                    callee: Box::new(callee),
                    args,
                    optional,
                }
            }
            Expr::New { callee, args } => {
                let later_suspends = args.iter().any(|a| expr_suspends(&a.expr, mode));
                let callee = self.capture(*callee, later_suspends)?;
                let args = self.lower_args(args)?;
                Expr::New {
                    callee: Box::new(callee),
                    args,
                }
            }
            Expr::Member {
                object,
                property,
                optional,
            } => {
                let prop_suspends = match &property {
                    MemberKey::Computed(k) => expr_suspends(k, mode),
                    MemberKey::Static(_) => false,
                };
                let object = self.capture(*object, prop_suspends)?;
                let property = match property {
                    MemberKey::Computed(k) => MemberKey::Computed(Box::new(self.lower_expr(*k)?)),
                    s => s,
                };
                Expr::Member {
                    object: Box::new(object),
                    property,
                    optional,
                }
            }
            Expr::Sequence(items) => {
                // Every item but the last is evaluated for effect, in
                // order; emit them as statements.
                let n = items.len();
                let mut last = Expr::Undefined;
                for (i, item) in items.into_iter().enumerate() {
                    let lowered = self.lower_expr(item)?;
                    if i.saturating_add(1) == n {
                        last = lowered;
                    } else {
                        self.out.push(Stmt::Expr(lowered));
                    }
                }
                last
            }
            Expr::Array(items) => {
                let exprs: Vec<Option<Expr>> = items
                    .iter()
                    .map(|s| s.as_ref().map(|s| s.expr.clone()))
                    .collect();
                let spreads: Vec<Option<bool>> = items.iter().map(|s| s.as_ref().map(|s| s.spread)).collect();
                let lowered = self.lower_ordered(exprs)?;
                Expr::Array(
                    lowered
                        .into_iter()
                        .zip(spreads)
                        .map(|(e, sp)| match (e, sp) {
                            (Some(expr), Some(spread)) => Some(SpreadElem { expr, spread }),
                            _ => None,
                        })
                        .collect(),
                )
            }
            Expr::Object(props) => {
                // Keys and values are evaluated in source order; each one
                // ahead of a suspension is captured.
                let mut out_props: Vec<ObjectProp> = Vec::with_capacity(props.len());
                let remaining: Vec<bool> = suffix_suspends_props(&props, mode);
                for (i, p) in props.into_iter().enumerate() {
                    let later = remaining.get(i.saturating_add(1)).copied().unwrap_or(false);
                    out_props.push(match p {
                        ObjectProp::KeyValue(k, v) => {
                            let v_suspends = expr_suspends(&v, mode);
                            let k = self.lower_key(k, later || v_suspends)?;
                            let v = self.capture(v, later)?;
                            ObjectProp::KeyValue(k, v)
                        }
                        ObjectProp::Shorthand(name) => {
                            if later {
                                ObjectProp::KeyValue(
                                    PropKey::Static(name.clone()),
                                    self.capture(Expr::Ident(name), true)?,
                                )
                            } else {
                                ObjectProp::Shorthand(name)
                            }
                        }
                        ObjectProp::ShorthandDefault(name, v) => {
                            ObjectProp::ShorthandDefault(name, self.lower_expr(v)?)
                        }
                        ObjectProp::Method(k, def, kind) => {
                            ObjectProp::Method(self.lower_key(k, later)?, def, kind)
                        }
                        ObjectProp::Spread(v) => ObjectProp::Spread(self.capture(v, later)?),
                    });
                }
                Expr::Object(out_props)
            }
            Expr::Template(parts) => {
                let exprs: Vec<Option<Expr>> = parts
                    .iter()
                    .map(|p| match p {
                        TemplateElem::Expr(e) => Some((**e).clone()),
                        TemplateElem::Str(_) => None,
                    })
                    .collect();
                let lowered = self.lower_ordered(exprs)?;
                Expr::Template(
                    parts
                        .into_iter()
                        .zip(lowered)
                        .map(|(p, e)| match (p, e) {
                            (TemplateElem::Expr(_), Some(e)) => TemplateElem::Expr(Box::new(e)),
                            (p, _) => p,
                        })
                        .collect(),
                )
            }
            // Leaves and nested functions never suspend (expr_suspends
            // said this one does, so this arm is unreachable in practice).
            other => other,
        })
    }

    /// Lower an assignment target: `a[await k]` evaluates the object and
    /// key before the value; a plain identifier is left alone.
    fn lower_target(&mut self, target: Expr, later_suspends: bool) -> Option<Expr> {
        match target {
            Expr::Member {
                object,
                property,
                optional,
            } => {
                let prop_suspends = match &property {
                    MemberKey::Computed(k) => expr_suspends(k, mode_of(self)),
                    MemberKey::Static(_) => false,
                };
                let object = self.capture(*object, later_suspends || prop_suspends)?;
                let property = match property {
                    MemberKey::Computed(k) => {
                        MemberKey::Computed(Box::new(self.capture(*k, later_suspends)?))
                    }
                    s => s,
                };
                Some(Expr::Member {
                    object: Box::new(object),
                    property,
                    optional,
                })
            }
            other => Some(other),
        }
    }

    fn lower_key(&mut self, k: PropKey, later: bool) -> Option<PropKey> {
        Some(match k {
            PropKey::Computed(e) => PropKey::Computed(Box::new(self.capture(*e, later)?)),
            s => s,
        })
    }

    /// Lower an argument list in order, capturing every argument that is
    /// evaluated before a later argument suspends.
    fn lower_args(&mut self, args: Vec<SpreadElem>) -> Option<Vec<SpreadElem>> {
        let exprs: Vec<Option<Expr>> = args.iter().map(|a| Some(a.expr.clone())).collect();
        let spreads: Vec<bool> = args.iter().map(|a| a.spread).collect();
        let lowered = self.lower_ordered(exprs)?;
        Some(
            lowered
                .into_iter()
                .zip(spreads)
                .map(|(e, spread)| SpreadElem {
                    expr: e.unwrap_or(Expr::Undefined),
                    spread,
                })
                .collect(),
        )
    }

    /// Lower a list of expressions evaluated left to right: an item is
    /// captured into a temporary when any LATER item suspends, so the
    /// values it produced before the suspension are the ones used.
    fn lower_ordered(&mut self, items: Vec<Option<Expr>>) -> Option<Vec<Option<Expr>>> {
        let mode = self.mode;
        let n = items.len();
        // later[i] = some item after i suspends.
        let mut later = vec![false; n];
        let mut acc = false;
        for i in (0..n).rev() {
            if let Some(slot) = later.get_mut(i) {
                *slot = acc;
            }
            if items.get(i).and_then(|e| e.as_ref()).map(|e| expr_suspends(e, mode)) == Some(true) {
                acc = true;
            }
        }
        let mut out = Vec::with_capacity(n);
        for (i, item) in items.into_iter().enumerate() {
            let force = later.get(i).copied().unwrap_or(false);
            out.push(match item {
                Some(e) => Some(self.capture(e, force)?),
                None => None,
            });
        }
        Some(out)
    }

    /// Lower a branch expression into statements that assign its value to
    /// `target` (the suspension inside it happens only when the branch
    /// runs).
    fn lower_branch(&mut self, e: Expr, target: &str) -> Option<Vec<Stmt>> {
        let saved = core::mem::take(&mut self.out);
        let value = self.lower_expr(e)?;
        let mut body = core::mem::replace(&mut self.out, saved);
        let mut l = Lower {
            mode: self.mode,
            next: self.next,
            out: Vec::new(),
        };
        l.assign(target, value);
        self.next = l.next;
        body.extend(l.out);
        Some(body)
    }

    /// Lower one statement into `out`.
    fn lower_stmt(&mut self, stmt: Stmt) -> Option<()> {
        if !stmt_suspends(&stmt, self.mode) {
            self.out.push(stmt);
            return Some(());
        }
        match stmt {
            Stmt::Expr(e) => {
                let e = self.lower_expr(e)?;
                self.out.push(Stmt::Expr(e));
            }
            Stmt::Throw(e) => {
                let e = self.lower_expr(e)?;
                self.out.push(Stmt::Throw(e));
            }
            Stmt::Return(Some(e)) => {
                let e = self.lower_expr(e)?;
                self.out.push(Stmt::Return(Some(e)));
            }
            Stmt::VarDecl { kind, decls } => {
                // Each declarator in order; a suspension in one initialiser
                // lands after the earlier declarators are bound.
                for (pat, init) in decls {
                    let init = match init {
                        Some(e) => Some(self.lower_expr(e)?),
                        None => None,
                    };
                    self.out.push(Stmt::VarDecl {
                        kind,
                        decls: vec![(pat, init)],
                    });
                }
            }
            Stmt::If { cond, then, alt } => {
                let cond = self.lower_expr(cond)?;
                self.out.push(Stmt::If { cond, then, alt });
            }
            Stmt::While { cond, body } => {
                // `while (await c) body` → `while (true) { let t = await c;
                // if (!t) break; body }`. A labelled `continue` inside the
                // body still targets this loop.
                let mut inner = Lower {
                    mode: self.mode,
                    next: self.next,
                    out: Vec::new(),
                };
                let c = inner.lower_expr(cond)?;
                self.next = inner.next;
                let mut block = inner.out;
                block.push(Stmt::If {
                    cond: Expr::Unary {
                        op: UnaryOp::Not,
                        expr: Box::new(c),
                    },
                    then: Box::new(Stmt::Break(None)),
                    alt: None,
                });
                block.push(*body);
                self.out.push(Stmt::While {
                    cond: Expr::Bool(true),
                    body: Box::new(Stmt::Block(block)),
                });
            }
            Stmt::DoWhile { body, cond } => {
                // `do body while (await c)` → `while (true) { body_block;
                // let t = await c; if (!t) break; }`, with `continue`
                // inside the body redirected at the condition through a
                // labelled inner block.
                let label = self.temp()?;
                let mut inner = Lower {
                    mode: self.mode,
                    next: self.next,
                    out: Vec::new(),
                };
                let c = inner.lower_expr(cond)?;
                self.next = inner.next;
                let mut block = vec![Stmt::Labeled {
                    label: label.clone(),
                    body: Box::new(Stmt::Block(vec![redirect_continue(*body, &label)])),
                }];
                block.extend(inner.out);
                block.push(Stmt::If {
                    cond: Expr::Unary {
                        op: UnaryOp::Not,
                        expr: Box::new(c),
                    },
                    then: Box::new(Stmt::Break(None)),
                    alt: None,
                });
                self.out.push(Stmt::While {
                    cond: Expr::Bool(true),
                    body: Box::new(Stmt::Block(block)),
                });
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => {
                // `for (init; await c; await u) body` → `{ init; while
                // (true) { let t = await c; if (!t) break; label: { body }
                // ; await u; } }`; `continue` in the body reaches the update.
                let mut block: Vec<Stmt> = Vec::new();
                if let Some(i) = init {
                    let mut inner = Lower {
                        mode: self.mode,
                        next: self.next,
                        out: Vec::new(),
                    };
                    inner.lower_stmt(*i)?;
                    self.next = inner.next;
                    block.extend(inner.out);
                }
                let label = self.temp()?;
                let mut loop_body: Vec<Stmt> = Vec::new();
                if let Some(c) = cond {
                    let mut inner = Lower {
                        mode: self.mode,
                        next: self.next,
                        out: Vec::new(),
                    };
                    let c = inner.lower_expr(c)?;
                    self.next = inner.next;
                    loop_body.extend(inner.out);
                    loop_body.push(Stmt::If {
                        cond: Expr::Unary {
                            op: UnaryOp::Not,
                            expr: Box::new(c),
                        },
                        then: Box::new(Stmt::Break(None)),
                        alt: None,
                    });
                }
                loop_body.push(Stmt::Labeled {
                    label: label.clone(),
                    body: Box::new(Stmt::Block(vec![redirect_continue(*body, &label)])),
                });
                if let Some(u) = update {
                    let mut inner = Lower {
                        mode: self.mode,
                        next: self.next,
                        out: Vec::new(),
                    };
                    let u = inner.lower_expr(u)?;
                    self.next = inner.next;
                    loop_body.extend(inner.out);
                    loop_body.push(Stmt::Expr(u));
                }
                block.push(Stmt::While {
                    cond: Expr::Bool(true),
                    body: Box::new(Stmt::Block(loop_body)),
                });
                self.out.push(Stmt::Block(block));
            }
            Stmt::ForIn {
                decl_kind,
                pat,
                object,
                body,
                of,
            } => {
                let object = self.lower_expr(object)?;
                self.out.push(Stmt::ForIn {
                    decl_kind,
                    pat,
                    object,
                    body,
                    of,
                });
            }
            Stmt::Switch { disc, cases } => {
                // A suspension in a case TEST is evaluated in order only
                // up to the first match; lowering that faithfully means an
                // if-chain. The discriminant is captured first.
                let disc_suspends_in_cases = cases
                    .iter()
                    .any(|(t, _)| t.as_ref().map(|e| expr_suspends(e, self.mode)).unwrap_or(false));
                let disc = self.lower_expr(disc)?;
                if !disc_suspends_in_cases {
                    self.out.push(Stmt::Switch { disc, cases });
                    return Some(());
                }
                let d = self.temp()?;
                self.declare(&d, disc);
                // matched = false; for each case in order: if (!matched &&
                // d === (await test)) matched = true; … then a switch on
                // the matched index so fall-through still works.
                let idx = self.temp()?;
                self.declare(&idx, Expr::Num(-1.0));
                let mut default_at: Option<usize> = None;
                for (i, (test, _)) in cases.iter().enumerate() {
                    let Some(test) = test else {
                        default_at = Some(i);
                        continue;
                    };
                    let mut inner = Lower {
                        mode: self.mode,
                        next: self.next,
                        out: Vec::new(),
                    };
                    let t = inner.lower_expr(test.clone())?;
                    self.next = inner.next;
                    let mut body = inner.out;
                    body.push(Stmt::If {
                        cond: Expr::Binary {
                            op: BinaryOp::StrictEq,
                            left: Box::new(Expr::Ident(d.clone())),
                            right: Box::new(t),
                        },
                        then: Box::new(Stmt::Expr(Expr::Assign {
                            op: AssignOp::Assign,
                            target: Box::new(Expr::Ident(idx.clone())),
                            value: Box::new(Expr::Num(i as f64)),
                        })),
                        alt: None,
                    });
                    self.out.push(Stmt::If {
                        cond: Expr::Binary {
                            op: BinaryOp::StrictEq,
                            left: Box::new(Expr::Ident(idx.clone())),
                            right: Box::new(Expr::Num(-1.0)),
                        },
                        then: Box::new(Stmt::Block(body)),
                        alt: None,
                    });
                }
                if let Some(di) = default_at {
                    self.out.push(Stmt::If {
                        cond: Expr::Binary {
                            op: BinaryOp::StrictEq,
                            left: Box::new(Expr::Ident(idx.clone())),
                            right: Box::new(Expr::Num(-1.0)),
                        },
                        then: Box::new(Stmt::Expr(Expr::Assign {
                            op: AssignOp::Assign,
                            target: Box::new(Expr::Ident(idx.clone())),
                            value: Box::new(Expr::Num(di as f64)),
                        })),
                        alt: None,
                    });
                }
                let new_cases: Vec<(Option<Expr>, Vec<Stmt>)> = cases
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, body))| (Some(Expr::Num(i as f64)), body))
                    .collect();
                self.out.push(Stmt::Switch {
                    disc: Expr::Ident(idx),
                    cases: new_cases,
                });
            }
            // Compound statements whose HEAD does not suspend are left to
            // the frame machine; their bodies are lowered when reached.
            other => self.out.push(other),
        }
        Some(())
    }
}

fn mode_of(l: &Lower) -> Mode {
    l.mode
}

/// Whether an expression can be re-evaluated after a suspension without
/// observable difference: literals and `this`. Identifiers are NOT pure
/// (the suspended code may reassign them), so they are captured too.
fn is_pure_leaf(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Num(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Null | Expr::Undefined | Expr::This
            | Expr::Function(_)
    )
}

/// For each property index, whether any property at or after it suspends.
fn suffix_suspends_props(props: &[ObjectProp], mode: Mode) -> Vec<bool> {
    let mut out = vec![false; props.len()];
    let mut acc = false;
    for i in (0..props.len()).rev() {
        let here = match props.get(i) {
            Some(ObjectProp::KeyValue(k, v)) => key_suspends(k, mode) || expr_suspends(v, mode),
            Some(ObjectProp::ShorthandDefault(_, v)) | Some(ObjectProp::Spread(v)) => {
                expr_suspends(v, mode)
            }
            Some(ObjectProp::Method(k, _, _)) => key_suspends(k, mode),
            _ => false,
        };
        acc = acc || here;
        if let Some(slot) = out.get_mut(i) {
            *slot = acc;
        }
    }
    out
}

fn key_suspends(k: &PropKey, mode: Mode) -> bool {
    match k {
        PropKey::Computed(e) => expr_suspends(e, mode),
        PropKey::Static(_) => false,
    }
}

/// Rewrite every unlabelled `continue` that targets the loop being
/// lowered (not one inside a nested loop) into `break label`, so the
/// lowered loop runs its update/condition statements next.
fn redirect_continue(stmt: Stmt, label: &str) -> Stmt {
    match stmt {
        Stmt::Continue(None) => Stmt::Break(Some(label.to_string())),
        Stmt::Block(body) => Stmt::Block(body.into_iter().map(|s| redirect_continue(s, label)).collect()),
        Stmt::If { cond, then, alt } => Stmt::If {
            cond,
            then: Box::new(redirect_continue(*then, label)),
            alt: alt.map(|a| Box::new(redirect_continue(*a, label))),
        },
        Stmt::Try {
            block,
            catch,
            finally,
        } => Stmt::Try {
            block: block.into_iter().map(|s| redirect_continue(s, label)).collect(),
            catch: catch.map(|(p, b)| (p, b.into_iter().map(|s| redirect_continue(s, label)).collect())),
            finally: finally.map(|b| b.into_iter().map(|s| redirect_continue(s, label)).collect()),
        },
        Stmt::Switch { disc, cases } => Stmt::Switch {
            disc,
            cases: cases
                .into_iter()
                .map(|(t, b)| (t, b.into_iter().map(|s| redirect_continue(s, label)).collect()))
                .collect(),
        },
        Stmt::Labeled { label: l, body } => Stmt::Labeled {
            label: l,
            body: Box::new(redirect_continue(*body, label)),
        },
        // A nested loop owns its own `continue`.
        other => other,
    }
}

/// Lower `stmt` for `mode` into a statement list the frame machine can
/// suspend on. `None` when the rewrite hit its temporary cap (the caller
/// reports a RangeError).
pub fn lower_statement(stmt: &Stmt, mode: Mode, counter: &mut usize) -> Option<Vec<Stmt>> {
    let mut l = Lower {
        mode,
        next: *counter,
        out: Vec::new(),
    };
    l.lower_stmt(stmt.clone())?;
    *counter = l.next;
    Some(l.out)
}

/// Convenience for callers holding an `Rc<Vec<Stmt>>` body.
pub fn lower_body(body: &[Stmt], mode: Mode, counter: &mut usize) -> Option<Rc<Vec<Stmt>>> {
    let mut out = Vec::with_capacity(body.len());
    for s in body {
        out.extend(lower_statement(s, mode, counter)?);
    }
    Some(Rc::new(out))
}
