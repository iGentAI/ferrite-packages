//! ast — the abstract syntax tree produced by the parser.
//!
//! Scope: the ES2017-ish subset that drives real pages — expressions,
//! statements, functions/closures, classes (constructor + methods), template
//! literals, destructuring in the common forms, async/await lowered onto
//! promises, and spread/rest.

use std::rc::Rc;

/// A complete parsed program (script, not module).
#[derive(Clone, Debug)]
pub struct Program {
    pub body: Vec<Stmt>,
    /// The script opens with a `"use strict"` directive.
    pub strict: bool,
}

/// Statements.
#[derive(Clone, Debug)]
pub enum Stmt {
    Expr(Expr),
    VarDecl {
        kind: DeclKind,
        decls: Vec<(Pattern, Option<Expr>)>,
    },
    Function(Rc<FnDef>),
    Return(Option<Expr>),
    If {
        cond: Expr,
        then: Box<Stmt>,
        alt: Option<Box<Stmt>>,
    },
    Block(Vec<Stmt>),
    For {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        update: Option<Expr>,
        body: Box<Stmt>,
    },
    ForIn {
        decl_kind: Option<DeclKind>,
        pat: Pattern,
        object: Expr,
        body: Box<Stmt>,
        of: bool,
    },
    While {
        cond: Expr,
        body: Box<Stmt>,
    },
    DoWhile {
        body: Box<Stmt>,
        cond: Expr,
    },
    Break(Option<String>),
    Continue(Option<String>),
    Throw(Expr),
    Try {
        block: Vec<Stmt>,
        catch: Option<(Option<Pattern>, Vec<Stmt>)>,
        finally: Option<Vec<Stmt>>,
    },
    Switch {
        disc: Expr,
        cases: Vec<(Option<Expr>, Vec<Stmt>)>,
    },
    Labeled {
        label: String,
        body: Box<Stmt>,
    },
    ClassDecl(Rc<ClassDef>),
    Empty,
}

/// `var` / `let` / `const`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclKind {
    Var,
    Let,
    Const,
}

/// Binding patterns (destructuring).
#[derive(Clone, Debug)]
pub enum Pattern {
    Ident(String),
    Array(Vec<Option<PatternElem>>),
    Object(Vec<ObjectPatternProp>),
}

/// One element of an array pattern.
#[derive(Clone, Debug)]
pub struct PatternElem {
    pub pat: Pattern,
    pub default: Option<Expr>,
    pub rest: bool,
}

/// One property of an object pattern.
#[derive(Clone, Debug)]
pub struct ObjectPatternProp {
    /// The static key, or the placeholder for a computed key (see
    /// `computed`).
    pub key: String,
    /// `{ [expr]: pat }` — the key is evaluated at bind time.
    pub computed: Option<Box<Expr>>,
    pub pat: Pattern,
    pub default: Option<Expr>,
    pub rest: bool,
}

/// A function definition (declaration, expression, method, or arrow).
#[derive(Clone, Debug)]
pub struct FnDef {
    pub name: Option<String>,
    pub params: Vec<PatternElem>,
    pub body: Vec<Stmt>,
    /// Arrow functions capture `this` lexically.
    pub arrow: bool,
    /// Async functions return promises and may `await`.
    pub is_async: bool,
    /// Concise arrow body (`x => x + 1`) is represented as a single
    /// `Stmt::Return`.
    pub is_expr_body: bool,
    /// `function*` / `*method()`: calls return a generator object whose
    /// body runs on the first `next()` (see `Interp::call`).
    pub is_generator: bool,
    /// Strict-mode code: the body (or an enclosing function / the script)
    /// opens with a `"use strict"` directive, or the function is a class
    /// member. A strict plain call keeps the `this` it was given (so
    /// `undefined` stays `undefined`); a sloppy one substitutes the global
    /// object (ES §10.2.1.2 OrdinaryCallBindThis).
    pub strict: bool,
}

/// A class definition.
#[derive(Clone, Debug)]
pub struct ClassDef {
    pub name: Option<String>,
    pub parent: Option<Expr>,
    pub constructor: Option<Rc<FnDef>>,
    pub members: Vec<ClassMember>,
}

/// One class body element other than the constructor.
#[derive(Clone, Debug)]
pub struct ClassMember {
    /// Method / accessor / field name (`#private` names keep their `#`).
    pub key: PropKey,
    /// The method body, or for a field a zero-arg function returning the
    /// initializer value (`Expr::Undefined` when absent), or for a static
    /// block the block body.
    pub def: Rc<FnDef>,
    pub is_static: bool,
    pub kind: MemberKind,
}

/// Class member kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    Method,
    Get,
    Set,
    Field,
    StaticBlock,
}

/// Method kinds — plain, getter, setter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodKind {
    Method,
    Get,
    Set,
}

/// Expressions.
#[derive(Clone, Debug)]
pub enum Expr {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undefined,
    Ident(String),
    This,
    Template(Vec<TemplateElem>),
    Regex {
        source: String,
        flags: String,
    },
    Array(Vec<Option<SpreadElem>>),
    Object(Vec<ObjectProp>),
    Function(Rc<FnDef>),
    Class(Rc<ClassDef>),
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Update {
        op: UpdateOp,
        prefix: bool,
        target: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Logical {
        op: LogicalOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Assign {
        op: AssignOp,
        target: Box<Expr>,
        value: Box<Expr>,
    },
    Cond {
        cond: Box<Expr>,
        then: Box<Expr>,
        alt: Box<Expr>,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<SpreadElem>,
        /// `a?.b()` — short-circuits on nullish callee.
        optional: bool,
    },
    New {
        callee: Box<Expr>,
        args: Vec<SpreadElem>,
    },
    Member {
        object: Box<Expr>,
        property: MemberKey,
        optional: bool,
    },
    Sequence(Vec<Expr>),
    Await(Box<Expr>),
    Spread(Box<Expr>),
    /// `yield x` / `yield* iterable` inside a generator body.
    Yield {
        arg: Option<Box<Expr>>,
        delegate: bool,
    },
}

/// A template literal element.
#[derive(Clone, Debug)]
pub enum TemplateElem {
    Str(String),
    Expr(Box<Expr>),
}

/// Argument or array element that may be spread (`...x`).
#[derive(Clone, Debug)]
pub struct SpreadElem {
    pub expr: Expr,
    pub spread: bool,
}

/// Object literal properties.
#[derive(Clone, Debug)]
pub enum ObjectProp {
    /// `key: value` (key may be computed).
    KeyValue(PropKey, Expr),
    /// `{ x }` shorthand.
    Shorthand(String),
    /// `{ x = 1 }` — only meaningful as a destructuring-assignment target
    /// (cover grammar); as a literal it reads as the shorthand `{ x }`.
    ShorthandDefault(String, Expr),
    /// `{ method() {} }`, `{ get x() {} }`, `{ set x(v) {} }`.
    Method(PropKey, Rc<FnDef>, MethodKind),
    /// `{ ...obj }`.
    Spread(Expr),
}

/// Property keys — static or computed.
#[derive(Clone, Debug)]
pub enum PropKey {
    Static(String),
    Computed(Box<Expr>),
}

/// Member access keys — `.name` or `[expr]`.
#[derive(Clone, Debug)]
pub enum MemberKey {
    Static(String),
    Computed(Box<Expr>),
}

/// Unary operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Plus,
    Not,
    BitNot,
    Typeof,
    Void,
    Delete,
}

/// `++` / `--`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateOp {
    Inc,
    Dec,
}

/// Binary (non-short-circuit) operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Pow,
    Eq,
    NotEq,
    StrictEq,
    StrictNotEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    UShr,
    In,
    Instanceof,
}

/// Short-circuit operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalOp {
    And,
    Or,
    Nullish,
}

/// Assignment operators (compound forms lower onto their binary op).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignOp {
    Assign,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Pow,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    UShr,
    And,
    Or,
    Nullish,
}
