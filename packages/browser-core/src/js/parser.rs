//! parser — recursive-descent JavaScript parser, std-only and panic-free.
//!
//! Consumes the token stream from [`super::lexer`] and produces the
//! [`super::ast`] tree. Errors are values (`ParseError`), never panics; the
//! engine reports them as script-level syntax errors and keeps the page
//! alive, matching the rest of the pipeline's infallible contract.

use std::rc::Rc;

use super::ast::{AssignOp, BinaryOp, ClassDef, ClassMember, DeclKind, Expr, FnDef, LogicalOp, MemberKey, MemberKind, MethodKind, ObjectPatternProp, ObjectProp, Pattern, PatternElem, Program, PropKey, SpreadElem, Stmt, TemplateElem, UnaryOp, UpdateOp};
use super::lexer::{lex, Keyword, Punct, TemplatePart, Token, TokenKind};

/// A syntax error with byte position.
#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub pos: usize,
}

/// Parse a complete script.
pub fn parse(src: &str) -> Result<Program, ParseError> {
    let tokens = lex(src);
    let mut p = Parser {
        tokens,
        pos: 0,
        depth: 0,
        in_generator: 0,
        strict: false,
    };
    // A script-level directive prologue makes the whole script strict.
    p.strict = p.directive_prologue_is_strict();
    let strict = p.strict;
    let mut body = Vec::new();
    while !p.at_eof() {
        body.push(p.statement()?);
    }
    Ok(Program { body, strict })
}

/// Parse the source of one template substitution (`${…}`) in the CONTEXT
/// of the enclosing code: inside a generator body `yield` is an
/// expression there too, and strictness is inherited. An empty `${}` is
/// a syntax error, as in every engine.
fn parse_substitution(src: &str, in_generator: u32, strict: bool) -> Result<Expr, ParseError> {
    let tokens = lex(src);
    let mut p = Parser {
        tokens,
        pos: 0,
        depth: 0,
        in_generator,
        strict,
    };
    if p.at_eof() {
        return p.err("empty template substitution");
    }
    let e = p.expression()?;
    let _ = p.eat_punct(Punct::Semi);
    if !p.at_eof() {
        return p.err("unexpected token in template substitution");
    }
    Ok(e)
}

/// Recursion guard: hostile input (deeply nested parens) must not blow the
/// native stack.
const MAX_DEPTH: u32 = 200;

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: u32,
    /// Nesting depth of generator bodies: `yield` is an expression only
    /// when this is non-zero (outside generators it is an identifier).
    in_generator: u32,
    /// Whether the code being parsed is strict-mode code: set by a
    /// `"use strict"` directive prologue (script or function body) and
    /// inside every class body; inherited by nested functions.
    strict: bool,
}

impl Parser {

    fn peek(&self) -> &TokenKind {
        self.tokens
            .get(self.pos)
            .map(|t| &t.kind)
            .unwrap_or(&TokenKind::Eof)
    }
    fn peek_at(&self, n: usize) -> &TokenKind {
        self.tokens
            .get(self.pos.saturating_add(n))
            .map(|t| &t.kind)
            .unwrap_or(&TokenKind::Eof)
    }
    fn newline_before(&self) -> bool {
        self.tokens
            .get(self.pos)
            .map(|t| t.newline_before)
            .unwrap_or(false)
    }
    fn cur_pos(&self) -> usize {
        self.tokens.get(self.pos).map(|t| t.pos).unwrap_or(0)
    }
    fn bump(&mut self) -> TokenKind {
        let k = self.peek().clone();
        if self.pos < self.tokens.len() {
            self.pos = self.pos.saturating_add(1);
        }
        k
    }
    fn at_eof(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }
    fn err<T>(&self, msg: &str) -> Result<T, ParseError> {
        Err(ParseError {
            message: msg.to_string(),
            pos: self.cur_pos(),
        })
    }
    fn is_punct(&self, p: Punct) -> bool {
        matches!(self.peek(), TokenKind::Punct(q) if *q == p)
    }
    fn eat_punct(&mut self, p: Punct) -> bool {
        if self.is_punct(p) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn expect_punct(&mut self, p: Punct, what: &str) -> Result<(), ParseError> {
        if self.eat_punct(p) {
            Ok(())
        } else {
            self.err(what)
        }
    }
    fn is_kw(&self, k: Keyword) -> bool {
        matches!(self.peek(), TokenKind::Keyword(q) if *q == k)
    }
    fn eat_kw(&mut self, k: Keyword) -> bool {
        if self.is_kw(k) {
            self.bump();
            true
        } else {
            false
        }
    }
    /// Identifier or contextually-identifier keyword (get/set/of/async/static…).
    fn ident_like(&mut self) -> Option<String> {
        match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.bump();
                Some(s)
            }
            TokenKind::Keyword(k) => {
                let s = match k {
                    Keyword::Get => "get",
                    Keyword::Set => "set",
                    Keyword::Of => "of",
                    Keyword::Async => "async",
                    Keyword::Static => "static",
                    Keyword::Undefined => "undefined",
                    _ => return None,
                };
                self.bump();
                Some(s.to_string())
            }
            _ => None,
        }
    }
    /// Property name position: any keyword or identifier or string/number.
    fn prop_name(&mut self) -> Option<String> {
        match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.bump();
                Some(s)
            }
            TokenKind::Str(s) => {
                self.bump();
                Some(s)
            }
            TokenKind::Num(n) => {
                self.bump();
                Some(num_to_prop(n))
            }
            TokenKind::Keyword(k) => {
                let s = keyword_text(k);
                self.bump();
                Some(s.to_string())
            }
            _ => None,
        }
    }

    /// Whether the directive prologue at the current position (a run of
    /// string-literal expression statements) contains `"use strict"`.
    /// Does not consume tokens.
    fn directive_prologue_is_strict(&self) -> bool {
        let mut i = self.pos;
        loop {
            let TokenKind::Str(s) = self.tokens.get(i).map(|t| &t.kind).cloned().unwrap_or(TokenKind::Eof) else {
                return false;
            };
            let next = self.tokens.get(i.saturating_add(1));
            let ends = match next.map(|t| &t.kind) {
                Some(TokenKind::Punct(Punct::Semi))
                | Some(TokenKind::Punct(Punct::RBrace))
                | Some(TokenKind::Eof)
                | None => true,
                _ => next.map(|t| t.newline_before).unwrap_or(true),
            };
            if !ends {
                // `"use strict".length` is an expression, not a directive.
                return false;
            }
            if s == "use strict" {
                return true;
            }
            i = i.saturating_add(
                if matches!(next.map(|t| &t.kind), Some(TokenKind::Punct(Punct::Semi))) { 2 } else { 1 },
            );
        }
    }

    /// Automatic semicolon insertion after a statement.
    fn semicolon(&mut self) -> Result<(), ParseError> {
        if self.eat_punct(Punct::Semi) {
            return Ok(());
        }
        if self.at_eof() || self.is_punct(Punct::RBrace) || self.newline_before() {
            return Ok(());
        }
        self.err("expected semicolon")
    }

    /// `: statements` of one `case` or `default` clause.
    fn switch_case_body(&mut self) -> Result<Vec<Stmt>, ParseError> {
        self.expect_punct(Punct::Colon, "expected :")?;
        let mut body = Vec::new();
        while !self.is_kw(Keyword::Case)
            && !self.is_kw(Keyword::Default)
            && !self.is_punct(Punct::RBrace)
            && !self.at_eof()
        {
            body.push(self.statement()?);
        }
        Ok(body)
    }

    fn statement(&mut self) -> Result<Stmt, ParseError> {
        self.depth = self.depth.saturating_add(1);
        let r = self.statement_inner();
        self.depth = self.depth.saturating_sub(1);
        r
    }

    fn statement_inner(&mut self) -> Result<Stmt, ParseError> {
        if self.depth > MAX_DEPTH {
            return self.err("nesting too deep");
        }
        match self.peek().clone() {
            TokenKind::Punct(Punct::Semi) => {
                self.bump();
                Ok(Stmt::Empty)
            }
            TokenKind::Punct(Punct::LBrace) => {
                self.bump();
                let mut body = Vec::new();
                while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                    body.push(self.statement()?);
                }
                self.expect_punct(Punct::RBrace, "expected }")?;
                Ok(Stmt::Block(body))
            }
            TokenKind::Keyword(Keyword::Let)
                if !matches!(
                    self.peek_at(1),
                    TokenKind::Ident(_)
                        | TokenKind::Keyword(_)
                        | TokenKind::Punct(Punct::LBracket)
                        | TokenKind::Punct(Punct::LBrace)
                ) =>
            {
                let e = self.expression()?;
                self.semicolon()?;
                Ok(Stmt::Expr(e))
            }
            TokenKind::Keyword(Keyword::Var)
            | TokenKind::Keyword(Keyword::Let)
            | TokenKind::Keyword(Keyword::Const) => {
                let stmt = self.var_decl()?;
                self.semicolon()?;
                Ok(stmt)
            }
            TokenKind::Keyword(Keyword::Function) => {
                self.bump();
                let f = self.function_rest(false)?;
                Ok(Stmt::Function(Rc::new(f)))
            }
            TokenKind::Keyword(Keyword::Async)
                if matches!(self.peek_at(1), TokenKind::Keyword(Keyword::Function))
                    && !self
                        .tokens
                        .get(self.pos.saturating_add(1))
                        .map(|t| t.newline_before)
                        .unwrap_or(true) =>
            {
                self.bump();
                self.bump();
                let f = self.function_rest(true)?;
                Ok(Stmt::Function(Rc::new(f)))
            }
            TokenKind::Keyword(Keyword::Class) => {
                self.bump();
                let c = self.class_rest()?;
                Ok(Stmt::ClassDecl(Rc::new(c)))
            }
            TokenKind::Keyword(Keyword::Return) => {
                self.bump();
                let arg = if self.is_punct(Punct::Semi)
                    || self.is_punct(Punct::RBrace)
                    || self.at_eof()
                    || self.newline_before()
                {
                    None
                } else {
                    Some(self.expression()?)
                };
                self.semicolon()?;
                Ok(Stmt::Return(arg))
            }
            TokenKind::Keyword(Keyword::If) => {
                self.bump();
                self.expect_punct(Punct::LParen, "expected ( after if")?;
                let cond = self.expression()?;
                self.expect_punct(Punct::RParen, "expected ) after if condition")?;
                let then = Box::new(self.statement()?);
                let alt = if self.eat_kw(Keyword::Else) {
                    Some(Box::new(self.statement()?))
                } else {
                    None
                };
                Ok(Stmt::If { cond, then, alt })
            }
            TokenKind::Keyword(Keyword::For) => self.for_statement(),
            TokenKind::Keyword(Keyword::While) => {
                self.bump();
                self.expect_punct(Punct::LParen, "expected ( after while")?;
                let cond = self.expression()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                let body = Box::new(self.statement()?);
                Ok(Stmt::While { cond, body })
            }
            TokenKind::Keyword(Keyword::Do) => {
                self.bump();
                let body = Box::new(self.statement()?);
                if !self.eat_kw(Keyword::While) {
                    return self.err("expected while after do body");
                }
                self.expect_punct(Punct::LParen, "expected (")?;
                let cond = self.expression()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                let _ = self.eat_punct(Punct::Semi);
                Ok(Stmt::DoWhile { body, cond })
            }
            TokenKind::Keyword(Keyword::Break) => {
                self.bump();
                let label = if !self.newline_before() {
                    self.ident_like()
                } else {
                    None
                };
                self.semicolon()?;
                Ok(Stmt::Break(label))
            }
            TokenKind::Keyword(Keyword::Continue) => {
                self.bump();
                let label = if !self.newline_before() {
                    self.ident_like()
                } else {
                    None
                };
                self.semicolon()?;
                Ok(Stmt::Continue(label))
            }
            TokenKind::Keyword(Keyword::Throw) => {
                self.bump();
                let e = self.expression()?;
                self.semicolon()?;
                Ok(Stmt::Throw(e))
            }
            TokenKind::Keyword(Keyword::Try) => {
                self.bump();
                self.expect_punct(Punct::LBrace, "expected { after try")?;
                let mut block = Vec::new();
                while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                    block.push(self.statement()?);
                }
                self.expect_punct(Punct::RBrace, "expected }")?;
                let catch = if self.eat_kw(Keyword::Catch) {
                    let param = if self.eat_punct(Punct::LParen) {
                        let p = self.pattern()?;
                        self.expect_punct(Punct::RParen, "expected )")?;
                        Some(p)
                    } else {
                        None
                    };
                    self.expect_punct(Punct::LBrace, "expected { after catch")?;
                    let mut body = Vec::new();
                    while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                        body.push(self.statement()?);
                    }
                    self.expect_punct(Punct::RBrace, "expected }")?;
                    Some((param, body))
                } else {
                    None
                };
                let finally = if self.eat_kw(Keyword::Finally) {
                    self.expect_punct(Punct::LBrace, "expected { after finally")?;
                    let mut body = Vec::new();
                    while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                        body.push(self.statement()?);
                    }
                    self.expect_punct(Punct::RBrace, "expected }")?;
                    Some(body)
                } else {
                    None
                };
                if catch.is_none() && finally.is_none() {
                    return self.err("try without catch or finally");
                }
                Ok(Stmt::Try {
                    block,
                    catch,
                    finally,
                })
            }
            TokenKind::Keyword(Keyword::Switch) => {
                self.bump();
                self.expect_punct(Punct::LParen, "expected (")?;
                let disc = self.expression()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                self.expect_punct(Punct::LBrace, "expected {")?;
                let mut cases = Vec::new();
                while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                    if self.eat_kw(Keyword::Case) {
                        let test = self.expression()?;
                        cases.push((Some(test), self.switch_case_body()?));
                    } else if self.eat_kw(Keyword::Default) {
                        cases.push((None, self.switch_case_body()?));
                    } else {
                        return self.err("expected case or default");
                    }
                }
                self.expect_punct(Punct::RBrace, "expected }")?;
                Ok(Stmt::Switch { disc, cases })
            }
            TokenKind::Ident(name) if matches!(self.peek_at(1), TokenKind::Punct(Punct::Colon)) => {
                self.bump();
                self.bump();
                let body = Box::new(self.statement()?);
                Ok(Stmt::Labeled { label: name, body })
            }
            // `yield` / `async` / `await` used as plain identifiers
            // (sloppy-mode bundles do this) fall to the expression path;
            // a bare `let` identifier was handled before the declaration
            // arm above.
            _ => {
                let e = self.expression()?;
                self.semicolon()?;
                Ok(Stmt::Expr(e))
            }
        }
    }

    fn var_decl(&mut self) -> Result<Stmt, ParseError> {
        let kind = match self.bump() {
            TokenKind::Keyword(Keyword::Var) => DeclKind::Var,
            TokenKind::Keyword(Keyword::Let) => DeclKind::Let,
            _ => DeclKind::Const,
        };
        let mut decls = Vec::new();
        loop {
            let pat = self.pattern()?;
            let init = if self.eat_punct(Punct::Assign) {
                Some(self.assignment()?)
            } else {
                None
            };
            decls.push((pat, init));
            if !self.eat_punct(Punct::Comma) {
                break;
            }
        }
        Ok(Stmt::VarDecl { kind, decls })
    }

    fn for_statement(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // for
        // `for await (x of y)`: the async iteration runs eagerly here (the
        // engine's await is synchronous), so it parses as a plain for-of.
        let _ = self.eat_kw(Keyword::Await);
        self.expect_punct(Punct::LParen, "expected ( after for")?;

        // Empty init.
        if self.eat_punct(Punct::Semi) {
            return self.for_classic(None);
        }

        // Declaration init — may become for-in/of.
        if self.is_kw(Keyword::Var) || self.is_kw(Keyword::Let) || self.is_kw(Keyword::Const) {
            let kind = match self.bump() {
                TokenKind::Keyword(Keyword::Var) => DeclKind::Var,
                TokenKind::Keyword(Keyword::Let) => DeclKind::Let,
                _ => DeclKind::Const,
            };
            let pat = self.pattern()?;
            if self.eat_kw(Keyword::Of) {
                let object = self.assignment()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                let body = Box::new(self.statement()?);
                return Ok(Stmt::ForIn {
                    decl_kind: Some(kind),
                    pat,
                    object,
                    body,
                    of: true,
                });
            }
            if self.eat_kw(Keyword::In) {
                let object = self.expression()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                let body = Box::new(self.statement()?);
                return Ok(Stmt::ForIn {
                    decl_kind: Some(kind),
                    pat,
                    object,
                    body,
                    of: false,
                });
            }
            // Classic for with declaration init.
            let init_expr = if self.eat_punct(Punct::Assign) {
                Some(self.assignment()?)
            } else {
                None
            };
            let mut decls = vec![(pat, init_expr)];
            while self.eat_punct(Punct::Comma) {
                let p = self.pattern()?;
                let e = if self.eat_punct(Punct::Assign) {
                    Some(self.assignment()?)
                } else {
                    None
                };
                decls.push((p, e));
            }
            self.expect_punct(Punct::Semi, "expected ; in for")?;
            return self.for_classic(Some(Box::new(Stmt::VarDecl { kind, decls })));
        }

        // Expression init — may become for-in/of with a bare target.
        let save = self.pos;
        if let Ok(pat) = self.pattern() {
            if self.eat_kw(Keyword::Of) {
                let object = self.assignment()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                let body = Box::new(self.statement()?);
                return Ok(Stmt::ForIn {
                    decl_kind: None,
                    pat,
                    object,
                    body,
                    of: true,
                });
            }
            if self.eat_kw(Keyword::In) {
                let object = self.expression()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                let body = Box::new(self.statement()?);
                return Ok(Stmt::ForIn {
                    decl_kind: None,
                    pat,
                    object,
                    body,
                    of: false,
                });
            }
        }
        self.pos = save;
        let init = self.expression()?;
        self.expect_punct(Punct::Semi, "expected ; in for")?;
        self.for_classic(Some(Box::new(Stmt::Expr(init))))
    }

    fn for_classic(&mut self, init: Option<Box<Stmt>>) -> Result<Stmt, ParseError> {
        let cond = if self.is_punct(Punct::Semi) {
            None
        } else {
            Some(self.expression()?)
        };
        self.expect_punct(Punct::Semi, "expected ; in for")?;
        let update = if self.is_punct(Punct::RParen) {
            None
        } else {
            Some(self.expression()?)
        };
        self.expect_punct(Punct::RParen, "expected )")?;
        let body = Box::new(self.statement()?);
        Ok(Stmt::For {
            init,
            cond,
            update,
            body,
        })
    }

    fn pattern(&mut self) -> Result<Pattern, ParseError> {
        match self.peek().clone() {
            TokenKind::Punct(Punct::LBracket) => {
                self.bump();
                let mut elems = Vec::new();
                while !self.is_punct(Punct::RBracket) && !self.at_eof() {
                    if self.eat_punct(Punct::Comma) {
                        elems.push(None);
                        continue;
                    }
                    let rest = self.eat_punct(Punct::DotDotDot);
                    let pat = self.pattern()?;
                    let default = if self.eat_punct(Punct::Assign) {
                        Some(self.assignment()?)
                    } else {
                        None
                    };
                    elems.push(Some(PatternElem { pat, default, rest }));
                    if !self.is_punct(Punct::RBracket) {
                        self.expect_punct(Punct::Comma, "expected , in array pattern")?;
                    }
                }
                self.expect_punct(Punct::RBracket, "expected ]")?;
                Ok(Pattern::Array(elems))
            }
            TokenKind::Punct(Punct::LBrace) => {
                self.bump();
                let mut props = Vec::new();
                while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                    if self.eat_punct(Punct::DotDotDot) {
                        let key = match self.ident_like() {
                            Some(k) => k,
                            None => {
                                return self.err("expected identifier after ... in object pattern")
                            }
                        };
                        props.push(ObjectPatternProp {
                            key: key.clone(),
                            computed: None,
                            pat: Pattern::Ident(key),
                            default: None,
                            rest: true,
                        });
                    } else {
                        // `{ [expr]: pat }` computed keys.
                        let computed = if self.eat_punct(Punct::LBracket) {
                            let e = self.assignment()?;
                            self.expect_punct(Punct::RBracket, "expected ]")?;
                            Some(Box::new(e))
                        } else {
                            None
                        };
                        let key = if computed.is_some() {
                            String::new()
                        } else {
                            match self.prop_name() {
                                Some(k) => k,
                                None => return self.err("expected property name in object pattern"),
                            }
                        };
                        let pat = if self.eat_punct(Punct::Colon) {
                            self.pattern()?
                        } else if computed.is_some() {
                            return self.err("computed key in object pattern needs a target");
                        } else {
                            Pattern::Ident(key.clone())
                        };
                        let default = if self.eat_punct(Punct::Assign) {
                            Some(self.assignment()?)
                        } else {
                            None
                        };
                        props.push(ObjectPatternProp {
                            key,
                            computed,
                            pat,
                            default,
                            rest: false,
                        });
                    }
                    if !self.is_punct(Punct::RBrace) {
                        self.expect_punct(Punct::Comma, "expected , in object pattern")?;
                    }
                }
                self.expect_punct(Punct::RBrace, "expected }")?;
                Ok(Pattern::Object(props))
            }
            _ => match self.ident_like() {
                Some(name) => Ok(Pattern::Ident(name)),
                None => self.err("expected binding pattern"),
            },
        }
    }

    fn function_rest(&mut self, is_async: bool) -> Result<FnDef, ParseError> {
        // `function* name() {}` — the star marks a generator.
        let is_generator = self.eat_punct(Punct::Star);
        let name = self.ident_like();
        self.expect_punct(Punct::LParen, "expected ( in function")?;
        let params = self.params_rest()?;
        let (body, strict) = self.generator_scoped(is_generator, |p| p.function_body())?;
        Ok(FnDef {
            name,
            params,
            body,
            arrow: false,
            is_async,
            is_expr_body: false,
            is_generator,
            strict,
        })
    }

    /// Run `f` with the generator flag set when `is_generator`, so `yield`
    /// inside the body parses as an expression. Nested non-generator
    /// functions reset the flag (a plain function inside a generator treats
    /// `yield` as an identifier again).
    fn generator_scoped<T>(
        &mut self,
        is_generator: bool,
        f: impl FnOnce(&mut Parser) -> Result<T, ParseError>,
    ) -> Result<T, ParseError> {
        let saved = self.in_generator;
        self.in_generator = if is_generator { 1 } else { 0 };
        let r = f(self);
        self.in_generator = saved;
        r
    }

    /// `{ statements }` of a function/method body, and whether the body is
    /// strict-mode code (inherited from the enclosing code or declared by
    /// the body's own directive prologue). Strictness is scoped to the
    /// body: a sloppy sibling after a strict function stays sloppy.
    fn function_body(&mut self) -> Result<(Vec<Stmt>, bool), ParseError> {
        self.expect_punct(Punct::LBrace, "expected { in function")?;
        let saved = self.strict;
        if !self.strict && self.directive_prologue_is_strict() {
            self.strict = true;
        }
        let strict = self.strict;
        let mut body = Vec::new();
        while !self.is_punct(Punct::RBrace) && !self.at_eof() {
            match self.statement() {
                Ok(s) => body.push(s),
                Err(e) => {
                    self.strict = saved;
                    return Err(e);
                }
            }
        }
        self.strict = saved;
        self.expect_punct(Punct::RBrace, "expected }")?;
        Ok((body, strict))
    }

    /// A method definition after its name: `(params) { body }`.
    fn method_def(
        &mut self,
        name: Option<String>,
        is_async: bool,
        is_generator: bool,
    ) -> Result<FnDef, ParseError> {
        self.expect_punct(Punct::LParen, "expected ( in method")?;
        let params = self.params_rest()?;
        let (body, strict) = self.generator_scoped(is_generator, |p| p.function_body())?;
        Ok(FnDef {
            name,
            params,
            body,
            arrow: false,
            is_async,
            is_expr_body: false,
            is_generator,
            strict,
        })
    }

    /// A property key in class/object position: identifier-like, string,
    /// number, `#private`, or `[computed]`.
    fn member_key(&mut self) -> Result<PropKey, ParseError> {
        if self.is_punct(Punct::LBracket) {
            self.bump();
            let e = self.assignment()?;
            self.expect_punct(Punct::RBracket, "expected ]")?;
            return Ok(PropKey::Computed(Box::new(e)));
        }
        if let TokenKind::Error('#') = self.peek().clone() {
            self.bump();
            return match self.prop_name() {
                Some(n) => Ok(PropKey::Static(format!("#{n}"))),
                None => self.err("expected private name after #"),
            };
        }
        match self.prop_name() {
            Some(n) => Ok(PropKey::Static(n)),
            None => self.err("expected property name"),
        }
    }

    fn params_rest(&mut self) -> Result<Vec<PatternElem>, ParseError> {
        let mut params = Vec::new();
        while !self.is_punct(Punct::RParen) && !self.at_eof() {
            let rest = self.eat_punct(Punct::DotDotDot);
            let pat = self.pattern()?;
            let default = if self.eat_punct(Punct::Assign) {
                Some(self.assignment()?)
            } else {
                None
            };
            params.push(PatternElem { pat, default, rest });
            if !self.is_punct(Punct::RParen) {
                self.expect_punct(Punct::Comma, "expected , in params")?;
            }
        }
        self.expect_punct(Punct::RParen, "expected )")?;
        Ok(params)
    }

    fn class_rest(&mut self) -> Result<ClassDef, ParseError> {
        // All parts of a class body are strict-mode code (ES §15.7.1).
        let saved_strict = self.strict;
        self.strict = true;
        let r = self.class_rest_inner();
        self.strict = saved_strict;
        r
    }

    fn class_rest_inner(&mut self) -> Result<ClassDef, ParseError> {
        let name = self.ident_like();
        let parent = if self.eat_kw(Keyword::Extends) {
            Some(self.postfix()?)
        } else {
            None
        };
        self.expect_punct(Punct::LBrace, "expected { in class")?;
        let mut constructor = None;
        let mut members = Vec::new();
        // A modifier keyword is a MODIFIER only when a member name follows;
        // `static(){}` / `get = 1` / `async;` name members called that.
        let name_follows = |p: &Parser| {
            !matches!(
                p.peek_at(1),
                TokenKind::Punct(Punct::LParen)
                    | TokenKind::Punct(Punct::Assign)
                    | TokenKind::Punct(Punct::Semi)
                    | TokenKind::Punct(Punct::RBrace)
            )
        };
        while !self.is_punct(Punct::RBrace) && !self.at_eof() {
            if self.eat_punct(Punct::Semi) {
                continue;
            }
            // `static { ... }` initialisation block.
            if self.is_kw(Keyword::Static)
                && matches!(self.peek_at(1), TokenKind::Punct(Punct::LBrace))
            {
                self.bump();
                let (body, _) = self.generator_scoped(false, |p| p.function_body())?;
                members.push(ClassMember {
                    key: PropKey::Static(String::new()),
                    def: Rc::new(FnDef {
                        name: None,
                        params: Vec::new(),
                        body,
                        arrow: false,
                        is_async: false,
                        is_expr_body: false,
                        is_generator: false,
                        strict: true,
                    }),
                    is_static: true,
                    kind: MemberKind::StaticBlock,
                });
                continue;
            }
            let is_static = self.is_kw(Keyword::Static) && name_follows(self);
            if is_static {
                self.bump();
            }
            let is_async = self.is_kw(Keyword::Async)
                && name_follows(self)
                && !self
                    .tokens
                    .get(self.pos.saturating_add(1))
                    .map(|t| t.newline_before)
                    .unwrap_or(true);
            if is_async {
                self.bump();
            }
            let is_generator = self.eat_punct(Punct::Star);
            let mut kind = MemberKind::Method;
            if (self.is_kw(Keyword::Get) || self.is_kw(Keyword::Set)) && name_follows(self) {
                kind = if self.is_kw(Keyword::Get) {
                    MemberKind::Get
                } else {
                    MemberKind::Set
                };
                self.bump();
            }
            let key = self.member_key()?;
            let static_name = match &key {
                PropKey::Static(s) => Some(s.clone()),
                PropKey::Computed(_) => None,
            };
            if self.is_punct(Punct::LParen) {
                let def = Rc::new(self.method_def(static_name.clone(), is_async, is_generator)?);
                if static_name.as_deref() == Some("constructor")
                    && kind == MemberKind::Method
                    && !is_static
                {
                    constructor = Some(def);
                } else {
                    members.push(ClassMember {
                        key,
                        def,
                        is_static,
                        kind,
                    });
                }
            } else {
                // Class field: `name = expr;` or bare `name;`. The
                // initializer is wrapped in a zero-arg function evaluated at
                // construction (instance) or class definition (static), with
                // `this` bound to the instance / constructor.
                let value = if self.eat_punct(Punct::Assign) {
                    self.assignment()?
                } else {
                    Expr::Undefined
                };
                self.semicolon_or_member_end()?;
                let def = Rc::new(FnDef {
                    name: static_name,
                    params: Vec::new(),
                    body: vec![Stmt::Return(Some(value))],
                    arrow: false,
                    is_async: false,
                    is_expr_body: true,
                    is_generator: false,
                    strict: true,
                });
                members.push(ClassMember {
                    key,
                    def,
                    is_static,
                    kind: MemberKind::Field,
                });
            }
        }
        self.expect_punct(Punct::RBrace, "expected }")?;
        Ok(ClassDef {
            name,
            parent,
            constructor,
            members,
        })
    }

    /// After a class field: `;`, a newline, `}` or EOF end it.
    fn semicolon_or_member_end(&mut self) -> Result<(), ParseError> {
        if self.eat_punct(Punct::Semi)
            || self.is_punct(Punct::RBrace)
            || self.at_eof()
            || self.newline_before()
        {
            return Ok(());
        }
        self.err("expected ; after class field")
    }

    fn expression(&mut self) -> Result<Expr, ParseError> {
        let first = self.assignment()?;
        if !self.is_punct(Punct::Comma) {
            return Ok(first);
        }
        let mut seq = vec![first];
        while self.eat_punct(Punct::Comma) {
            seq.push(self.assignment()?);
        }
        Ok(Expr::Sequence(seq))
    }

    fn assignment(&mut self) -> Result<Expr, ParseError> {
        self.depth = self.depth.saturating_add(1);
        let r = self.assignment_inner();
        self.depth = self.depth.saturating_sub(1);
        r
    }

    fn assignment_inner(&mut self) -> Result<Expr, ParseError> {
        if self.depth > MAX_DEPTH {
            return self.err("expression nesting too deep");
        }
        // `yield` / `yield x` / `yield* x` (generator bodies). A `yield`
        // directly followed by a token that cannot start an expression is
        // the bare form.
        if self.is_kw(Keyword::Yield) && self.in_generator > 0 {
            self.bump();
            let delegate = self.eat_punct(Punct::Star);
            let ends = self.at_eof()
                || self.newline_before()
                || matches!(
                    self.peek(),
                    TokenKind::Punct(
                        Punct::RParen
                            | Punct::RBracket
                            | Punct::RBrace
                            | Punct::Comma
                            | Punct::Semi
                            | Punct::Colon
                    )
                );
            let arg = if ends && !delegate {
                None
            } else {
                Some(Box::new(self.assignment()?))
            };
            return Ok(Expr::Yield { arg, delegate });
        }
        // Arrow functions: `x => ...`, `(a, b) => ...`, `async x => ...`.
        if let Some(arrow) = self.try_arrow()? {
            return Ok(arrow);
        }
        let target = self.conditional()?;
        let op = match self.peek() {
            TokenKind::Punct(Punct::Assign) => Some(AssignOp::Assign),
            TokenKind::Punct(Punct::PlusAssign) => Some(AssignOp::Add),
            TokenKind::Punct(Punct::MinusAssign) => Some(AssignOp::Sub),
            TokenKind::Punct(Punct::StarAssign) => Some(AssignOp::Mul),
            TokenKind::Punct(Punct::SlashAssign) => Some(AssignOp::Div),
            TokenKind::Punct(Punct::PercentAssign) => Some(AssignOp::Rem),
            TokenKind::Punct(Punct::StarStarAssign) => Some(AssignOp::Pow),
            TokenKind::Punct(Punct::AmpAssign) => Some(AssignOp::BitAnd),
            TokenKind::Punct(Punct::PipeAssign) => Some(AssignOp::BitOr),
            TokenKind::Punct(Punct::CaretAssign) => Some(AssignOp::BitXor),
            TokenKind::Punct(Punct::ShlAssign) => Some(AssignOp::Shl),
            TokenKind::Punct(Punct::ShrAssign) => Some(AssignOp::Shr),
            TokenKind::Punct(Punct::UShrAssign) => Some(AssignOp::UShr),
            TokenKind::Punct(Punct::AndAssign) => Some(AssignOp::And),
            TokenKind::Punct(Punct::OrAssign) => Some(AssignOp::Or),
            TokenKind::Punct(Punct::QuestionQuestionAssign) => Some(AssignOp::Nullish),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let value = self.assignment()?;
            return Ok(Expr::Assign {
                op,
                target: Box::new(target),
                value: Box::new(value),
            });
        }
        // `{x = 1}` is only legal as a destructuring-assignment target; as a
        // stand-alone object literal it is a syntax error.
        if let Expr::Object(props) = &target {
            if props
                .iter()
                .any(|p| matches!(p, ObjectProp::ShorthandDefault(..)))
            {
                return self.err("invalid shorthand property initializer");
            }
        }
        Ok(target)
    }

    /// Try to parse an arrow function from the current position; backtracks
    /// and returns None when the tokens are not an arrow head.
    fn try_arrow(&mut self) -> Result<Option<Expr>, ParseError> {
        let save = self.pos;
        let is_async = if self.is_kw(Keyword::Async)
            && !self
                .tokens
                .get(self.pos.saturating_add(1))
                .map(|t| t.newline_before)
                .unwrap_or(true)
            && (matches!(self.peek_at(1), TokenKind::Ident(_))
                || matches!(self.peek_at(1), TokenKind::Punct(Punct::LParen)))
        {
            self.bump();
            true
        } else {
            false
        };

        // Single identifier arrow.
        if let TokenKind::Ident(name) = self.peek().clone() {
            if matches!(self.peek_at(1), TokenKind::Punct(Punct::Arrow)) {
                self.bump();
                self.bump();
                let params = vec![PatternElem {
                    pat: Pattern::Ident(name),
                    default: None,
                    rest: false,
                }];
                return Ok(Some(self.arrow_body(params, is_async)?));
            }
            if is_async {
                self.pos = save;
                return Ok(None);
            }
        }

        // Parenthesized parameter list arrow.
        if self.is_punct(Punct::LParen) {
            // Scan ahead for the matching ) and check the next token is =>.
            let mut depth = 0usize;
            let mut i = self.pos;
            let close = loop {
                match self.tokens.get(i).map(|t| &t.kind) {
                    None | Some(TokenKind::Eof) => break None,
                    Some(TokenKind::Punct(Punct::LParen)) => depth = depth.saturating_add(1),
                    Some(TokenKind::Punct(Punct::RParen)) => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break Some(i);
                        }
                    }
                    _ => {}
                }
                i = i.saturating_add(1);
            };
            if let Some(close) = close {
                if matches!(
                    self.tokens.get(close.saturating_add(1)).map(|t| &t.kind),
                    Some(TokenKind::Punct(Punct::Arrow))
                ) {
                    self.bump(); // (
                    let params = self.params_rest()?;
                    if !self.eat_punct(Punct::Arrow) {
                        self.pos = save;
                        return Ok(None);
                    }
                    return Ok(Some(self.arrow_body(params, is_async)?));
                }
            }
        }
        self.pos = save;
        Ok(None)
    }

    fn arrow_body(&mut self, params: Vec<PatternElem>, is_async: bool) -> Result<Expr, ParseError> {
        if self.is_punct(Punct::LBrace) {
            let (body, strict) = self.generator_scoped(false, |p| p.function_body())?;
            Ok(Expr::Function(Rc::new(FnDef {
                name: None,
                params,
                body,
                arrow: true,
                is_async,
                is_expr_body: false,
                is_generator: false,
                strict,
            })))
        } else {
            let strict = self.strict;
            let value = self.assignment()?;
            Ok(Expr::Function(Rc::new(FnDef {
                name: None,
                params,
                body: vec![Stmt::Return(Some(value))],
                arrow: true,
                is_async,
                is_expr_body: true,
                is_generator: false,
                strict,
            })))
        }
    }

    fn conditional(&mut self) -> Result<Expr, ParseError> {
        let cond = self.nullish()?;
        if self.eat_punct(Punct::Question) {
            let then = self.assignment()?;
            self.expect_punct(Punct::Colon, "expected : in conditional")?;
            let alt = self.assignment()?;
            return Ok(Expr::Cond {
                cond: Box::new(cond),
                then: Box::new(then),
                alt: Box::new(alt),
            });
        }
        Ok(cond)
    }

    fn nullish(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.logical_or()?;
        while self.eat_punct(Punct::QuestionQuestion) {
            let right = self.logical_or()?;
            left = Expr::Logical {
                op: LogicalOp::Nullish,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn logical_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.logical_and()?;
        while self.eat_punct(Punct::OrOr) {
            let right = self.logical_and()?;
            left = Expr::Logical {
                op: LogicalOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn logical_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.bitor()?;
        while self.eat_punct(Punct::AndAnd) {
            let right = self.bitor()?;
            left = Expr::Logical {
                op: LogicalOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn bitor(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.bitxor()?;
        while self.is_punct(Punct::Pipe) {
            self.bump();
            let right = self.bitxor()?;
            left = Expr::Binary {
                op: BinaryOp::BitOr,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn bitxor(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.bitand()?;
        while self.is_punct(Punct::Caret) {
            self.bump();
            let right = self.bitand()?;
            left = Expr::Binary {
                op: BinaryOp::BitXor,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn bitand(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.equality()?;
        while self.is_punct(Punct::Amp) {
            self.bump();
            let right = self.equality()?;
            left = Expr::Binary {
                op: BinaryOp::BitAnd,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn equality(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.relational()?;
        loop {
            let op = match self.peek() {
                TokenKind::Punct(Punct::Eq) => BinaryOp::Eq,
                TokenKind::Punct(Punct::NotEq) => BinaryOp::NotEq,
                TokenKind::Punct(Punct::StrictEq) => BinaryOp::StrictEq,
                TokenKind::Punct(Punct::StrictNotEq) => BinaryOp::StrictNotEq,
                _ => break,
            };
            self.bump();
            let right = self.relational()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn relational(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.shift()?;
        loop {
            let op = match self.peek() {
                TokenKind::Punct(Punct::Lt) => BinaryOp::Lt,
                TokenKind::Punct(Punct::Gt) => BinaryOp::Gt,
                TokenKind::Punct(Punct::LtEq) => BinaryOp::LtEq,
                TokenKind::Punct(Punct::GtEq) => BinaryOp::GtEq,
                TokenKind::Keyword(Keyword::In) => BinaryOp::In,
                TokenKind::Keyword(Keyword::Instanceof) => BinaryOp::Instanceof,
                _ => break,
            };
            self.bump();
            let right = self.shift()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn shift(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.additive()?;
        loop {
            let op = match self.peek() {
                TokenKind::Punct(Punct::Shl) => BinaryOp::Shl,
                TokenKind::Punct(Punct::Shr) => BinaryOp::Shr,
                TokenKind::Punct(Punct::UShr) => BinaryOp::UShr,
                _ => break,
            };
            self.bump();
            let right = self.additive()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn additive(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.multiplicative()?;
        loop {
            let op = match self.peek() {
                TokenKind::Punct(Punct::Plus) => BinaryOp::Add,
                TokenKind::Punct(Punct::Minus) => BinaryOp::Sub,
                _ => break,
            };
            self.bump();
            let right = self.multiplicative()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.exponent()?;
        loop {
            let op = match self.peek() {
                TokenKind::Punct(Punct::Star) => BinaryOp::Mul,
                TokenKind::Punct(Punct::Slash) => BinaryOp::Div,
                TokenKind::Punct(Punct::Percent) => BinaryOp::Rem,
                _ => break,
            };
            self.bump();
            let right = self.exponent()?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn exponent(&mut self) -> Result<Expr, ParseError> {
        let base = self.unary()?;
        if self.is_punct(Punct::StarStar) {
            self.bump();
            let exp = self.exponent()?; // right-associative
            return Ok(Expr::Binary {
                op: BinaryOp::Pow,
                left: Box::new(base),
                right: Box::new(exp),
            });
        }
        Ok(base)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        self.depth = self.depth.saturating_add(1);
        let r = self.unary_inner();
        self.depth = self.depth.saturating_sub(1);
        r
    }

    fn unary_inner(&mut self) -> Result<Expr, ParseError> {
        if self.depth > MAX_DEPTH {
            return self.err("expression nesting too deep");
        }
        let op = match self.peek() {
            TokenKind::Punct(Punct::Minus) => Some(UnaryOp::Neg),
            TokenKind::Punct(Punct::Plus) => Some(UnaryOp::Plus),
            TokenKind::Punct(Punct::Not) => Some(UnaryOp::Not),
            TokenKind::Punct(Punct::Tilde) => Some(UnaryOp::BitNot),
            TokenKind::Keyword(Keyword::Typeof) => Some(UnaryOp::Typeof),
            TokenKind::Keyword(Keyword::Void) => Some(UnaryOp::Void),
            TokenKind::Keyword(Keyword::Delete) => Some(UnaryOp::Delete),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let expr = self.unary()?;
            return Ok(Expr::Unary {
                op,
                expr: Box::new(expr),
            });
        }
        if self.is_kw(Keyword::Await) {
            self.bump();
            let expr = self.unary()?;
            return Ok(Expr::Await(Box::new(expr)));
        }
        if self.is_punct(Punct::PlusPlus) || self.is_punct(Punct::MinusMinus) {
            let op = if self.is_punct(Punct::PlusPlus) {
                UpdateOp::Inc
            } else {
                UpdateOp::Dec
            };
            self.bump();
            let target = self.unary()?;
            return Ok(Expr::Update {
                op,
                prefix: true,
                target: Box::new(target),
            });
        }
        let mut expr = self.postfix()?;
        if !self.newline_before()
            && (self.is_punct(Punct::PlusPlus) || self.is_punct(Punct::MinusMinus))
        {
            let op = if self.is_punct(Punct::PlusPlus) {
                UpdateOp::Inc
            } else {
                UpdateOp::Dec
            };
            self.bump();
            expr = Expr::Update {
                op,
                prefix: false,
                target: Box::new(expr),
            };
        }
        Ok(expr)
    }

    fn postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = if self.is_kw(Keyword::New) {
            self.parse_new()?
        } else {
            self.primary()?
        };
        loop {
            match self.peek().clone() {
                TokenKind::Punct(Punct::Dot) => {
                    self.bump();
                    // `this.#x`: a private name keeps its `#` as the key, the
                    // same spelling the class body installed it under.
                    let private = matches!(self.peek(), TokenKind::Error('#'));
                    if private {
                        self.bump();
                    }
                    let name = match self.prop_name() {
                        Some(n) if private => format!("#{n}"),
                        Some(n) => n,
                        None => return self.err("expected property name after ."),
                    };
                    expr = Expr::Member {
                        object: Box::new(expr),
                        property: MemberKey::Static(name),
                        optional: false,
                    };
                }
                TokenKind::Punct(Punct::QuestionDot) => {
                    self.bump();
                    if self.is_punct(Punct::LParen) {
                        self.bump();
                        let args = self.args_rest()?;
                        expr = Expr::Call {
                            callee: Box::new(expr),
                            args,
                            optional: true,
                        };
                    } else if self.is_punct(Punct::LBracket) {
                        self.bump();
                        let key = self.expression()?;
                        self.expect_punct(Punct::RBracket, "expected ]")?;
                        expr = Expr::Member {
                            object: Box::new(expr),
                            property: MemberKey::Computed(Box::new(key)),
                            optional: true,
                        };
                    } else {
                        let name = match self.prop_name() {
                            Some(n) => n,
                            None => return self.err("expected property name after ?."),
                        };
                        expr = Expr::Member {
                            object: Box::new(expr),
                            property: MemberKey::Static(name),
                            optional: true,
                        };
                    }
                }
                TokenKind::Punct(Punct::LBracket) => {
                    self.bump();
                    let key = self.expression()?;
                    self.expect_punct(Punct::RBracket, "expected ]")?;
                    expr = Expr::Member {
                        object: Box::new(expr),
                        property: MemberKey::Computed(Box::new(key)),
                        optional: false,
                    };
                }
                TokenKind::Punct(Punct::LParen) => {
                    self.bump();
                    let args = self.args_rest()?;
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        args,
                        optional: false,
                    };
                }
                TokenKind::Template(parts) => {
                    // Tagged template: lower to a call with the cooked strings
                    // array and the expression values.
                    self.bump();
                    let mut strings = Vec::new();
                    let mut exprs = Vec::new();
                    for part in parts {
                        match part {
                            TemplatePart::Str(s) => strings.push(s),
                            TemplatePart::Expr(src) => {
                                exprs.push(parse_substitution(&src, self.in_generator, self.strict)?);
                            }
                        }
                    }
                    let mut args = vec![SpreadElem {
                        expr: Expr::Array(
                            strings
                                .into_iter()
                                .map(|s| {
                                    Some(SpreadElem {
                                        expr: Expr::Str(s),
                                        spread: false,
                                    })
                                })
                                .collect(),
                        ),
                        spread: false,
                    }];
                    for e in exprs {
                        args.push(SpreadElem {
                            expr: e,
                            spread: false,
                        });
                    }
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        args,
                        optional: false,
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_new(&mut self) -> Result<Expr, ParseError> {
        self.bump(); // new
        // `new.target`: the interpreter binds it per call as a hidden name.
        if self.eat_punct(Punct::Dot) {
            return match self.ident_like() {
                Some(n) if n == "target" => Ok(Expr::Ident("new.target".to_string())),
                _ => self.err("expected new.target"),
            };
        }
        let mut callee = if self.is_kw(Keyword::New) {
            self.parse_new()?
        } else {
            self.primary()?
        };
        // Member chain binds tighter than the call in `new a.b.C()`.
        loop {
            match self.peek().clone() {
                TokenKind::Punct(Punct::Dot) => {
                    self.bump();
                    let name = match self.prop_name() {
                        Some(n) => n,
                        None => return self.err("expected property after . in new"),
                    };
                    callee = Expr::Member {
                        object: Box::new(callee),
                        property: MemberKey::Static(name),
                        optional: false,
                    };
                }
                TokenKind::Punct(Punct::LBracket) => {
                    self.bump();
                    let key = self.expression()?;
                    self.expect_punct(Punct::RBracket, "expected ]")?;
                    callee = Expr::Member {
                        object: Box::new(callee),
                        property: MemberKey::Computed(Box::new(key)),
                        optional: false,
                    };
                }
                _ => break,
            }
        }
        let args = if self.eat_punct(Punct::LParen) {
            self.args_rest()?
        } else {
            Vec::new()
        };
        Ok(Expr::New {
            callee: Box::new(callee),
            args,
        })
    }

    fn args_rest(&mut self) -> Result<Vec<SpreadElem>, ParseError> {
        let mut args = Vec::new();
        while !self.is_punct(Punct::RParen) && !self.at_eof() {
            let spread = self.eat_punct(Punct::DotDotDot);
            let expr = self.assignment()?;
            args.push(SpreadElem { expr, spread });
            if !self.is_punct(Punct::RParen) {
                self.expect_punct(Punct::Comma, "expected , in arguments")?;
            }
        }
        self.expect_punct(Punct::RParen, "expected )")?;
        Ok(args)
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.bump() {
            TokenKind::Num(n) => Ok(Expr::Num(n)),
            TokenKind::Str(s) => Ok(Expr::Str(s)),
            TokenKind::Regex { source, flags } => Ok(Expr::Regex { source, flags }),
            TokenKind::Template(parts) => {
                let mut elems = Vec::new();
                for part in parts {
                    match part {
                        TemplatePart::Str(s) => elems.push(TemplateElem::Str(s)),
                        TemplatePart::Expr(src) => {
                            let e = parse_substitution(&src, self.in_generator, self.strict)?;
                            elems.push(TemplateElem::Expr(Box::new(e)));
                        }
                    }
                }
                Ok(Expr::Template(elems))
            }
            TokenKind::Ident(name) => Ok(Expr::Ident(name)),
            TokenKind::Keyword(Keyword::This) => Ok(Expr::This),
            TokenKind::Keyword(Keyword::Null) => Ok(Expr::Null),
            TokenKind::Keyword(Keyword::Undefined) => Ok(Expr::Undefined),
            TokenKind::Keyword(Keyword::True) => Ok(Expr::Bool(true)),
            TokenKind::Keyword(Keyword::False) => Ok(Expr::Bool(false)),
            TokenKind::Keyword(Keyword::Function) => {
                let f = self.function_rest(false)?;
                Ok(Expr::Function(Rc::new(f)))
            }
            TokenKind::Keyword(Keyword::Async)
                if self.is_kw(Keyword::Function) && !self.newline_before() =>
            {
                self.bump();
                let f = self.function_rest(true)?;
                Ok(Expr::Function(Rc::new(f)))
            }
            TokenKind::Keyword(Keyword::Let) => Ok(Expr::Ident("let".to_string())),
            TokenKind::Keyword(Keyword::Class) => {
                let c = self.class_rest()?;
                Ok(Expr::Class(Rc::new(c)))
            }
            TokenKind::Keyword(Keyword::Super) => {
                // super.x / super(...) are handled by the interpreter via
                // the special identifier.
                Ok(Expr::Ident("super".to_string()))
            }
            TokenKind::Keyword(Keyword::Get) => Ok(Expr::Ident("get".to_string())),
            TokenKind::Keyword(Keyword::Set) => Ok(Expr::Ident("set".to_string())),
            TokenKind::Keyword(Keyword::Of) => Ok(Expr::Ident("of".to_string())),
            TokenKind::Keyword(Keyword::Static) => Ok(Expr::Ident("static".to_string())),
            TokenKind::Keyword(Keyword::Async) => Ok(Expr::Ident("async".to_string())),
            TokenKind::Keyword(Keyword::Await) => {
                // `await` in non-async position — treat as identifier.
                Ok(Expr::Ident("await".to_string()))
            }
            TokenKind::Keyword(Keyword::Yield) => Ok(Expr::Ident("yield".to_string())),
            TokenKind::Punct(Punct::LParen) => {
                let e = self.expression()?;
                self.expect_punct(Punct::RParen, "expected )")?;
                Ok(e)
            }
            TokenKind::Punct(Punct::LBracket) => {
                let mut elems = Vec::new();
                while !self.is_punct(Punct::RBracket) && !self.at_eof() {
                    if self.eat_punct(Punct::Comma) {
                        elems.push(None);
                        continue;
                    }
                    let spread = self.eat_punct(Punct::DotDotDot);
                    let expr = self.assignment()?;
                    elems.push(Some(SpreadElem { expr, spread }));
                    if !self.is_punct(Punct::RBracket) && !self.eat_punct(Punct::Comma) {
                        break;
                    }
                }
                self.expect_punct(Punct::RBracket, "expected ]")?;
                Ok(Expr::Array(elems))
            }
            TokenKind::Punct(Punct::LBrace) => {
                let mut props = Vec::new();
                while !self.is_punct(Punct::RBrace) && !self.at_eof() {
                    if self.eat_punct(Punct::DotDotDot) {
                        let e = self.assignment()?;
                        props.push(ObjectProp::Spread(e));
                    } else {
                        let is_async = self.is_kw(Keyword::Async)
                            && !matches!(
                                self.peek_at(1),
                                TokenKind::Punct(Punct::Colon)
                                    | TokenKind::Punct(Punct::Comma)
                                    | TokenKind::Punct(Punct::RBrace)
                                    | TokenKind::Punct(Punct::LParen)
                                    | TokenKind::Punct(Punct::Assign)
                            );
                        if is_async {
                            self.bump();
                        }
                        let is_generator = self.eat_punct(Punct::Star);
                        let accessor = if (self.is_kw(Keyword::Get) || self.is_kw(Keyword::Set))
                            && !matches!(
                                self.peek_at(1),
                                TokenKind::Punct(Punct::Colon)
                                    | TokenKind::Punct(Punct::Comma)
                                    | TokenKind::Punct(Punct::RBrace)
                                    | TokenKind::Punct(Punct::LParen)
                                    | TokenKind::Punct(Punct::Assign)
                            ) {
                            let k = if self.is_kw(Keyword::Get) {
                                MethodKind::Get
                            } else {
                                MethodKind::Set
                            };
                            self.bump();
                            Some(k)
                        } else {
                            None
                        };
                        // Computed key: [expr]
                        let key = if self.is_punct(Punct::LBracket) {
                            self.bump();
                            let e = self.assignment()?;
                            self.expect_punct(Punct::RBracket, "expected ]")?;
                            PropKey::Computed(Box::new(e))
                        } else {
                            match self.prop_name() {
                                Some(n) => PropKey::Static(n),
                                None => return self.err("expected property name"),
                            }
                        };
                        if self.is_punct(Punct::LParen) {
                            // Method (or accessor).
                            let name = match &key {
                                PropKey::Static(s) => Some(s.clone()),
                                PropKey::Computed(_) => None,
                            };
                            let def = Rc::new(self.method_def(name, is_async, is_generator)?);
                            props.push(ObjectProp::Method(
                                key,
                                def,
                                accessor.unwrap_or(MethodKind::Method),
                            ));
                        } else if self.eat_punct(Punct::Colon) {
                            let v = self.assignment()?;
                            props.push(ObjectProp::KeyValue(key, v));
                        } else {
                            match key {
                                PropKey::Static(name) => {
                                    if self.eat_punct(Punct::Assign) {
                                        // Cover grammar `{x = 1}`: a
                                        // destructuring-assignment default.
                                        let d = self.assignment()?;
                                        props.push(ObjectProp::ShorthandDefault(name, d));
                                    } else {
                                        props.push(ObjectProp::Shorthand(name));
                                    }
                                }
                                PropKey::Computed(_) => {
                                    return self.err("computed key needs a value")
                                }
                            }
                        }
                    }
                    if !self.is_punct(Punct::RBrace) && !self.eat_punct(Punct::Comma) {
                        break;
                    }
                }
                self.expect_punct(Punct::RBrace, "expected }")?;
                Ok(Expr::Object(props))
            }
            TokenKind::Punct(Punct::DotDotDot) => {
                let e = self.assignment()?;
                Ok(Expr::Spread(Box::new(e)))
            }
            TokenKind::Eof => self.err("unexpected end of script"),
            TokenKind::Error(c) => Err(ParseError {
                message: format!("unexpected character '{c}'"),
                pos: self.cur_pos(),
            }),
            other => Err(ParseError {
                message: format!("unexpected token {other:?}"),
                pos: self.cur_pos(),
            }),
        }
    }
}

fn keyword_text(k: Keyword) -> &'static str {
    match k {
        Keyword::Var => "var",
        Keyword::Let => "let",
        Keyword::Const => "const",
        Keyword::Function => "function",
        Keyword::Return => "return",
        Keyword::If => "if",
        Keyword::Else => "else",
        Keyword::For => "for",
        Keyword::While => "while",
        Keyword::Do => "do",
        Keyword::Break => "break",
        Keyword::Continue => "continue",
        Keyword::New => "new",
        Keyword::Delete => "delete",
        Keyword::Typeof => "typeof",
        Keyword::Instanceof => "instanceof",
        Keyword::In => "in",
        Keyword::Of => "of",
        Keyword::This => "this",
        Keyword::Null => "null",
        Keyword::True => "true",
        Keyword::False => "false",
        Keyword::Undefined => "undefined",
        Keyword::Switch => "switch",
        Keyword::Case => "case",
        Keyword::Default => "default",
        Keyword::Throw => "throw",
        Keyword::Try => "try",
        Keyword::Catch => "catch",
        Keyword::Finally => "finally",
        Keyword::Class => "class",
        Keyword::Extends => "extends",
        Keyword::Super => "super",
        Keyword::Async => "async",
        Keyword::Await => "await",
        Keyword::Yield => "yield",
        Keyword::Void => "void",
        Keyword::Get => "get",
        Keyword::Set => "set",
        Keyword::Static => "static",
    }
}

fn num_to_prop(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}
