//! lexer — tokenize JavaScript source, std-only and panic-free.
//!
//! Scope: the language subset that drives real pages (ES2017-ish minus
//! modules): all expression/statement punctuation, string/template/numeric
//! literals, regex literals (disambiguated from division by previous-token
//! context), comments, and automatic-semicolon-relevant newline tracking.
//!
//! Hostile input never panics: every access is bounds-checked and unknown
//! characters become `Token::Error`, which the parser reports as a syntax
//! error for the enclosing script.

/// A single token with its source span and newline flag.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    /// Byte offset where the token starts (for error messages).
    pub pos: usize,
    /// A line terminator appeared between the previous token and this one
    /// (drives automatic semicolon insertion and restricted productions).
    pub newline_before: bool,
}

/// Token kinds. Keywords are distinguished from identifiers at lex time.
#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    Ident(String),
    Keyword(Keyword),
    Num(f64),
    Str(String),
    /// Template literal parts: cooked strings + the raw expressions between.
    Template(Vec<TemplatePart>),
    Regex {
        source: String,
        flags: String,
    },
    Punct(Punct),
    Eof,
    /// An unrecognized character; surfaces as a syntax error at parse time.
    Error(char),
}

/// One segment of a template literal.
#[derive(Clone, Debug, PartialEq)]
pub enum TemplatePart {
    /// Literal (cooked) text.
    Str(String),
    /// `${ ... }` — the source of the embedded expression, re-lexed by the
    /// parser.
    Expr(String),
}

/// Reserved words the parser treats specially.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyword {
    Var,
    Let,
    Const,
    Function,
    Return,
    If,
    Else,
    For,
    While,
    Do,
    Break,
    Continue,
    New,
    Delete,
    Typeof,
    Instanceof,
    In,
    Of,
    This,
    Null,
    True,
    False,
    Undefined,
    Switch,
    Case,
    Default,
    Throw,
    Try,
    Catch,
    Finally,
    Class,
    Extends,
    Super,
    Async,
    Await,
    Yield,
    Void,
    Get,
    Set,
    Static,
}

impl Keyword {
    fn from_str(s: &str) -> Option<Keyword> {
        Some(match s {
            "var" => Keyword::Var,
            "let" => Keyword::Let,
            "const" => Keyword::Const,
            "function" => Keyword::Function,
            "return" => Keyword::Return,
            "if" => Keyword::If,
            "else" => Keyword::Else,
            "for" => Keyword::For,
            "while" => Keyword::While,
            "do" => Keyword::Do,
            "break" => Keyword::Break,
            "continue" => Keyword::Continue,
            "new" => Keyword::New,
            "delete" => Keyword::Delete,
            "typeof" => Keyword::Typeof,
            "instanceof" => Keyword::Instanceof,
            "in" => Keyword::In,
            "of" => Keyword::Of,
            "this" => Keyword::This,
            "null" => Keyword::Null,
            "true" => Keyword::True,
            "false" => Keyword::False,
            "undefined" => Keyword::Undefined,
            "switch" => Keyword::Switch,
            "case" => Keyword::Case,
            "default" => Keyword::Default,
            "throw" => Keyword::Throw,
            "try" => Keyword::Try,
            "catch" => Keyword::Catch,
            "finally" => Keyword::Finally,
            "class" => Keyword::Class,
            "extends" => Keyword::Extends,
            "super" => Keyword::Super,
            "async" => Keyword::Async,
            "await" => Keyword::Await,
            "yield" => Keyword::Yield,
            "void" => Keyword::Void,
            "get" => Keyword::Get,
            "set" => Keyword::Set,
            "static" => Keyword::Static,
            _ => return None,
        })
    }
}

/// Punctuators and operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Punct {
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Comma,
    Dot,
    DotDotDot,
    Arrow,
    Question,
    QuestionDot,
    QuestionQuestion,
    Colon,
    Assign,
    PlusAssign,
    MinusAssign,
    StarAssign,
    SlashAssign,
    PercentAssign,
    StarStarAssign,
    AmpAssign,
    PipeAssign,
    CaretAssign,
    ShlAssign,
    ShrAssign,
    UShrAssign,
    AndAssign,
    OrAssign,
    QuestionQuestionAssign,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    StarStar,
    PlusPlus,
    MinusMinus,
    Eq,
    NotEq,
    StrictEq,
    StrictNotEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,
    UShr,
    AndAnd,
    OrOr,
    Not,
}

/// Inside a template substitution scan: whether a `/` following the last
/// significant character opens a regex literal. After a value-ending
/// character (identifier, number, closing bracket, quote) it is division;
/// after an operator, opening bracket, comma or at the start it is a regex.
/// Identifier characters are conservatively treated as values, which also
/// covers keywords such as `return` (rare inside a substitution).
fn regex_after(last: Option<char>) -> bool {
    match last {
        None => true,
        Some(c) => !(c.is_alphanumeric()
            || matches!(c, '_' | '$' | ')' | ']' | '}' | '"' | '\'' | '`')),
    }
}

/// Tokenize `src` completely. Never fails; malformed pieces become
/// `TokenKind::Error` tokens the parser turns into a script-level error.
pub fn lex(src: &str) -> Vec<Token> {
    Lexer {
        chars: src.chars().collect(),
        pos: 0,
        out: Vec::new(),
        newline: false,
    }
    .run()
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    out: Vec<Token>,
    newline: bool,
}

impl Lexer {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn peek2(&self) -> Option<char> {
        self.chars.get(self.pos.saturating_add(1)).copied()
    }
    fn peek3(&self) -> Option<char> {
        self.chars.get(self.pos.saturating_add(2)).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos = self.pos.saturating_add(1);
        }
        c
    }
    fn push(&mut self, kind: TokenKind, pos: usize) {
        let newline_before = self.newline;
        self.newline = false;
        self.out.push(Token {
            kind,
            pos,
            newline_before,
        });
    }

    /// The previous significant token decides whether `/` starts a regex
    /// (expression position) or is division (after a value).
    fn regex_allowed(&self) -> bool {
        match self.out.last().map(|t| &t.kind) {
            None => true,
            Some(TokenKind::Ident(_))
            | Some(TokenKind::Num(_))
            | Some(TokenKind::Str(_))
            | Some(TokenKind::Template(_))
            | Some(TokenKind::Regex { .. }) => false,
            Some(TokenKind::Keyword(k)) => !matches!(
                k,
                Keyword::This
                    | Keyword::Null
                    | Keyword::True
                    | Keyword::False
                    | Keyword::Undefined
                    | Keyword::Super
            ),
            Some(TokenKind::Punct(Punct::RParen)) => {
                // `)` closes a VALUE (`(a+b) / 2`) except when it closes the
                // head of `if` / `while` / `for` / `with`, after which a
                // statement — and so a regex literal — begins:
                // `for (x of xs) /re/.test(x)`.
                self.paren_closes_statement_head()
            }
            Some(TokenKind::Punct(Punct::RBrace)) => {
                // `}` closes a VALUE only when it ends an object literal in
                // expression position; a block's `}` is followed by a new
                // statement, where `/` opens a regex. The distinction needs
                // the parser, so the lexer takes the statement reading when
                // the brace closes a `{` that itself followed a `)` / `{` /
                // `}` / `;` / `else` / `do` / `try` / `finally` / an arrow
                // (a block), and the value reading otherwise. A line break
                // before the `/` also reads as a new statement: no minifier
                // emits `}\n/2`, while `var o = {}\n/re/.test(s)` is common.
                self.newline || self.brace_closes_block()
            }
            Some(TokenKind::Punct(p)) => !matches!(
                p,
                Punct::RBracket | Punct::PlusPlus | Punct::MinusMinus
            ),
            _ => true,
        }
    }

    /// Index of the token matching the LAST emitted closing delimiter
    /// (`)` or `}`), scanning back over nested pairs of the same kind.
    fn matching_open(&self, open: Punct, close: Punct) -> Option<usize> {
        let mut depth = 0usize;
        for (i, tok) in self.out.iter().enumerate().rev() {
            match &tok.kind {
                TokenKind::Punct(p) if *p == close => depth = depth.saturating_add(1),
                TokenKind::Punct(p) if *p == open => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Whether the `)` just emitted closes an `if (…)` / `while (…)` /
    /// `for (…)` / `with (…)` head: walk back to its matching `(` (over any
    /// nested parentheses) and look at the token before it.
    fn paren_closes_statement_head(&self) -> bool {
        let Some(open) = self.matching_open(Punct::LParen, Punct::RParen) else {
            return false;
        };
        let before = open.checked_sub(1).and_then(|i| self.out.get(i)).map(|t| &t.kind);
        matches!(
            before,
            Some(TokenKind::Keyword(Keyword::If | Keyword::While | Keyword::For))
        )
    }

    /// Whether the `}` just emitted closes a BLOCK (so a statement, and
    /// possibly a regex literal, follows) rather than an object literal.
    fn brace_closes_block(&self) -> bool {
        let Some(open) = self.matching_open(Punct::LBrace, Punct::RBrace) else {
            return true;
        };
        let before = open.checked_sub(1).and_then(|i| self.out.get(i)).map(|t| &t.kind);
        match before {
            // Start of input: a block.
            None => true,
            // `) {`, `{ {`, `} {`, `; {`, `=> {`: a block body.
            Some(TokenKind::Punct(
                Punct::RParen | Punct::LBrace | Punct::RBrace | Punct::Semi | Punct::Arrow,
            )) => true,
            Some(TokenKind::Keyword(
                Keyword::Else | Keyword::Do | Keyword::Try | Keyword::Finally,
            )) => true,
            // `= {`, `( {`, `, {`, `return {`, `: {` …: an object literal.
            _ => false,
        }
    }

    fn run(mut self) -> Vec<Token> {
        loop {
            // Skip whitespace and comments, tracking line terminators.
            loop {
                match self.peek() {
                    Some(c) if c == '\n' || c == '\u{2028}' || c == '\u{2029}' => {
                        self.newline = true;
                        self.bump();
                    }
                    Some(c) if c.is_whitespace() => {
                        self.bump();
                    }
                    Some('/') if self.peek2() == Some('/') => {
                        while let Some(c) = self.peek() {
                            if c == '\n' {
                                break;
                            }
                            self.bump();
                        }
                    }
                    Some('/') if self.peek2() == Some('*') => {
                        self.bump();
                        self.bump();
                        loop {
                            match self.bump() {
                                None => break,
                                Some('\n') => self.newline = true,
                                Some('*') if self.peek() == Some('/') => {
                                    self.bump();
                                    break;
                                }
                                Some(_) => {}
                            }
                        }
                    }
                    // HTML-like comments (ES Annex B.1.1, classic scripts
                    // only): `<!--` opens a single-line comment anywhere,
                    // and `-->` does so at the start of a line. Legacy
                    // inline scripts still wrap their body in them (`<!--`
                    // … `//-->`), and Chrome runs the body; before this the
                    // `<` was a syntax error and the whole script was lost.
                    Some('<')
                        if self.peek2() == Some('!')
                            && self.peek3() == Some('-')
                            && self.chars.get(self.pos.saturating_add(3)) == Some(&'-') =>
                    {
                        self.skip_to_line_end();
                    }
                    Some('-')
                        if self.peek2() == Some('-')
                            && self.peek3() == Some('>')
                            && (self.newline || self.out.is_empty()) =>
                    {
                        self.skip_to_line_end();
                    }
                    _ => break,
                }
            }
            let pos = self.pos;
            let Some(c) = self.peek() else {
                self.push(TokenKind::Eof, pos);
                return self.out;
            };
            if c.is_ascii_alphabetic() || c == '_' || c == '$' || !c.is_ascii() {
                let mut ident = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '$' || !c.is_ascii() {
                        ident.push(c);
                        self.bump();
                    } else {
                        break;
                    }
                }
                match Keyword::from_str(&ident) {
                    Some(k) => self.push(TokenKind::Keyword(k), pos),
                    None => self.push(TokenKind::Ident(ident), pos),
                }
            } else if c.is_ascii_digit()
                || (c == '.' && self.peek2().is_some_and(|d| d.is_ascii_digit()))
            {
                self.lex_number(pos);
            } else if c == '"' || c == '\'' {
                self.lex_string(c, pos);
            } else if c == '`' {
                self.lex_template(pos);
            } else if c == '/' && self.regex_allowed() {
                self.lex_regex(pos);
            } else {
                self.lex_punct(pos);
            }
        }
    }

    /// Consume the rest of the current line (the line terminator itself
    /// is left for the outer loop, which records it as a newline).
    fn skip_to_line_end(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' || c == '\u{2028}' || c == '\u{2029}' {
                break;
            }
            self.bump();
        }
    }

    fn lex_number(&mut self, pos: usize) {
        let mut text = String::new();
        // Hex / octal / binary.
        if self.peek() == Some('0')
            && matches!(
                self.peek2(),
                Some('x') | Some('X') | Some('o') | Some('O') | Some('b') | Some('B')
            )
        {
            self.bump();
            let radix_char = self.bump().unwrap_or('x');
            let radix = match radix_char {
                'x' | 'X' => 16,
                'o' | 'O' => 8,
                _ => 2,
            };
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == '_' {
                    if c != '_' {
                        text.push(c);
                    }
                    self.bump();
                } else {
                    break;
                }
            }
            let val = u64::from_str_radix(&text, radix)
                .map(|v| v as f64)
                .unwrap_or(f64::NAN);
            self.push(TokenKind::Num(val), pos);
            return;
        }
        let mut seen_dot = false;
        let mut seen_exp = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '_' {
                if c != '_' {
                    text.push(c);
                }
                self.bump();
            } else if c == '.' && !seen_dot && !seen_exp {
                seen_dot = true;
                text.push('.');
                self.bump();
            } else if (c == 'e' || c == 'E') && !seen_exp {
                seen_exp = true;
                text.push('e');
                self.bump();
                if matches!(self.peek(), Some('+') | Some('-')) {
                    if let Some(s) = self.bump() {
                        text.push(s);
                    }
                }
            } else if c == 'n' {
                // BigInt suffix: treat as plain number.
                self.bump();
                break;
            } else {
                break;
            }
        }
        self.push(TokenKind::Num(text.parse::<f64>().unwrap_or(f64::NAN)), pos);
    }

    fn lex_escape(&mut self, out: &mut String) {
        match self.bump() {
            None => {}
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('v') => out.push('\u{b}'),
            Some('0') if !self.peek().is_some_and(|c| c.is_ascii_digit()) => out.push('\0'),
            Some('x') => {
                let mut v = 0u32;
                for _ in 0..2 {
                    if let Some(d) = self.peek().and_then(|c| c.to_digit(16)) {
                        v = v.saturating_mul(16).saturating_add(d);
                        self.bump();
                    }
                }
                out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
            }
            Some('u') => {
                let mut v = 0u32;
                if self.peek() == Some('{') {
                    self.bump();
                    while let Some(c) = self.peek() {
                        if c == '}' {
                            self.bump();
                            break;
                        }
                        if let Some(d) = c.to_digit(16) {
                            v = v.saturating_mul(16).saturating_add(d);
                        }
                        self.bump();
                    }
                } else {
                    for _ in 0..4 {
                        if let Some(d) = self.peek().and_then(|c| c.to_digit(16)) {
                            v = v.saturating_mul(16).saturating_add(d);
                            self.bump();
                        }
                    }
                }
                out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
            }
            Some('\n') => {} // line continuation
            Some(c) => out.push(c),
        }
    }

    fn lex_string(&mut self, quote: char, pos: usize) {
        self.bump();
        let mut s = String::new();
        loop {
            match self.bump() {
                None => break,
                Some(c) if c == quote => break,
                Some('\\') => self.lex_escape(&mut s),
                Some(c) => s.push(c),
            }
        }
        self.push(TokenKind::Str(s), pos);
    }

    fn lex_template(&mut self, pos: usize) {
        self.bump();
        let mut parts: Vec<TemplatePart> = Vec::new();
        let mut cur = String::new();
        loop {
            match self.bump() {
                None => break,
                Some('`') => break,
                Some('\\') => self.lex_escape(&mut cur),
                Some('$') if self.peek() == Some('{') => {
                    self.bump();
                    if !cur.is_empty() {
                        parts.push(TemplatePart::Str(core::mem::take(&mut cur)));
                    }
                    // Capture the raw expression source up to the matching
                    // `}` — skipping braces that live inside nested string,
                    // template, or comment tokens (`${a ? "{" : "("}`).
                    let expr = self.lex_template_expr();
                    parts.push(TemplatePart::Expr(expr));
                }
                Some(c) => cur.push(c),
            }
        }
        if !cur.is_empty() {
            parts.push(TemplatePart::Str(cur));
        }
        self.push(TokenKind::Template(parts), pos);
    }

    /// Scan the raw source of a `${ ... }` substitution, honouring nested
    /// strings (quotes), nested templates (recursively), regex literals and
    /// comments so an embedded `}` or quote inside one of them does not end
    /// the substitution or open a bogus string.
    fn lex_template_expr(&mut self) -> String {
        let mut depth = 1usize;
        let mut expr = String::new();
        // The last significant character decides whether a `/` opens a
        // regex literal (expression position) or is a division operator.
        let mut last_sig: Option<char> = None;
        loop {
            match self.bump() {
                None => break,
                Some('{') => {
                    depth = depth.saturating_add(1);
                    expr.push('{');
                    last_sig = Some('{');
                }
                Some('}') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                    expr.push('}');
                    last_sig = Some('}');
                }
                Some(q) if q == '"' || q == '\'' => {
                    expr.push(q);
                    loop {
                        match self.bump() {
                            None => break,
                            Some('\\') => {
                                expr.push('\\');
                                if let Some(c) = self.bump() {
                                    expr.push(c);
                                }
                            }
                            Some(c) => {
                                expr.push(c);
                                if c == q {
                                    break;
                                }
                            }
                        }
                    }
                    last_sig = Some(q);
                }
                Some('`') => {
                    // Nested template: copy it verbatim, recursing into its
                    // own substitutions so their braces balance locally.
                    expr.push('`');
                    loop {
                        match self.bump() {
                            None => break,
                            Some('\\') => {
                                expr.push('\\');
                                if let Some(c) = self.bump() {
                                    expr.push(c);
                                }
                            }
                            Some('`') => {
                                expr.push('`');
                                break;
                            }
                            Some('$') if self.peek() == Some('{') => {
                                self.bump();
                                expr.push_str("${");
                                let inner = self.lex_template_expr();
                                expr.push_str(&inner);
                                expr.push('}');
                            }
                            Some(c) => expr.push(c),
                        }
                    }
                    last_sig = Some('`');
                }
                Some('/') if self.peek() == Some('/') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some('/') if self.peek() == Some('*') => {
                    self.bump();
                    loop {
                        match self.bump() {
                            None => break,
                            Some('*') if self.peek() == Some('/') => {
                                self.bump();
                                break;
                            }
                            Some(_) => {}
                        }
                    }
                    expr.push(' ');
                }
                Some('/') if regex_after(last_sig) => {
                    // Regex literal: copy through the closing `/`, honouring
                    // escapes and character classes (`/[/]/`).
                    expr.push('/');
                    let mut in_class = false;
                    loop {
                        match self.bump() {
                            None => break,
                            Some('\\') => {
                                expr.push('\\');
                                if let Some(c) = self.bump() {
                                    expr.push(c);
                                }
                            }
                            Some('[') => {
                                in_class = true;
                                expr.push('[');
                            }
                            Some(']') => {
                                in_class = false;
                                expr.push(']');
                            }
                            Some('/') if !in_class => {
                                expr.push('/');
                                break;
                            }
                            Some('\n') => {
                                expr.push('\n');
                                break;
                            }
                            Some(c) => expr.push(c),
                        }
                    }
                    while let Some(c) = self.peek() {
                        if c.is_ascii_alphabetic() {
                            expr.push(c);
                            self.bump();
                        } else {
                            break;
                        }
                    }
                    last_sig = Some(')');
                }
                Some(c) => {
                    expr.push(c);
                    if !c.is_whitespace() {
                        last_sig = Some(c);
                    }
                }
            }
        }
        expr
    }

    fn lex_regex(&mut self, pos: usize) {
        self.bump(); // leading /
        let mut source = String::new();
        let mut in_class = false;
        loop {
            match self.bump() {
                None => break,
                Some('\\') => {
                    source.push('\\');
                    if let Some(c) = self.bump() {
                        source.push(c);
                    }
                }
                Some('[') => {
                    in_class = true;
                    source.push('[');
                }
                Some(']') => {
                    in_class = false;
                    source.push(']');
                }
                Some('/') if !in_class => break,
                Some(c) => source.push(c),
            }
        }
        let mut flags = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphabetic() {
                flags.push(c);
                self.bump();
            } else {
                break;
            }
        }
        self.push(TokenKind::Regex { source, flags }, pos);
    }

    fn lex_punct(&mut self, pos: usize) {
        use self::Punct::*;
        let c = self.bump().unwrap_or(' ');
        let c2 = self.peek();
        let c3 = self.peek2();
        let c4 = self.peek3();
        let (p, extra) = match c {
            '(' => (LParen, 0),
            ')' => (RParen, 0),
            '{' => (LBrace, 0),
            '}' => (RBrace, 0),
            '[' => (LBracket, 0),
            ']' => (RBracket, 0),
            ';' => (Semi, 0),
            ',' => (Comma, 0),
            ':' => (Colon, 0),
            '~' => (Tilde, 0),
            '.' => {
                if c2 == Some('.') && c3 == Some('.') {
                    (DotDotDot, 2)
                } else {
                    (Dot, 0)
                }
            }
            '?' => match (c2, c3) {
                // `a?.01:b` is a conditional with a fraction, not optional
                // chaining (ECMA-262 §12.7: `?.` is not followed by a digit).
                (Some('.'), Some(d)) if d.is_ascii_digit() => (Question, 0),
                (Some('.'), _) => (QuestionDot, 1),
                (Some('?'), Some('=')) => (QuestionQuestionAssign, 2),
                (Some('?'), _) => (QuestionQuestion, 1),
                _ => (Question, 0),
            },
            '=' => match (c2, c3) {
                (Some('='), Some('=')) => (StrictEq, 2),
                (Some('='), _) => (Eq, 1),
                (Some('>'), _) => (Arrow, 1),
                _ => (Assign, 0),
            },
            '!' => match (c2, c3) {
                (Some('='), Some('=')) => (StrictNotEq, 2),
                (Some('='), _) => (NotEq, 1),
                _ => (Not, 0),
            },
            '<' => match (c2, c3) {
                (Some('<'), Some('=')) => (ShlAssign, 2),
                (Some('<'), _) => (Shl, 1),
                (Some('='), _) => (LtEq, 1),
                _ => (Lt, 0),
            },
            '>' => match (c2, c3, c4) {
                (Some('>'), Some('>'), Some('=')) => (UShrAssign, 3),
                (Some('>'), Some('>'), _) => (UShr, 2),
                (Some('>'), Some('='), _) => (ShrAssign, 2),
                (Some('>'), _, _) => (Shr, 1),
                (Some('='), _, _) => (GtEq, 1),
                _ => (Gt, 0),
            },
            '+' => match c2 {
                Some('+') => (PlusPlus, 1),
                Some('=') => (PlusAssign, 1),
                _ => (Plus, 0),
            },
            '-' => match c2 {
                Some('-') => (MinusMinus, 1),
                Some('=') => (MinusAssign, 1),
                _ => (Minus, 0),
            },
            '*' => match (c2, c3) {
                (Some('*'), Some('=')) => (StarStarAssign, 2),
                (Some('*'), _) => (StarStar, 1),
                (Some('='), _) => (StarAssign, 1),
                _ => (Star, 0),
            },
            '/' => match c2 {
                Some('=') => (SlashAssign, 1),
                _ => (Slash, 0),
            },
            '%' => match c2 {
                Some('=') => (PercentAssign, 1),
                _ => (Percent, 0),
            },
            '&' => match (c2, c3) {
                (Some('&'), Some('=')) => (AndAssign, 2),
                (Some('&'), _) => (AndAnd, 1),
                (Some('='), _) => (AmpAssign, 1),
                _ => (Amp, 0),
            },
            '|' => match (c2, c3) {
                (Some('|'), Some('=')) => (OrAssign, 2),
                (Some('|'), _) => (OrOr, 1),
                (Some('='), _) => (PipeAssign, 1),
                _ => (Pipe, 0),
            },
            '^' => match c2 {
                Some('=') => (CaretAssign, 1),
                _ => (Caret, 0),
            },
            other => {
                self.push(TokenKind::Error(other), pos);
                return;
            }
        };
        for _ in 0..extra {
            self.bump();
        }
        self.push(TokenKind::Punct(p), pos);
    }
}
