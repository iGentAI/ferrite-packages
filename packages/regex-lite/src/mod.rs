//! regex-lite — a small backtracking regular-expression engine for constrained
//! Ferrite apps: literals, `.`, escapes (`\d \w \s` and friends), character
//! classes (ranges, negation), groups (capturing, named and `(?:`), lookaround,
//! backreferences, alternation,
//! anchors (`^ $ \b`), and the quantifiers `* + ? {n,m}` (greedy and lazy),
//! with JavaScript's matching semantics: the first match by backtracking
//! order, and captures inside a repeated group reset on every iteration.
//!
//! Panic-free and bounded: compilation rejects unsupported syntax, and groups
//! nested deeper than [`MAX_GROUP_NESTING`], with `None` (callers degrade to
//! "no match"). Matching runs the compiled pattern with an explicit
//! backtracking stack, so neither a long pattern nor a long input deepens the
//! native stack; it remembers states that already failed, from one start
//! position to the next, so nested repetition does not backtrack
//! exponentially and everyday patterns such as `.*foo` run in time linear in
//! the input; and it charges a step budget that grows with the input and
//! caps its stack, so a pathological pattern cannot hang the engine or
//! exhaust its memory. A search past either bound
//! has no answer: `try_is_match`, `try_find` and `try_find_captures` return
//! it as a [`SearchLimit`], and `is_match`, `find` and `find_captures`
//! answer it as no match, so use the `try_` forms wherever a missed match
//! would be a wrong answer.
//!
//! Extracted from `packages/browser-core/src/js/regex.rs` so agent tooling can
//! share it without carrying a browser.

// A consumer vendors this file as a private module and uses a subset of its
// surface; the rest would read as dead code there. The package's own test
// builds keep the lint.
#![cfg_attr(not(test), allow(dead_code))]

/// One compiled pattern element.
#[derive(Clone, Debug)]
enum Node {
    Char(char),
    AnyChar,
    Class {
        neg: bool,
        items: Vec<ClassItem>,
    },
    Group {
        alts: Vec<Vec<Node>>,
        cap: Option<usize>,
    },
    Look {
        alts: Vec<Vec<Node>>,
        negated: bool,
        reverse: bool,
    },
    BackRef(usize),
    NamedBackRef(String),
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
    Repeat {
        node: Box<Node>,
        min: u32,
        max: u32,
        lazy: bool,
    },
}

#[derive(Clone, Debug)]
enum ClassItem {
    Char(char),
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
}

/// A compiled pattern.
pub struct Regex {
    prog: Vec<Inst>,
    /// The instructions where a search remembers failed states.
    memo: Vec<MemoPoint>,
    /// Per instruction: its index in `memo`, or [`NO_MEMO`].
    memo_of: Vec<u32>,
    /// How characters compare (the `i` and `u` flags).
    case: Case,
    /// The `m` flag: `^` and `$` also match at line terminators.
    multiline: bool,
    /// The `s` flag: `.` also matches line terminators.
    dot_all: bool,
    /// Number of capturing groups (group 0 = whole match not counted here).
    n_caps: usize,
    /// Number of repeated groups, each with a loop register.
    n_regs: usize,
    /// The pattern is this plain text, matched case-sensitively: found by
    /// substring search, in linear time however long it and the input are.
    literal: Option<String>,
    /// Every match begins at the start of the input (the pattern begins
    /// with `^` and has no `m` flag, or it has the `y` flag), so no later
    /// start position is tried.
    anchored: bool,
    /// Text every match contains (case-sensitive patterns only): an input
    /// without it is answered "no match" without a search.
    required: Option<String>,
}

/// Captured groups from a successful match. `groups[0]` is the whole match;
/// `groups[n]` is capture group n (None when the group did not participate).
/// Each group is the input's text, as it was, whatever the flags.
///
/// Positions count the input's `char`s (Unicode scalar values) from its
/// start: they are neither byte offsets into the `&str` nor JavaScript's
/// UTF-16 indices. They agree with JavaScript's `index` and `lastIndex`
/// only for text within the Basic Multilingual Plane; a character above
/// U+FFFF counts once here and twice there. To slice the input, convert
/// with `char_indices`.
pub struct Captures {
    pub groups: Vec<Option<String>>,
    /// Index, in `char`s, of the first character of the whole match.
    pub start: usize,
    /// Index, in `char`s, one past the last character of the whole match.
    pub end: usize,
}

/// A bound that ended a search before it could tell whether, or where, the
/// pattern matches. [`Regex::is_match`], [`Regex::find`] and
/// [`Regex::find_captures`] answer such a search as no match; their `try_`
/// forms return this instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchLimit {
    /// The step budget ran out (runaway backtracking, or a scan that is
    /// quadratic in the line).
    Steps,
    /// The backtracking stack reached its cap (32 MiB): a repetition whose
    /// iterations each leave a way back, run over a very long input.
    Backtrack,
    /// The input has more characters than a search can index (`u32`).
    InputLength,
}

impl std::fmt::Display for SearchLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SearchLimit::Steps => "the regular expression ran out of search steps",
            SearchLimit::Backtrack => "the regular expression's backtracking stack is full",
            SearchLimit::InputLength => "the input is too long for the regular expression engine",
        })
    }
}

/// Compile `source` with JavaScript's `flags`, as `new RegExp(source,
/// flags)` would: `i` ignores case (by JavaScript's two rules, with and
/// without `u`), `m` makes `^` and `$` match at line terminators too, `s`
/// makes `.` match them, `u` changes how escapes read and how case is
/// compared, and `y` (sticky) tries the pattern at the start of the input
/// only, where a search from `lastIndex` 0 tries it; `g` and `d` change
/// nothing for one search. A flag JavaScript does not know, a repeated
/// flag, and `v` (whose class syntax this engine does not read) refuse
/// the pattern, as does syntax this engine does not support.
pub fn compile(source: &str, flags: &str) -> Option<Regex> {
    let flags = Flags::parse(flags)?;
    let chars: Vec<char> = source.chars().collect();
    let mut p = Parser {
        chars,
        pos: 0,
        depth: 0,
        next_cap: 1,
        unicode: flags.unicode,
        names: Default::default(),
    };
    let alts = p.parse_alternation()?;
    if p.pos != p.chars.len() {
        return None;
    }
    let case_insensitive = flags.case != Case::Sensitive;
    let literal = match alts.as_slice() {
        [only] if !case_insensitive => only
            .iter()
            .map(|n| match n {
                Node::Char(c) => Some(*c),
                _ => None,
            })
            .collect::<Option<String>>(),
        _ => None,
    };
    let anchored =
        flags.sticky || (!flags.multiline && alts.iter().all(|alt| starts_anchored(alt)));
    let required = match alts.as_slice() {
        [only] if !case_insensitive => Some(required_text(only)).filter(|t| !t.is_empty()),
        _ => None,
    };
    if !references_exist(&alts, p.next_cap, &p.names) {
        return None;
    }
    let mut c = Compiler {
        prog: Vec::new(),
        loops: Vec::new(),
        joins: Vec::new(),
        names: p.names,
        capture_sensitive: false,
        reverse: false,
    };
    c.alternation(&alts);
    c.emit(Inst::Match);
    let (memo, memo_of) = if c.capture_sensitive {
        // A failed (instruction, position) can succeed with other captures.
        (Vec::new(), vec![NO_MEMO; c.prog.len()])
    } else {
        c.memo_points()
    };
    Some(Regex {
        prog: c.prog,
        memo,
        memo_of,
        case: flags.case,
        multiline: flags.multiline,
        dot_all: flags.dot_all,
        n_caps: p.next_cap - 1,
        n_regs: c.loops.len(),
        literal,
        anchored,
        required,
    })
}

/// The flags of a pattern, as [`compile`] reads them.
struct Flags {
    case: Case,
    multiline: bool,
    dot_all: bool,
    unicode: bool,
    sticky: bool,
}

impl Flags {
    /// JavaScript's flags `d g i m s u y`, each at most once; `None` for any
    /// other letter, a repeated one, and `v`.
    fn parse(flags: &str) -> Option<Flags> {
        let mut seen = String::new();
        for f in flags.chars() {
            if !"dgimsuy".contains(f) || seen.contains(f) {
                return None;
            }
            seen.push(f);
        }
        let has = |f: char| seen.contains(f);
        let unicode = has('u');
        Some(Flags {
            case: match (has('i'), unicode) {
                (false, _) => Case::Sensitive,
                (true, false) => Case::Upper,
                (true, true) => Case::Fold,
            },
            multiline: has('m'),
            dot_all: has('s'),
            unicode,
            sticky: has('y'),
        })
    }
}

/// How two characters compare: JavaScript's Canonicalize (ECMA-262,
/// 22.2.2.7.3) under each combination of the `i` and `u` flags. A literal
/// matches a character, and a class contains it, when some member of the
/// class has the same canonical form as the character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    /// No `i`: a character is its own canonical form.
    Sensitive,
    /// `i` without `u`: the character's uppercase, when that is one UTF-16
    /// code unit and does not turn a non-ASCII character into an ASCII one.
    /// So `ß` (uppercase `SS`), `ſ` and the Kelvin sign (which would become
    /// ASCII `S` and `K`, or stay `K`) keep their own forms, and a character
    /// above U+FFFF, two code units to JavaScript, has no case at all.
    Upper,
    /// `i` with `u`: Unicode simple case folding, so `ſ` matches `s`, the
    /// Kelvin sign `k`, and `ẞ` `ß`.
    Fold,
}

impl Case {
    /// The canonical form of `c`.
    fn canon(self, c: char) -> char {
        match self {
            Case::Sensitive => c,
            Case::Upper => table_map(CANON_RUNS, c),
            Case::Fold => table_map(FOLD_RUNS, c),
        }
    }

    /// Every character whose canonical form is `target` (itself canonical),
    /// `target` first.
    fn class(self, target: char) -> ([char; CASE_CLASS_MAX], usize) {
        match self {
            Case::Sensitive => ([target; CASE_CLASS_MAX], 1),
            Case::Upper => table_class(CANON_RUNS, target),
            Case::Fold => table_class(FOLD_RUNS, target),
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: u32,
    /// Next capturing-group index (1-based; 0 is the whole match).
    next_cap: usize,
    /// The `u` flag, which changes how escapes read.
    unicode: bool,
    names: std::collections::BTreeMap<String, usize>,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn parse_alternation(&mut self) -> Option<Vec<Vec<Node>>> {
        let mut alts = Vec::new();
        let mut cur: Vec<Node> = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(')') if self.depth > 0 => break,
                Some('|') => {
                    self.bump();
                    alts.push(core::mem::take(&mut cur));
                }
                Some(_) => {
                    let node = self.parse_quantified()?;
                    cur.push(node);
                }
            }
        }
        alts.push(cur);
        Some(alts)
    }

    /// Consumes a run of ASCII digits and returns it.
    fn digits(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek().filter(char::is_ascii_digit) {
            self.pos += 1;
            out.push(c);
        }
        out
    }

    fn parse_quantified(&mut self) -> Option<Node> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.bump();
                (0, u32::MAX)
            }
            Some('+') => {
                self.bump();
                (1, u32::MAX)
            }
            Some('?') => {
                self.bump();
                (0, 1)
            }
            Some('{') => {
                // {n} {n,} {n,m} — otherwise a literal brace.
                let save = self.pos;
                self.bump();
                let min: u32 = match self.digits().parse() {
                    Ok(v) => v,
                    Err(_) => {
                        self.pos = save;
                        return Some(atom);
                    }
                };
                let max = match self.peek() {
                    Some(',') => {
                        self.bump();
                        let m = self.digits();
                        if m.is_empty() {
                            u32::MAX
                        } else {
                            m.parse().ok()?
                        }
                    }
                    _ => min,
                };
                if self.peek() != Some('}') {
                    self.pos = save;
                    return Some(atom);
                }
                self.bump();
                // JavaScript refuses `{3,1}` as out of order.
                if min > max {
                    return None;
                }
                (min, max)
            }
            _ => return Some(atom),
        };
        if matches!(
            atom,
            Node::Start
                | Node::End
                | Node::WordBoundary
                | Node::NotWordBoundary
                | Node::Look { reverse: true, .. }
        ) || (self.unicode && matches!(atom, Node::Look { .. }))
        {
            return None;
        }
        let lazy = if self.peek() == Some('?') {
            self.bump();
            true
        } else {
            false
        };
        Some(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            lazy,
        })
    }

    fn parse_atom(&mut self) -> Option<Node> {
        match self.bump()? {
            '.' => Some(Node::AnyChar),
            '^' => Some(Node::Start),
            '$' => Some(Node::End),
            '(' => {
                let mut cap = None;
                let mut look = None;
                if self.peek() == Some('?') {
                    self.bump();
                    match self.bump()? {
                        ':' => {}
                        '=' => look = Some((false, false)),
                        '!' => look = Some((true, false)),
                        '<' => match self.peek()? {
                            '=' | '!' => look = Some((self.bump()? == '!', true)),
                            _ => {
                                let name = self.group_name()?;
                                if self.names.insert(name, self.next_cap).is_some() {
                                    return None;
                                }
                                cap = Some(self.next_cap);
                                self.next_cap += 1;
                            }
                        },
                        _ => return None,
                    }
                } else {
                    cap = Some(self.next_cap);
                    self.next_cap += 1;
                }
                if self.depth >= MAX_GROUP_NESTING {
                    return None;
                }
                self.depth += 1;
                let alts = self.parse_alternation()?;
                self.depth -= 1;
                if self.bump()? != ')' {
                    return None;
                }
                if let Some((negated, reverse)) = look {
                    return Some(Node::Look {
                        alts,
                        negated,
                        reverse,
                    });
                }
                if cap.is_none() {
                    if let Some(one) = single_character(&alts) {
                        return Some(one);
                    }
                }
                Some(Node::Group { alts, cap })
            }
            '[' => self.parse_class(),
            '\\' => self.parse_escape(),
            ')' | '*' | '+' | '?' => None,
            '{' | '}' | ']' if self.unicode => None,
            c => Some(Node::Char(c)),
        }
    }

    fn group_name(&mut self) -> Option<String> {
        let mut name = String::new();
        while self.peek()? != '>' {
            let c = self.bump()?;
            let c = if c == '\\' && self.bump()? == 'u' {
                self.char_escape('u', false)?
            } else {
                c
            };
            let valid = c == '$'
                || c == '_'
                || c.is_alphabetic()
                || (!name.is_empty()
                    && (c.is_alphanumeric() || matches!(c, '\u{200c}' | '\u{200d}')));
            if !valid {
                return None;
            }
            name.push(c);
        }
        self.bump();
        (!name.is_empty()).then_some(name)
    }

    fn parse_escape(&mut self) -> Option<Node> {
        let c = self.bump()?;
        if let Some(item) = class_escape(c) {
            return Some(Node::Class {
                neg: false,
                items: vec![item],
            });
        }
        Some(match c {
            'b' => Node::WordBoundary,
            'B' => Node::NotWordBoundary,
            '1'..='9' => {
                let mut digits = String::from(c);
                digits.push_str(&self.digits());
                Node::BackRef(digits.parse().ok()?)
            }
            'k' if self.peek() == Some('<') => {
                self.bump();
                Node::NamedBackRef(self.group_name()?)
            }
            'p' | 'P' if self.unicode => return None,
            other => Node::Char(self.char_escape(other, false)?),
        })
    }

    /// The character the escape `\<c>` stands for, as JavaScript reads it:
    /// the control escapes, `\0`, `\cX`, `\xHH`, `\uHHHH` (and `\u{…}`
    /// under the `u` flag), and `\b`, a backspace, inside a class; any other
    /// character stands for itself. Without the `u` flag an escape that does
    /// not complete (`\x4`, `\u12`) stands for its letter, as JavaScript's
    /// Annex B reads it, and `\0` before octal digits is a legacy octal
    /// escape (`\012` is a line feed). `None` for what this engine refuses:
    /// `\c` without a letter, an escape the `u` flag makes an error, and a
    /// code point that is not a character.
    fn char_escape(&mut self, c: char, in_class: bool) -> Option<char> {
        Some(match c {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => '\u{c}',
            'v' => '\u{b}',
            'b' if in_class => '\u{8}',
            '0' if self.unicode && self.peek().is_some_and(|d| d.is_ascii_digit()) => return None,
            '0' => self.legacy_octal(0),
            'c' => {
                let letter = self.peek().filter(char::is_ascii_alphabetic)?;
                self.bump();
                char::from_u32(letter as u32 % 32)?
            }
            'x' => match self.hex_digits(2) {
                Some(v) => char::from_u32(v)?,
                None if self.unicode => return None,
                None => 'x',
            },
            'u' if self.unicode && self.peek() == Some('{') => {
                self.bump();
                let mut v = 0u32;
                let mut digits = 0;
                loop {
                    let d = self.bump()?;
                    if d == '}' && digits > 0 {
                        break;
                    }
                    v = v.saturating_mul(16).saturating_add(d.to_digit(16)?);
                    digits += 1;
                }
                char::from_u32(v)?
            }
            'u' => match self.hex_digits(4) {
                Some(v) => char::from_u32(v)?,
                None if self.unicode => return None,
                None => 'u',
            },
            other => other,
        })
    }

    /// A legacy octal escape whose first digit, `first`, has been read: up to
    /// two more octal digits, while the value stays within `\377`.
    fn legacy_octal(&mut self, first: u32) -> char {
        let mut v = first;
        for _ in 0..2 {
            match self.peek().and_then(|d| d.to_digit(8)) {
                Some(d) if v * 8 + d <= 0o377 => {
                    self.bump();
                    v = v * 8 + d;
                }
                _ => break,
            }
        }
        char::from_u32(v).unwrap_or('\0')
    }

    /// The value of the next `n` characters when all are hexadecimal digits
    /// (and they are consumed); otherwise nothing is consumed.
    fn hex_digits(&mut self, n: usize) -> Option<u32> {
        let digits = self.chars.get(self.pos..self.pos + n)?;
        let v = digits
            .iter()
            .try_fold(0u32, |v, d| Some(v * 16 + d.to_digit(16)?))?;
        self.pos += n;
        Some(v)
    }

    fn parse_class(&mut self) -> Option<Node> {
        let neg = if self.peek() == Some('^') {
            self.bump();
            true
        } else {
            false
        };
        let mut items = Vec::new();
        loop {
            let c = self.bump()?;
            if c == ']' {
                break;
            }
            let lo = match self.class_atom(c)? {
                Ok(lo) => lo,
                Err(item) => {
                    items.push(item);
                    continue;
                }
            };
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|&c| c != ']') {
                self.bump();
                let c = self.bump()?;
                match self.class_atom(c)? {
                    // JavaScript refuses a range out of order, such as `[z-a]`.
                    Ok(hi) if hi < lo => return None,
                    Ok(hi) => items.push(ClassItem::Range(lo, hi)),
                    // A class escape at either end makes no range: `[a-\d]`
                    // is `a`, `-` and the digits (Annex B).
                    Err(item) => {
                        items.push(ClassItem::Char(lo));
                        items.push(ClassItem::Char('-'));
                        items.push(item);
                    }
                }
            } else {
                items.push(ClassItem::Char(lo));
            }
        }
        Some(Node::Class { neg, items })
    }

    /// One member of a class, beginning with `c`: a character, or a class
    /// escape (`\d`, `\w`, `\s` and their negations) as `Err`.
    fn class_atom(&mut self, c: char) -> Option<Result<char, ClassItem>> {
        if c != '\\' {
            return Some(Ok(c));
        }
        let c = self.bump()?;
        if let Some(item) = class_escape(c) {
            return Some(Err(item));
        }
        Some(match c {
            // Without the `u` flag a digit after a backslash in a class is a
            // legacy octal escape (`\8` and `\9` stand for themselves); with
            // it, an error, as is a Unicode property escape here.
            '1'..='9' | 'p' | 'P' if self.unicode => return None,
            d @ '1'..='7' => Ok(self.legacy_octal(d as u32 - '0' as u32)),
            e => Ok(self.char_escape(e, true)?),
        })
    }
}

/// The class member `\<c>` stands for, when `c` names one.
fn class_escape(c: char) -> Option<ClassItem> {
    Some(match c {
        'd' => ClassItem::Digit(false),
        'D' => ClassItem::Digit(true),
        'w' => ClassItem::Word(false),
        'W' => ClassItem::Word(true),
        's' => ClassItem::Space(false),
        'S' => ClassItem::Space(true),
        _ => return None,
    })
}

/// JavaScript's basic word characters, for `\w` and `\b`: ASCII letters,
/// digits and `_`. Under the `i` and `u` flags together the set also holds
/// the characters that fold into it (see [`Regex::is_word`]).
fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// JavaScript's `\s`: its white space and line terminators. Unlike Rust's
/// `char::is_whitespace`, it includes U+FEFF and not U+0085.
fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// JavaScript's line terminators, which `.` does not match.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// The one-character node a non-capturing group stands for, when every
/// alternative is a single literal or (non-negated) class: `(?:x|y)` is
/// `[xy]` and `(?:[ab])` is `[ab]`. Each alternative consumes exactly one
/// character and leaves the same continuation, so the order in which they
/// are tried cannot change the answer, and a repetition of the group then
/// runs as a repeated single character, with one backtracking entry for the
/// whole run instead of several per iteration. Literals and class members
/// fold alike under `i`.
fn single_character(alts: &[Vec<Node>]) -> Option<Node> {
    if let [only] = alts {
        if let [node @ (Node::Char(_) | Node::AnyChar | Node::Class { .. })] = only.as_slice() {
            return Some(node.clone());
        }
    }
    if alts.len() < 2 {
        return None;
    }
    let mut items = Vec::new();
    for alt in alts {
        match alt.as_slice() {
            [Node::Char(c)] => items.push(ClassItem::Char(*c)),
            [Node::Class {
                neg: false,
                items: more,
            }] => items.extend(more.iter().cloned()),
            _ => return None,
        }
    }
    Some(Node::Class { neg: false, items })
}

/// Whether every match of `seq` must begin at the start of the input: its
/// first element is `^`, or a group all of whose alternatives begin with
/// `^`, or a repetition of such a group that must run at least once.
fn starts_anchored(seq: &[Node]) -> bool {
    match seq.first() {
        Some(Node::Start) => true,
        Some(Node::Group { alts, .. }) => alts.iter().all(|alt| starts_anchored(alt)),
        Some(Node::Repeat { node, min, .. }) if *min >= 1 => {
            starts_anchored(std::slice::from_ref(node.as_ref()))
        }
        _ => false,
    }
}

/// The longest text every match of `seq` must contain: runs of literals
/// that the pattern cannot match without, collected through zero-width
/// assertions, plain groups and the mandatory part of repetitions. A
/// case-sensitive search whose input lacks it cannot match, which settles
/// most non-matching lines without running the pattern at all.
fn required_text(seq: &[Node]) -> String {
    fn flush(runs: &mut Vec<String>, cur: &mut String) {
        if !cur.is_empty() {
            runs.push(std::mem::take(cur));
        }
    }
    fn collect(seq: &[Node], runs: &mut Vec<String>, cur: &mut String) {
        for node in seq {
            match node {
                Node::Char(c) => cur.push(*c),
                Node::Start | Node::End | Node::WordBoundary | Node::NotWordBoundary => {}
                Node::Group { alts, .. } if alts.len() == 1 => {
                    if let Some(only) = alts.first() {
                        collect(only, runs, cur);
                    }
                }
                Node::Repeat { node, min, max, .. } if *min >= 1 => match node.as_ref() {
                    Node::Char(c) => {
                        for _ in 0..(*min).min(64) {
                            cur.push(*c);
                        }
                        if *max != *min || *min > 64 {
                            flush(runs, cur);
                        }
                    }
                    inner => {
                        flush(runs, cur);
                        collect(std::slice::from_ref(inner), runs, cur);
                        flush(runs, cur);
                    }
                },
                _ => flush(runs, cur),
            }
        }
    }
    let mut runs = Vec::new();
    let mut cur = String::new();
    collect(seq, &mut runs, &mut cur);
    flush(&mut runs, &mut cur);
    runs.into_iter()
        .max_by_key(|r| r.chars().count())
        .unwrap_or_default()
}

/// Groups nested deeper than this are refused at compile time.
pub const MAX_GROUP_NESTING: u32 = 64;

/// Steps every search may take, whatever the length of its input.
const MATCH_STEPS: u64 = 200_000;

/// Further steps a search may take for each input character, on top of one
/// per instruction of the pattern and one per loop state the search can
/// remember at a position (up to [`MAX_STEPS_PER_CHAR`] in all), so a line of
/// any length can be scanned: a remembered state is explored once, so a
/// search stays well inside this, and runaway backtracking does not.
const STEPS_PER_CHAR: u64 = 32;
const MAX_STEPS_PER_CHAR: u64 = 256;

/// Entries the backtracking stack may hold (16 bytes each, so 32 MiB).
const MAX_BACKTRACK: usize = 1 << 21;

/// Bits one search may spend remembering failed states densely (8 MiB),
/// and failed states it may remember in a hash set beyond that (see
/// [`Search::seen_before`]).
const MAX_DENSE_MEMO_BITS: u64 = 1 << 26;
const MAX_HASHED_MEMO: usize = 1 << 18;

/// No memo point at this instruction.
const NO_MEMO: u32 = u32::MAX;

/// An unset capture position in a [`Backtrack`] entry.
const UNSET: u32 = u32::MAX;

/// One instruction of a compiled pattern. Matching walks the program with an
/// explicit backtracking stack, so neither a long pattern nor a long input
/// deepens the native stack.
#[derive(Clone, Debug)]
enum Inst {
    /// Match one character against a `Char`, `AnyChar` or `Class` node.
    One(Node),
    /// A zero-width `Start`, `End`, `WordBoundary` or `NotWordBoundary`.
    Assert(Node),
    Look {
        end: usize,
        negated: bool,
        reverse: bool,
        captures: (usize, usize),
    },
    BackRef(usize),
    /// Continue at `first`; if that fails, resume at `second`.
    Split {
        first: usize,
        second: usize,
    },
    Jump(usize),
    /// Capture group `n` opens here.
    Open(usize),
    /// Capture group `n` closes here.
    Close(usize),
    /// A repeated single-character node: one character per iteration, so
    /// its backtracking is one stack entry, not one per iteration. `cap` is
    /// the capturing group that is the repeated atom, as in `(x|y)*`: after
    /// one or more iterations it holds the last character taken.
    RepeatOne {
        node: Node,
        min: u32,
        max: u32,
        lazy: bool,
        cap: Option<usize>,
    },
    /// Reset loop register `reg` before a loop's first iteration.
    LoopInit(usize),
    /// Choose between another iteration (the next instruction) and `exit`.
    LoopHead {
        reg: usize,
        min: u32,
        max: u32,
        lazy: bool,
        exit: usize,
    },
    /// Begin an iteration: count it, note where it starts, and clear the
    /// captures `caps.0..caps.1` inside the repeated atom, which JavaScript
    /// resets at the start of every iteration.
    IterStart {
        reg: usize,
        caps: (usize, usize),
    },
    /// End an iteration. Past the minimum, an iteration that consumed
    /// nothing fails (JavaScript's rule, which also keeps `(a*)*` finite);
    /// otherwise go back to the loop's head.
    LoopEnd {
        reg: usize,
        min: u32,
        head: usize,
    },
    Match,
}

/// One entry of the backtracking stack: a place to resume, or a state
/// change to undo on the way back to one. Positions are `u32`; a search
/// over more characters than that is refused.
#[derive(Clone, Copy, Debug)]
enum Backtrack {
    /// Resume at `pc` and `pos`.
    Choice { pc: u32, pos: u32 },
    /// The greedy `RepeatOne` at `pc` now ends at `cur` and may give
    /// characters back down to `lo`.
    Greedy { pc: u32, lo: u32, cur: u32 },
    /// The lazy `RepeatOne` at `pc` now ends at `cur` and may take more
    /// characters, up to `hi`.
    Lazy { pc: u32, cur: u32, hi: u32 },
    /// The ends `lo..=hi` of the `RepeatOne` before instruction `next` (its
    /// last end to try) have been tried and failed: remember that, for the
    /// loop state they were tried in (see [`Search::failed_ends`]).
    Failed { next: u32, lo: u32, hi: u32 },
    /// Restore loop register `reg`.
    Loop { reg: u32, count: u32, start: u32 },
    /// Restore the open position of group `n`.
    Open { n: u32, at: u32 },
    /// Restore capture slot `n` (`start == UNSET`: not set).
    Cap { n: u32, start: u32, end: u32 },
}

/// An instruction several paths reach, where a search remembers the states
/// it has already explored.
#[derive(Clone, Debug)]
struct MemoPoint {
    /// The loops whose registers the rest of the search can observe there.
    live: Vec<LiveLoop>,
    /// How many distinct observable loop states there are.
    states: u64,
}

/// A loop whose register is live at a memo point, and how much of the
/// register the rest of the search can observe.
#[derive(Clone, Debug)]
struct LiveLoop {
    reg: usize,
    min: u32,
    max: u32,
    /// The memo point lies inside the loop's body, where whether the
    /// iteration has consumed anything yet still matters.
    in_body: bool,
}

/// Compiles the parsed pattern into a program.
struct Compiler {
    prog: Vec<Inst>,
    /// (head, end, min, max) of each loop, indexed by register.
    loops: Vec<(usize, usize, u32, u32)>,
    /// Instructions several paths reach: loop heads, the end of an
    /// alternation, the continuation of a single-character repetition.
    joins: Vec<usize>,
    names: std::collections::BTreeMap<String, usize>,
    capture_sensitive: bool,
    reverse: bool,
}

impl Compiler {
    fn emit(&mut self, inst: Inst) -> usize {
        self.prog.push(inst);
        self.prog.len() - 1
    }

    fn patch(&mut self, at: usize, inst: Inst) {
        if let Some(slot) = self.prog.get_mut(at) {
            *slot = inst;
        }
    }

    fn alternation(&mut self, alts: &[Vec<Node>]) {
        let Some((last, rest)) = alts.split_last() else {
            return;
        };
        let mut jumps = Vec::new();
        for alt in rest {
            let split = self.emit(Inst::Jump(0));
            self.sequence(alt);
            jumps.push(self.emit(Inst::Jump(0)));
            let second = self.prog.len();
            self.patch(
                split,
                Inst::Split {
                    first: split + 1,
                    second,
                },
            );
        }
        self.sequence(last);
        if !rest.is_empty() {
            let end = self.prog.len();
            for j in jumps {
                self.patch(j, Inst::Jump(end));
            }
            self.joins.push(end);
        }
    }

    fn sequence(&mut self, seq: &[Node]) {
        if self.reverse {
            for node in seq.iter().rev() {
                self.node(node);
            }
        } else {
            for node in seq {
                self.node(node);
            }
        }
    }

    fn node(&mut self, node: &Node) {
        match node {
            Node::Char(_) | Node::AnyChar | Node::Class { .. } => {
                self.emit(Inst::One(node.clone()));
            }
            Node::Start | Node::End | Node::WordBoundary | Node::NotWordBoundary => {
                self.emit(Inst::Assert(node.clone()));
            }
            Node::Group { alts, cap } => {
                if let Some(n) = cap {
                    self.emit(Inst::Open(*n));
                }
                self.alternation(alts);
                if let Some(n) = cap {
                    self.emit(Inst::Close(*n));
                }
            }
            Node::BackRef(n) => {
                self.capture_sensitive = true;
                self.emit(Inst::BackRef(*n));
            }
            Node::NamedBackRef(name) => {
                self.capture_sensitive = true;
                self.emit(Inst::BackRef(self.names[name]));
            }
            Node::Look {
                alts,
                negated,
                reverse,
            } => {
                self.capture_sensitive = true;
                let head = self.emit(Inst::Jump(0));
                let old_direction = self.reverse;
                self.reverse = *reverse;
                self.alternation(alts);
                self.reverse = old_direction;
                self.emit(Inst::Match);
                self.patch(
                    head,
                    Inst::Look {
                        end: self.prog.len(),
                        negated: *negated,
                        reverse: *reverse,
                        captures: cap_span(node).unwrap_or((0, 0)),
                    },
                );
            }
            Node::Repeat {
                node: atom,
                min,
                max,
                lazy,
            } => {
                let (min, max, lazy) = (*min, *max, *lazy);
                // A single character, or a capturing group of single-character
                // alternatives such as `(x|y)` (whose capture is the last
                // character taken), repeats without a loop, so a long run
                // leaves one way back instead of several per iteration.
                let one = match atom.as_ref() {
                    node @ (Node::Char(_) | Node::AnyChar | Node::Class { .. }) => {
                        Some((node.clone(), None))
                    }
                    Node::Group { alts, cap: Some(n) } => {
                        single_character(alts).map(|node| (node, Some(*n)))
                    }
                    _ => None,
                };
                if let Some((node, cap)) = one.filter(|_| !self.reverse) {
                    self.emit(Inst::RepeatOne {
                        node,
                        min,
                        max,
                        lazy,
                        cap,
                    });
                    if max > min {
                        self.joins.push(self.prog.len());
                    }
                    return;
                }
                let reg = self.loops.len();
                self.loops.push((0, 0, min, max));
                self.emit(Inst::LoopInit(reg));
                let head = self.emit(Inst::Jump(0));
                let caps = cap_span(atom).unwrap_or((0, 0));
                self.emit(Inst::IterStart { reg, caps });
                self.node(atom);
                let end = self.emit(Inst::LoopEnd { reg, min, head });
                let exit = self.prog.len();
                self.patch(
                    head,
                    Inst::LoopHead {
                        reg,
                        min,
                        max,
                        lazy,
                        exit,
                    },
                );
                if let Some(span) = self.loops.get_mut(reg) {
                    *span = (head, end, min, max);
                }
                self.joins.push(head);
            }
        }
    }

    /// The memo points, and for each instruction the index of its memo
    /// point or [`NO_MEMO`]. A join whose observable loop state does not fit
    /// a 64-bit key is not memoized.
    fn memo_points(&self) -> (Vec<MemoPoint>, Vec<u32>) {
        let mut points = Vec::new();
        let mut index = vec![NO_MEMO; self.prog.len()];
        let mut joins = self.joins.clone();
        joins.sort_unstable();
        joins.dedup();
        for pc in joins {
            let mut live = Vec::new();
            let mut radix: u64 = 1;
            let mut fits = true;
            for (reg, &(head, end, min, max)) in self.loops.iter().enumerate() {
                if pc < head || pc > end {
                    continue;
                }
                let in_body = pc > head;
                let digits = count_radix(min, max) * if in_body { 2 } else { 1 };
                match radix.checked_mul(digits) {
                    Some(r) => radix = r,
                    None => fits = false,
                }
                live.push(LiveLoop {
                    reg,
                    min,
                    max,
                    in_body,
                });
            }
            if let (true, Some(slot)) = (fits, index.get_mut(pc)) {
                *slot = points.len() as u32;
                points.push(MemoPoint {
                    live,
                    states: radix,
                });
            }
        }
        (points, index)
    }
}

/// How many values of a loop's count the rest of a search can tell apart:
/// all of `0..=max` for a bounded loop; for an unbounded one, every count
/// past the minimum behaves alike.
fn count_radix(min: u32, max: u32) -> u64 {
    if max == u32::MAX {
        u64::from(min) + 2
    } else {
        u64::from(max) + 1
    }
}

fn references_exist(
    alts: &[Vec<Node>],
    captures: usize,
    names: &std::collections::BTreeMap<String, usize>,
) -> bool {
    fn node_valid(
        node: &Node,
        captures: usize,
        names: &std::collections::BTreeMap<String, usize>,
    ) -> bool {
        match node {
            Node::BackRef(n) => *n < captures,
            Node::NamedBackRef(name) => names.contains_key(name),
            Node::Group { alts, .. } | Node::Look { alts, .. } => {
                references_exist(alts, captures, names)
            }
            Node::Repeat { node, .. } => node_valid(node, captures, names),
            _ => true,
        }
    }
    alts.iter()
        .flatten()
        .all(|node| node_valid(node, captures, names))
}

/// The capture groups inside `node`, as a half-open range of slots (groups
/// are numbered in order of their opening parenthesis, so they are
/// contiguous).
fn cap_span(node: &Node) -> Option<(usize, usize)> {
    let join = |a: Option<(usize, usize)>, b: Option<(usize, usize)>| match (a, b) {
        (Some((lo, hi)), Some((l2, h2))) => Some((lo.min(l2), hi.max(h2))),
        (a, None) => a,
        (None, b) => b,
    };
    match node {
        Node::Group { alts, cap } => {
            let own = cap.map(|n| (n, n + 1));
            alts.iter().flatten().map(cap_span).fold(own, join)
        }
        Node::Look { alts, .. } => alts.iter().flatten().map(cap_span).fold(None, join),
        Node::Repeat { node, .. } => cap_span(node),
        _ => None,
    }
}

/// How one search ended at one start position.
enum Outcome {
    Match(usize),
    NoMatch,
    /// The step budget or the backtracking stack ran out: the whole search
    /// ends without an answer.
    Limit(SearchLimit),
}

/// The state of one search over one input.
struct Search<'r> {
    re: &'r Regex,
    chars: Vec<char>,
    caps: Vec<Option<(usize, usize)>>,
    open: Vec<usize>,
    /// Per loop: (iterations begun, position the current one began at).
    regs: Vec<(u32, u32)>,
    stack: Vec<Backtrack>,
    /// Per memo point: the first bit of its dense table in `dense`, or
    /// `None` when it is remembered in `hashed`.
    dense_at: Vec<Option<u64>>,
    dense: Vec<u64>,
    hashed: std::collections::HashSet<(u32, u32, u64), std::hash::BuildHasherDefault<StateHasher>>,
    /// Per instruction: the last run of characters a `RepeatOne` there was
    /// found to match, as (first, end, whether `end` is where the run
    /// stops), so a run is scanned once however many start positions and
    /// iterations look at it.
    runs: Vec<(u32, u32, bool)>,
    /// Per (instruction after a `RepeatOne`, loop state): a range of
    /// positions known to fail there. Ends of a repetition in this range are
    /// skipped in one step instead of being tried one by one, which keeps
    /// `.*foo`, `\w+\s+foo` and `^(a+)+$` linear in the line.
    failed_ends: std::collections::HashMap<
        (u32, u64),
        (u32, u32),
        std::hash::BuildHasherDefault<StateHasher>,
    >,
    steps: u64,
}

impl Search<'_> {
    fn push(&mut self, entry: Backtrack) -> bool {
        if self.stack.len() >= MAX_BACKTRACK {
            return false;
        }
        self.stack.push(entry);
        true
    }

    fn charge(&mut self) -> bool {
        if self.steps == 0 {
            return false;
        }
        self.steps -= 1;
        true
    }

    fn reg(&self, reg: usize) -> (u32, u32) {
        self.regs.get(reg).copied().unwrap_or((0, 0))
    }

    fn set_reg(&mut self, reg: usize, value: (u32, u32)) -> bool {
        let old = self.reg(reg);
        if !self.push(Backtrack::Loop {
            reg: reg as u32,
            count: old.0,
            start: old.1,
        }) {
            return false;
        }
        if let Some(slot) = self.regs.get_mut(reg) {
            *slot = value;
        }
        true
    }

    fn set_cap(&mut self, n: usize, value: Option<(usize, usize)>) -> bool {
        let old = self.caps.get(n).copied().flatten();
        let (start, end) = old.map_or((UNSET, UNSET), |(a, b)| (a as u32, b as u32));
        if !self.push(Backtrack::Cap {
            n: n as u32,
            start,
            end,
        }) {
            return false;
        }
        if let Some(slot) = self.caps.get_mut(n) {
            *slot = value;
        }
        true
    }

    /// Whether this state (instruction, position, observable loop state)
    /// was reached before; records it if not. Captures never decide whether a
    /// search matches (there are no backreferences), so a state reached again
    /// either failed already or is still being explored further up the same
    /// path, which an iteration that consumed nothing cannot complete; either
    /// way it cannot lead to a match. Remembering them makes nested
    /// repetition such as `(?:(?:a|aa)+)+c` polynomial instead of
    /// exponential. A memo point gets a dense bit table while
    /// [`MAX_DENSE_MEMO_BITS`] lasts, and a hash set after that, which stops
    /// growing at [`MAX_HASHED_MEMO`]; past that the search goes on without.
    fn seen_before(&mut self, pc: usize, pos: usize) -> bool {
        let re = self.re;
        let Some(&i) = re.memo_of.get(pc) else {
            return false;
        };
        let Some(point) = re.memo.get(i as usize) else {
            return false;
        };
        let key = self.memo_key(point, Some(pos));
        if let Some(Some(first)) = self.dense_at.get(i as usize) {
            let width = self.chars.len() as u64 + 1;
            let bit = first + key * width + pos as u64;
            let Some(word) = self.dense.get_mut((bit / 64) as usize) else {
                return false;
            };
            let mask = 1u64 << (bit % 64);
            let seen = *word & mask != 0;
            *word |= mask;
            return seen;
        }
        let state = (pc as u32, pos as u32, key);
        if self.hashed.contains(&state) {
            return true;
        }
        if self.hashed.len() < MAX_HASHED_MEMO {
            self.hashed.insert(state);
        }
        false
    }

    /// The observable loop state at a memo point: each live loop's count (as
    /// far as the rest of the search can tell counts apart) and, inside a
    /// loop's body, whether the current iteration has consumed anything,
    /// that is whether `pos` differs from where the iteration began. `None`
    /// for `pos` stands for a position past every iteration's beginning.
    fn memo_key(&self, point: &MemoPoint, pos: Option<usize>) -> u64 {
        let mut key: u64 = 0;
        for l in &point.live {
            let (count, start) = self.reg(l.reg);
            let c = if l.max == u32::MAX {
                u64::from(count.min(l.min.saturating_add(1)))
            } else {
                u64::from(count)
            };
            key = key * count_radix(l.min, l.max) + c;
            if l.in_body {
                key = key * 2 + u64::from(pos.is_some_and(|p| p as u32 == start));
            }
        }
        key
    }

    /// The memo point at `next` (the instruction after a `RepeatOne`), and
    /// the key of its loop state for positions past every iteration's
    /// beginning, under which failed ends are remembered.
    fn ends_key(&self, next: usize) -> Option<(&'_ MemoPoint, u64)> {
        let re = self.re;
        let i = *re.memo_of.get(next)?;
        let point = re.memo.get(i as usize)?;
        Some((point, self.memo_key(point, None)))
    }

    /// Whether `pos` is where a live loop's current iteration began, the one
    /// position whose loop state the failed-ends key does not describe.
    fn begins_iteration(&self, point: &MemoPoint, pos: usize) -> bool {
        point
            .live
            .iter()
            .any(|l| l.in_body && self.reg(l.reg).1 == pos as u32)
    }

    /// The first end of a repetition to try at or past `q`, moving down
    /// (`up` false) or up, skipping a range of ends already known to fail.
    fn skip_failed(&self, next: usize, q: usize, up: bool) -> usize {
        let Some((point, key)) = self.ends_key(next) else {
            return q;
        };
        if self.begins_iteration(point, q) {
            return q;
        }
        match self.failed_ends.get(&(next as u32, key)) {
            Some(&(a, b)) if (a as usize) <= q && q <= b as usize => {
                if up {
                    b as usize + 1
                } else {
                    (a as usize).wrapping_sub(1)
                }
            }
            _ => q,
        }
    }

    /// Records that every end `lo..=hi` of the repetition before `next`
    /// failed in the current loop state. A range next to or overlapping the
    /// one remembered extends it; otherwise it replaces it (start positions
    /// move forward, so the latest range is the useful one).
    fn record_failed(&mut self, next: usize, lo: usize, hi: usize) {
        let Some((point, key)) = self.ends_key(next) else {
            return;
        };
        let lo = if self.begins_iteration(point, lo) {
            lo + 1
        } else {
            lo
        };
        if lo > hi {
            return;
        }
        let (lo, hi) = (lo as u32, hi as u32);
        let slot = (next as u32, key);
        let merged = match self.failed_ends.get(&slot) {
            Some(&(a, b)) if lo <= b.saturating_add(1) && a <= hi.saturating_add(1) => {
                (a.min(lo), b.max(hi))
            }
            _ => (lo, hi),
        };
        if self.failed_ends.len() < MAX_HASHED_MEMO || self.failed_ends.contains_key(&slot) {
            self.failed_ends.insert(slot, merged);
        }
    }

    /// Where the run of characters `node` matches from `pos` ends, looking
    /// no further than `limit`: the first position at or past `pos` that
    /// `node` does not match, or `limit`. Each character is charged a step
    /// the first time it is scanned; a run already scanned is answered from
    /// [`Search::runs`]. `None` when the step budget runs out.
    fn run_end(&mut self, pc: usize, node: &Node, pos: usize, limit: usize) -> Option<usize> {
        let (first, end, stops) = self.runs.get(pc).copied().unwrap_or((u32::MAX, 0, false));
        let (first, end) = (first as usize, end as usize);
        // Characters `first..end` are known to match, so from `pos` inside
        // that range the run reaches at least `end`.
        let known = first <= pos && pos <= end;
        let (from, mut q) = if known {
            if stops || end >= limit {
                return Some(end.min(limit));
            }
            (first, end)
        } else {
            (pos, pos)
        };
        let mut ends_here = false;
        while q < limit {
            // A scan from before the known run that reaches it continues
            // from its end (backtracking moves start positions backwards).
            if !known && q == first {
                if stops && end <= limit {
                    q = end;
                    ends_here = true;
                    break;
                }
                q = end.min(limit);
                continue;
            }
            if !self.re.match_one(node, &self.chars, q) {
                ends_here = true;
                break;
            }
            if !self.charge() {
                return None;
            }
            q += 1;
        }
        let stops = ends_here || q == self.chars.len();
        if let Some(slot) = self.runs.get_mut(pc) {
            *slot = (from as u32, q as u32, stops);
        }
        Some(q)
    }

    /// Runs the program from `start`. A search that ends without a match
    /// leaves every capture and register as it found them.
    fn run(&mut self, start: usize) -> Outcome {
        self.run_at(0, start, 0, false)
    }

    // Assertion programs are structurally nested (parser depth <= 64),
    // and all share the outer search's steps and explicit stack limit.
    fn run_at(&mut self, mut pc: usize, mut pos: usize, floor: usize, reverse: bool) -> Outcome {
        loop {
            if !self.charge() {
                return Outcome::Limit(SearchLimit::Steps);
            }
            let next = if self.seen_before(pc, pos) {
                Step::Fail
            } else {
                self.exec(pc, pos, reverse)
            };
            match next {
                Step::Go(p, q) => {
                    pc = p;
                    pos = q;
                }
                Step::Match(end) => return Outcome::Match(end),
                Step::Limit(limit) => return Outcome::Limit(limit),
                Step::Fail => match self.backtrack(floor) {
                    Some((p, q)) => {
                        pc = p;
                        pos = q;
                    }
                    None => return Outcome::NoMatch,
                },
            }
        }
    }

    fn look(
        &mut self,
        pc: usize,
        pos: usize,
        end: usize,
        negated: bool,
        reverse: bool,
        captures: (usize, usize),
    ) -> Step {
        let floor = self.stack.len();
        match self.run_at(pc + 1, pos, floor, reverse) {
            Outcome::Limit(limit) => Step::Limit(limit),
            Outcome::NoMatch if negated => Step::Go(end, pos),
            Outcome::NoMatch => Step::Fail,
            Outcome::Match(_) => {
                let carried = if negated {
                    Vec::new()
                } else {
                    self.caps[captures.0..captures.1].to_vec()
                };
                self.unwind(floor);
                if negated {
                    return Step::Fail;
                }
                for (n, value) in (captures.0..captures.1).zip(carried) {
                    if !self.charge() {
                        return Step::Limit(SearchLimit::Steps);
                    }
                    if self.caps[n] != value && !self.set_cap(n, value) {
                        return Step::Limit(SearchLimit::Backtrack);
                    }
                }
                Step::Go(end, pos)
            }
        }
    }

    fn backreference(&mut self, next: usize, n: usize, pos: usize, reverse: bool) -> Step {
        let Some((start, end)) = self.caps[n] else {
            return Step::Go(next, pos);
        };
        let len = end - start;
        let candidate = if reverse {
            pos.checked_sub(len).map(|from| (from, pos))
        } else {
            pos.checked_add(len).map(|to| (pos, to))
        };
        let Some((from, to)) = candidate.filter(|&(_, to)| to <= self.chars.len()) else {
            return Step::Fail;
        };
        for (a, b) in (start..end).zip(from..to) {
            if !self.charge() {
                return Step::Limit(SearchLimit::Steps);
            }
            if self.re.case.canon(self.chars[a]) != self.re.case.canon(self.chars[b]) {
                return Step::Fail;
            }
        }
        Step::Go(next, if reverse { from } else { to })
    }

    fn exec(&mut self, pc: usize, pos: usize, reverse: bool) -> Step {
        let re = self.re;
        let Some(inst) = re.prog.get(pc) else {
            return Step::Fail;
        };
        let ok = |pushed: bool, next: Step| {
            if pushed {
                next
            } else {
                Step::Limit(SearchLimit::Backtrack)
            }
        };
        match inst {
            Inst::One(node) => {
                let Some(at) = (if reverse {
                    pos.checked_sub(1)
                } else {
                    Some(pos)
                }) else {
                    return Step::Fail;
                };
                if re.match_one(node, &self.chars, at) {
                    Step::Go(pc + 1, if reverse { at } else { at + 1 })
                } else {
                    Step::Fail
                }
            }
            Inst::Look {
                end,
                negated,
                reverse,
                captures,
            } => self.look(pc, pos, *end, *negated, *reverse, *captures),
            Inst::BackRef(n) => self.backreference(pc + 1, *n, pos, reverse),
            Inst::Assert(node) => {
                if self.assertion_holds(node, pos) {
                    Step::Go(pc + 1, pos)
                } else {
                    Step::Fail
                }
            }
            Inst::Split { first, second } => ok(
                self.push(Backtrack::Choice {
                    pc: *second as u32,
                    pos: pos as u32,
                }),
                Step::Go(*first, pos),
            ),
            Inst::Jump(to) => Step::Go(*to, pos),
            Inst::Open(n) => {
                let at = self.open.get(*n).copied().unwrap_or(0) as u32;
                let pushed = self.push(Backtrack::Open { n: *n as u32, at });
                if let Some(slot) = self.open.get_mut(*n) {
                    *slot = pos;
                }
                ok(pushed, Step::Go(pc + 1, pos))
            }
            Inst::Close(n) => {
                let from = self.open.get(*n).copied().unwrap_or(pos);
                ok(
                    self.set_cap(*n, Some((from.min(pos), from.max(pos)))),
                    Step::Go(pc + 1, pos),
                )
            }
            Inst::RepeatOne {
                node,
                min,
                max,
                lazy,
                cap,
            } => {
                // The repetition may end anywhere in `lo..=hi`: past its
                // minimum and within the run of characters it matches.
                let len = self.chars.len();
                let lo = pos.saturating_add(*min as usize);
                if lo > len {
                    return Step::Fail;
                }
                let limit = if *max == u32::MAX {
                    len
                } else {
                    pos.saturating_add(*max as usize).min(len)
                };
                let Some(hi) = self.run_end(pc, node, pos, limit) else {
                    return Step::Limit(SearchLimit::Steps);
                };
                if hi < lo {
                    return Step::Fail;
                }
                if hi == lo {
                    return self.took(*cap, pos, lo, Step::Go(pc + 1, lo));
                }
                // Greedy tries the ends longest first, lazy shortest first;
                // either way an end already known to fail is skipped.
                let next = pc + 1;
                let first = if *lazy {
                    self.skip_failed(next, lo, true)
                } else {
                    self.skip_failed(next, hi, false)
                };
                if first < lo || first > hi {
                    return Step::Fail;
                }
                // One entry either way: the remaining ends, or, when this is
                // the last, a note to remember that it failed.
                let entry = match (*lazy, first) {
                    (true, q) if q < hi => Backtrack::Lazy {
                        pc: pc as u32,
                        cur: q as u32,
                        hi: hi as u32,
                    },
                    (false, q) if q > lo => Backtrack::Greedy {
                        pc: pc as u32,
                        lo: lo as u32,
                        cur: q as u32,
                    },
                    (_, q) => Backtrack::Failed {
                        next: next as u32,
                        lo: q as u32,
                        hi: q as u32,
                    },
                };
                if !self.push(entry) {
                    return Step::Limit(SearchLimit::Backtrack);
                }
                self.took(*cap, pos, first, Step::Go(next, first))
            }
            Inst::LoopInit(reg) => {
                let start = self.reg(*reg).1;
                ok(self.set_reg(*reg, (0, start)), Step::Go(pc + 1, pos))
            }
            Inst::LoopHead {
                reg,
                min,
                max,
                lazy,
                exit,
            } => {
                let count = self.reg(*reg).0;
                if count < *min {
                    Step::Go(pc + 1, pos)
                } else if count >= *max {
                    Step::Go(*exit, pos)
                } else if *lazy {
                    let entry = Backtrack::Choice {
                        pc: (pc + 1) as u32,
                        pos: pos as u32,
                    };
                    ok(self.push(entry), Step::Go(*exit, pos))
                } else {
                    let entry = Backtrack::Choice {
                        pc: *exit as u32,
                        pos: pos as u32,
                    };
                    ok(self.push(entry), Step::Go(pc + 1, pos))
                }
            }
            Inst::IterStart { reg, caps } => {
                let count = self.reg(*reg).0.saturating_add(1);
                if !self.set_reg(*reg, (count, pos as u32)) {
                    return Step::Limit(SearchLimit::Backtrack);
                }
                for n in caps.0..caps.1 {
                    if self.caps.get(n).copied().flatten().is_some() && !self.set_cap(n, None) {
                        return Step::Limit(SearchLimit::Backtrack);
                    }
                }
                Step::Go(pc + 1, pos)
            }
            Inst::LoopEnd { reg, min, head } => {
                let (count, start) = self.reg(*reg);
                if count > *min && pos as u32 == start {
                    Step::Fail
                } else {
                    Step::Go(*head, pos)
                }
            }
            Inst::Match => Step::Match(pos),
        }
    }

    /// A `RepeatOne` whose atom is capturing group `cap` that began at
    /// `from` now ends at `to`: after one iteration or more the group holds
    /// the last character taken; after none it keeps what it held.
    fn took(&mut self, cap: Option<usize>, from: usize, to: usize, next: Step) -> Step {
        match cap {
            Some(n) if to > from => {
                if self.set_cap(n, Some((to - 1, to))) {
                    next
                } else {
                    Step::Limit(SearchLimit::Backtrack)
                }
            }
            _ => next,
        }
    }

    /// The capturing group of the `RepeatOne` at `pc`, and its minimum.
    fn repeat_cap(&self, pc: usize) -> (Option<usize>, u32) {
        match self.re.prog.get(pc) {
            Some(Inst::RepeatOne { cap, min, .. }) => (*cap, *min),
            _ => (None, 0),
        }
    }

    fn assertion_holds(&self, node: &Node, pos: usize) -> bool {
        let before = pos.checked_sub(1).and_then(|i| self.chars.get(i)).copied();
        let after = self.chars.get(pos).copied();
        match node {
            Node::Start => before.is_none_or(|c| self.re.multiline && is_line_terminator(c)),
            Node::End => after.is_none_or(|c| self.re.multiline && is_line_terminator(c)),
            Node::WordBoundary | Node::NotWordBoundary => {
                let before = before.is_some_and(|c| self.re.is_word(c));
                let after = after.is_some_and(|c| self.re.is_word(c));
                (before != after) == matches!(node, Node::WordBoundary)
            }
            _ => false,
        }
    }

    /// [`Search::took`] on the way back, for a later end `to` of the
    /// repetition that began at `from`. It pushes without the cap's check:
    /// the stack holds at most one entry more than before the repetition's
    /// own entry was popped, and the next step forward checks the cap.
    fn retake(&mut self, cap: Option<usize>, from: usize, to: usize) {
        if let (Some(n), true) = (cap, to > from) {
            let old = self.caps.get(n).copied().flatten();
            let (start, end) = old.map_or((UNSET, UNSET), |(a, b)| (a as u32, b as u32));
            self.stack.push(Backtrack::Cap {
                n: n as u32,
                start,
                end,
            });
            if let Some(slot) = self.caps.get_mut(n) {
                *slot = Some((to - 1, to));
            }
        }
    }

    /// Undoes state changes back to the most recent place to resume, and
    /// returns it; `None` when nothing is left to try.
    fn backtrack(&mut self, floor: usize) -> Option<(usize, usize)> {
        while self.stack.len() > floor {
            let entry = self.stack.pop()?;
            match entry {
                Backtrack::Choice { pc, pos } => return Some((pc as usize, pos as usize)),
                // The end `cur` has just failed, and the ends between it and
                // the next one to try are already known to: remember them
                // together, then try the next end.
                Backtrack::Greedy { pc, lo, cur } => {
                    let (next, lo, cur) = (pc as usize + 1, lo as usize, cur as usize);
                    let q = self.skip_failed(next, cur - 1, false);
                    if q < lo || q == usize::MAX {
                        self.record_failed(next, lo, cur);
                        continue;
                    }
                    self.record_failed(next, q + 1, cur);
                    self.stack.push(if q > lo {
                        Backtrack::Greedy {
                            pc,
                            lo: lo as u32,
                            cur: q as u32,
                        }
                    } else {
                        Backtrack::Failed {
                            next: next as u32,
                            lo: q as u32,
                            hi: q as u32,
                        }
                    });
                    // The repetition began at `lo - min`.
                    let (cap, min) = self.repeat_cap(pc as usize);
                    self.retake(cap, lo - min as usize, q);
                    return Some((next, q));
                }
                Backtrack::Lazy { pc, cur, hi } => {
                    let (next, cur, hi) = (pc as usize + 1, cur as usize, hi as usize);
                    let q = self.skip_failed(next, cur + 1, true);
                    if q > hi {
                        self.record_failed(next, cur, hi);
                        continue;
                    }
                    self.record_failed(next, cur, q - 1);
                    self.stack.push(if q < hi {
                        Backtrack::Lazy {
                            pc,
                            cur: q as u32,
                            hi: hi as u32,
                        }
                    } else {
                        Backtrack::Failed {
                            next: next as u32,
                            lo: q as u32,
                            hi: q as u32,
                        }
                    });
                    // A later end than `cur`, so at least one iteration.
                    let (cap, _) = self.repeat_cap(pc as usize);
                    self.retake(cap, cur, q);
                    return Some((next, q));
                }
                Backtrack::Failed { next, lo, hi } => {
                    self.record_failed(next as usize, lo as usize, hi as usize);
                }
                state => self.undo(state),
            }
        }
        None
    }

    fn unwind(&mut self, floor: usize) {
        while self.stack.len() > floor {
            if let Some(entry) = self.stack.pop() {
                self.undo(entry);
            }
        }
    }

    fn undo(&mut self, entry: Backtrack) {
        match entry {
            Backtrack::Loop { reg, count, start } => {
                if let Some(slot) = self.regs.get_mut(reg as usize) {
                    *slot = (count, start);
                }
            }
            Backtrack::Open { n, at } => {
                if let Some(slot) = self.open.get_mut(n as usize) {
                    *slot = at as usize;
                }
            }
            Backtrack::Cap { n, start, end } => {
                if let Some(slot) = self.caps.get_mut(n as usize) {
                    *slot = (start != UNSET).then_some((start as usize, end as usize));
                }
            }
            _ => {}
        }
    }
}

/// Hashes a memo state (three small integers) with one multiply per word:
/// the default hasher's resistance to chosen keys buys nothing here.
#[derive(Default)]
struct StateHasher(u64);

impl std::hash::Hasher for StateHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

/// What executing one instruction leads to.
enum Step {
    Go(usize, usize),
    Fail,
    Match(usize),
    Limit(SearchLimit),
}

impl Regex {
    /// Does the pattern match anywhere in `input`?
    ///
    /// A search that reaches a [`SearchLimit`] answers `false`, the same as
    /// no match. Use [`Regex::try_is_match`] wherever that would be a wrong
    /// answer.
    pub fn is_match(&self, input: &str) -> bool {
        self.find(input).is_some()
    }

    /// Does the pattern match anywhere in `input`? `Err` when the search
    /// reached a [`SearchLimit`] before it could tell.
    pub fn try_is_match(&self, input: &str) -> Result<bool, SearchLimit> {
        Ok(self.try_find_captures(input)?.is_some())
    }

    /// First match: (char start, char end) over the char vector.
    ///
    /// A search that reaches a [`SearchLimit`] answers `None`, the same as
    /// no match. Use [`Regex::try_find`] wherever that would be a wrong
    /// answer.
    pub fn find(&self, input: &str) -> Option<(usize, usize)> {
        self.find_captures(input).map(|c| (c.start, c.end))
    }

    /// First match: (char start, char end) over the char vector. `Err` when
    /// the search reached a [`SearchLimit`] before it could tell.
    pub fn try_find(&self, input: &str) -> Result<Option<(usize, usize)>, SearchLimit> {
        Ok(self.try_find_captures(input)?.map(|c| (c.start, c.end)))
    }

    /// First match with capture groups. `groups[0]` is the whole match;
    /// non-participating groups are `None`.
    ///
    /// A search that reaches a [`SearchLimit`] answers `None`, the same as
    /// no match. Use [`Regex::try_find_captures`] wherever that would be a
    /// wrong answer.
    pub fn find_captures(&self, input: &str) -> Option<Captures> {
        self.try_find_captures(input).ok().flatten()
    }

    /// First match with capture groups, as [`Regex::find_captures`]; `Err`
    /// when the search reached a [`SearchLimit`] before it could tell
    /// whether, or where, the pattern matches.
    pub fn try_find_captures(&self, input: &str) -> Result<Option<Captures>, SearchLimit> {
        if let Some(literal) = &self.literal {
            // A sticky pattern (the only plain text that is anchored) is
            // tried at the start only.
            let found = if self.anchored {
                input.starts_with(literal.as_str()).then_some(0)
            } else {
                input.find(literal.as_str())
            };
            let Some(at) = found else {
                return Ok(None);
            };
            let start = input.get(..at).map_or(0, |before| before.chars().count());
            return Ok(Some(Captures {
                groups: vec![Some(literal.clone())],
                start,
                end: start + literal.chars().count(),
            }));
        }
        if let Some(required) = &self.required {
            if !input.contains(required.as_str()) {
                return Ok(None);
            }
        }
        let chars: Vec<char> = input.chars().collect();
        // Positions live in u32 on the backtracking stack.
        if chars.len() >= UNSET as usize {
            return Err(SearchLimit::InputLength);
        }
        let width = chars.len() as u64 + 1;
        let mut dense_bits = 0u64;
        let dense_at = self
            .memo
            .iter()
            .map(|point| {
                let need = point.states.saturating_mul(width);
                (dense_bits.saturating_add(need) <= MAX_DENSE_MEMO_BITS).then(|| {
                    dense_bits += need;
                    dense_bits - need
                })
            })
            .collect();
        let states = self
            .memo
            .iter()
            .fold(0u64, |sum, point| sum.saturating_add(point.states));
        let per_char = STEPS_PER_CHAR
            .saturating_add(self.prog.len() as u64)
            .saturating_add(states)
            .min(MAX_STEPS_PER_CHAR);
        let mut search = Search {
            re: self,
            chars,
            caps: vec![None; self.n_caps + 1],
            open: vec![0; self.n_caps + 1],
            regs: vec![(0, 0); self.n_regs],
            stack: Vec::new(),
            dense_at,
            dense: vec![0; dense_bits.div_ceil(64) as usize],
            hashed: Default::default(),
            runs: vec![(u32::MAX, 0, false); self.prog.len()],
            failed_ends: Default::default(),
            steps: MATCH_STEPS.saturating_add(per_char.saturating_mul(width)),
        };
        // A state that failed from one start position fails from every later
        // one (captures never decide the outcome), so the remembered states
        // and failed ends carry over from start to start.
        let last = if self.anchored { 0 } else { search.chars.len() };
        for start in 0..=last {
            match search.run(start) {
                Outcome::Match(end) => {
                    let chars = &search.chars;
                    let groups = std::iter::once(Some((start, end)))
                        .chain(search.caps.iter().skip(1).copied())
                        .map(|s| {
                            s.and_then(|(a, b)| {
                                chars.get(a..b).map(|cs| cs.iter().collect::<String>())
                            })
                        })
                        .collect();
                    return Ok(Some(Captures { groups, start, end }));
                }
                Outcome::NoMatch => {}
                Outcome::Limit(limit) => return Err(limit),
            }
        }
        Ok(None)
    }

    /// Whether `c` is a word character for `\w` and `\b`: the basic ones,
    /// and under `i` and `u` together also those that fold into them (`ſ`
    /// and the Kelvin sign), as JavaScript's WordCharacters has it.
    fn is_word(&self, c: char) -> bool {
        is_word(c) || (self.case == Case::Fold && is_word(simple_fold(c)))
    }

    fn match_one(&self, node: &Node, chars: &[char], pos: usize) -> bool {
        let Some(&c) = chars.get(pos) else {
            return false;
        };
        let case = self.case;
        match node {
            Node::Char(p) => case.canon(*p) == case.canon(c),
            Node::AnyChar => self.dot_all || !is_line_terminator(c),
            Node::Class { neg, items } => {
                // A class contains `c` when one of its members has `c`'s
                // canonical form. For a literal member that is one
                // comparison; for a range it is whether any character with
                // that form lies in the range (`[Ā-ɏ]` holds `ſ`, so under
                // `iu` it contains `s` and `S`), and the characters with one
                // form are few (at most [`CASE_CLASS_MAX`]). `\d`, `\w` and
                // `\s` hold every case form of their members already.
                let canon = case.canon(c);
                let mut forms = None;
                let mut hit = false;
                for item in items {
                    hit = match item {
                        ClassItem::Char(p) => case.canon(*p) == canon,
                        ClassItem::Range(lo, hi) => {
                            let (class_forms, n) = *forms.get_or_insert_with(|| case.class(canon));
                            class_forms.iter().take(n).any(|f| lo <= f && f <= hi)
                        }
                        ClassItem::Digit(n) => c.is_ascii_digit() != *n,
                        ClassItem::Word(n) => self.is_word(c) != *n,
                        ClassItem::Space(n) => is_space(c) != *n,
                    };
                    if hit {
                        break;
                    }
                }
                hit != *neg
            }
            _ => false,
        }
    }
}

/// The most characters that share one canonical form, under either rule:
/// four (`Θ θ ϑ ϴ` fold together; `Ι ι ͅ ι` uppercase to `Ι`).
const CASE_CLASS_MAX: usize = 4;

/// JavaScript's Canonicalize without the `u` flag, for every UTF-16 code
/// unit it changes: the unit's uppercase (String.prototype.toUpperCase),
/// unless that is more than one unit or turns a non-ASCII unit into an ASCII
/// one. Encoded as runs like [`FOLD_RUNS`]. Generated from Node 26's
/// `toUpperCase` (Unicode 17); only code points below U+10000 appear, since
/// to JavaScript without `u` a character above that is two code units,
/// which have no case.
const CANON_RUNS: &[(u32, u16, u8, i32)] = &[
    (0x0061, 26, 1, -32), (0x00B5, 1, 1, 743), (0x00E0, 23, 1, -32), (0x00F8, 7, 1, -32),
    (0x00FF, 1, 1, 121), (0x0101, 24, 2, -1), (0x0133, 3, 2, -1), (0x013A, 8, 2, -1),
    (0x014B, 23, 2, -1), (0x017A, 3, 2, -1), (0x0180, 1, 1, 195), (0x0183, 2, 2, -1),
    (0x0188, 1, 1, -1), (0x018C, 1, 1, -1), (0x0192, 1, 1, -1), (0x0195, 1, 1, 97),
    (0x0199, 1, 1, -1), (0x019A, 1, 1, 163), (0x019B, 1, 1, 42561), (0x019E, 1, 1, 130),
    (0x01A1, 3, 2, -1), (0x01A8, 1, 1, -1), (0x01AD, 1, 1, -1), (0x01B0, 1, 1, -1),
    (0x01B4, 2, 2, -1), (0x01B9, 1, 1, -1), (0x01BD, 1, 1, -1), (0x01BF, 1, 1, 56),
    (0x01C5, 1, 1, -1), (0x01C6, 1, 1, -2), (0x01C8, 1, 1, -1), (0x01C9, 1, 1, -2),
    (0x01CB, 1, 1, -1), (0x01CC, 1, 1, -2), (0x01CE, 8, 2, -1), (0x01DD, 1, 1, -79),
    (0x01DF, 9, 2, -1), (0x01F2, 1, 1, -1), (0x01F3, 1, 1, -2), (0x01F5, 1, 1, -1),
    (0x01F9, 20, 2, -1), (0x0223, 9, 2, -1), (0x023C, 1, 1, -1), (0x023F, 2, 1, 10815),
    (0x0242, 1, 1, -1), (0x0247, 5, 2, -1), (0x0250, 1, 1, 10783), (0x0251, 1, 1, 10780),
    (0x0252, 1, 1, 10782), (0x0253, 1, 1, -210), (0x0254, 1, 1, -206), (0x0256, 2, 1, -205),
    (0x0259, 1, 1, -202), (0x025B, 1, 1, -203), (0x025C, 1, 1, 42319), (0x0260, 1, 1, -205),
    (0x0261, 1, 1, 42315), (0x0263, 1, 1, -207), (0x0264, 1, 1, 42343), (0x0265, 1, 1, 42280),
    (0x0266, 1, 1, 42308), (0x0268, 1, 1, -209), (0x0269, 1, 1, -211), (0x026A, 1, 1, 42308),
    (0x026B, 1, 1, 10743), (0x026C, 1, 1, 42305), (0x026F, 1, 1, -211), (0x0271, 1, 1, 10749),
    (0x0272, 1, 1, -213), (0x0275, 1, 1, -214), (0x027D, 1, 1, 10727), (0x0280, 1, 1, -218),
    (0x0282, 1, 1, 42307), (0x0283, 1, 1, -218), (0x0287, 1, 1, 42282), (0x0288, 1, 1, -218),
    (0x0289, 1, 1, -69), (0x028A, 2, 1, -217), (0x028C, 1, 1, -71), (0x0292, 1, 1, -219),
    (0x029D, 1, 1, 42261), (0x029E, 1, 1, 42258), (0x0345, 1, 1, 84), (0x0371, 2, 2, -1),
    (0x0377, 1, 1, -1), (0x037B, 3, 1, 130), (0x03AC, 1, 1, -38), (0x03AD, 3, 1, -37),
    (0x03B1, 17, 1, -32), (0x03C2, 1, 1, -31), (0x03C3, 9, 1, -32), (0x03CC, 1, 1, -64),
    (0x03CD, 2, 1, -63), (0x03D0, 1, 1, -62), (0x03D1, 1, 1, -57), (0x03D5, 1, 1, -47),
    (0x03D6, 1, 1, -54), (0x03D7, 1, 1, -8), (0x03D9, 12, 2, -1), (0x03F0, 1, 1, -86),
    (0x03F1, 1, 1, -80), (0x03F2, 1, 1, 7), (0x03F3, 1, 1, -116), (0x03F5, 1, 1, -96),
    (0x03F8, 1, 1, -1), (0x03FB, 1, 1, -1), (0x0430, 32, 1, -32), (0x0450, 16, 1, -80),
    (0x0461, 17, 2, -1), (0x048B, 27, 2, -1), (0x04C2, 7, 2, -1), (0x04CF, 1, 1, -15),
    (0x04D1, 48, 2, -1), (0x0561, 38, 1, -48), (0x10D0, 43, 1, 3008), (0x10FD, 3, 1, 3008),
    (0x13F8, 6, 1, -8), (0x1C80, 1, 1, -6254), (0x1C81, 1, 1, -6253), (0x1C82, 1, 1, -6244),
    (0x1C83, 2, 1, -6242), (0x1C85, 1, 1, -6243), (0x1C86, 1, 1, -6236), (0x1C87, 1, 1, -6181),
    (0x1C88, 1, 1, 35266), (0x1C8A, 1, 1, -1), (0x1D79, 1, 1, 35332), (0x1D7D, 1, 1, 3814),
    (0x1D8E, 1, 1, 35384), (0x1E01, 75, 2, -1), (0x1E9B, 1, 1, -59), (0x1EA1, 48, 2, -1),
    (0x1F00, 8, 1, 8), (0x1F10, 6, 1, 8), (0x1F20, 8, 1, 8), (0x1F30, 8, 1, 8), (0x1F40, 6, 1, 8),
    (0x1F51, 4, 2, 8), (0x1F60, 8, 1, 8), (0x1F70, 2, 1, 74), (0x1F72, 4, 1, 86),
    (0x1F76, 2, 1, 100), (0x1F78, 2, 1, 128), (0x1F7A, 2, 1, 112), (0x1F7C, 2, 1, 126),
    (0x1FB0, 2, 1, 8), (0x1FBE, 1, 1, -7205), (0x1FD0, 2, 1, 8), (0x1FE0, 2, 1, 8),
    (0x1FE5, 1, 1, 7), (0x214E, 1, 1, -28), (0x2170, 16, 1, -16), (0x2184, 1, 1, -1),
    (0x24D0, 26, 1, -26), (0x2C30, 48, 1, -48), (0x2C61, 1, 1, -1), (0x2C65, 1, 1, -10795),
    (0x2C66, 1, 1, -10792), (0x2C68, 3, 2, -1), (0x2C73, 1, 1, -1), (0x2C76, 1, 1, -1),
    (0x2C81, 50, 2, -1), (0x2CEC, 2, 2, -1), (0x2CF3, 1, 1, -1), (0x2D00, 38, 1, -7264),
    (0x2D27, 1, 1, -7264), (0x2D2D, 1, 1, -7264), (0xA641, 23, 2, -1), (0xA681, 14, 2, -1),
    (0xA723, 7, 2, -1), (0xA733, 31, 2, -1), (0xA77A, 2, 2, -1), (0xA77F, 5, 2, -1),
    (0xA78C, 1, 1, -1), (0xA791, 2, 2, -1), (0xA794, 1, 1, 48), (0xA797, 10, 2, -1),
    (0xA7B5, 8, 2, -1), (0xA7C8, 2, 2, -1), (0xA7CD, 8, 2, -1), (0xA7F6, 1, 1, -1),
    (0xAB53, 1, 1, -928), (0xAB70, 80, 1, -38864), (0xFF41, 26, 1, -32),
];

/// Unicode simple case folding (CaseFolding.txt 17.0.0, statuses C and S):
/// every mapping, encoded as runs `(first, count, stride, delta)` meaning code
/// point `first + k*stride` (for `k < count`) folds to itself plus `delta`.
/// Runs are sorted by `first` and their spans never overlap. Generated from
/// the Unicode data file; multi-character (F) and Turkic (T) mappings are
/// deliberately absent, so `ß` folds to itself and `ı`/`İ` have no fold.
/// (Deliberately no formatter-skip attribute: the Core code gate refuses
/// unreviewed attributes.)
const FOLD_RUNS: &[(u32, u16, u8, i32)] = &[
    (0x0041, 26, 1, 32), (0x00B5, 1, 1, 775), (0x00C0, 23, 1, 32), (0x00D8, 7, 1, 32),
    (0x0100, 24, 2, 1), (0x0132, 3, 2, 1), (0x0139, 8, 2, 1), (0x014A, 23, 2, 1),
    (0x0178, 1, 1, -121), (0x0179, 3, 2, 1), (0x017F, 1, 1, -268), (0x0181, 1, 1, 210),
    (0x0182, 2, 2, 1), (0x0186, 1, 1, 206), (0x0187, 1, 1, 1), (0x0189, 2, 1, 205),
    (0x018B, 1, 1, 1), (0x018E, 1, 1, 79), (0x018F, 1, 1, 202), (0x0190, 1, 1, 203),
    (0x0191, 1, 1, 1), (0x0193, 1, 1, 205), (0x0194, 1, 1, 207), (0x0196, 1, 1, 211),
    (0x0197, 1, 1, 209), (0x0198, 1, 1, 1), (0x019C, 1, 1, 211), (0x019D, 1, 1, 213),
    (0x019F, 1, 1, 214), (0x01A0, 3, 2, 1), (0x01A6, 1, 1, 218), (0x01A7, 1, 1, 1),
    (0x01A9, 1, 1, 218), (0x01AC, 1, 1, 1), (0x01AE, 1, 1, 218), (0x01AF, 1, 1, 1),
    (0x01B1, 2, 1, 217), (0x01B3, 2, 2, 1), (0x01B7, 1, 1, 219), (0x01B8, 1, 1, 1),
    (0x01BC, 1, 1, 1), (0x01C4, 1, 1, 2), (0x01C5, 1, 1, 1), (0x01C7, 1, 1, 2), (0x01C8, 1, 1, 1),
    (0x01CA, 1, 1, 2), (0x01CB, 9, 2, 1), (0x01DE, 9, 2, 1), (0x01F1, 1, 1, 2), (0x01F2, 2, 2, 1),
    (0x01F6, 1, 1, -97), (0x01F7, 1, 1, -56), (0x01F8, 20, 2, 1), (0x0220, 1, 1, -130),
    (0x0222, 9, 2, 1), (0x023A, 1, 1, 10795), (0x023B, 1, 1, 1), (0x023D, 1, 1, -163),
    (0x023E, 1, 1, 10792), (0x0241, 1, 1, 1), (0x0243, 1, 1, -195), (0x0244, 1, 1, 69),
    (0x0245, 1, 1, 71), (0x0246, 5, 2, 1), (0x0345, 1, 1, 116), (0x0370, 2, 2, 1),
    (0x0376, 1, 1, 1), (0x037F, 1, 1, 116), (0x0386, 1, 1, 38), (0x0388, 3, 1, 37),
    (0x038C, 1, 1, 64), (0x038E, 2, 1, 63), (0x0391, 17, 1, 32), (0x03A3, 9, 1, 32),
    (0x03C2, 1, 1, 1), (0x03CF, 1, 1, 8), (0x03D0, 1, 1, -30), (0x03D1, 1, 1, -25),
    (0x03D5, 1, 1, -15), (0x03D6, 1, 1, -22), (0x03D8, 12, 2, 1), (0x03F0, 1, 1, -54),
    (0x03F1, 1, 1, -48), (0x03F4, 1, 1, -60), (0x03F5, 1, 1, -64), (0x03F7, 1, 1, 1),
    (0x03F9, 1, 1, -7), (0x03FA, 1, 1, 1), (0x03FD, 3, 1, -130), (0x0400, 16, 1, 80),
    (0x0410, 32, 1, 32), (0x0460, 17, 2, 1), (0x048A, 27, 2, 1), (0x04C0, 1, 1, 15),
    (0x04C1, 7, 2, 1), (0x04D0, 48, 2, 1), (0x0531, 38, 1, 48), (0x10A0, 38, 1, 7264),
    (0x10C7, 1, 1, 7264), (0x10CD, 1, 1, 7264), (0x13F8, 6, 1, -8), (0x1C80, 1, 1, -6222),
    (0x1C81, 1, 1, -6221), (0x1C82, 1, 1, -6212), (0x1C83, 2, 1, -6210), (0x1C85, 1, 1, -6211),
    (0x1C86, 1, 1, -6204), (0x1C87, 1, 1, -6180), (0x1C88, 1, 1, 35267), (0x1C89, 1, 1, 1),
    (0x1C90, 43, 1, -3008), (0x1CBD, 3, 1, -3008), (0x1E00, 75, 2, 1), (0x1E9B, 1, 1, -58),
    (0x1E9E, 1, 1, -7615), (0x1EA0, 48, 2, 1), (0x1F08, 8, 1, -8), (0x1F18, 6, 1, -8),
    (0x1F28, 8, 1, -8), (0x1F38, 8, 1, -8), (0x1F48, 6, 1, -8), (0x1F59, 4, 2, -8),
    (0x1F68, 8, 1, -8), (0x1F88, 8, 1, -8), (0x1F98, 8, 1, -8), (0x1FA8, 8, 1, -8),
    (0x1FB8, 2, 1, -8), (0x1FBA, 2, 1, -74), (0x1FBC, 1, 1, -9), (0x1FBE, 1, 1, -7173),
    (0x1FC8, 4, 1, -86), (0x1FCC, 1, 1, -9), (0x1FD3, 1, 1, -7235), (0x1FD8, 2, 1, -8),
    (0x1FDA, 2, 1, -100), (0x1FE3, 1, 1, -7219), (0x1FE8, 2, 1, -8), (0x1FEA, 2, 1, -112),
    (0x1FEC, 1, 1, -7), (0x1FF8, 2, 1, -128), (0x1FFA, 2, 1, -126), (0x1FFC, 1, 1, -9),
    (0x2126, 1, 1, -7517), (0x212A, 1, 1, -8383), (0x212B, 1, 1, -8262), (0x2132, 1, 1, 28),
    (0x2160, 16, 1, 16), (0x2183, 1, 1, 1), (0x24B6, 26, 1, 26), (0x2C00, 48, 1, 48),
    (0x2C60, 1, 1, 1), (0x2C62, 1, 1, -10743), (0x2C63, 1, 1, -3814), (0x2C64, 1, 1, -10727),
    (0x2C67, 3, 2, 1), (0x2C6D, 1, 1, -10780), (0x2C6E, 1, 1, -10749), (0x2C6F, 1, 1, -10783),
    (0x2C70, 1, 1, -10782), (0x2C72, 1, 1, 1), (0x2C75, 1, 1, 1), (0x2C7E, 2, 1, -10815),
    (0x2C80, 50, 2, 1), (0x2CEB, 2, 2, 1), (0x2CF2, 1, 1, 1), (0xA640, 23, 2, 1),
    (0xA680, 14, 2, 1), (0xA722, 7, 2, 1), (0xA732, 31, 2, 1), (0xA779, 2, 2, 1),
    (0xA77D, 1, 1, -35332), (0xA77E, 5, 2, 1), (0xA78B, 1, 1, 1), (0xA78D, 1, 1, -42280),
    (0xA790, 2, 2, 1), (0xA796, 10, 2, 1), (0xA7AA, 1, 1, -42308), (0xA7AB, 1, 1, -42319),
    (0xA7AC, 1, 1, -42315), (0xA7AD, 1, 1, -42305), (0xA7AE, 1, 1, -42308), (0xA7B0, 1, 1, -42258),
    (0xA7B1, 1, 1, -42282), (0xA7B2, 1, 1, -42261), (0xA7B3, 1, 1, 928), (0xA7B4, 8, 2, 1),
    (0xA7C4, 1, 1, -48), (0xA7C5, 1, 1, -42307), (0xA7C6, 1, 1, -35384), (0xA7C7, 2, 2, 1),
    (0xA7CB, 1, 1, -42343), (0xA7CC, 1, 1, 1), (0xA7CE, 1, 1, 1), (0xA7D0, 1, 1, 1),
    (0xA7D2, 2, 2, 1), (0xA7D6, 3, 2, 1),
    (0xA7DC, 1, 1, -42561), (0xA7F5, 1, 1, 1), (0xAB70, 80, 1, -38864), (0xFB05, 1, 1, 1),
    (0xFF21, 26, 1, 32), (0x10400, 40, 1, 40), (0x104B0, 36, 1, 40), (0x10570, 11, 1, 39),
    (0x1057C, 15, 1, 39), (0x1058C, 7, 1, 39), (0x10594, 2, 1, 39), (0x10C80, 51, 1, 64),
    (0x10D50, 22, 1, 32), (0x118A0, 32, 1, 32), (0x16E40, 32, 1, 32), (0x16EA0, 25, 1, 27),
    (0x1E900, 34, 1, 34),
];

/// Whether `cp` is a member of run `(first, count, stride, _)`.
fn run_member(cp: u32, (first, count, stride, _): (u32, u16, u8, i32)) -> bool {
    if cp < first {
        return false;
    }
    let off = cp - first;
    let stride = u32::from(stride);
    off.is_multiple_of(stride) && off / stride < u32::from(count)
}

/// Unicode simple case folding (CaseFolding.txt, statuses C and S), looked up
/// in [`FOLD_RUNS`]. Multi-character mappings are ignored, so `ß` (uppercase
/// `SS`) folds to itself, never to `s`; dotless `ı` and dotted `İ` have no
/// simple fold and stay distinct from `i`.
fn simple_fold(c: char) -> char {
    table_map(FOLD_RUNS, c)
}

/// The character `c` maps to in `table` (itself when no run holds it).
fn table_map(table: &[(u32, u16, u8, i32)], c: char) -> char {
    let cp = c as u32;
    // Last run starting at or before `cp`; spans never overlap, so it is the
    // only run that can contain `cp`.
    let idx = table.partition_point(|run| run.0 <= cp);
    let Some(&run) = idx.checked_sub(1).and_then(|i| table.get(i)) else {
        return c;
    };
    if !run_member(cp, run) {
        return c;
    }
    u32::try_from(i64::from(cp) + i64::from(run.3))
        .ok()
        .and_then(char::from_u32)
        .unwrap_or(c)
}

/// The class of `target` (which `table` maps to itself): `target` and
/// every character `table` maps onto it.
fn table_class(table: &[(u32, u16, u8, i32)], target: char) -> ([char; CASE_CLASS_MAX], usize) {
    let mut forms = [target; CASE_CLASS_MAX];
    let mut n = 1;
    for &run in table {
        let Ok(src) = u32::try_from(i64::from(target as u32) - i64::from(run.3)) else {
            continue;
        };
        if run_member(src, run) {
            if let (Some(x), Some(slot)) = (char::from_u32(src), forms.get_mut(n)) {
                *slot = x;
                n += 1;
            }
        }
    }
    (forms, n)
}

// `pub(crate)`: the package's harness (`harness/lib.rs`, outside the vendored
// tree) runs the long-line tests again on a small stack.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn basic_matching() {
        assert!(compile("h(ell)o", "").unwrap().is_match("hello"));
        assert!(compile("^ab+c$", "").unwrap().is_match("abbbc"));
        assert!(!compile("^ab+c$", "").unwrap().is_match("ac"));
        assert!(compile("[a-f]\\d{2,3}", "").unwrap().is_match("zzc42zz"));
        assert!(compile("HeLLo", "i").unwrap().is_match("hello"));
        assert!(compile("a|b", "").unwrap().is_match("xbx"));
        assert!(compile("\\bword\\b", "").unwrap().is_match("a word here"));
        assert!(!compile("\\bword\\b", "").unwrap().is_match("wordy"));
    }

    #[test]
    fn lookaround_and_backreferences_match_the_ecmascript_oracle() {
        fn check(pattern: &str, flags: &str, input: &str, expected: Option<&[Option<&str>]>) {
            let regex = compile(pattern, flags).unwrap_or_else(|| panic!("compile {pattern:?}"));
            let result = regex
                .try_find_captures(input)
                .unwrap()
                .map(|capture| capture.groups);
            let expected =
                expected.map(|groups| groups.iter().map(|part| part.map(str::to_owned)).collect());
            assert_eq!(result, expected, "pattern {pattern:?} on {input:?}");
        }
        check(r"^(?=aa)a+b$", "u", "aab", Some(&[Some("aab")]));
        check(r"^(?=aa)a+b$", "u", "ab", None);
        check(r"(?<!cat)dog", "u", "catdog a dog", Some(&[Some("dog")]));
        check(
            r"(?<=([ab]+)([bc]+))$",
            "u",
            "abc",
            Some(&[Some(""), Some("a"), Some("bc")]),
        );
        check(
            r"(?=(a+))a*b\1",
            "u",
            "baabac",
            Some(&[Some("aba"), Some("a")]),
        );
        check(
            r"^(a|(b))\2c$",
            "u",
            "ac",
            Some(&[Some("ac"), Some("a"), None]),
        );
        check(
            r"^(?<p>Ãb)-\k<p>$",
            "iu",
            "Ãb-ãB",
            Some(&[Some("Ãb-ãB"), Some("Ãb")]),
        );
        check(r"^(.)\1$", "u", "🐸🐸", Some(&[Some("🐸🐸"), Some("🐸")]));
        check(
            r"^(a|ab)\1$",
            "u",
            "abab",
            Some(&[Some("abab"), Some("ab")]),
        );
        check(r"(?<=\1(a))b", "u", "aab", Some(&[Some("b"), Some("a")]));
        check(r"^(?!(a))\1b$", "u", "b", Some(&[Some("b"), None]));
        check(r"(?=a(?=b))ab", "u", "zab", Some(&[Some("ab")]));
        check(r"^(?:(?=(a))a|b)+\1$", "u", "ab", Some(&[Some("ab"), None]));
    }

    #[test]
    fn hostile_patterns_do_not_hang() {
        // Catastrophic backtracking pattern: budget stops it.
        let r = compile("(a+)+$", "").unwrap();
        let _ = r.is_match(&"a".repeat(60));
        // Unsupported syntax rejected at compile time.
        assert!(compile("(?=lookahead", "").is_none());
        assert!(compile("back\\1ref", "u").is_none());
    }

    #[test]
    fn case_insensitive_classes_fold_single_characters_only() {
        // `ß` uppercases to the two characters `SS`; neither is a case
        // form of `ß` on its own.
        assert!(!compile("^[S]$", "i").unwrap().is_match("ß"));
        assert!(!compile("^[^ß]$", "i").unwrap().is_match("ß"));
        assert!(compile("^[s]$", "i").unwrap().is_match("S"));
        assert!(!compile("^[s]$", "i").unwrap().is_match("ß"));
        assert!(!compile("^[ß]$", "i").unwrap().is_match("s"));
    }

    /// Review finding: classes folded only the input character, so `[σ]`
    /// rejected `ς` and `[ẞ]` rejected `ß`. Both sides now go through one
    /// canonical form, in both directions, for classes, ranges and literals.
    /// `σ ς Σ` share one under either rule; `ẞ ß` and `ſ s` only under `u`'s
    /// simple case folding (JavaScript without `u` compares uppercase forms,
    /// and `ß` uppercases to two letters, `ſ` to ASCII).
    #[test]
    fn case_insensitive_matching_folds_both_sides() {
        for (pattern, input, without_u) in [
            ("^[σ]$", "ς", true),
            ("^[ς]$", "σ", true),
            ("^[Σ]$", "ς", true),
            ("^[ς]$", "Σ", true),
            ("^[ẞ]$", "ß", false),
            ("^[ß]$", "ẞ", false),
            ("^[ẞ-ẞ]$", "ß", false),
            ("^[σ-σ]$", "ς", true),
            ("^σ$", "ς", true),
            ("^ς$", "σ", true),
            ("^ẞ$", "ß", false),
            ("^ß$", "ẞ", false),
        ] {
            assert!(
                compile(pattern, "iu").unwrap().is_match(input),
                "{pattern} should match {input} under iu"
            );
            assert_eq!(
                compile(pattern, "i").unwrap().is_match(input),
                without_u,
                "{pattern} on {input} under i"
            );
            assert!(
                !compile(pattern, "").unwrap().is_match(input),
                "{pattern} is case-sensitive without i"
            );
        }
        for flags in ["i", "iu"] {
            assert!(!compile("^[^σ]$", flags).unwrap().is_match("ς"));
        }
        assert!(!compile("^[^ẞ]$", "iu").unwrap().is_match("ß"));
        assert!(compile("^[^ẞ]$", "i").unwrap().is_match("ß"));
        assert!(compile("^[s]$", "iu").unwrap().is_match("ſ"));
        assert!(!compile("^[s]$", "i").unwrap().is_match("ſ"));
        // Dotless ı and dotted İ have no simple fold onto i (review finding).
        for flags in ["i", "iu"] {
            for pattern in [
                "^i$", "^[i]$", "^I$", "^[I]$", "^[a-z]$", "^[A-Z]$", "^[h-j]$", "^i",
            ] {
                assert!(
                    !compile(pattern, flags).unwrap().is_match("ı"),
                    "{pattern} must not match ı"
                );
                assert!(
                    !compile(pattern, flags).unwrap().is_match("İ"),
                    "{pattern} must not match İ"
                );
            }
            assert!(!compile("^ı$", flags).unwrap().is_match("i"));
            assert!(!compile("^[ı]$", flags).unwrap().is_match("I"));
            assert!(compile("^[i]$", flags).unwrap().is_match("I"));
            assert!(compile("^[^I]$", flags).unwrap().is_match("İ"));
        }
        // Every CaseFolding C/S mapping whose target is not the plain
        // single-character lowercase (Unicode 15 table).
        for (from, to) in [
            (0x00B5, 0x03BC),
            (0x017F, 0x0073),
            (0x0345, 0x03B9),
            (0x03C2, 0x03C3),
            (0x03D0, 0x03B2),
            (0x03D1, 0x03B8),
            (0x03D5, 0x03C6),
            (0x03D6, 0x03C0),
            (0x03F0, 0x03BA),
            (0x03F1, 0x03C1),
            (0x03F5, 0x03B5),
            (0x1C80, 0x0432),
            (0x1C81, 0x0434),
            (0x1C82, 0x043E),
            (0x1C83, 0x0441),
            (0x1C84, 0x0442),
            (0x1C85, 0x0442),
            (0x1C86, 0x044A),
            (0x1C87, 0x0463),
            (0x1C88, 0xA64B),
            (0x1E9B, 0x1E61),
            (0x1FBE, 0x03B9),
            (0x13F8, 0x13F0),
            (0x13FD, 0x13F5),
            (0xAB70, 0x13A0),
            (0xABBF, 0x13EF),
        ] {
            let (f, t) = (char::from_u32(from).unwrap(), char::from_u32(to).unwrap());
            assert_eq!(simple_fold(f), t, "fold of U+{from:04X}");
            assert!(
                compile(&format!("^[{t}]$"), "iu")
                    .unwrap()
                    .is_match(&f.to_string()),
                "[U+{to:04X}] ~ U+{from:04X}"
            );
            assert!(
                compile(&format!("^{f}$"), "iu")
                    .unwrap()
                    .is_match(&t.to_string()),
                "U+{from:04X} ~ U+{to:04X}"
            );
        }
        // Cherokee: both cases fold onto the uppercase letter.
        assert!(compile("^\u{13A0}$", "iu").unwrap().is_match("\u{AB70}"));
    }

    /// Review finding: ranges wider than 128 code points were only compared
    /// against the input's lower/upper forms, so `[Ā-ɏ]` (which contains `ſ`,
    /// folding to `s`) rejected `s` and `S` case-insensitively. Under `iu`
    /// every member of the fold class counts; under `i` alone neither `ſ` nor
    /// the Kelvin sign shares a form with ASCII, as in JavaScript.
    #[test]
    fn case_insensitive_wide_ranges_include_fold_variants() {
        let r = compile("^[\u{0100}-\u{024F}]$", "iu").unwrap();
        assert!(r.is_match("s"), "[Ā-ɏ] contains ſ, which folds to s");
        assert!(r.is_match("S"));
        assert!(!compile("^[\u{0100}-\u{024F}]$", "").unwrap().is_match("s"));
        assert!(!compile("^[\u{0100}-\u{024F}]$", "i").unwrap().is_match("s"));
        // Kelvin sign K (U+212A) folds to k: a wide range around it matches k/K.
        let kelvin = compile("^[\u{2000}-\u{21FF}]$", "iu").unwrap();
        assert!(kelvin.is_match("k") && kelvin.is_match("K"));
        assert!(!kelvin.is_match("j"));
        assert!(!compile("^[\u{2000}-\u{21FF}]$", "i").unwrap().is_match("k"));
        // And the other direction: a wide ASCII-containing range matches ſ and K.
        let ascii = compile("^[\u{0020}-\u{00FF}]$", "iu").unwrap();
        assert!(ascii.is_match("\u{017F}") && ascii.is_match("\u{212A}"));
        assert!(!ascii.is_match("\u{0131}"), "dotless ı has no simple fold");
        let ascii = compile("^[\u{0020}-\u{00FF}]$", "i").unwrap();
        assert!(!ascii.is_match("\u{017F}") && !ascii.is_match("\u{212A}"));
    }

    /// Review finding: `simple_fold` covered only a hand-picked subset of the
    /// Unicode simple folds, so e.g. U+1FD3 and U+0390 (which fold together)
    /// did not match each other case-insensitively.
    #[test]
    fn simple_fold_covers_the_complete_unicode_table() {
        for (a, b) in [
            (0x1FD3, 0x0390),
            (0x1FE3, 0x03B0),
            (0xFB05, 0xFB06),
            (0x1E9E, 0x00DF),
            (0x2126, 0x03C9),
            (0x1E921, 0x1E943),
        ] {
            let (a, b) = (char::from_u32(a).unwrap(), char::from_u32(b).unwrap());
            assert_eq!(
                simple_fold(a),
                simple_fold(b),
                "{a:?} and {b:?} share a fold"
            );
            assert!(compile(&format!("^{a}$"), "iu")
                .unwrap()
                .is_match(&b.to_string()));
            assert!(compile(&format!("^[{b}]$"), "iu")
                .unwrap()
                .is_match(&a.to_string()));
            assert!(!compile(&format!("^{a}$"), "i")
                .unwrap()
                .is_match(&b.to_string()));
        }
        // Table invariants, for both tables: sorted, non-overlapping spans,
        // idempotent mappings, and classes no larger than CASE_CLASS_MAX.
        for table in [FOLD_RUNS, CANON_RUNS] {
            let mut prev_end = 0u32;
            for &(first, count, stride, delta) in table {
                assert!(first >= prev_end, "runs overlap at U+{first:04X}");
                prev_end = first + (u32::from(count) - 1) * u32::from(stride) + 1;
                for k in 0..u32::from(count) {
                    let src = char::from_u32(first + k * u32::from(stride)).unwrap();
                    let dst =
                        char::from_u32((i64::from(src as u32) + i64::from(delta)) as u32).unwrap();
                    assert_eq!(table_map(table, src), dst);
                    assert_eq!(
                        table_map(table, dst),
                        dst,
                        "U+{:04X} does not map to itself",
                        dst as u32
                    );
                    let (forms, n) = table_class(table, dst);
                    assert!(forms[..n].contains(&src) && n <= CASE_CLASS_MAX);
                }
            }
        }
    }

    /// Review finding: `i` folded case by Unicode's simple case folding,
    /// which JavaScript uses only under the `u` flag; without it JavaScript
    /// compares uppercase forms, and only those that are one UTF-16 unit and
    /// do not turn a non-ASCII letter into an ASCII one. Captures under `i`
    /// were the lowercased text, at positions counted in it. Expected answers
    /// are Node's.
    #[test]
    fn case_insensitive_matching_follows_javascripts_rule_for_each_flag() {
        let find = |pattern: &str, flags: &str, input: &str| {
            compile(pattern, flags)
                .unwrap()
                .try_find(input)
                .unwrap()
                .is_some()
        };
        for (pattern, input, with_i, with_iu) in [
            ("^s$", "ſ", false, true),
            ("^k$", "\u{212A}", false, true),
            ("^[a-z]$", "\u{212A}", false, true),
            ("^ß$", "ẞ", false, true),
            ("^µ$", "Μ", true, true),
            ("^µ$", "μ", true, true),
            ("^ǅ$", "ǆ", true, true),
            ("^ǅ$", "Ǆ", true, true),
            ("^\\u0345$", "ι", true, true),
            ("^ϑ$", "Θ", true, true),
            ("^ϴ$", "θ", false, true),
            ("^Ω$", "\u{2126}", false, true),
            ("^Å$", "\u{212B}", false, true),
            ("^\u{10400}$", "\u{10428}", false, true),
            ("\\w", "ſ", false, true),
            ("^[\\w]$", "\u{212A}", false, true),
            ("\\W", "\u{212A}", true, false),
            ("a\\b", "aſ", true, false),
        ] {
            assert_eq!(
                find(pattern, "i", input),
                with_i,
                "/{pattern}/i on {input:?}"
            );
            assert_eq!(
                find(pattern, "iu", input),
                with_iu,
                "/{pattern}/iu on {input:?}"
            );
        }
        // The captured text is the input's, at the input's positions.
        let caps = compile("([a-z]+) (\\d+)", "i")
            .unwrap()
            .find_captures("Ticket 123")
            .unwrap();
        assert_eq!(caps.groups[1].as_deref(), Some("Ticket"));
        assert_eq!(compile("^i", "i").unwrap().find("İx"), None);
        let caps = compile("ÉTÉ", "i")
            .unwrap()
            .find_captures("un été")
            .unwrap();
        assert_eq!(
            (caps.start, caps.end, caps.groups[0].as_deref()),
            (3, 6, Some("été"))
        );
    }

    /// Review finding: the `m`, `s` and `y` flags were accepted and ignored,
    /// and any other letter was accepted as a flag. Expected answers are
    /// Node's.
    #[test]
    fn flags_m_s_and_y_act_as_in_javascript() {
        let find = |pattern: &str, flags: &str, input: &str| {
            compile(pattern, flags)
                .unwrap_or_else(|| panic!("/{pattern}/{flags} compiles"))
                .try_find_captures(input)
                .unwrap()
                .map(|c| (c.start, c.end, c.groups.get(1).cloned().flatten()))
        };
        let span = |a: usize, b: usize| Some((a, b, None));
        for (pattern, flags, input, want) in [
            ("^b", "", "a\nb", None),
            ("^b", "m", "a\nb", span(2, 3)),
            ("a$", "m", "a\r\nb", span(0, 1)),
            ("^$", "m", "a\n\nb", span(2, 2)),
            ("^b$", "m", "a\u{2028}b\u{2029}c", span(2, 3)),
            ("^\\w+$", "m", "a b\n\u{85}cd", None),
            ("^.+$", "m", "x\r\nabc", span(0, 1)),
            (
                "(?:^|,)(\\w+)$",
                "m",
                "a,b\nc,d",
                Some((1, 3, Some("b".to_string()))),
            ),
            ("a.b", "", "a\nb", None),
            ("a.b", "s", "a\nb", span(0, 3)),
            ("a.b", "s", "a\u{2028}b", span(0, 3)),
            ("^.+$", "s", "a\r\nb", span(0, 4)),
            ("^.+$", "ms", "a\r\nb", span(0, 4)),
            ("b", "y", "ab", None),
            ("a", "y", "ab", span(0, 1)),
            ("^b", "my", "a\nb", None),
            ("foo", "y", "xfoo", None),
            ("foo", "y", "foox", span(0, 3)),
            ("b", "g", "ab", span(1, 2)),
            ("a", "dgimsuy", "a", span(0, 1)),
        ] {
            assert_eq!(
                find(pattern, flags, input),
                want,
                "/{pattern}/{flags} on {input:?}"
            );
        }
        // JavaScript refuses an unknown or repeated flag; `v` changes the
        // class syntax, which this engine does not read.
        for flags in ["x", "ii", "I", "v", "iv"] {
            assert!(compile("a", flags).is_none(), "flags {flags:?} are refused");
        }
    }

    #[test]
    fn case_insensitive_classes_and_group_quantifiers_backtrack() {
        assert!(compile("^[A-Z]+$", "i").unwrap().is_match("hello"));
        assert!(compile("^[FOO]+$", "i").unwrap().is_match("fOo"));
        assert!(!compile("^[^A-Z]+$", "i").unwrap().is_match("hello"));

        let r = compile("^(a+)ab$", "").unwrap();
        let caps = r
            .find_captures("aaab")
            .expect("group quantifier backtracks");
        assert_eq!(caps.groups[0].as_deref(), Some("aaab"));
        assert_eq!(caps.groups[1].as_deref(), Some("aa"));

        let lazy = compile("^(a+?)$", "").unwrap();
        let caps = lazy
            .find_captures("aaa")
            .expect("lazy group quantifier expands");
        assert_eq!(caps.groups[1].as_deref(), Some("aaa"));
    }

    /// Review finding: a repeated group committed to the first branch that
    /// advanced in each iteration, so `^(ab|a)+b$` rejected `ab`.
    #[test]
    fn repeated_groups_backtrack_into_their_branches() {
        let r = compile("^(ab|a)+b$", "").unwrap();
        assert!(r.is_match("ab"));
        assert!(r.is_match("abab"));
        assert!(!r.is_match("aa"));
        let caps = r.find_captures("abab").unwrap();
        assert_eq!(caps.groups[0].as_deref(), Some("abab"));
        assert_eq!(
            caps.groups[1].as_deref(),
            Some("a"),
            "the last iteration took the shorter branch"
        );
        assert!(compile("^(a|ab){2}$", "").unwrap().is_match("abab"));
        assert!(!compile("^(a|ab){3}$", "").unwrap().is_match("abab"));
        assert!(compile("^(?:a|ab)+?c$", "").unwrap().is_match("ababc"));
        assert!(compile("^(?:x|xy)*z$", "").unwrap().is_match("xyxz"));
        assert!(compile("^(?:ab)+$", "")
            .unwrap()
            .is_match(&"ab".repeat(5_000)));
    }

    /// The answer (whole match and every group) as `[start, end, group 1, …]`.
    /// A search that ends on a bound fails the test: it has no answer.
    fn answer(pattern: &str, input: &str) -> Option<(usize, usize, Vec<Option<String>>)> {
        let found = compile(pattern, "").unwrap().try_find_captures(input);
        let caps = found.unwrap_or_else(|limit| panic!("{pattern} on {input:?}: {limit}"))?;
        Some((
            caps.start,
            caps.end,
            caps.groups.into_iter().skip(1).collect(),
        ))
    }

    fn groups(gs: &[Option<&str>]) -> Vec<Option<String>> {
        gs.iter().map(|g| g.map(str::to_string)).collect()
    }

    /// Review finding: captures inside a repeated group kept an earlier
    /// iteration's text, and some searches stopped at a shorter match, where
    /// JavaScript resets the captures of the repeated atom at the start of
    /// every iteration. Expected answers are JavaScript RegExp's.
    #[test]
    fn captures_inside_a_repeated_group_reset_on_every_iteration() {
        for (pattern, input, want) in [
            ("^(?:(a)|b)+$", "ab", Some((0, 2, groups(&[None])))),
            ("^(?:(a)|(b))+$", "ab", Some((0, 2, groups(&[None, Some("b")])))),
            ("(?:(a)|b){2}", "ab", Some((0, 2, groups(&[None])))),
            ("^(?:x(y)?)+$", "xyx", Some((0, 3, groups(&[None])))),
            ("^(?:a(?:(b)|c))+$", "abac", Some((0, 4, groups(&[None])))),
            ("(?:(a?)b)+", "ab b", Some((0, 2, groups(&[Some("a")])))),
            (
                "(z)((a+)?(b+)?(c))*",
                "zaacbbbcac",
                Some((0, 10, groups(&[Some("z"), Some("ac"), Some("a"), None, Some("c")]))),
            ),
            (
                "(a{1,2}?[ab](b{0,3}|[ab]+ba+){2}?|a?b{0,3}){2}",
                "aba",
                Some((0, 3, groups(&[Some("a"), None]))),
            ),
            (
                "(?:^(?:(([ab]*?)+c|.{2}b*?|bc{0,3}){0,3}))$",
                "accaaa",
                Some((0, 6, groups(&[Some("aa"), None]))),
            ),
            (
                "(((.*.)*){2}([ab]a+?|(.?.?|[ab]{0,3}.b+))[ab]{1,2}|b{2}){0,3}b{2}?",
                "bbbba",
                Some((0, 4, groups(&[Some("bb"), Some(""), None, Some(""), Some("")]))),
            ),
            (
                "^(?:a*(c*?|c?(?:c{1,2}?c??.|(?:a{1,2}[ab]??b?){1,2}b)?|(?:b(b?a+b{1,2}){1,2}b|(?:[ab]{2}|a[ab]{0,3}b)+){0,3}c+?b+)?)",
                "caaabc",
                Some((0, 1, groups(&[Some("c"), None]))),
            ),
        ] {
            assert_eq!(answer(pattern, input), want, "{pattern} on {input}");
        }
    }

    /// Searches through nested repetition used to run out of steps and
    /// answer no match where JavaScript finds one. Expected answers are
    /// JavaScript RegExp's.
    #[test]
    fn nested_repetition_finds_the_match_within_budget() {
        assert_eq!(
            answer(
                "(?:(?:.{1,2}?|[ab]{0,3}|c?.{0,3}?([ab]??(?:[ab]+a{0,3})*)){2}?(?:((?:a{2}|bb{2}?a+?)?[ab]*|[ab]b??)){2}|a)$",
                "bcbabc"
            ),
            Some((0, 6, groups(&[None, Some("")])))
        );
        assert_eq!(
            answer(
                "(?:a*([ab]{0,3}(?:c{0,3}(a+.+.){2}|a)(?:c[ab][ab]{0,3}?|.([ab]{2})?(aa{1,2}?|b??){1,2})*|b+?((?:a{2}|[ab]a{2}.)c)+){0,3}(?:((?:[ab])?(b+?|a?[ab]*?[ab])??|bb?a{2}?){1,2}?)+)$",
                "bcbac"
            ),
            Some((2, 5, groups(&[Some("bac"), None, None, Some(""), None, Some(""), None])))
        );
        // Exponential in a naive backtracker; the remembered failures keep it
        // polynomial, so the other branch is still reached.
        let input = "a".repeat(30);
        assert_eq!(
            compile("(?:(?:a|aa)+)+c|a", "").unwrap().try_find(&input),
            Ok(Some((0, 1)))
        );
        assert_eq!(
            compile("(?:(?:a|aa)+)+c|b|a$", "")
                .unwrap()
                .try_find(&input),
            Ok(Some((29, 30)))
        );
        // A finished search, not one that ran out of steps (which `is_match`
        // would also answer as false).
        let nested = compile("^(a+)+$", "").unwrap();
        assert_eq!(
            nested.try_is_match(&format!("{}b", "a".repeat(5_000))),
            Ok(false)
        );
        assert_eq!(nested.try_is_match(&"a".repeat(5_000)), Ok(true));
    }

    /// Review finding: characters were read by Rust's rules where JavaScript
    /// has its own. `.` matched a carriage return (so `^.*$` matched a CRLF
    /// line), `\w` and `\b` took non-ASCII letters, `\s` followed Rust's
    /// white space (U+0085 in, U+FEFF out), and inside a class `\x41`,
    /// `\b` and the other character escapes read as their letter. Expected
    /// answers are Node's RegExp's.
    #[test]
    fn characters_and_escapes_read_as_javascript_reads_them() {
        let find = |pattern: &str, flags: &str, input: &str| {
            compile(pattern, flags)
                .unwrap_or_else(|| panic!("{pattern} compiles"))
                .try_find(input)
                .unwrap()
        };
        let u41 = format!("A{}", "u".repeat(41));
        for (pattern, flags, input, want) in [
            (".", "", "\r\u{2028}\u{2029}\n\u{85}", Some((4, 5))),
            ("^.*$", "", "abc\r", None),
            ("^.*", "", "abc\rdef", Some((0, 3))),
            ("\\w+", "", "héllo", Some((0, 1))),
            ("\\bfoo", "", "éfoo", Some((1, 4))),
            ("\\s", "", "a\u{85}b\u{feff}c", Some((3, 4))),
            ("\\S+", "", "\u{85}\u{a0}", Some((0, 1))),
            ("[^\\x00-\\x7f]", "", "aé", Some((1, 2))),
            ("[\\b]", "", "a\u{8}", Some((1, 2))),
            ("\\x4", "", "x4", Some((0, 2))),
            ("\\u12", "", "u12", Some((0, 3))),
            ("\\u{41}", "", u41.as_str(), Some((1, 42))),
            ("\\u{41}", "u", "A", Some((0, 1))),
            ("\\cJ", "", "a\nb", Some((1, 2))),
            ("[\\cA-\\cZ]+", "", "a\u{1}\u{1a}", Some((1, 3))),
            ("\\012", "", "a\n", Some((1, 2))),
            ("[\\1]", "", "1\u{1}", Some((1, 2))),
            ("[a-\\d]+", "", "-a5b", Some((0, 3))),
            ("\\k", "", "k", Some((0, 1))),
        ] {
            assert_eq!(
                find(pattern, flags, input),
                want,
                "/{pattern}/{flags} on {input:?}"
            );
        }
        // JavaScript refuses a range out of order and a missing named group.
        // A Unicode property escape remains unsupported here.
        for (pattern, flags) in [("[z-a]", ""), ("\\k<n>(?<m>a)", "u"), ("\\p{L}", "u")] {
            assert!(
                compile(pattern, flags).is_none(),
                "/{pattern}/{flags} is refused"
            );
        }
    }

    /// Review finding: bounding recursion depth made a literal of more than
    /// about a thousand characters, and any line of more than about 200,000
    /// characters, answer no match. Matching is iterative now, and the step
    /// budget grows with the input. This test and the other long-line tests
    /// marked `pub(crate)` run again on a 256 KiB stack, no larger than a
    /// small wasm stack, in the package's harness (`harness/lib.rs`), which
    /// may spawn a thread where vendored source may not.
    #[test]
    pub(crate) fn long_literals_and_long_lines_match_on_a_small_stack() {
        let literal = "ab".repeat(100_000);
        let line = format!("xx{literal}yy");
        assert_eq!(
            compile(&literal, "").unwrap().find(&line),
            Some((2, 200_002))
        );
        // Case-insensitive literals take the general matcher.
        let upper = line.to_uppercase();
        assert_eq!(
            compile(&literal, "i").unwrap().find(&upper),
            Some((2, 200_002))
        );
        assert_eq!(
            compile(&format!("^xx{literal}yy$"), "")
                .unwrap()
                .find(&line),
            Some((0, 200_004))
        );
        // A literal that keeps almost matching along the whole line.
        let near = format!("{}b", "a".repeat(1_000));
        let line = format!("{}b", "a".repeat(300_000));
        assert_eq!(
            compile(&near, "").unwrap().find(&line),
            Some((299_000, 300_001))
        );
        let line = format!("{}foo", "x".repeat(300_000));
        for pattern in [
            ".*foo",
            "foo",
            "fo+",
            "x+foo",
            "(?:x|y)*foo",
            "^.*foo$",
            "^(?:x|y)+(f)oo$",
        ] {
            let found = compile(pattern, "").unwrap().find(&line);
            let want = if pattern.starts_with('f') {
                (300_000, 300_003)
            } else {
                (0, 300_003)
            };
            assert_eq!(found, Some(want), "{pattern}");
        }
        let line = format!("{}foo", "x".repeat(1_000_000));
        for pattern in [".*foo", "foo", "fo+", "^x*foo$"] {
            assert!(
                compile(pattern, "").unwrap().is_match(&line),
                "{pattern} on a million characters"
            );
        }
    }

    /// The parser refuses groups nested past MAX_GROUP_NESTING (its only
    /// recursion), and long repetitions match without deepening the stack.
    #[test]
    pub(crate) fn deep_patterns_are_refused_and_long_repetitions_match() {
        let nest = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
        assert!(compile(&nest(64), "").unwrap().is_match("a"));
        assert!(compile(&nest(65), "").is_none());
        assert!(compile(&nest(100_000), "").is_none());
        assert!(compile("^(?:ab)+$", "")
            .unwrap()
            .is_match(&"ab".repeat(50_000)));
        assert!(compile("^a*$", "").unwrap().is_match(&"a".repeat(50_000)));
        let exact = compile("^(?:a|ab)+c$", "").unwrap();
        assert!(exact.is_match(&format!("{}c", "ab".repeat(50))));
        assert!(exact.is_match(&format!("{}c", "ab".repeat(5_000))));
        assert!(!exact.is_match(&format!("{}a", "ab".repeat(5_000))));
        // Out-of-order counts are a syntax error in JavaScript.
        assert!(compile("a{3,1}", "").is_none());
    }

    /// Review finding: a search past the step budget or the backtracking
    /// stack's cap answered "no match", indistinguishable from a real one,
    /// so a repeated alternation silently missed a match on a line of 800,000
    /// characters. The `try_` forms report the bound instead; the plain forms
    /// keep answering no match, as documented.
    #[test]
    pub(crate) fn a_search_past_a_bound_reports_it() {
        // Each iteration of a repeated group of several characters
        // leaves a way back, so the stack fills long before the end of
        // the line, where it matches.
        let line = format!("{}foo", "xy".repeat(500_000));
        let re = compile("(xy|z)*foo", "").unwrap();
        assert_eq!(re.try_find(&line), Err(SearchLimit::Backtrack));
        assert_eq!(re.try_is_match(&line), Err(SearchLimit::Backtrack));
        assert!(matches!(
            re.try_find_captures(&line),
            Err(SearchLimit::Backtrack)
        ));
        assert_eq!(re.find(&line), None);
        assert!(!re.is_match(&line));
        // Below the bound the same search answers.
        let short = format!("{}foo", "xy".repeat(20_000));
        assert_eq!(re.try_find(&short), Ok(Some((0, 40_003))));
        // A repetition with a large count is quadratic: from each start
        // position it counts its iterations afresh, up to the bound, and a
        // count is part of the state, so nothing carries over between starts.
        let line = format!("ef{}eg", "ab".repeat(20_000));
        let re = compile("(?:ab|cd){1,5000}ef", "").unwrap();
        assert_eq!(re.try_find(&line), Err(SearchLimit::Steps));
        assert_eq!(re.find(&line), None);
        // A search that finishes inside its bounds answers, match or not.
        assert_eq!(re.try_find(&format!("ef{}eg", "ab".repeat(20))), Ok(None));
        assert_eq!(re.try_find("xxabef"), Ok(Some((2, 6))));
        assert_eq!(compile("foo", "").unwrap().try_find(&line), Ok(None));
        assert_eq!(compile("x", "").unwrap().try_find("ax"), Ok(Some((1, 2))));
        assert_eq!(
            SearchLimit::Steps.to_string(),
            "the regular expression ran out of search steps"
        );
    }

    /// Review finding: a repeated capturing group of single characters, such
    /// as `(x|y)*foo`, ran as a loop that left several ways back on the
    /// backtracking stack per iteration, so on a line of several hundred
    /// thousand characters the stack filled and the search had no answer.
    /// It now repeats as a single character does, with one way back for the
    /// whole run, and the group holds the last character taken. Expected
    /// answers are Node's.
    #[test]
    pub(crate) fn single_character_alternations_repeat_without_a_frame_per_iteration() {
        for (pattern, flags, input, want) in [
            (
                "(x|y)*foo",
                "",
                "xyxfoo",
                Some((0, 6, groups(&[Some("x")]))),
            ),
            (
                "(x|y)*?foo",
                "",
                "xyxfoo",
                Some((0, 6, groups(&[Some("x")]))),
            ),
            (
                "(x|y)+(x)foo",
                "",
                "xyxfoo",
                Some((0, 6, groups(&[Some("y"), Some("x")]))),
            ),
            ("(?:(a|b)*c)+", "", "abcbbcc", Some((0, 7, groups(&[None])))),
            (
                "((a|b)+)*c",
                "",
                "abac",
                Some((0, 4, groups(&[Some("aba"), Some("a")]))),
            ),
            (
                "(a|b){2,3}",
                "",
                "ababab",
                Some((0, 3, groups(&[Some("a")]))),
            ),
            (
                "(a|b){2,3}?b",
                "",
                "aaab",
                Some((0, 4, groups(&[Some("a")]))),
            ),
            ("(.)*", "s", "ab\n", Some((0, 3, groups(&[Some("\n")])))),
            ("^(x|y)*$", "", "", Some((0, 0, groups(&[None])))),
            ("(x|y)?z", "", "z", Some((0, 1, groups(&[None])))),
        ] {
            let caps = compile(pattern, flags)
                .unwrap()
                .try_find_captures(input)
                .unwrap();
            let got = caps.map(|c| (c.start, c.end, c.groups.into_iter().skip(1).collect()));
            assert_eq!(got, want, "/{pattern}/{flags} on {input:?}");
        }
        let n = 1_000_000;
        let xy = "xy".repeat(n / 2);
        let ends = format!("{xy}foo");
        let starts = format!("foo{xy}");
        for (pattern, input, want) in [
            (
                "(x|y)*foo",
                ends.as_str(),
                Some((0, n + 3, groups(&[Some("y")]))),
            ),
            ("(x|y)*?foo", &ends, Some((0, n + 3, groups(&[Some("y")])))),
            ("^(x|y)+foo$", &ends, Some((0, n + 3, groups(&[Some("y")])))),
            (
                "([xy])*(f)oo",
                &ends,
                Some((0, n + 3, groups(&[Some("y"), Some("f")]))),
            ),
            ("(x|y)*foo", &starts, Some((0, 3, groups(&[None])))),
            ("(x|y)*foo$", &starts, None),
            ("(x|y)+(?:z|w)", &xy, None),
        ] {
            let caps = compile(pattern, "").unwrap().try_find_captures(input);
            let got =
                caps.map(|c| c.map(|c| (c.start, c.end, c.groups.into_iter().skip(1).collect())));
            assert_eq!(got, Ok(want), "{pattern}");
        }
    }

    /// Review finding: everyday searches ran out of steps on ordinary long
    /// lines, because every start position scanned the rest of the line
    /// again (`.*foo` on a thousand characters, `\w+\s+foo` on three
    /// thousand) and `^(a+)+$` retried each split of the run. Failed states
    /// carry over between start positions, a run of characters is scanned
    /// once, ends of a repetition already known to fail are skipped together,
    /// and a pattern anchored at `^` is tried at the start only, so these
    /// finish in time linear in the line, with or without the text the
    /// pattern requires.
    #[test]
    pub(crate) fn everyday_searches_finish_on_long_lines() {
        let n = 1_000_000;
        let xs = "x".repeat(n);
        let words = {
            let mut s = String::new();
            let mut i = 0;
            while s.len() < n {
                s.push_str(["alpha", "beta_2", "gamma", "xfoo", "delta9"][i % 5]);
                s.push(if i % 7 == 0 { '\t' } else { ' ' });
                i += 1;
            }
            s
        };
        let a_then_b = format!("{}b", "a".repeat(n));
        for (pattern, input, want) in [
            // Without the required text: answered before the search.
            (".*foo", xs.as_str(), None),
            ("\\w+\\s+foo", xs.as_str(), None),
            // With it, the search itself must be linear.
            (".*foo$", &*format!("foo{xs}"), None),
            (".*?foo$", &*format!("foo{xs}"), None),
            ("x*foo$", &*format!("foo{xs}"), None),
            ("(?:x|y)*foo$", &*format!("foo{xs}"), None),
            ("(x+x+)+y", &*format!("y{xs}"), None),
            ("\\w+\\s+foo", words.as_str(), None),
            ("\\w+\\s+xfoo", words.as_str(), Some((13, 23))),
            ("\\b\\w+\\s+foo\\b", words.as_str(), None),
            ("(?:\\w+\\s)+foo", words.as_str(), None),
            ("^.*foo.*z$", words.as_str(), None),
            ("(.*) (.*)foo$", words.as_str(), None),
            ("^(a+)+$", a_then_b.as_str(), None),
            ("(a+)+$", a_then_b.as_str(), None),
            ("^(?:a+|b)+$", a_then_b.as_str(), Some((0, n + 1))),
        ] {
            assert_eq!(
                compile(pattern, "").unwrap().try_find(input),
                Ok(want),
                "{pattern}"
            );
        }
    }
}
