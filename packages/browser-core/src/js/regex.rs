//! regex — a small backtracking regular-expression engine for the page-script
//! subset that dominates real sites: literals, `.`, escapes (`\d \w \s` and
//! friends), character classes (ranges, negation), groups (capturing, named
//! and `(?:`), lookahead and lookbehind, backreferences, alternation,
//! anchors (`^ $ \b`, multiline with `m`), and the quantifiers `* + ? {n,m}`
//! (greedy and lazy). `i` compares case-insensitively against the ORIGINAL
//! text (captures keep their case); `s` lets `.` cross newlines.
//!
//! Panic-free and bounded: compilation rejects unsupported syntax with `None`
//! (callers degrade to "no match"), and matching charges a step budget so a
//! pathological pattern cannot hang the engine.

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
    /// `(?=…)` / `(?!…)`: zero-width, matches when the body matches (or
    /// fails to, when `neg`) at the current position.
    LookAhead { alts: Vec<Vec<Node>>, neg: bool },
    /// `(?<=…)` / `(?<!…)`: zero-width, matches when the body matches some
    /// span ENDING at the current position.
    LookBehind { alts: Vec<Vec<Node>>, neg: bool },
    /// `\n`: the text capture group `n` matched (empty when it did not
    /// participate).
    BackRef(usize),
    /// Runtime-only: the end of a capturing group's body. `Group` matching
    /// appends this marker (carrying the body's start) and then the REST of
    /// the pattern to the body, so a body whose quantifier chose too short
    /// or too long a span is retried when the tail fails — `/^(a+?)$/`
    /// must grow the lazy repeat until `$` matches.
    CapClose { cap: Option<usize>, start: usize },
}

#[derive(Clone, Debug)]
enum ClassItem {
    Char(char),
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
    /// `\p{L}` / `\P{L}`: letters (the Unicode property classes bundles
    /// actually use are letters and digits; anything else approximates to
    /// alphanumeric).
    Letter(bool),
    Alnum(bool),
}

/// Compiled regex: alternation of sequences.
pub struct Regex {
    alts: Vec<Vec<Node>>,
    case_insensitive: bool,
    multiline: bool,
    dot_all: bool,
    /// Number of capturing groups (group 0 = whole match not counted here).
    n_caps: usize,
    /// Group names by capture index (index 0 is the whole match, unnamed).
    names: Vec<Option<String>>,
}

/// Captured groups from a successful match. `groups[0]` is the whole match;
/// `groups[n]` is capture group n (None when the group did not participate).
pub struct Captures {
    pub groups: Vec<Option<String>>,
    /// Group names by capture index (`None` for unnamed groups and group 0).
    pub names: Vec<Option<String>>,
    /// Char index of the whole match start (for `String.replace` scanning).
    pub start: usize,
    /// Char index one past the whole match end.
    pub end: usize,
}

/// Compile `source` with JS-style `flags`: `i` (case-insensitive), `m`
/// (multiline anchors), `s` (dotAll) affect matching; `g`, `u`, `y`, `d`,
/// `v` are accepted and handled by the callers (`lastIndex`, stickiness).
pub fn compile(source: &str, flags: &str) -> Option<Regex> {
    let chars: Vec<char> = source.chars().collect();
    let mut p = Parser {
        chars,
        pos: 0,
        depth: 0,
        next_cap: 1,
        names: vec![None],
        forward_refs: Vec::new(),
        unicode: flags.contains('u') || flags.contains('v'),
    };
    let mut alts = p.parse_alternation()?;
    if p.pos != p.chars.len() {
        return None;
    }
    // Resolve forward named references now that every group is known: a
    // placeholder `BackRef(usize::MAX - k)` stands for forward ref k.
    if !p.forward_refs.is_empty() {
        let mut resolved: Vec<usize> = Vec::with_capacity(p.forward_refs.len());
        for (name, _) in &p.forward_refs {
            let idx = p
                .names
                .iter()
                .position(|n| n.as_deref() == Some(name.as_str()))?;
            resolved.push(idx);
        }
        for alt in alts.iter_mut() {
            resolve_forward_refs(alt, &resolved);
        }
    }
    Some(Regex {
        alts,
        case_insensitive: flags.contains('i'),
        multiline: flags.contains('m'),
        dot_all: flags.contains('s'),
        n_caps: p.next_cap - 1,
        names: p.names,
    })
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: u32,
    /// Next capturing-group index (1-based; 0 is the whole match).
    next_cap: usize,
    /// Group names by capture index.
    names: Vec<Option<String>>,
    /// `\k<name>` references seen before their group was declared, to be
    /// resolved once the whole pattern is parsed (the spec allows forward
    /// named references; an unmatched one is a syntax error).
    forward_refs: Vec<(String, usize)>,
    /// The `u` / `v` flag: `\p{…}` is a property escape only in Unicode
    /// mode; outside it `\p` is the identity escape for `p`.
    unicode: bool,
}

impl Parser {
    /// The code point of a `\u` escape whose `u` is already consumed:
    /// `\u{...}` or exactly four hex digits.
    fn unicode_escape(&mut self) -> Option<char> {
        let mut v = 0u32;
        if self.peek() == Some('{') {
            self.bump();
            while let Some(c) = self.bump() {
                if c == '}' {
                    break;
                }
                v = v.saturating_mul(16).saturating_add(c.to_digit(16)?);
            }
        } else {
            for _ in 0..4 {
                v = v
                    .saturating_mul(16)
                    .saturating_add(self.bump()?.to_digit(16)?);
            }
        }
        char::from_u32(v)
    }

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
                let mut n = String::new();
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    if let Some(c) = self.bump() {
                        n.push(c);
                    }
                }
                let min: u32 = match n.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        self.pos = save;
                        return Some(atom);
                    }
                };
                let max = match self.peek() {
                    Some(',') => {
                        self.bump();
                        let mut m = String::new();
                        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                            if let Some(c) = self.bump() {
                                m.push(c);
                            }
                        }
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
                (min, max)
            }
            _ => return Some(atom),
        };
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
                // (?:…), (?<name>…), (?=…), (?!…), (?<=…), (?<!…), or a
                // plain capturing group.
                let mut cap: Option<usize> = None;
                let mut look: Option<(bool, bool)> = None; // (behind, neg)
                if self.peek() == Some('?') {
                    self.bump();
                    match self.bump()? {
                        ':' => {}
                        '=' => look = Some((false, false)),
                        '!' => look = Some((false, true)),
                        '<' => match self.peek() {
                            Some('=') => {
                                self.bump();
                                look = Some((true, false));
                            }
                            Some('!') => {
                                self.bump();
                                look = Some((true, true));
                            }
                            _ => {
                                // Named group: record the name at this
                                // capture index. Duplicate names are a
                                // syntax error.
                                let mut name = String::new();
                                loop {
                                    let c = self.bump()?;
                                    if c == '>' {
                                        break;
                                    }
                                    name.push(c);
                                }
                                if name.is_empty()
                                    || self.names.iter().any(|n| n.as_deref() == Some(name.as_str()))
                                {
                                    return None;
                                }
                                cap = Some(self.next_cap);
                                self.next_cap += 1;
                                self.names.push(Some(name));
                            }
                        },
                        _ => return None,
                    }
                } else {
                    cap = Some(self.next_cap);
                    self.next_cap += 1;
                    self.names.push(None);
                }
                self.depth += 1;
                let alts = self.parse_alternation()?;
                self.depth = self.depth.saturating_sub(1);
                if self.bump()? != ')' {
                    return None;
                }
                match look {
                    Some((false, neg)) => Some(Node::LookAhead { alts, neg }),
                    Some((true, neg)) => Some(Node::LookBehind { alts, neg }),
                    None => Some(Node::Group { alts, cap }),
                }
            }
            '[' => self.parse_class(),
            '\\' => self.parse_escape(),
            ')' => None,
            c => Some(Node::Char(c)),
        }
    }

    fn parse_escape(&mut self) -> Option<Node> {
        let c = self.bump()?;
        Some(match c {
            'd' => Node::Class {
                neg: false,
                items: vec![ClassItem::Digit(false)],
            },
            'D' => Node::Class {
                neg: false,
                items: vec![ClassItem::Digit(true)],
            },
            'w' => Node::Class {
                neg: false,
                items: vec![ClassItem::Word(false)],
            },
            'W' => Node::Class {
                neg: false,
                items: vec![ClassItem::Word(true)],
            },
            's' => Node::Class {
                neg: false,
                items: vec![ClassItem::Space(false)],
            },
            'S' => Node::Class {
                neg: false,
                items: vec![ClassItem::Space(true)],
            },
            'b' => Node::WordBoundary,
            'B' => Node::NotWordBoundary,
            'n' => Node::Char('\n'),
            't' => Node::Char('\t'),
            'r' => Node::Char('\r'),
            'f' => Node::Char('\u{c}'),
            'v' => Node::Char('\u{b}'),
            '0' => Node::Char('\0'),
            'x' => {
                let h1 = self.bump()?.to_digit(16)?;
                let h2 = self.bump()?.to_digit(16)?;
                Node::Char(char::from_u32(h1 * 16 + h2)?)
            }
            'u' => Node::Char(self.unicode_escape()?),
            // Backreference `\1`..`\99`.
            '1'..='9' => {
                let mut n = c.to_digit(10)? as usize;
                if let Some(d) = self.peek().and_then(|d| d.to_digit(10)) {
                    self.bump();
                    n = n * 10 + d as usize;
                }
                Node::BackRef(n)
            }
            // `\k<name>`: a named backreference.
            'k' => {
                if self.bump()? != '<' {
                    return None;
                }
                let mut name = String::new();
                loop {
                    let c = self.bump()?;
                    if c == '>' {
                        break;
                    }
                    name.push(c);
                }
                match self
                    .names
                    .iter()
                    .position(|n| n.as_deref() == Some(name.as_str()))
                {
                    Some(idx) => Node::BackRef(idx),
                    None => {
                        // Forward reference: resolved after the parse.
                        let k = self.forward_refs.len();
                        self.forward_refs.push((name, k));
                        Node::BackRef(usize::MAX - k)
                    }
                }
            }
            'p' | 'P' if self.unicode => {
                let neg = c == 'P';
                if self.bump()? != '{' {
                    return None;
                }
                let mut prop = String::new();
                loop {
                    let c = self.bump()?;
                    if c == '}' {
                        break;
                    }
                    prop.push(c);
                }
                let item = unicode_property_item(&prop, neg)?;
                Node::Class {
                    neg: false,
                    items: vec![item],
                }
            }
            other => Node::Char(other),
        })
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
            let lo = if c == '\\' {
                let e = self.bump()?;
                match e {
                    'd' => {
                        items.push(ClassItem::Digit(false));
                        continue;
                    }
                    'D' => {
                        items.push(ClassItem::Digit(true));
                        continue;
                    }
                    'w' => {
                        items.push(ClassItem::Word(false));
                        continue;
                    }
                    'W' => {
                        items.push(ClassItem::Word(true));
                        continue;
                    }
                    's' => {
                        items.push(ClassItem::Space(false));
                        continue;
                    }
                    'S' => {
                        items.push(ClassItem::Space(true));
                        continue;
                    }
                    'p' | 'P' if self.unicode => {
                        if self.bump()? != '{' {
                            return None;
                        }
                        let mut prop = String::new();
                        loop {
                            let c = self.bump()?;
                            if c == '}' {
                                break;
                            }
                            prop.push(c);
                        }
                        items.push(unicode_property_item(&prop, e == 'P')?);
                        continue;
                    }
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    'f' => '\u{c}',
                    'v' => '\u{b}',
                    'b' => '\u{8}',
                    '0' => '\0',
                    'x' => {
                        let h1 = self.bump()?.to_digit(16)?;
                        let h2 = self.bump()?.to_digit(16)?;
                        char::from_u32(h1 * 16 + h2)?
                    }
                    'u' => self.unicode_escape()?,
                    other => other,
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|&c| c != ']') {
                self.bump();
                let hi = self.bump()?;
                let hi = if hi == '\\' { self.bump()? } else { hi };
                items.push(ClassItem::Range(lo, hi));
            } else {
                items.push(ClassItem::Char(lo));
            }
        }
        Some(Node::Class { neg, items })
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Replace forward-reference placeholders (`BackRef(usize::MAX - k)`) with
/// the resolved capture indices, recursively.
fn resolve_forward_refs(seq: &mut [Node], resolved: &[usize]) {
    for node in seq.iter_mut() {
        match node {
            Node::BackRef(n) if *n > usize::MAX / 2 => {
                let k = usize::MAX - *n;
                if let Some(idx) = resolved.get(k) {
                    *n = *idx;
                }
            }
            Node::Group { alts, .. }
            | Node::LookAhead { alts, .. }
            | Node::LookBehind { alts, .. } => {
                for alt in alts.iter_mut() {
                    resolve_forward_refs(alt, resolved);
                }
            }
            Node::Repeat { node, .. } => {
                let mut one = [core::mem::replace(node.as_mut(), Node::Start)];
                resolve_forward_refs(&mut one, resolved);
                let [inner] = one;
                **node = inner;
            }
            _ => {}
        }
    }
}

/// The class item a `\p{…}` property name stands for. Unknown names are
/// rejected (a SyntaxError in the spec), so callers degrade to no match.
fn unicode_property_item(prop: &str, neg: bool) -> Option<ClassItem> {
    let (key, name) = match prop.split_once('=') {
        Some((k, v)) => (Some(k), v),
        None => (None, prop),
    };
    if matches!(key, Some(k) if !matches!(k, "General_Category" | "gc" | "Script" | "sc" | "Script_Extensions" | "scx")) {
        return None;
    }
    Some(match name {
        "L" | "Letter" | "Alphabetic" | "Alpha" | "Lu" | "Ll" | "Lt" | "Lm" | "Lo"
        | "Uppercase_Letter" | "Lowercase_Letter" | "Cased_Letter" | "LC" | "ID_Start"
        | "ID_Continue" | "Any" => ClassItem::Letter(neg),
        "N" | "Nd" | "Number" | "Decimal_Number" | "Nl" | "No" => ClassItem::Digit(neg),
        "White_Space" | "Space_Separator" | "Zs" | "space" => ClassItem::Space(neg),
        // Scripts and remaining categories: letters-or-digits is the closest
        // std-only answer, and is what the bundles use them for (tokenizing).
        "Latin" | "Latn" | "Greek" | "Cyrillic" | "Han" | "Hiragana" | "Katakana"
        | "Arabic" | "Hebrew" | "Emoji" | "Emoji_Presentation" | "Extended_Pictographic"
        | "P" | "Punctuation" | "S" | "Symbol" | "M" | "Mark" | "Mn" | "Mc" | "Me" | "Z"
        | "Separator" | "C" | "Other" | "Cc" | "Cf" | "Sc" | "Sm" | "Sk" | "So" | "Pc"
        | "Pd" | "Ps" | "Pe" | "Pi" | "Pf" | "Po" | "Regional_Indicator" | "ASCII"
        | "ASCII_Hex_Digit" | "Hex_Digit" | "Dash" | "Diacritic" | "Math" => {
            ClassItem::Alnum(neg)
        }
        _ => return None,
    })
}

type CapSlots = Vec<Option<(usize, usize)>>;

impl Regex {
    /// Does the pattern match anywhere in `input`?
    pub fn is_match(&self, input: &str) -> bool {
        self.find(input).is_some()
    }

    /// First match: (char start, char end) over the char vector.
    pub fn find(&self, input: &str) -> Option<(usize, usize)> {
        self.find_captures(input).map(|c| (c.start, c.end))
    }

    /// Number of capturing groups (excluding the whole match).
    pub fn capture_count(&self) -> usize {
        self.n_caps
    }

    /// Group names by capture index (index 0 is unnamed).
    pub fn group_names(&self) -> &[Option<String>] {
        &self.names
    }

    /// First match with capture groups. `groups[0]` is the whole match;
    /// non-participating groups are `None`. Captured text is the ORIGINAL
    /// input text, case included.
    pub fn find_captures(&self, input: &str) -> Option<Captures> {
        self.find_captures_from(input, 0, false)
    }

    /// Like [`Regex::find_captures`] but starting the scan at char index
    /// `from` (the `lastIndex` of a global/sticky regex). With `sticky` the
    /// match must begin exactly at `from`.
    pub fn find_captures_from(&self, input: &str, from: usize, sticky: bool) -> Option<Captures> {
        let chars: Vec<char> = input.chars().collect();
        if from > chars.len() {
            return None;
        }
        let budget = &mut 200_000u32;
        let mut caps: CapSlots = vec![None; self.n_caps + 1];
        let last = if sticky { from } else { chars.len() };
        for start in from..=last {
            for alt in &self.alts {
                for slot in caps.iter_mut() {
                    *slot = None;
                }
                if let Some(end) = self.match_seq(alt, &chars, start, budget, &mut caps) {
                    if let Some(slot) = caps.get_mut(0) {
                        *slot = Some((start, end));
                    }
                    let groups = caps
                        .iter()
                        .map(|s| {
                            s.and_then(|(a, b)| {
                                chars.get(a..b).map(|cs| cs.iter().collect::<String>())
                            })
                        })
                        .collect();
                    return Some(Captures {
                        groups,
                        names: self.names.clone(),
                        start,
                        end,
                    });
                }
            }
            if *budget == 0 {
                return None;
            }
        }
        None
    }

    /// Whether `a` and `b` are the same character under the `i` flag.
    fn chars_eq(&self, a: char, b: char) -> bool {
        if a == b {
            return true;
        }
        self.case_insensitive && a.to_lowercase().eq(b.to_lowercase())
    }

    fn match_seq(
        &self,
        seq: &[Node],
        chars: &[char],
        pos: usize,
        budget: &mut u32,
        caps: &mut CapSlots,
    ) -> Option<usize> {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let Some(node) = seq.first() else {
            return Some(pos);
        };
        let rest = seq.get(1..).unwrap_or(&[]);
        match node {
            Node::Start => {
                let at_line_start = self.multiline
                    && pos
                        .checked_sub(1)
                        .and_then(|i| chars.get(i))
                        .is_some_and(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'));
                if pos == 0 || at_line_start {
                    self.match_seq(rest, chars, pos, budget, caps)
                } else {
                    None
                }
            }
            Node::End => {
                let at_line_end = self.multiline
                    && chars
                        .get(pos)
                        .is_some_and(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'));
                if pos == chars.len() || at_line_end {
                    self.match_seq(rest, chars, pos, budget, caps)
                } else {
                    None
                }
            }
            Node::LookAhead { alts, neg } => {
                let saved = caps.clone();
                let mut hit = false;
                for alt in alts {
                    if self.match_seq(alt, chars, pos, budget, caps).is_some() {
                        hit = true;
                        break;
                    }
                    *caps = saved.clone();
                }
                if *neg {
                    *caps = saved;
                }
                if hit != *neg {
                    self.match_seq(rest, chars, pos, budget, caps)
                } else {
                    None
                }
            }
            Node::LookBehind { alts, neg } => {
                let saved = caps.clone();
                let mut hit = false;
                'outer: for start in (0..=pos).rev() {
                    for alt in alts {
                        if self.match_seq(alt, chars, start, budget, caps) == Some(pos) {
                            hit = true;
                            break 'outer;
                        }
                        *caps = saved.clone();
                    }
                    if *budget == 0 {
                        break;
                    }
                }
                if *neg {
                    *caps = saved;
                }
                if hit != *neg {
                    self.match_seq(rest, chars, pos, budget, caps)
                } else {
                    None
                }
            }
            Node::BackRef(n) => {
                // A group that has not participated matches the empty string.
                let span = caps.get(*n).copied().flatten();
                let len = match span {
                    Some((a, b)) => {
                        let l = b.saturating_sub(a);
                        for i in 0..l {
                            let (Some(x), Some(y)) = (chars.get(a + i), chars.get(pos + i)) else {
                                return None;
                            };
                            if !self.chars_eq(*x, *y) {
                                return None;
                            }
                        }
                        l
                    }
                    None => 0,
                };
                self.match_seq(rest, chars, pos + len, budget, caps)
            }
            Node::WordBoundary | Node::NotWordBoundary => {
                let before = pos
                    .checked_sub(1)
                    .and_then(|i| chars.get(i))
                    .copied()
                    .is_some_and(is_word);
                let after = chars.get(pos).copied().is_some_and(is_word);
                let at_boundary = before != after;
                let want = matches!(node, Node::WordBoundary);
                if at_boundary == want {
                    self.match_seq(rest, chars, pos, budget, caps)
                } else {
                    None
                }
            }
            Node::Repeat {
                node,
                min,
                max,
                lazy,
            } => self.match_repeat(node, *min, *max, *lazy, rest, chars, pos, budget, caps),
            Node::Group { alts, cap } => {
                for alt in alts {
                    // Save capture state so a failed branch cannot leak
                    // captures recorded inside it (backtracking restore).
                    let saved = caps.clone();
                    // The body runs WITH the continuation appended: a
                    // quantifier inside the body then backtracks against
                    // the tail instead of committing to its first choice.
                    let mut seq: Vec<Node> = Vec::with_capacity(alt.len() + 1 + rest.len());
                    seq.extend(alt.iter().cloned());
                    seq.push(Node::CapClose { cap: *cap, start: pos });
                    seq.extend(rest.iter().cloned());
                    if let Some(end) = self.match_seq(&seq, chars, pos, budget, caps) {
                        return Some(end);
                    }
                    *caps = saved;
                }
                None
            }
            Node::CapClose { cap, start } => {
                if let Some(n) = cap {
                    if let Some(slot) = caps.get_mut(*n) {
                        *slot = Some((*start, pos));
                    }
                }
                self.match_seq(rest, chars, pos, budget, caps)
            }
            single => {
                if self.match_one(single, chars, pos) {
                    self.match_seq(rest, chars, pos + 1, budget, caps)
                } else {
                    None
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn match_repeat(
        &self,
        node: &Node,
        min: u32,
        max: u32,
        lazy: bool,
        rest: &[Node],
        chars: &[char],
        pos: usize,
        budget: &mut u32,
        caps: &mut CapSlots,
    ) -> Option<usize> {
        // Collect all reachable end positions by repeating `node`, and the
        // CAPTURE STATE that produced each endpoint. When the tail then
        // backtracks to a shorter (greedy) or longer (lazy) endpoint, the
        // capture slots must reflect THAT iteration count — not whichever
        // iteration ran last — so each candidate carries its own snapshot.
        let mut ends: Vec<(usize, CapSlots)> = vec![(pos, caps.clone())];
        let mut cur = pos;
        let mut count = 0u32;
        while count < max {
            let stepped = match node {
                Node::Group { alts, cap } => {
                    let mut best = None;
                    for alt in alts {
                        if let Some(e) = self.match_seq(alt, chars, cur, budget, caps) {
                            if e > cur {
                                // JS semantics: a repeated capture holds its
                                // LAST iteration's text.
                                if let Some(n) = cap {
                                    if let Some(slot) = caps.get_mut(*n) {
                                        *slot = Some((cur, e));
                                    }
                                }
                                best = Some(e);
                                break;
                            }
                        }
                    }
                    best
                }
                single => {
                    if self.match_one(single, chars, cur) {
                        Some(cur + 1)
                    } else {
                        None
                    }
                }
            };
            match stepped {
                Some(e) => {
                    cur = e;
                    count += 1;
                    ends.push((cur, caps.clone()));
                }
                None => break,
            }
            if *budget == 0 {
                break;
            }
        }
        if count < min {
            return None;
        }
        let usable = ends.get(min as usize..).unwrap_or(&[]);
        let try_endpoint = |e: usize, snap: &CapSlots, caps: &mut CapSlots, budget: &mut u32| {
            *caps = snap.clone();
            self.match_seq(rest, chars, e, budget, caps)
        };
        if lazy {
            for (e, snap) in usable {
                if let Some(end) = try_endpoint(*e, snap, caps, budget) {
                    return Some(end);
                }
            }
        } else {
            for (e, snap) in usable.iter().rev() {
                if let Some(end) = try_endpoint(*e, snap, caps, budget) {
                    return Some(end);
                }
            }
        }
        None
    }

    fn match_one(&self, node: &Node, chars: &[char], pos: usize) -> bool {
        let Some(&c) = chars.get(pos) else {
            return false;
        };
        match node {
            Node::Char(p) => self.chars_eq(*p, c),
            Node::AnyChar => self.dot_all || !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'),
            Node::Class { neg, items } => {
                let mut hit = false;
                // Under `i`, a character is in a range when any of its case
                // forms is.
                let forms: Vec<char> = if self.case_insensitive {
                    let mut v = vec![c];
                    v.extend(c.to_lowercase());
                    v.extend(c.to_uppercase());
                    v
                } else {
                    vec![c]
                };
                for item in items {
                    let m = match item {
                        ClassItem::Char(p) => forms.contains(p),
                        ClassItem::Range(lo, hi) => forms.iter().any(|f| *lo <= *f && *f <= *hi),
                        ClassItem::Digit(n) => c.is_ascii_digit() != *n,
                        ClassItem::Word(n) => is_word(c) != *n,
                        ClassItem::Space(n) => c.is_whitespace() != *n,
                        ClassItem::Letter(n) => c.is_alphabetic() != *n,
                        ClassItem::Alnum(n) => c.is_alphanumeric() != *n,
                    };
                    if m {
                        hit = true;
                        break;
                    }
                }
                hit != *neg
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn hostile_patterns_do_not_hang() {
        // Catastrophic backtracking pattern: budget stops it.
        let r = compile("(a+)+$", "").unwrap();
        let _ = r.is_match(&"a".repeat(60));
        // Unbalanced syntax rejected at compile time.
        assert!(compile("(abc", "").is_none());
        assert!(compile("\\k<nope>", "").is_none());
        assert!(compile("(?<x>a)(?<x>b)", "").is_none());
        assert!(compile("\\p{DefinitelyUnknown}", "u").is_none());
        // Outside Unicode mode `\p` is the identity escape for `p`.
        assert!(compile("\\p{L}", "").unwrap().is_match("p{L}"));
        assert!(!compile("\\p{L}", "").unwrap().is_match("a"));
        assert!(compile("\\p{L}", "u").unwrap().is_match("a"));
        // A forward named reference compiles; before its group matched it
        // is the empty string.
        let r = compile("\\k<x>(?<x>a)", "").unwrap();
        assert_eq!(r.find("a"), Some((0, 1)));
    }

    #[test]
    fn lookaround_backrefs_named_groups_and_flags() {
        let r = compile("(?<y>\\d{4})-(?<m>\\d{2})", "").unwrap();
        let c = r.find_captures("on 2024-07 ok").unwrap();
        assert_eq!(c.groups[1].as_deref(), Some("2024"));
        assert_eq!(c.names[2].as_deref(), Some("m"));
        assert!(compile("a(?=b)", "").unwrap().is_match("ab"));
        assert!(!compile("a(?=b)", "").unwrap().is_match("ac"));
        assert!(compile("a(?!b)", "").unwrap().is_match("ac"));
        assert!(compile("(?<=\\$)\\d+", "").unwrap().is_match("cost $42"));
        assert!(!compile("(?<!\\$)\\b\\d+", "").unwrap().is_match("$42"));
        assert!(compile("(a)\\1", "").unwrap().is_match("aa"));
        assert!(!compile("(a)\\1", "").unwrap().is_match("ab"));
        assert!(compile("^b", "m").unwrap().is_match("a\nb"));
        assert!(!compile("^b", "").unwrap().is_match("a\nb"));
        assert!(compile("a.b", "s").unwrap().is_match("a\nb"));
        assert!(!compile("a.b", "").unwrap().is_match("a\nb"));
        // `i` keeps the original case in captures and handles ranges.
        let c = compile("([a-c]+)", "i").unwrap().find_captures("xxABCxx").unwrap();
        assert_eq!(c.groups[1].as_deref(), Some("ABC"));
        // A quantifier INSIDE a group backtracks against the tail: the lazy
        // repeat grows until `$` matches, the greedy one shrinks until the
        // literal after the group matches (page.js's route compiler emits
        // `^(?:\/([^/]+?))\/?$`, which matched nothing before this).
        let c = compile("^(a+?)$", "").unwrap().find_captures("aaa").unwrap();
        assert_eq!(c.groups[1].as_deref(), Some("aaa"));
        let c = compile("^(.+?)b$", "").unwrap().find_captures("aab").unwrap();
        assert_eq!(c.groups[1].as_deref(), Some("aa"));
        let c = compile("^(?:/([^/]+?))/?$", "").unwrap().find_captures("/css/").unwrap();
        assert_eq!(c.groups[1].as_deref(), Some("css"));
        let c = compile("^(a+)ab$", "").unwrap().find_captures("aaab").unwrap();
        assert_eq!(c.groups[1].as_deref(), Some("aa"));
        // From an offset, and sticky.
        let r = compile("a", "").unwrap();
        assert_eq!(r.find_captures_from("aXa", 1, false).map(|c| c.start), Some(2));
        assert!(r.find_captures_from("aXa", 1, true).is_none());
    }
}
