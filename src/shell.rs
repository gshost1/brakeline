//! Heuristic classification of shell commands an agent is about to run.
//!
//! This is a guard rail, not a sandbox: it parses the common shapes agents
//! actually emit. Deliberately obfuscated commands can get past it.

use crate::config::ShellConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Safe,
    /// Allowed, but the workspace should be snapshotted first.
    Destructive(String),
    /// Refused outright.
    Blocked(String),
}

const MAX_NESTING: usize = 3;

/// The verdict the hook acts on: the stricter of this parser's and the
/// older one's (`shell_legacy`). Each parser misses shapes the other
/// catches, so a command gets through only when both call it safe.
pub fn classify(command: &str, cfg: &ShellConfig) -> Verdict {
    let legacy = crate::shell_legacy::classify(command, cfg);
    // Crafted nesting makes the new tokenizer slow (about 1.4 ms a byte), and
    // a hook that times out lets the call through. Past this size, judge with
    // the old parser alone and snapshot at least.
    if command.len() > MAX_NEW_PARSER_LEN {
        let too_long = Verdict::Destructive(format!(
            "command is over {} KB, too long to check fully",
            MAX_NEW_PARSER_LEN / 1024
        ));
        return strictest(too_long, legacy);
    }
    strictest(classify_new(command, cfg), legacy)
}

const MAX_NEW_PARSER_LEN: usize = 16 * 1024;

fn strictest(new: Verdict, legacy: Verdict) -> Verdict {
    let rank = |v: &Verdict| match v {
        Verdict::Safe => 0,
        Verdict::Destructive(_) => 1,
        Verdict::Blocked(_) => 2,
    };
    if rank(&legacy) > rank(&new) {
        legacy
    } else {
        new
    }
}

fn classify_new(command: &str, cfg: &ShellConfig) -> Verdict {
    let lowered = command.to_ascii_lowercase();
    for needle in &cfg.blocked_substrings {
        if lowered.contains(&needle.to_ascii_lowercase()) {
            return Verdict::Blocked(format!("matches blocked pattern `{needle}`"));
        }
    }
    let mut findings = Findings::default();
    scan(command, cfg, 0, &mut findings);
    if let Some(reason) = findings.blocked {
        Verdict::Blocked(reason)
    } else if let Some(reason) = findings.destructive {
        Verdict::Destructive(reason)
    } else {
        Verdict::Safe
    }
}

#[derive(Default)]
struct Findings {
    blocked: Option<String>,
    destructive: Option<String>,
}

impl Findings {
    fn block(&mut self, reason: String) {
        self.blocked.get_or_insert(reason);
    }
    fn destructive(&mut self, reason: String) {
        self.destructive.get_or_insert(reason);
    }
}

fn scan(command: &str, cfg: &ShellConfig, depth: usize, out: &mut Findings) {
    let compact: String = command.chars().filter(|c| !c.is_whitespace()).collect();
    if cfg.block_catastrophic && compact.contains(":(){:|:&};:") {
        out.block("fork bomb".into());
    }
    let Tokens {
        segments,
        stdin_docs,
        too_deep,
    } = tokenize(command);
    if too_deep {
        too_deep_to_check(cfg, out);
    }
    for segment in &segments {
        analyze_segment(&segment.words, &segment.writes, cfg, depth, out);
    }
    // Heredoc bodies and here-strings are commands unless they provably feed
    // a program that only reads data. Which segment a pipe hands them to is
    // not tracked, so any shell-like command on the line makes every body
    // count.
    if stdin_docs.is_empty() {
        return;
    }
    // A body piped on to a command that is not a known data reader may be
    // run too (`| $SHELL`, `| at now`, `| parallel`).
    let line_runs_shell = segments
        .iter()
        .any(|s| feeds_shell(&s.words) || (s.piped && !is_data_sink(&s.words)));
    for doc in &stdin_docs {
        if !line_runs_shell && doc.is_data() {
            continue;
        }
        if depth < MAX_NESTING {
            scan(&doc.body, cfg, depth + 1, out);
        } else {
            too_deep_to_check(cfg, out);
        }
    }
}

fn too_deep_to_check(cfg: &ShellConfig, out: &mut Findings) {
    let reason = "command nests too deeply to check".to_string();
    if cfg.block_catastrophic {
        out.block(reason);
    } else {
        out.destructive(reason);
    }
}

/// A shell by name, including versioned ones (`bash5`, `bash-5.2`).
fn is_shell(program: &str) -> bool {
    let program = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-');
    matches!(
        program,
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "mksh" | "ash" | "fish" | "csh" | "tcsh"
    )
}

/// A command that may run text it is given as shell commands: a shell,
/// `eval`, `source`, `ssh`, `su`, `sudo -s`, container and chroot
/// launchers. Errs towards yes.
fn feeds_shell(words: &[String]) -> bool {
    if starts_login_shell(words) {
        return true;
    }
    let words = strip_wrappers(words);
    let Some(first) = words.first() else {
        return false;
    };
    let program = basename(first);
    // A program named by an expansion could be anything.
    if program.contains(['$', '`']) {
        return true;
    }
    is_shell(program)
        || matches!(
            program,
            "eval"
                | "source"
                | "."
                | "ssh"
                | "su"
                | "sudo"
                | "doas"
                | "busybox"
                | "script"
                | "docker"
                | "podman"
                | "nerdctl"
                | "kubectl"
                | "chroot"
                | "nsenter"
                | "unshare"
        )
}

/// `sudo -s`, `sudo -i`, `sudo --login`, `doas -s`: the wrapper starts a
/// shell, which reads commands from stdin when no command follows.
fn starts_login_shell(words: &[String]) -> bool {
    (0..words.len()).any(|i| {
        let wrapper = basename(&words[i]);
        if !matches!(wrapper, "sudo" | "doas") {
            return false;
        }
        let Some((shorts, longs)) = wrapper_value_options(wrapper) else {
            return false;
        };
        let mut j = i + 1;
        while let Some(opt) = words.get(j).filter(|o| o.starts_with('-') && *o != "--") {
            j += 1;
            if opt.starts_with("--sh")
                || opt.starts_with("--lo")
                || (!opt.starts_with("--") && opt.contains(['s', 'i']))
            {
                return true;
            }
            let next = words.get(j).map(String::as_str);
            if value_option(opt, next, shorts, longs).is_some_and(|o| o.uses_next_word) {
                j += 1;
            }
        }
        false
    })
}

/// Programs that read stdin as data, never as shell commands. Interpreters
/// of other languages count: a Python script is not judged as shell.
fn is_data_sink(words: &[String]) -> bool {
    let words = strip_wrappers(words);
    let Some(first) = words.first() else {
        return false;
    };
    let program = basename(first);
    matches!(
        program,
        "cat"
            | "tee"
            | "git"
            | "grep"
            | "egrep"
            | "fgrep"
            | "rg"
            | "wc"
            | "sort"
            | "head"
            | "tail"
            | "jq"
            | "node"
            | "ruby"
            | "perl"
    ) || program
        .strip_prefix("python")
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Takes a substitution's output as data when it is an argument of one of
/// these: `git commit -m "$(cat <<'EOF' ... EOF)"`.
fn takes_output_as_data(words: &[String]) -> bool {
    is_data_sink(words)
        || strip_wrappers(words)
            .first()
            .is_some_and(|w| matches!(basename(w), "echo" | "printf"))
}

impl StdinDoc {
    /// Data only when it feeds a known data reader and, inside a
    /// substitution, that substitution is an argument of one too.
    fn is_data(&self) -> bool {
        self.consumer_reads_data == Some(true)
            && (!self.in_subst || self.outer_takes_data == Some(true))
    }
}

/// Splits a command line into simple commands, honoring quotes. Operators
/// (`;`, `&&`, `||`, `|`, `&`, newlines, subshell parentheses) all start a
/// new segment. Each `$(...)`, backtick or `<(...)` substitution becomes
/// segments of its own and leaves its source text as one word in place.
/// Comments, heredoc bodies and redirections are dropped.
pub fn split_segments(input: &str) -> Vec<Vec<String>> {
    tokenize(input)
        .segments
        .into_iter()
        .map(|s| s.words)
        .filter(|w| !w.is_empty())
        .collect()
}

/// A simple command: its words, minus redirections, and the files its
/// output redirections write to, as (truncates, target).
#[derive(Debug, Default)]
struct Segment {
    words: Vec<String>,
    writes: Vec<(bool, String)>,
    /// `stdin_docs` from this index on were found while reading it.
    first_doc: usize,
    /// Reads the output of the command before it through `|` or `|&`.
    piped: bool,
}

/// Whether the next word is in command position: only reserved words that
/// precede a command (`then case ...`, `do case ...`) come before it.
fn at_command_start(words: &[String]) -> bool {
    words.iter().all(|w| {
        matches!(
            w.as_str(),
            "then" | "do" | "else" | "elif" | "if" | "while" | "until" | "{" | "!" | "time"
        )
    })
}

/// Nesting of substitutions, quotes and arithmetic the lexer follows before
/// giving up on the command. Keeps the recursion far from the stack limit.
const MAX_LEX_DEPTH: usize = 64;

/// Arithmetic `((`/`$((` guesses that may fail before the lexer stops
/// trying, so adversarial input stays linear-ish.
const MAX_ARITH_MISSES: usize = 64;

/// A heredoc body or here-string: what a command gets on stdin.
#[derive(Debug, Default)]
struct StdinDoc {
    body: String,
    /// Whether the command it is redirected into only reads data (see
    /// `is_data_sink`); `None` if unknown.
    consumer_reads_data: Option<bool>,
    /// Inside `$(...)`, backticks or `<(...)`/`>(...)`, where what the
    /// consumer prints may be run.
    in_subst: bool,
    /// For a doc inside a substitution: whether the outermost command that
    /// has the substitution among its words takes its output as data.
    outer_takes_data: Option<bool>,
    /// The `parse_list` call whose segment it is redirected from.
    list: usize,
}

struct Tokens {
    segments: Vec<Segment>,
    /// Heredoc bodies and here-strings: what the commands get on stdin.
    stdin_docs: Vec<StdinDoc>,
    /// The command nested too deeply to read.
    too_deep: bool,
}

fn tokenize(input: &str) -> Tokens {
    let mut lexer = Lexer::new(input, 0);
    lexer.parse_list(false);
    Tokens {
        segments: lexer.segments,
        stdin_docs: lexer.stdin_docs,
        too_deep: lexer.too_deep,
    }
}

struct Heredoc {
    /// Its entry in `stdin_docs`.
    slot: usize,
    delimiter: String,
    strip_tabs: bool,
    /// A quoted delimiter turns off expansion in the body.
    quoted: bool,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
    segments: Vec<Segment>,
    heredocs: Vec<Heredoc>,
    stdin_docs: Vec<StdinDoc>,
    too_deep: bool,
    arith_misses: usize,
    /// Once the arithmetic budget is spent, `<<` may be a shift the lexer
    /// can no longer tell apart, so no heredoc is read: their bodies are
    /// then scanned as commands rather than hiding later lines.
    no_heredocs: bool,
    /// How many substitutions enclose the current position.
    subst: usize,
    /// The `parse_list` call being read, and a counter to number them.
    list: usize,
    lists: usize,
}

fn is_metachar(c: char) -> bool {
    c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>')
}

impl Lexer {
    fn new(input: &str, depth: usize) -> Self {
        Lexer {
            chars: input.chars().collect(),
            pos: 0,
            depth,
            segments: Vec::new(),
            heredocs: Vec::new(),
            stdin_docs: Vec::new(),
            too_deep: false,
            arith_misses: 0,
            no_heredocs: false,
            subst: 0,
            list: usize::MAX,
            lists: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.chars.get(self.pos + n).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn source(&self, start: usize) -> String {
        self.chars[start..self.pos].iter().collect()
    }

    fn give_up(&mut self) {
        self.too_deep = true;
        self.pos = self.chars.len();
    }

    /// Runs `f` on a fresh lexer over `text`, one level deeper, and keeps
    /// the segments it finds. `subst` says whether `text` is the body of a
    /// command substitution.
    fn sub(&mut self, text: &str, subst: bool, f: impl FnOnce(&mut Lexer)) {
        if self.depth >= MAX_LEX_DEPTH {
            self.give_up();
            return;
        }
        let mut sub = Lexer::new(text, self.depth + 1);
        sub.subst = self.subst + usize::from(subst);
        f(&mut sub);
        self.segments.append(&mut sub.segments);
        for mut doc in sub.stdin_docs {
            doc.list = usize::MAX; // its consumer is settled
            self.stdin_docs.push(doc);
        }
        if sub.too_deep {
            self.give_up();
        }
    }

    /// Finds the `))` closing an arithmetic expression whose body starts at
    /// `start`. `None` means it is not arithmetic after all (bash then reads
    /// `((` as nested subshells and `$((` as a command substitution).
    fn arith_end(&mut self, start: usize) -> Option<usize> {
        if self.arith_misses >= MAX_ARITH_MISSES {
            return None;
        }
        let mut depth = 0usize;
        let mut i = start;
        while let Some(&c) = self.chars.get(i) {
            match c {
                '(' => depth += 1,
                ')' if depth > 0 => depth -= 1,
                ')' => {
                    if self.chars.get(i + 1) == Some(&')') {
                        return Some(i);
                    }
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        self.arith_misses += 1;
        if self.arith_misses >= MAX_ARITH_MISSES {
            self.no_heredocs = true;
        }
        None
    }

    /// Reads commands until the end of input, or, inside a substitution,
    /// until its closing `)`.
    fn parse_list(&mut self, in_subst: bool) {
        if self.depth >= MAX_LEX_DEPTH {
            self.give_up();
            return;
        }
        self.depth += 1;
        let outer_list = self.list;
        self.list = self.lists;
        self.lists += 1;
        let mut cur = Segment {
            first_doc: self.stdin_docs.len(),
            ..Segment::default()
        };
        let mut parens = 0usize;
        // For each open `case`, the subshell depth it sits at: a `)` there
        // ends a pattern, not a subshell or the substitution.
        let mut cases: Vec<usize> = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                '\n' => {
                    self.pos += 1;
                    self.end_segment(&mut cur);
                    self.read_heredocs();
                    cur.first_doc = self.stdin_docs.len();
                }
                c if c.is_whitespace() => self.pos += 1,
                ';' => {
                    self.pos += 1;
                    self.end_segment(&mut cur);
                }
                '|' => {
                    self.pos += 1;
                    let or = self.peek() == Some('|');
                    if or || self.peek() == Some('&') {
                        self.pos += 1;
                    }
                    self.end_segment(&mut cur);
                    cur.piped = !or;
                }
                '&' if self.peek_at(1) == Some('>') => {
                    self.pos += 1;
                    self.redirect(&mut cur, true);
                }
                '&' => {
                    self.pos += 1;
                    self.end_segment(&mut cur);
                }
                '(' => {
                    let arith = (cur.words.is_empty() && self.peek_at(1) == Some('('))
                        .then(|| self.arith_end(self.pos + 2))
                        .flatten();
                    self.end_segment(&mut cur);
                    if let Some(end) = arith {
                        let body: String = self.chars[self.pos + 2..end].iter().collect();
                        self.pos = end + 2;
                        self.sub(&body, false, |l| l.expansions(&mut String::new(), None));
                    } else {
                        self.pos += 1;
                        parens += 1;
                    }
                }
                ')' => {
                    self.pos += 1;
                    self.end_segment(&mut cur);
                    if cases.last() == Some(&parens) {
                        // a case pattern
                    } else if parens > 0 {
                        parens -= 1;
                    } else if in_subst {
                        break;
                    }
                }
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                }
                '<' | '>' => self.redirect(&mut cur, false),
                _ => {
                    let Some((word, quoted)) = self.read_word() else {
                        continue;
                    };
                    if !quoted
                        && !word.is_empty()
                        && word.chars().all(|c| c.is_ascii_digit())
                        && matches!(self.peek(), Some('<' | '>'))
                    {
                        self.redirect(&mut cur, false);
                        continue;
                    }
                    // `case` and `esac` count wherever a command can start.
                    if !quoted && at_command_start(&cur.words) {
                        match word.as_str() {
                            "case" => cases.push(parens),
                            "esac" => {
                                cases.pop();
                            }
                            _ => {}
                        }
                    }
                    cur.words.push(word);
                }
            }
        }
        self.end_segment(&mut cur);
        self.list = outer_list;
        self.depth -= 1;
    }

    /// Ends the current simple command. Heredocs and here-strings redirected
    /// from it learn their consumer; those inside substitutions among its
    /// words learn that it holds them.
    fn end_segment(&mut self, cur: &mut Segment) {
        let first_doc = cur.first_doc.min(self.stdin_docs.len());
        let docs = &mut self.stdin_docs[first_doc..];
        if !docs.is_empty() {
            let reads_data = is_data_sink(&cur.words);
            let takes_data = takes_output_as_data(&cur.words);
            for doc in docs {
                if doc.list == self.list {
                    doc.consumer_reads_data.get_or_insert(reads_data);
                } else {
                    doc.outer_takes_data = Some(takes_data);
                }
            }
        }
        let empty = cur.words.is_empty() && cur.writes.is_empty();
        // `a |` then a newline or comment: the pipe still feeds what follows.
        let piped = empty && cur.piped;
        if !empty {
            self.segments.push(std::mem::take(cur));
        }
        *cur = Segment {
            first_doc: self.stdin_docs.len(),
            piped,
            ..Segment::default()
        };
    }

    /// Reads one shell word, removing quotes. `quoted` reports whether any
    /// part of it was quoted or escaped. `None` if nothing but line
    /// continuations was there.
    fn read_word(&mut self) -> Option<(String, bool)> {
        let mut word = String::new();
        let mut in_word = false;
        let mut quoted = false;
        while let Some(c) = self.peek() {
            if is_metachar(c) {
                break;
            }
            self.pos += 1;
            match c {
                '\'' => {
                    in_word = true;
                    quoted = true;
                    while let Some(q) = self.bump() {
                        if q == '\'' {
                            break;
                        }
                        word.push(q);
                    }
                }
                '"' => {
                    in_word = true;
                    quoted = true;
                    self.expansions(&mut word, Some('"'));
                }
                '\\' => match self.bump() {
                    Some('\n') | None => {}
                    Some(n) => {
                        in_word = true;
                        quoted = true;
                        word.push(n);
                    }
                },
                '$' => {
                    in_word = true;
                    self.dollar(&mut word, false);
                }
                '`' => {
                    in_word = true;
                    self.backtick(&mut word);
                }
                c => {
                    in_word = true;
                    word.push(c);
                }
            }
        }
        in_word.then_some((word, quoted))
    }

    /// Double-quote rules: only `$`, backticks and a few escapes are
    /// special. Stops after `terminator`, or reads to the end (heredoc
    /// bodies, arithmetic).
    fn expansions(&mut self, word: &mut String, terminator: Option<char>) {
        if self.depth >= MAX_LEX_DEPTH {
            self.give_up();
            return;
        }
        self.depth += 1;
        while let Some(c) = self.bump() {
            match c {
                c if Some(c) == terminator => break,
                '\\' => match self.peek() {
                    Some('\n') => self.pos += 1,
                    Some(n @ ('$' | '`' | '"' | '\\')) => {
                        self.pos += 1;
                        word.push(n);
                    }
                    _ => word.push('\\'),
                },
                '$' => self.dollar(word, true),
                '`' => self.backtick(word),
                c => word.push(c),
            }
        }
        self.depth -= 1;
    }

    /// After a `$`: command substitution, arithmetic, ANSI-C quoting, or a
    /// plain `$`.
    fn dollar(&mut self, word: &mut String, in_double_quotes: bool) {
        let start = self.pos - 1;
        match self.peek() {
            Some('(') => {
                if self.peek_at(1) == Some('(')
                    && let Some(end) = self.arith_end(self.pos + 2)
                {
                    let body: String = self.chars[self.pos + 2..end].iter().collect();
                    self.pos = end + 2;
                    self.sub(&body, false, |l| l.expansions(&mut String::new(), None));
                } else {
                    self.pos += 1;
                    self.subst += 1;
                    self.parse_list(true);
                    self.subst -= 1;
                }
                word.push_str(&self.source(start));
            }
            Some('\'') if !in_double_quotes => {
                self.pos += 1;
                while let Some(q) = self.bump() {
                    match q {
                        '\'' => break,
                        '\\' => self.ansi_c_escape(word),
                        q => word.push(q),
                    }
                }
            }
            _ => word.push('$'),
        }
    }

    /// After a backslash inside `$'...'`: decode the escape the way bash
    /// does, so `$'\x72\x6d'` reads as `rm`.
    fn ansi_c_escape(&mut self, word: &mut String) {
        let Some(n) = self.bump() else { return };
        let number = |lexer: &mut Self, radix: u32, max: usize, first: Option<char>| {
            let mut digits: String = first.into_iter().collect();
            while digits.len() < max
                && let Some(d) = lexer.peek().filter(|d| d.is_digit(radix))
            {
                digits.push(d);
                lexer.pos += 1;
            }
            u32::from_str_radix(&digits, radix)
                .ok()
                .and_then(char::from_u32)
        };
        let decoded = match n {
            'x' => number(self, 16, 2, None),
            'u' => number(self, 16, 4, None),
            'U' => number(self, 16, 8, None),
            '0'..='7' => number(self, 8, 3, Some(n)),
            'n' => Some('\n'),
            't' => Some('\t'),
            'r' => Some('\r'),
            'a' => Some('\u{7}'),
            'b' => Some('\u{8}'),
            'e' | 'E' => Some('\u{1b}'),
            'f' => Some('\u{c}'),
            'v' => Some('\u{b}'),
            'c' => self
                .bump()
                .map(|c| char::from((c.to_ascii_uppercase() as u8) ^ 0x40)),
            other => Some(other),
        };
        match decoded {
            Some(c) => word.push(c),
            // `\x` with no digits stays as written.
            None => {
                word.push('\\');
                word.push(n);
            }
        }
    }

    /// After an opening backtick: the command up to the closing one.
    fn backtick(&mut self, word: &mut String) {
        let start = self.pos - 1;
        let mut inner = String::new();
        while let Some(c) = self.bump() {
            match c {
                '`' => break,
                '\\' => match self.peek() {
                    Some(n @ ('`' | '\\' | '$')) => {
                        self.pos += 1;
                        inner.push(n);
                    }
                    _ => inner.push('\\'),
                },
                c => inner.push(c),
            }
        }
        self.sub(&inner, true, |l| l.parse_list(false));
        word.push_str(&self.source(start));
    }

    /// At `<` or `>` (after `&` for `&>`): records file writes, consumes the
    /// target, and queues heredocs.
    fn redirect(&mut self, cur: &mut Segment, both: bool) {
        let Some(op) = self.bump() else { return };
        if op == '<' {
            match self.peek() {
                Some('<') if self.peek_at(1) == Some('<') => {
                    self.pos += 2;
                    if let Some(text) = self.redirect_target() {
                        self.new_doc(text);
                    }
                }
                Some('<') if self.no_heredocs => {
                    self.pos += 1;
                    self.redirect_target();
                }
                Some('<') => {
                    self.pos += 1;
                    let strip_tabs = self.peek() == Some('-');
                    if strip_tabs {
                        self.pos += 1;
                    }
                    if let Some((delimiter, quoted)) = self.redirect_word() {
                        let slot = self.new_doc(String::new());
                        self.heredocs.push(Heredoc {
                            slot,
                            delimiter,
                            strip_tabs,
                            quoted,
                        });
                    }
                }
                Some('(') => cur.words.push(self.process_substitution()),
                Some('&' | '>') => {
                    self.pos += 1;
                    self.redirect_target();
                }
                _ => {
                    self.redirect_target();
                }
            }
            return;
        }
        let mut truncates = true;
        let mut dup = false;
        match self.peek() {
            Some('>') => {
                self.pos += 1;
                truncates = false;
            }
            Some('|') => self.pos += 1,
            Some('&') if !both => {
                self.pos += 1;
                dup = true;
            }
            Some('(') if !both => {
                cur.words.push(self.process_substitution());
                return;
            }
            _ => {}
        }
        if let Some(target) = self.redirect_target() {
            let fd = target == "-" || target.chars().all(|c| c.is_ascii_digit());
            if !(dup && fd) {
                cur.writes.push((truncates, target));
            }
        }
    }

    /// Records a heredoc or here-string redirected from the command being
    /// read, and returns its slot.
    fn new_doc(&mut self, body: String) -> usize {
        self.stdin_docs.push(StdinDoc {
            body,
            in_subst: self.subst > 0,
            list: self.list,
            ..StdinDoc::default()
        });
        self.stdin_docs.len() - 1
    }

    fn redirect_word(&mut self) -> Option<(String, bool)> {
        while self.peek().is_some_and(|c| c == ' ' || c == '\t') {
            self.pos += 1;
        }
        if self.peek().is_none_or(is_metachar) {
            return None;
        }
        self.read_word()
    }

    fn redirect_target(&mut self) -> Option<String> {
        self.redirect_word().map(|(w, _)| w)
    }

    /// At the `(` of `<(...)` or `>(...)`.
    fn process_substitution(&mut self) -> String {
        let start = self.pos - 1;
        self.pos += 1;
        self.subst += 1;
        self.parse_list(true);
        self.subst -= 1;
        self.source(start)
    }

    /// Consumes the bodies of the heredocs queued on the line just ended.
    fn read_heredocs(&mut self) {
        for doc in std::mem::take(&mut self.heredocs) {
            let mut body = String::new();
            while self.pos < self.chars.len() {
                let end = self.chars[self.pos..]
                    .iter()
                    .position(|&c| c == '\n')
                    .map_or(self.chars.len(), |p| self.pos + p);
                let line: String = self.chars[self.pos..end].iter().collect();
                self.pos = (end + 1).min(self.chars.len());
                let candidate = if doc.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if candidate == doc.delimiter {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if !doc.quoted {
                self.sub(&body, false, |l| l.expansions(&mut String::new(), None));
            }
            self.stdin_docs[doc.slot].body = body;
        }
    }
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Options that take a value, per wrapper: (short letters, long names).
/// Getting one wrong shifts the parse, so `sudo -D /tmp rm -rf ~` would
/// look like the program `/tmp`. Options whose value is optional and only
/// ever inline (xargs `--replace[=R]`) are flags here.
fn wrapper_value_options(wrapper: &str) -> Option<(&'static str, &'static [&'static str])> {
    Some(match wrapper {
        "sudo" => (
            "aCcDghpRrTtUu",
            &[
                "auth-type",
                "chdir",
                "chroot",
                "close-from",
                "command-timeout",
                "group",
                "host",
                "login-class",
                "other-user",
                "prompt",
                "role",
                "type",
                "user",
            ],
        ),
        "doas" => ("aCu", &[]),
        "env" => ("CLPSu", &["chdir", "split-string", "unset"]),
        "exec" => ("a", &[]),
        "command" | "builtin" | "nohup" | "busybox" => ("", &[]),
        "time" => ("fo", &["format", "output"]),
        "nice" => ("n", &["adjustment"]),
        "xargs" => (
            "adEILnPs",
            &[
                "arg-file",
                "delimiter",
                "max-args",
                "max-chars",
                "max-procs",
                "process-slot-var",
            ],
        ),
        "stdbuf" => ("eio", &["error", "input", "output"]),
        "timeout" => ("ks", &["kill-after", "signal"]),
        _ => return None,
    })
}

/// A wrapper option that takes a value: its name (the short letter or the
/// full long name) and the value, inline (`-uroot`, `--user=root`) or the
/// next word (`-u root`, `-Eu root`, or `--us root`, since getopt_long
/// accepts any unambiguous prefix).
struct ValueOption<'a> {
    name: &'a str,
    value: Option<&'a str>,
    uses_next_word: bool,
}

fn value_option<'a>(
    opt: &'a str,
    next: Option<&'a str>,
    shorts: &str,
    longs: &[&'static str],
) -> Option<ValueOption<'a>> {
    let (name, inline) = match opt.strip_prefix("--") {
        Some(long) => {
            let (given, inline) = match long.split_once('=') {
                Some((given, value)) => (given, Some(value)),
                None => (long, None),
            };
            let name = *longs
                .iter()
                .find(|l| !given.is_empty() && l.starts_with(given))?;
            (name, inline)
        }
        None => {
            let p = opt.get(1..)?.find(|c| shorts.contains(c))?;
            let inline = &opt[p + 2..];
            (&opt[p + 1..p + 2], (!inline.is_empty()).then_some(inline))
        }
    };
    Some(ValueOption {
        name,
        value: inline.or(next),
        uses_next_word: inline.is_none(),
    })
}

/// Splits an `env -S` string the way env does: quotes, `\_` as a separator
/// (a space inside double quotes), `\c` and `#` ending the string. `${VAR}`
/// stays unexpanded. Strings env would reject are split leniently, since
/// env then runs nothing.
fn env_split_words(s: &str) -> Vec<String> {
    fn escaped(c: char) -> char {
        match c {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => '\x0c',
            'v' => '\x0b',
            c => c,
        }
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '#' if !in_word => break,
            '\'' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '\'' => break,
                        '\\' => match chars.next() {
                            Some(n @ ('\\' | '\'')) => word.push(n),
                            Some(n) => {
                                word.push('\\');
                                word.push(n);
                            }
                            None => word.push('\\'),
                        },
                        _ => word.push(q),
                    }
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some('_') => word.push(' '),
                            Some(n) => word.push(escaped(n)),
                            None => {}
                        },
                        _ => word.push(q),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('_') => {
                    if in_word {
                        words.push(std::mem::take(&mut word));
                        in_word = false;
                    }
                }
                Some('c') | None => break,
                Some(n) => {
                    in_word = true;
                    word.push(escaped(n));
                }
            },
            _ => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// How far `strip_once` got: the index where the real program starts, or,
/// for `env -S`, the rewritten words env really runs.
enum Strip {
    ProgramAt(usize),
    EnvSplit(Vec<String>),
}

/// Drops env assignments and wrapper commands (`sudo`, `env`, `xargs`, ...)
/// so the real program name comes first. `env -S 'str'` has its option word
/// replaced in place by the words of `str`, which env then goes on to parse.
fn strip_wrappers(words: &[String]) -> Vec<String> {
    let mut words = words.to_vec();
    loop {
        match strip_once(&words) {
            Strip::ProgramAt(i) => {
                words.drain(..i);
                return words;
            }
            // Each rewrite drops the `-S` option word, so this terminates.
            Strip::EnvSplit(next) => words = next,
        }
    }
}

fn strip_once(words: &[String]) -> Strip {
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        let is_assignment = w.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_')
        });
        if is_assignment
            || matches!(
                w,
                "{" | "}" | "!" | "if" | "then" | "else" | "elif" | "do" | "while" | "until"
            )
        {
            i += 1;
            continue;
        }
        // `function name { body }`: the body follows the name.
        if w == "function" {
            i += 2;
            continue;
        }
        let wrapper = basename(w);
        let Some((shorts, longs)) = wrapper_value_options(wrapper) else {
            break;
        };
        i += 1;
        // Skip the wrapper's own options and their values. A bare `-` is
        // env's `-i`.
        while let Some(opt) = words.get(i).filter(|o| o.starts_with('-')) {
            let opt_start = i;
            i += 1;
            if opt == "--" {
                break;
            }
            // `command -v`/`-V` only looks the name up.
            if wrapper == "command" && !opt.starts_with("--") && opt.contains(['v', 'V']) {
                return Strip::ProgramAt(words.len());
            }
            let next = words.get(i).map(String::as_str);
            let Some(option) = value_option(opt, next, shorts, longs) else {
                continue;
            };
            if option.uses_next_word {
                i += 1;
            }
            if wrapper == "env" && matches!(option.name, "S" | "split-string") {
                let mut env = words[..opt_start].to_vec();
                env.extend(env_split_words(option.value.unwrap_or("")));
                env.extend_from_slice(&words[i.min(words.len())..]);
                return Strip::EnvSplit(env);
            }
        }
        if wrapper == "timeout" {
            i += 1; // duration
        }
    }
    Strip::ProgramAt(i.min(words.len()))
}

/// Device paths that are streams or scratch space, not disks: writing them
/// loses nothing.
fn is_scratch_device(target: &str) -> bool {
    matches!(
        target,
        "/dev/null"
            | "/dev/zero"
            | "/dev/random"
            | "/dev/urandom"
            | "/dev/stdin"
            | "/dev/stdout"
            | "/dev/stderr"
            | "/dev/console"
    ) || (["/dev/fd/", "/dev/tty", "/dev/pts/", "/dev/shm/"]
        .iter()
        .any(|p| target.starts_with(p))
        && !target.split('/').any(|part| part == ".."))
}

/// Any other device file, such as a disk.
fn is_raw_device(target: &str) -> bool {
    target.starts_with("/dev/") && !is_scratch_device(target)
}

/// Judges one write to `target` by `what` (`> f`, `tee f`, `dd of=f`): a
/// device that is not scratch space is a disk; otherwise a truncating
/// write outside scratch space loses the old contents.
fn judge_write(target: &str, truncates: bool, what: &str, cfg: &ShellConfig, out: &mut Findings) {
    if is_raw_device(target) {
        let reason = format!("writes to the raw device `{target}`");
        if cfg.block_catastrophic {
            out.block(reason);
        } else {
            out.destructive(reason);
        }
    } else if truncates && !is_scratch_target(target) {
        out.destructive(format!("`{what}` overwrites the file"));
    }
}

/// Redirect targets whose contents nobody needs back.
fn is_scratch_target(target: &str) -> bool {
    is_scratch_device(target)
        || ["/tmp/", "/private/tmp/", "$TMPDIR", "${TMPDIR}"]
            .iter()
            .any(|p| target.starts_with(p))
}

fn analyze_segment(
    segment: &[String],
    writes: &[(bool, String)],
    cfg: &ShellConfig,
    depth: usize,
    out: &mut Findings,
) {
    for (truncates, target) in writes {
        judge_write(target, *truncates, &format!("> {target}"), cfg, out);
    }
    let words = strip_wrappers(segment);
    let Some(first) = words.first() else { return };
    let program = basename(first);
    let args = &words[1..];

    match program {
        p if is_shell(p) => {
            if let Some(pos) = args.iter().position(|a| {
                a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
            }) && let Some(inner) = args
                .get(pos + 1)
                .filter(|a| *a != "--")
                .or_else(|| args.get(pos + 2))
                && depth < MAX_NESTING
            {
                scan(inner, cfg, depth + 1, out);
            }
        }
        "eval" => {
            if depth < MAX_NESTING {
                scan(&args.join(" "), cfg, depth + 1, out);
            }
        }
        "rm" => analyze_rm(args, cfg, out),
        "find" => analyze_find(args, cfg, depth, out),
        "git" => analyze_git(args, cfg, out),
        "mv" => out.destructive("`mv` can overwrite files".into()),
        "unlink" | "shred" | "truncate" => out.destructive(format!("`{program}` removes data")),
        "sed" | "perl" if edits_in_place(program, args) => {
            out.destructive(format!("`{program} -i` edits files in place"))
        }
        "tee" => analyze_tee(args, cfg, out),
        "rsync" => {
            if args
                .iter()
                .any(|a| a.starts_with("--delete") || a == "--del")
            {
                out.destructive("`rsync --delete` removes files at the destination".into());
            } else if args.iter().any(|a| a == "--remove-source-files") {
                out.destructive("`rsync --remove-source-files` deletes the sources".into());
            }
        }
        "dd" => {
            for target in args.iter().filter_map(|a| a.strip_prefix("of=")) {
                judge_write(target, true, &format!("dd of={target}"), cfg, out);
            }
        }
        p if p.starts_with("mkfs") => {
            if cfg.block_catastrophic {
                out.block(format!("`{p}` formats a filesystem"));
            }
        }
        "diskutil" => {
            if cfg.block_catastrophic
                && args.iter().any(|a| {
                    let a = a.to_ascii_lowercase();
                    a.starts_with("erase")
                        || matches!(
                            a.as_str(),
                            "zerodisk"
                                | "randomdisk"
                                | "secureerase"
                                | "partitiondisk"
                                | "reformat"
                                | "deletecontainer"
                                | "deletevolume"
                                | "splitpartition"
                                | "mergepartitions"
                        )
                })
            {
                out.block("`diskutil` erases or repartitions a disk".into());
            }
        }
        "chmod" | "chown" | "chgrp" => {
            let recursive = args.iter().any(|a| {
                a == "--recursive"
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains('R'))
            });
            if cfg.block_catastrophic
                && recursive
                && args
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .any(|a| is_catastrophic_target(a))
            {
                out.block(format!(
                    "recursive `{program}` on a system or home directory"
                ));
            }
        }
        _ => {}
    }
}

/// Rough test for "this shell command probably changed files", used to tell
/// progress apart from an agent re-running the same thing.
pub fn mutates(command: &str) -> bool {
    if crate::shell_legacy::mutates(command) {
        return true;
    }
    if matches!(
        classify_new(command, &ShellConfig::default()),
        Verdict::Destructive(_)
    ) {
        return true;
    }
    tokenize(command).segments.iter().any(|segment| {
        let redirects = segment.writes.iter().any(|(_, t)| !is_scratch_device(t));
        let words = strip_wrappers(&segment.words);
        let program = words.first().map(|w| basename(w)).unwrap_or("");
        let sub = words.get(1).map(String::as_str).unwrap_or("");
        redirects
            || matches!(
                program,
                "cp" | "touch" | "mkdir" | "ln" | "patch" | "tee" | "install"
            )
            || (program == "git"
                && matches!(
                    sub,
                    "apply"
                        | "am"
                        | "commit"
                        | "merge"
                        | "rebase"
                        | "pull"
                        | "cherry-pick"
                        | "revert"
                        | "switch"
                        | "checkout"
                        | "stash"
                ))
            || matches!(
                (program, sub),
                (
                    "npm" | "pnpm" | "yarn" | "bun",
                    "install" | "add" | "remove"
                ) | ("cargo", "add" | "remove" | "fmt" | "fix")
                    | ("go", "mod" | "get")
                    | ("pip" | "pip3" | "uv", "install" | "add")
            )
    })
}

/// `sed -i`, `sed -Ei.bak`, `perl -0pi`, `perl -lpi.bak`: an `i` anywhere in
/// a short-option cluster, before an option whose value eats the rest.
fn edits_in_place(program: &str, args: &[String]) -> bool {
    // Options whose value is the rest of the cluster (or the next word).
    let takes_value = if program == "sed" {
        "efl"
    } else {
        "CDFIMVdeEmx"
    };
    args.iter().any(|a| {
        if a.starts_with("--in-place") {
            return true;
        }
        let Some(cluster) = a.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            return false;
        };
        let mut chars = cluster.chars().peekable();
        while let Some(c) = chars.next() {
            if c == 'i' || (program == "sed" && c == 'I') {
                return true;
            }
            if takes_value.contains(c) {
                return false;
            }
            // perl's `-0777`, `-0x1F` and `-l12` take a number.
            if program == "perl" && matches!(c, '0' | 'l') {
                let hex = c == '0' && chars.next_if_eq(&'x').is_some();
                while chars
                    .next_if(|d| d.is_ascii_digit() || (hex && d.is_ascii_hexdigit()))
                    .is_some()
                {}
            }
        }
        false
    })
}

fn analyze_tee(args: &[String], cfg: &ShellConfig, out: &mut Findings) {
    let mut append = false;
    let mut targets = Vec::new();
    let mut end_of_options = false;
    for a in args {
        // `>(cmd)` is a pipe; its command is judged as a segment of its own.
        if a.starts_with(">(") || a.starts_with("<(") {
            continue;
        }
        if end_of_options || !a.starts_with('-') || a == "-" {
            targets.push(a.as_str());
        } else if a == "--" {
            end_of_options = true;
        } else if a == "--append" || (!a.starts_with("--") && a.contains('a')) {
            append = true;
        }
    }
    for t in targets.into_iter().filter(|t| *t != "-") {
        judge_write(t, !append, &format!("tee {t}"), cfg, out);
    }
}

fn analyze_rm(args: &[String], cfg: &ShellConfig, out: &mut Findings) {
    let mut recursive = false;
    let mut no_preserve_root = false;
    let mut targets = Vec::new();
    let mut end_of_options = false;
    for a in args {
        if end_of_options || !a.starts_with('-') || a == "-" {
            targets.push(a.as_str());
        } else if a == "--" {
            end_of_options = true;
        } else if a == "--recursive" {
            recursive = true;
        } else if a == "--no-preserve-root" {
            no_preserve_root = true;
        } else if !a.starts_with("--") && (a.contains('r') || a.contains('R')) {
            recursive = true;
        }
    }
    if cfg.block_catastrophic {
        if no_preserve_root {
            out.block("`rm --no-preserve-root`".into());
            return;
        }
        if let Some(t) = targets.iter().find(|t| is_catastrophic_target(t)) {
            out.block(format!("`rm` targets `{t}`"));
            return;
        }
        if recursive && let Some(t) = targets.iter().find(|t| is_unguarded_variable_path(t)) {
            out.block(format!(
                "`rm -r {t}` would hit `/` if the variable is empty; use `${{VAR:?}}`"
            ));
            return;
        }
    }
    out.destructive("`rm` deletes files".into());
}

fn analyze_find(args: &[String], cfg: &ShellConfig, depth: usize, out: &mut Findings) {
    // Each `-exec ... ;` payload is a command of its own; judge it as one.
    let mut payload_findings = Findings::default();
    let mut deletes = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-delete" {
            deletes = true;
        } else if matches!(a, "-exec" | "-execdir" | "-ok" | "-okdir") {
            let start = i + 1;
            let end = args[start..]
                .iter()
                .position(|w| w == ";" || w == "+")
                .map_or(args.len(), |p| start + p);
            if depth < MAX_NESTING {
                analyze_segment(
                    &args[start..end],
                    &[],
                    cfg,
                    depth + 1,
                    &mut payload_findings,
                );
            }
            i = end;
        }
        i += 1;
    }
    if let Some(reason) = payload_findings.blocked {
        out.block(format!("`find -exec` runs {reason}"));
        return;
    }
    if !deletes && payload_findings.destructive.is_none() {
        return;
    }
    let roots: Vec<&str> = args
        .iter()
        .take_while(|a| !a.starts_with('-') && !a.starts_with('(') && !a.starts_with('!'))
        .map(String::as_str)
        .collect();
    if cfg.block_catastrophic
        && let Some(root) = roots.iter().find(|r| is_catastrophic_target(r))
    {
        out.block(format!("`find {root}` with deletion"));
        return;
    }
    out.destructive(payload_findings.destructive.map_or_else(
        || "`find` with deletion".into(),
        |r| format!("`find -exec`: {r}"),
    ));
}

fn analyze_git(args: &[String], cfg: &ShellConfig, out: &mut Findings) {
    // Skip global options such as `-C dir` and `-c key=value`.
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        i += if matches!(args[i].as_str(), "-C" | "-c" | "--git-dir" | "--work-tree") {
            2
        } else {
            1
        };
    }
    let Some(sub) = args.get(i) else { return };
    let rest = &args[i + 1..];
    let has = |flags: &[&str]| rest.iter().any(|a| flags.contains(&a.as_str()));
    let has_prefix = |prefixes: &[&str]| {
        rest.iter()
            .any(|a| prefixes.iter().any(|p| a.starts_with(p)))
    };
    let short_flag = |c: char| {
        rest.iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains(c))
    };

    match sub.as_str() {
        "restore" => {
            let staged_only = has(&["--staged", "-S"]) && !has(&["--worktree", "-W"]);
            if !staged_only {
                out.destructive("`git restore` discards working-tree changes".into());
            }
        }
        "checkout" => {
            if has(&["--", ".", "-f", "-B", "-p", "--patch", "--theirs", "--ours"])
                || has_prefix(&["--force", "--pathspec-from-file"])
                || checkout_names_paths(rest)
            {
                out.destructive("`git checkout` with paths or force discards changes".into());
            }
        }
        "switch" => {
            if has(&["-f", "-C"]) || has_prefix(&["--force", "--discard-changes"]) {
                out.destructive("`git switch` with force discards changes".into());
            }
        }
        "reset" => {
            if has(&["--hard", "--merge", "--keep"]) {
                out.destructive("`git reset --hard` discards changes".into());
            }
        }
        "clean" => {
            if !short_flag('n') && !has(&["--dry-run"]) {
                out.destructive("`git clean` deletes untracked files".into());
            }
        }
        "rm" => out.destructive("`git rm` deletes files".into()),
        "stash" => {
            if rest
                .first()
                .is_some_and(|a| matches!(a.as_str(), "drop" | "clear"))
            {
                out.destructive("`git stash` drop/clear".into());
            }
        }
        "push" => {
            let forced = rest.iter().any(|a| {
                a == "--force"
                    || a == "--mirror"
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
                    || (a.starts_with('+') && a.len() > 1)
            });
            if cfg.block_force_push && forced {
                out.block("force push rewrites remote history".into());
            }
        }
        _ => {}
    }
}

/// Whether `git checkout <rest>` restores files rather than switching
/// branches. The classifier does not see the working tree, so this guesses
/// from the operands: two or more mean `<tree-ish> <paths>`; a single one
/// counts as a path if it cannot be a ref (see `looks_like_path`).
fn checkout_names_paths(rest: &[String]) -> bool {
    let mut operands = Vec::new();
    let mut i = 0;
    while let Some(a) = rest.get(i) {
        i += 1;
        if matches!(a.as_str(), "-b" | "-B" | "--orphan") {
            i += 1; // the new branch name
        } else if !a.starts_with('-') || a == "-" {
            operands.push(a.as_str());
        }
    }
    operands.len() >= 2 || operands.first().is_some_and(|a| looks_like_path(a))
}

/// A checkout operand that is a path rather than a branch, tag or commit.
/// Git refs cannot end in `/`, contain `*?[:` or have a component starting
/// with `.`, so those are paths. Otherwise a final component with a file
/// extension (`main.rs`, `Cargo.toml`) is taken as a file; versions like
/// `v1.2.3` or `2.x` are not. Extensionless files (`Makefile`) are missed.
fn looks_like_path(a: &str) -> bool {
    if a == "-" || a.is_empty() {
        return false;
    }
    if a.starts_with(['/', ':']) || a.ends_with('/') || a.contains(['*', '?', '[']) {
        return true;
    }
    if a.split('/').any(|c| c.starts_with('.')) {
        return true;
    }
    if a.contains(['~', '^', '@']) {
        return false;
    }
    let last = a.rsplit('/').next().unwrap_or(a);
    last.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty()
            && ext.starts_with(|c: char| c.is_ascii_alphabetic())
            && ext.chars().all(|c| c.is_ascii_alphanumeric())
            && !ext.eq_ignore_ascii_case("x")
    })
}

fn is_catastrophic_target(target: &str) -> bool {
    let t = target.trim();
    if t.is_empty() {
        return false;
    }
    let trimmed = t.trim_end_matches('/');
    let t = if trimmed.is_empty() { "/" } else { trimmed };
    const EXACT: &[&str] = &[
        "/",
        "/*",
        "~",
        "~/*",
        "$HOME",
        "${HOME}",
        "$HOME/*",
        "${HOME}/*",
        "..",
        "../*",
        "/Users",
        "/Users/*",
        "/home",
        "/home/*",
        "/root",
        "/etc",
        "/usr",
        "/var",
        "/bin",
        "/sbin",
        "/lib",
        "/opt",
        "/System",
        "/Library",
        "/Applications",
        "/private",
        "/boot",
        "/dev",
    ];
    if EXACT.contains(&t)
        || t.strip_suffix("/*")
            .is_some_and(|base| EXACT.contains(&base))
    {
        return true;
    }
    // A single user's home directory or everything in it, e.g. /Users/alice,
    // /home/bob/*, /home/$USER, ~carol. Any single component counts.
    let home = t.strip_suffix("/*").map_or(t, |b| b.trim_end_matches('/'));
    for prefix in ["/Users/", "/home/", "~"] {
        if let Some(rest) = home.strip_prefix(prefix)
            && !rest.is_empty()
            && !rest.contains('/')
        {
            return true;
        }
    }
    false
}

/// `$DIR/...` or `${DIR}/...` without a `:?` guard expands to `/...` when unset.
fn is_unguarded_variable_path(target: &str) -> bool {
    let Some(rest) = target.strip_prefix('$') else {
        return false;
    };
    let (name, after) = if let Some(braced) = rest.strip_prefix('{') {
        match braced.split_once('}') {
            Some((inner, after)) => {
                if inner.contains(":?") {
                    return false;
                }
                (inner, after)
            }
            None => return false,
        }
    } else {
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    };
    !name.is_empty() && after.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    // These tests pin the new parser on its own; `combined` below covers the
    // verdict the hook acts on.
    use super::classify_new as classify;

    fn cfg() -> ShellConfig {
        ShellConfig::default()
    }

    fn blocked(cmd: &str) -> bool {
        matches!(classify(cmd, &cfg()), Verdict::Blocked(_))
    }

    fn destructive(cmd: &str) -> bool {
        matches!(classify(cmd, &cfg()), Verdict::Destructive(_))
    }

    #[test]
    fn safe_everyday_commands() {
        for cmd in [
            "cargo test --all",
            "git status && git diff",
            "ls -la | grep rm",
            "echo 'rm -rf /'",
            "git checkout -b feature",
            "git push origin main",
            "git push --force-with-lease origin feature",
            "npm run build",
            "grep -rn 'git reset --hard' docs/",
        ] {
            assert_eq!(classify(cmd, &cfg()), Verdict::Safe, "{cmd}");
        }
    }

    #[test]
    fn blocks_catastrophic_deletes() {
        for cmd in [
            "rm -rf /",
            "rm -rf ~",
            "rm -rf ~/",
            "sudo rm -rf /*",
            "rm -fr $HOME",
            "rm -rf \"$HOME\"",
            "rm -rf $BUILD_DIR/",
            "rm -rf ${OUT}/*",
            "cd /tmp && rm -rf ..",
            "{ rm -rf /; }",
            "if true; then rm -rf ~; fi",
            "rm -rf /Users/alice",
            "bash -c 'rm -rf /'",
            "sh -lc \"cd x; rm -rf ~\"",
            "rm --no-preserve-root -rf /",
            "find / -name '*.log' -delete",
            "find ~ -exec rm {} ;",
            "dd if=/dev/zero of=/dev/disk2",
            "mkfs.ext4 /dev/sdb1",
            "chmod -R 777 /",
            ":(){ :|:& };:",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
    }

    #[test]
    fn timeout_options_with_values_are_skipped() {
        for cmd in [
            "timeout -s KILL 10 rm -rf ~/",
            "timeout -k 5 30 rm -rf /",
            "timeout --signal KILL 10 rm -rf ~",
            "timeout --kill-after 5 30 rm -rf /",
            "timeout --signal=KILL 10 rm -rf ~",
            "timeout -sKILL 10 rm -rf ~",
            "timeout -vs KILL 10 rm -rf ~",
            "timeout --preserve-status -s TERM -k 1 10 rm -rf ~",
            "timeout -- 10 rm -rf ~",
            "sudo timeout -s KILL 10 rm -rf /",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(destructive("timeout -s KILL 10 rm -rf build"));
        assert!(destructive("timeout -k 5 30 rm -rf build"));
        assert!(destructive("timeout 10 rm -rf build"));
        assert_eq!(
            classify("timeout -s INT 30 cargo test", &cfg()),
            Verdict::Safe
        );
    }

    #[test]
    fn wrapper_options_with_values_are_skipped() {
        for cmd in [
            "sudo -u root rm -rf ~",
            "sudo -uroot rm -rf ~",
            "sudo -Eu root rm -rf ~",
            "sudo --user=root rm -rf ~",
            "sudo --user root rm -rf ~",
            "sudo -D /tmp rm -rf ~",
            "sudo -p prompt rm -rf ~",
            "sudo -U bob rm -rf ~",
            "sudo -h host rm -rf ~",
            "sudo -s rm -rf ~",
            "sudo -- rm -rf ~",
            "doas -u root rm -rf /",
            "env -C /tmp rm -rf ~",
            "env -u PATH rm -rf ~",
            "env -- rm -rf ~",
            "env -i FOO=1 rm -rf ~",
            "env - rm -rf ~",
            "doas -a style rm -rf /",
            "sudo -a type rm -rf ~",
            "sudo -c class rm -rf ~",
            "sudo --us root rm -rf ~",
            "timeout --sig KILL 10 rm -rf ~",
            "timeout --kill 5 10 rm -rf ~",
            "xargs --replace rm -rf ~",
            "xargs --max-lines rm -rf ~",
            "xargs --replace={} rm -rf ~",
            "exec -a name rm -rf ~",
            "time -o out.txt rm -rf ~",
            "time -f %e rm -rf ~",
            "nice -n 5 rm -rf ~",
            "nice --adjustment 5 rm -rf ~",
            "nice -5 rm -rf ~",
            "stdbuf -o L rm -rf ~",
            "stdbuf -oL rm -rf ~",
            "xargs -L 1 rm -rf ~",
            "xargs -d x rm -rf ~",
            "xargs -I {} rm -rf ~",
            "xargs -0 -n 1 rm -rf ~",
            "nohup nice -n 5 timeout -s KILL 10 rm -rf ~",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(destructive("sudo -D /tmp rm -rf build"));
        assert!(destructive("xargs -L 1 rm -rf build"));
    }

    #[test]
    fn env_split_string_is_judged_as_a_command() {
        for cmd in [
            "env -S 'rm -rf ~'",
            "env -S\"rm -rf /\"",
            "env -vS 'rm -rf ~'",
            "env --split-string='rm -rf ~'",
            "env --split-string 'sudo rm -rf /'",
            "env --split='rm -rf ~'",
            "env -S 'rm -rf' ~",
            "env -S rm -rf ~",
            "env -S '-u FOO rm -rf ~'",
            "env -S 'rm\\_-rf\\_~'",
            "env -S 'env -S \"rm -rf ~\"'",
            "sudo env -S 'rm -rf /'",
            "FOO=1 env -i -S 'rm -rf ~'",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(destructive("env -S 'rm -rf build'"));
        assert!(destructive("env -S 'rm -rf' build"));
        assert_eq!(classify("env -S 'cargo test'", &cfg()), Verdict::Safe);
        // Words before `-S` keep applying.
        assert!(blocked("sudo env -u X -S 'rm -rf' /"));
        assert!(blocked("env -S '-C / rm' -rf ~"));
        // env does not expand `~` in the string, so this is a literal `./~`;
        // blocking it anyway is the deliberate, conservative choice.
        assert!(blocked("env -S 'rm -rf ~'"));
        // env's own string rules, not the shell's.
        assert!(blocked("env -S 'rm -rf /\\c'"));
        assert!(blocked("env -S 'rm -rf ${HOME}\\c ignored'"));
        assert!(blocked("env -S '\"rm\" -rf / # comment'"));
        assert_eq!(classify("env -S '# rm -rf /'", &cfg()), Verdict::Safe);
        assert_eq!(
            classify("env -S 'echo a > f; rm -rf /'", &cfg()),
            Verdict::Safe
        );
        // Nesting has no depth limit to slip past.
        assert!(blocked(
            "env -S 'env -S \"env -S \\\"env -S rm -rf ~\\\"\"'"
        ));
        // The split string is the program; what follows is its arguments.
        assert_eq!(classify("env -S 'echo' rm -rf ~", &cfg()), Verdict::Safe);
        assert!(mutates("env -S 'touch a'"));
        // Arguments after the split string keep their word boundaries.
        assert!(destructive("env -S 'rm -rf' \"it's a dir\""));
        assert_eq!(classify("env -S 'echo' \"it's ~\"", &cfg()), Verdict::Safe);
    }

    #[test]
    fn guarded_variable_is_only_destructive() {
        assert!(destructive("rm -rf ${BUILD_DIR:?}/dist"));
        assert!(destructive("rm -rf \"$TMP\""));
    }

    #[test]
    fn blocks_force_push() {
        assert!(blocked("git push --force origin main"));
        assert!(blocked("git push -f"));
        assert!(blocked("git push origin +main"));
        let mut c = cfg();
        c.block_force_push = false;
        assert_eq!(classify("git push -f", &c), Verdict::Safe);
    }

    #[test]
    fn detects_destructive_git_and_file_commands() {
        for cmd in [
            "git restore .",
            "git restore src/main.rs",
            "git checkout -- .",
            "git checkout .",
            "git reset --hard HEAD~1",
            "git -C repo reset --hard",
            "git clean -fd",
            "git stash drop",
            "rm -rf target",
            "rm file.txt",
            "mv a.txt b.txt",
            "sed -i '' 's/a/b/' file",
            "find . -name '*.tmp' -delete",
            "cargo build && rm -rf dist",
            "ls | xargs rm",
            "FOO=1 rm x",
            "/bin/rm -r build",
        ] {
            assert!(destructive(cmd), "{cmd}");
        }
        assert_eq!(classify("git restore --staged a.rs", &cfg()), Verdict::Safe);
    }

    #[test]
    fn blocked_substrings_are_case_insensitive() {
        let mut c = cfg();
        c.blocked_substrings = vec!["terraform destroy".into()];
        assert!(matches!(
            classify("TERRAFORM DESTROY -auto-approve", &c),
            Verdict::Blocked(_)
        ));
    }

    #[test]
    fn catastrophic_checks_can_be_disabled() {
        let mut c = cfg();
        c.block_catastrophic = false;
        assert!(matches!(classify("rm -rf /", &c), Verdict::Destructive(_)));
    }

    #[test]
    fn find_exec_payloads_are_judged_as_commands() {
        assert!(blocked("find / -execdir sh -c 'rm -rf ~' \\;"));
        assert!(blocked("find . -execdir bash -c 'rm -rf $HOME' \\;"));
        assert!(blocked("find ~ -exec rm {} +"));
        assert!(destructive("find . -name '*.bak' -exec rm {} \\;"));
        assert!(destructive("find . -exec sh -c 'echo x > {}' \\;"));
        assert_eq!(
            classify("find . -name '*.rs' -exec grep -l foo {} +", &cfg()),
            Verdict::Safe
        );
    }

    #[test]
    fn truncating_redirects_are_destructive() {
        assert!(destructive("echo override > src/lib.rs"));
        assert!(destructive("cat foo > ~/.bashrc"));
        assert!(destructive("> important_file.py"));
        for cmd in [
            "echo x >> log.txt",
            "cargo test > /tmp/out.log 2>&1",
            "make 2>/dev/null",
            "cmd > $TMPDIR/x",
        ] {
            assert_eq!(classify(cmd, &cfg()), Verdict::Safe, "{cmd}");
        }
    }

    #[test]
    fn system_directory_globs_are_catastrophic() {
        assert!(blocked("rm -rf /etc/*"));
        assert!(blocked("rm -rf /usr/*"));
        assert!(destructive("rm -rf build/*"));
    }

    #[test]
    fn long_flag_variants_are_caught() {
        assert!(destructive("git checkout --force-create feature"));
        assert!(destructive("git switch --force-create feature"));
        assert!(destructive("git switch -C feature"));
        assert!(destructive("sed --in-place 's/a/b/' f"));
    }

    #[test]
    fn dry_runs_do_not_snapshot() {
        for cmd in [
            "git clean -n",
            "git clean -nd",
            "git clean --dry-run",
            "git stash pop",
        ] {
            assert_eq!(classify(cmd, &cfg()), Verdict::Safe, "{cmd}");
        }
        assert!(destructive("git clean -fd"));
    }

    #[test]
    fn mutation_heuristic() {
        for cmd in [
            "echo x > out.txt",
            "cat a >> b",
            "git commit -m x",
            "cp a b",
            "npm install",
            "rm x",
            "cargo fmt",
        ] {
            assert!(mutates(cmd), "{cmd}");
        }
        for cmd in [
            "cargo test 2>&1",
            "ls > /dev/null",
            "grep -r x .",
            "git status",
            "cargo build 2>/dev/null",
        ] {
            assert!(!mutates(cmd), "{cmd}");
        }
    }

    #[test]
    fn tokenizer_honors_quotes_and_operators() {
        let segs = split_segments("echo \"a; b\" && rm 'x y' | cat");
        assert_eq!(
            segs,
            vec![
                vec!["echo".to_string(), "a; b".to_string()],
                vec!["rm".to_string(), "x y".to_string()],
                vec!["cat".to_string()],
            ]
        );
    }

    fn safe(cmd: &str) -> bool {
        classify(cmd, &cfg()) == Verdict::Safe
    }

    #[test]
    fn line_continuations_join_words() {
        assert!(blocked("cd build && \\\n  rm -rf ~"));
        assert!(blocked("sudo \\\n rm -rf /"));
        assert!(blocked("rm -rf \\\n/"));
        assert!(blocked("echo \"a\\\nb\"; rm -rf ~"));
        assert_eq!(
            split_segments("cargo \\\n  test"),
            vec![vec!["cargo".to_string(), "test".to_string()]]
        );
    }

    #[test]
    fn comments_are_skipped() {
        assert!(blocked("# Let's clean up\nrm -rf ~/\necho 'done'"));
        assert!(safe("cargo test # cleanup; rm -rf /"));
        assert!(safe("# rm -rf ~"));
        // `#` inside a word is not a comment.
        assert!(blocked("echo a#b; rm -rf ~"));
        assert!(blocked("echo ${#x}; rm -rf ~"));
        assert!(blocked("echo \"#\"; rm -rf ~"));
    }

    #[test]
    fn heredoc_bodies_are_data() {
        assert!(blocked("cat > /tmp/a.txt <<EOF\nIt's fine\nEOF\nrm -rf ~"));
        assert!(blocked("cat <<-'EOF' > /tmp/a\n\tIt's\n\tEOF\nrm -rf ~"));
        assert!(blocked("cat <<\"EOF\" > /tmp/a\nIt's\nEOF\nrm -rf ~"));
        assert!(blocked("cat <<\\EOF > /tmp/a\nIt's\nEOF\nrm -rf ~"));
        assert!(blocked("cat <<A - /dev/stdin <<B\nx'\nA\ny'\nB\nrm -rf ~"));
        // The file a heredoc overwrites still counts; its body does not.
        assert_eq!(
            classify(
                "cat > scripts/clean.sh <<'EOF'\n#!/bin/sh\nrm -rf \"$OUT_DIR\"/*\nEOF",
                &cfg()
            ),
            Verdict::Destructive("`> scripts/clean.sh` overwrites the file".into())
        );
        assert!(safe(
            "cat > /tmp/notes.md <<'EOF'\ngit push --force origin main\nEOF"
        ));
        assert!(safe("git commit -F- <<'EOF'\nrm -rf ~\nEOF"));
        // An unquoted delimiter still expands substitutions in the body.
        assert!(blocked("cat > /tmp/a <<EOF\n$(rm -rf ~)\nEOF"));
        assert!(blocked("cat > /tmp/a <<EOF\n`rm -rf ~`\nEOF"));
        assert!(safe("cat > /tmp/a <<'EOF'\n$(rm -rf ~)\nEOF"));
        assert!(safe("cat > /tmp/a <<EOF\n\\$(rm -rf ~)\nEOF"));
        // A heredoc inside a substitution.
        assert!(blocked("msg=$(cat <<'EOF'\nIt's\nEOF\n); rm -rf ~"));
        // Unterminated: the shell reads the body to the end, and so do we.
        assert!(safe("cat > /tmp/a <<EOF\nrm -rf ~"));
        // Shifts in arithmetic are not heredocs.
        assert!(blocked("(( x = 1 << 2 ))\nrm -rf ~"));
        assert!(blocked("echo $(( 1 << 2 ))\nrm -rf ~"));
        assert!(blocked("(( $(rm -rf ~) ))"));
        assert!(blocked("((cd x; rm -rf ~) )"));
        // Here-strings are one word, not a heredoc.
        assert!(blocked("cat <<< \"it's\"; rm -rf ~"));
    }

    #[test]
    fn heredocs_fed_to_a_shell_are_commands() {
        for cmd in [
            "bash <<'EOF'\nrm -rf ~\nEOF",
            "cat <<'EOF' | sh\nrm -rf ~\nEOF",
            "sudo bash -s <<EOF\nrm -rf /\nEOF",
            "bash -s -- arg <<'EOF'\nrm -rf ~\nEOF",
            "ssh host <<'EOF'\nrm -rf ~\nEOF",
            "docker exec -i box sh <<'EOF'\nrm -rf /\nEOF",
            "bash <<< 'rm -rf ~'",
            "sh -x <<'EOF'\ncd x\nrm -rf ~\nEOF",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(destructive("bash <<'EOF'\ngit reset --hard\nEOF"));
        for cmd in [
            "cat <<'EOF' > /tmp/x\nrm -rf ~\nEOF",
            "grep bash <<'EOF'\nrm -rf ~\nEOF",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
    }

    #[test]
    fn heredocs_are_commands_unless_a_data_reader_takes_them() {
        for cmd in [
            // Inside a substitution whose output is run.
            "eval \"$(cat <<'EOF'\nrm -rf ~\nEOF\n)\"",
            "bash -c \"$(cat <<'EOF'\nrm -rf ~\nEOF\n)\"",
            "$(cat <<'EOF'\nrm -rf ~\nEOF\n)",
            "echo \"$(cat <<'EOF'\nrm -rf ~\nEOF\n)\" | sh",
            "bash <(cat <<EOF\nrm -rf ~\nEOF\n)",
            "x=`cat <<EOF\nrm -rf ~\nEOF\n`",
            // Shell options with values are not a script file.
            "bash -e -o pipefail <<'EOF'\nrm -rf ~\nEOF",
            "bash -O extglob <<EOF\nrm -rf ~\nEOF",
            "bash --rcfile x.rc <<EOF\nrm -rf ~\nEOF",
            // A wrapper that starts a shell.
            "sudo -s <<'EOF'\nrm -rf /\nEOF",
            "sudo -i <<EOF\nrm -rf /\nEOF",
            "doas -s <<EOF\nrm -rf /\nEOF",
            "cat <<EOF | sudo -u root -s\nrm -rf /\nEOF",
            "cat <<EOF | sudo --user root --login\nrm -rf /\nEOF",
            // Piped on to something that may run it.
            "cat <<'EOF' | $SHELL\nrm -rf ~\nEOF",
            "cat <<'EOF' | bash-5.2\nrm -rf ~\nEOF",
            "cat <<'EOF' | at now\nrm -rf ~\nEOF",
            "cat <<'EOF' | parallel\nrm -rf ~\nEOF",
            "cat <<'EOF' |\nrm -rf ~\nEOF\n  sh",
            "cat <<'EOF' |& sh\nrm -rf ~\nEOF",
            "cat <<'EOF' | sort | sh\nrm -rf ~\nEOF",
            // Reading stdin as a script.
            "bash /dev/stdin <<'EOF'\nrm -rf ~\nEOF",
            "source /dev/stdin <<EOF\nrm -rf ~\nEOF",
            ". /dev/stdin <<EOF\nrm -rf ~\nEOF",
            // A script given stdin may run it; and an unknown consumer.
            "bash -c 'cat' <<'EOF'\nrm -rf ~\nEOF",
            "bash build.sh <<'EOF'\nrm -rf ~\nEOF",
            "mystery-tool <<'EOF'\nrm -rf ~\nEOF",
            "mystery-tool <<< 'rm -rf ~'",
            // A data reader, but a shell elsewhere on the line.
            "cat <<EOF | python3\nimport os\nEOF\nbash <<X\nrm -rf ~\nX",
            "cat > x.sh <<'EOF'\nrm -rf ~\nEOF\nbash x.sh",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        for cmd in [
            "cat > /tmp/notes.md <<'EOF'\ngit push --force origin main\nEOF",
            "git commit -F - <<'EOF'\nfix: rm -rf handling\nEOF",
            "python3 - <<'EOF'\nimport shutil\nEOF",
            "python3.12 - <<'EOF'\nrm -rf ~\nEOF",
            "git commit -m \"$(cat <<'EOF'\nfix: rm -rf ~ handling\nIt's done\nEOF\n)\"",
            "git commit -m \"`cat <<EOF\nrm -rf ~\nEOF\n`\"",
            "jq . <<< '{\"rm\": \"rm -rf ~\"}'",
            "cat <<'EOF' | sort | head -n 3\nrm -rf ~\nEOF",
            "cat <<'EOF' > /tmp/x || echo failed\nrm -rf ~\nEOF",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
        assert_eq!(
            classify(
                "cat > scripts/clean.sh <<'EOF'\n#!/bin/sh\nrm -rf \"$OUT_DIR\"/*\nEOF",
                &cfg()
            ),
            Verdict::Destructive("`> scripts/clean.sh` overwrites the file".into())
        );
        // Past the nesting limit a body that must be read is not skipped.
        assert!(blocked(
            "bash -c \"bash -c 'bash -c \\\"bash <<< true\\\"'\""
        ));
    }

    #[test]
    fn spent_arithmetic_budget_reads_no_heredocs() {
        let misses = "((a) ); ".repeat(MAX_ARITH_MISSES);
        assert!(blocked(&format!("{misses}echo $((1<<2))\nrm -rf ~")));
        assert!(blocked(&format!("{misses}(( x = 1 << 2 ))\nrm -rf ~")));
        // Real heredocs after that point are read as commands.
        assert!(blocked(&format!("{misses}cat <<EOF\nrm -rf ~\nEOF")));
    }

    #[test]
    fn case_counts_at_any_command_position() {
        for cmd in [
            "echo \"$(if true; then case a in a) rm -rf ~;; esac; fi)\"",
            "echo \"$(for x in 1; do case a in a) rm -rf ~;; esac; done)\"",
            "echo \"$(if false; then :; else case a in a) rm -rf ~;; esac; fi)\"",
            "echo \"$({ case a in a) rm -rf ~;; esac; })\"",
            "echo \"$(true && case a in a) rm -rf ~;; esac)\"",
            "echo \"$( (case a in a) echo;; esac); rm -rf ~ )\"",
            "echo \"$(case a in (a) echo;; esac)\"; rm -rf ~",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        // The substitution ends after `esac`; the rest is quoted text.
        assert!(safe("echo \"$(case a in (a) echo;; esac); rm -rf ~\""));
    }

    #[test]
    fn substitutions_are_judged_wherever_they_appear() {
        assert!(blocked("echo \"$(rm -rf ~)\""));
        assert!(blocked("echo \"`rm -rf ~`\""));
        assert!(destructive("out=\"$(git reset --hard origin/main 2>&1)\""));
        assert!(blocked("rm -rf $(git rev-parse --show-toplevel) ~"));
        assert!(blocked("chmod -R 777 $(whoami) ~"));
        assert!(blocked("echo \"$(echo \")\"; rm -rf ~)\""));
        assert!(blocked("diff <(ls) <(rm -rf ~)"));
        assert!(blocked("tee >(rm -rf ~) < /dev/null"));
        assert!(blocked("echo x | tee >(rm -rf ~)"));
        assert!(blocked("x=$(echo $(rm -rf ~))"));
        assert!(blocked("x=$( (cd a; ls) ; rm -rf ~)"));
        assert!(blocked("echo \"$(case $x in a) rm -rf ~;; esac)\""));
        assert!(blocked("echo `echo \\`rm -rf ~\\``"));
        assert!(safe("echo \"\\$(rm -rf ~)\""));
        assert!(safe("echo '$(rm -rf ~)'"));
        assert!(safe("git log --format=\"$(echo %H)\" | head"));
        // ANSI-C quotes can hold an escaped quote.
        assert!(blocked("echo $'it\\'s'; rm -rf ~"));
        // The substitution stays one word of the outer command.
        assert_eq!(
            split_segments("rm -rf $(pwd) build"),
            vec![
                vec!["pwd".to_string()],
                vec![
                    "rm".to_string(),
                    "-rf".to_string(),
                    "$(pwd)".to_string(),
                    "build".to_string()
                ],
            ]
        );
    }

    #[test]
    fn redirect_operators_are_tokens() {
        for cmd in [
            "echo x >| src/main.rs",
            "echo x >& src/main.rs",
            "echo x >&src/main.rs",
            "cmd &> out.log",
            "cmd &>out.log",
            "echo a>b",
            "echo x 1> src/main.rs",
        ] {
            assert_eq!(
                classify(cmd, &cfg()),
                Verdict::Destructive(format!(
                    "`> {}` overwrites the file",
                    if cmd.contains("out.log") {
                        "out.log"
                    } else if cmd.ends_with("a>b") {
                        "b"
                    } else {
                        "src/main.rs"
                    }
                )),
                "{cmd}"
            );
        }
        for cmd in [
            "cmd &>> out.log",
            "cmd >&2",
            "cmd 2>&1",
            "cmd 2>&-",
            "cmd &> /dev/null",
            "echo a>/tmp/x",
            "sort < in.txt",
            "cmd 2>> err.log",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
        assert!(mutates("cmd &>> out.log"));
        assert!(!mutates("cmd >&2"));
    }

    #[test]
    fn quoted_operators_are_not_redirects() {
        for cmd in [
            "grep -n \">\" src/main.rs",
            "grep '>>' f",
            "echo \"a > b\"",
            "awk '$1 > 3' f",
            "echo \\> f",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
    }

    #[test]
    fn single_home_globs_are_catastrophic() {
        for cmd in [
            "rm -rf /Users/alice/*",
            "rm -rf /home/bob/*",
            "rm -rf /home/bob/",
            "rm -rf ~bob",
            "rm -rf ~bob/*",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        for cmd in [
            "rm -rf /Users/$USER",
            "rm -rf /home/$USER",
            "rm -rf \"/Users/$(whoami)\"",
            "rm -rf /home/.snapshots",
            "rm -rf /Users/$USER/*",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(destructive("rm -rf /Users/alice/project/*"));
        assert!(destructive("rm -rf /home/bob/build"));
        assert!(destructive("rm -rf /home/$USER/build"));
    }

    #[test]
    fn recursive_flag_clusters_are_caught() {
        for cmd in [
            "chmod -Rv 777 ~",
            "sudo chown -Rf nobody /",
            "chmod -vR 755 /etc",
            "chmod --recursive 777 /",
            "chgrp -R staff ~",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(safe("chmod -v 644 ~/notes.txt"));
        assert!(safe("chmod -R 755 build"));
    }

    #[test]
    fn writes_to_raw_devices_are_blocked() {
        for cmd in [
            "cat disk.img > /dev/disk2",
            "cat disk.img >> /dev/sda",
            "cat disk.img &> /dev/rdisk3",
            "cat disk.img | sudo tee /dev/nvme0n1",
            "dd if=x.img of=/dev/disk4",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        for cmd in [
            "make > /dev/null 2>&1",
            "echo hi > /dev/stderr",
            "echo hi > /dev/stdout",
            "echo hi > /dev/tty",
            "echo hi >/dev/fd/3",
            "dd if=/dev/zero of=/dev/null count=1",
            "cat x > /dev/shm/x",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
        assert!(destructive("dd if=a.img of=out.img"));
        let mut c = cfg();
        c.block_catastrophic = false;
        assert!(matches!(
            classify("cat x > /dev/disk2", &c),
            Verdict::Destructive(_)
        ));
    }

    #[test]
    fn function_bodies_are_judged() {
        for cmd in [
            "function cleanup { rm -rf ~; }; cleanup",
            "function cleanup() { rm -rf ~; }",
            "cleanup() { rm -rf ~; }; cleanup",
            "cleanup () {\n  rm -rf ~\n}",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
    }

    #[test]
    fn diskutil_destructive_verbs_are_blocked() {
        for cmd in [
            "diskutil secureErase 0 disk2",
            "diskutil partitionDisk disk2 GPT JHFS+ New 100%",
            "diskutil reformat disk2",
            "diskutil eraseDisk APFS X disk2",
            "diskutil apfs deleteContainer disk3",
            "diskutil apfs deleteVolume disk3s5",
            "diskutil zeroDisk disk2",
        ] {
            assert!(blocked(cmd), "{cmd}");
        }
        assert!(safe("diskutil list"));
        assert!(safe("diskutil info disk2"));
    }

    #[test]
    fn git_checkout_of_paths_is_destructive() {
        for cmd in [
            "git checkout src/main.rs",
            "git checkout HEAD src/main.rs",
            "git checkout main Cargo.toml",
            "git checkout HEAD~1 Makefile",
            "git checkout .gitignore",
            "git checkout .github/workflows/ci.yml",
            "git checkout src/",
            "git checkout ./README",
            "git checkout '*.rs'",
            "git checkout --pathspec-from-file=paths.txt",
        ] {
            assert!(destructive(cmd), "{cmd}");
        }
        for cmd in [
            "git checkout -b x",
            "git checkout main",
            "git checkout feature/foo",
            "git checkout -b feature origin/feature",
            "git checkout -t origin/feature",
            "git checkout --track origin/feature",
            "git checkout -",
            "git checkout HEAD~1",
            "git checkout v1.2.3",
            "git checkout release/2.x",
            "git checkout -q --detach main",
            "git checkout --orphan gh-pages",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
    }

    #[test]
    fn in_place_flag_clusters_are_caught() {
        for cmd in [
            "sed -Ei 's/a/b/' f",
            "sed -ri 's/a/b/' f",
            "sed -i.bak 's/a/b/' f",
            "sed -n -i 's/a/b/p' f",
            "sed -I '' 's/a/b/' f",
            "perl -0pi -e 's/a/b/' f",
            "perl -lpi -e 's/a/b/' f",
            "perl -0777pi -e 's/a/b/' f",
            "perl -pi.bak -e 's/a/b/' f",
            "perl -i -pe 's/a/b/' f",
            "perl -pie 's/a/b/' f",
            "perl -0x1Fpi -e 's/a/b/' f",
        ] {
            assert!(destructive(cmd), "{cmd}");
        }
        for cmd in [
            "sed -n 's/i/x/p' f",
            "sed -e 's/i/x/' f",
            "sed -E 's/a/b/' f",
            "sed -ne 's/i/x/p' f",
            "perl -ne 'print if /i/' f",
            "perl -lane 'print $F[0]' f",
            "perl -Mstrict -e 'print 1'",
            "perl -Ilib -e 'print 1'",
            "perl -le 'print 1'",
            "perl -0777 -ne 'print' f",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
    }

    #[test]
    fn tee_and_rsync_overwrites_are_destructive() {
        for cmd in [
            "echo x | tee src/lib.rs",
            "echo x | tee -p out.txt",
            "echo x | tee -- -a",
            "echo x | tee >(wc -l) out.txt",
            "rsync -a --delete dist/ src/",
            "rsync -av --delete-after a/ b/",
            "rsync -a --del a/ b/",
            "rsync -a --remove-source-files a/ b/",
        ] {
            assert!(destructive(cmd), "{cmd}");
        }
        for cmd in [
            "echo x | tee -a log.txt",
            "echo x | tee --append log.txt",
            "echo x | tee /tmp/x",
            "echo x | tee /dev/null",
            "echo x | tee",
            "echo x | tee >(gzip > /tmp/out.gz)",
            "echo x | tee >(wc -l) /tmp/x",
            "rsync -a dist/ out/",
            "cp a b",
        ] {
            assert!(safe(cmd), "{cmd}");
        }
    }

    #[test]
    fn command_lookup_is_not_a_wrapper() {
        for cmd in ["command -v rm", "command -V rm", "command -pv rm"] {
            assert!(safe(cmd), "{cmd}");
        }
        assert!(blocked("command rm -rf ~"));
        assert!(blocked("command -p rm -rf ~"));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let deep = "$(".repeat(10_000);
        let deep_quoted = "\"$(".repeat(10_000);
        let deep_arith = "$((".repeat(10_000);
        let parens = "((".repeat(5_000);
        let ticks = "`\\`".repeat(5_000);
        for cmd in [
            "\\",
            "a\\",
            "'",
            "\"",
            "$(",
            "$((",
            "((",
            "))",
            "`",
            "<<",
            "<<-",
            "cat <<EOF",
            "cat <<'",
            "$'",
            "$'\\",
            ">&",
            "&>",
            ">",
            "<(",
            "é$(ü) «»\u{feff}<<ß\nß",
            "#",
            "\n\n",
            deep.as_str(),
            deep_quoted.as_str(),
            deep_arith.as_str(),
            parens.as_str(),
            ticks.as_str(),
        ] {
            let _ = classify(cmd, &cfg());
            let _ = mutates(cmd);
            let _ = split_segments(cmd);
        }
        assert!(blocked(&format!("{deep}rm -rf ~")));
    }
}

#[cfg(test)]
mod combined {
    use super::*;

    fn verdict(cmd: &str) -> Verdict {
        classify(cmd, &ShellConfig::default())
    }

    fn new_only(cmd: &str) -> Verdict {
        classify_new(cmd, &ShellConfig::default())
    }

    /// Shapes the new tokenizer misreads (found in review round 3) that the
    /// old parser still catches, so the combined verdict blocks them.
    #[test]
    fn old_parser_covers_new_parser_misses() {
        for cmd in [
            "echo ${x:- #}; rm -rf ~",
            "(( x = '))' )); rm -rf ~",
            "(( '))' )) && rm -rf ~",
            "cat > x.sh <<EOF\nrm -rf ~\nEOF\n./x.sh",
        ] {
            assert!(
                !matches!(new_only(cmd), Verdict::Blocked(_)),
                "{cmd:?} is no longer a miss for the new parser"
            );
            assert!(matches!(verdict(cmd), Verdict::Blocked(_)), "{cmd:?}");
        }
    }

    /// Bypasses both parsers missed, found in review.
    #[test]
    fn review_bypasses_are_blocked() {
        for cmd in [
            "echo x > /dev/shm/../sda",
            "cat img | tee /dev/pts/../sda",
            "$'\\x72\\x6d' -rf ~",
            "$'\\162\\155' -rf ~",
            "bash5 -c 'rm -rf ~'",
            "bash-5.2 -c 'rm -rf ~'",
            "busybox rm -rf ~",
            "busybox sh -c 'rm -rf ~'",
            "bash -c -- 'rm -rf ~'",
            "cat <<$'E\\x4fF'\nhi\nEOF\nrm -rf ~",
            "dd if=/dev/zero of=/dev/fd/../disk0",
        ] {
            assert!(
                matches!(verdict(cmd), Verdict::Blocked(_)),
                "{cmd:?}: {:?}",
                verdict(cmd)
            );
        }
        assert_eq!(verdict("echo $'a\\tb\\x'"), Verdict::Safe);
        assert_eq!(verdict("echo hi > /dev/shm/scratch"), Verdict::Safe);
    }

    #[test]
    fn very_long_commands_skip_the_new_parser_but_still_snapshot() {
        let nested = format!("x<<E\n{}E\nrm -rf ~", "$(x<<E\n".repeat(6000));
        let start = std::time::Instant::now();
        assert!(matches!(verdict(&nested), Verdict::Blocked(_)));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        let big_write = format!("cat > notes.md <<'EOF'\n{}EOF", "hello\n".repeat(4000));
        assert!(matches!(verdict(&big_write), Verdict::Destructive(_)));
    }

    #[test]
    fn stricter_verdict_wins_both_ways() {
        // Only the new parser sees this one.
        assert!(matches!(verdict("chmod -Rv 777 ~"), Verdict::Blocked(_)));
        assert!(matches!(verdict("rm -rf ~"), Verdict::Blocked(_)));
        assert_eq!(verdict("cargo test --all"), Verdict::Safe);
        assert!(matches!(
            verdict("git reset --hard"),
            Verdict::Destructive(_)
        ));
    }

    /// False alarms the old parser already raises on main and the new one
    /// fixed. The combined verdict keeps them: it errs on the safe side and
    /// is never more permissive than main was.
    #[test]
    fn inherits_old_false_alarms() {
        let rank = |v: &Verdict| match v {
            Verdict::Safe => 0,
            Verdict::Destructive(_) => 1,
            Verdict::Blocked(_) => 2,
        };
        for cmd in [
            "cargo test # cleanup; rm -rf /",
            "cat > /tmp/notes.md <<'EOF'\ngit push --force origin main\nEOF",
            "grep -n \">\" src/main.rs",
            "command -v rm",
        ] {
            assert!(rank(&verdict(cmd)) > rank(&new_only(cmd)), "{cmd:?}");
        }
    }
}
