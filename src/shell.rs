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

pub fn classify(command: &str, cfg: &ShellConfig) -> Verdict {
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
    for segment in split_segments(command) {
        analyze_segment(&segment, cfg, depth, out);
    }
}

/// Splits a command line into simple commands, honoring quotes. Operators
/// (`;`, `&&`, `||`, `|`, `&`, newlines, subshell and substitution markers)
/// all start a new segment.
pub fn split_segments(input: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = input.chars().peekable();

    let flush_word = |word: &mut String, in_word: &mut bool, words: &mut Vec<String>| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };

    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = chars.next() {
                                word.push(n);
                            }
                        }
                        _ => word.push(q),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next()
                    && n != '\n'
                {
                    word.push(n);
                }
            }
            ';' | '&' | '|' | '\n' | '(' | ')' | '`' => {
                flush_word(&mut word, &mut in_word, &mut words);
                if !words.is_empty() {
                    segments.push(std::mem::take(&mut words));
                }
            }
            '$' if chars.peek() == Some(&'(') => {
                flush_word(&mut word, &mut in_word, &mut words);
                if !words.is_empty() {
                    segments.push(std::mem::take(&mut words));
                }
                chars.next();
            }
            c if c.is_whitespace() => flush_word(&mut word, &mut in_word, &mut words),
            _ => {
                in_word = true;
                word.push(c);
            }
        }
    }
    flush_word(&mut word, &mut in_word, &mut words);
    if !words.is_empty() {
        segments.push(words);
    }
    segments
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Drops env assignments and wrapper commands (`sudo`, `env`, `xargs`, ...)
/// so the real program name comes first.
fn strip_wrappers(words: &[String]) -> &[String] {
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        let is_assignment = w.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_')
        });
        if is_assignment {
            i += 1;
            continue;
        }
        match basename(w) {
            "{" | "}" | "!" | "if" | "then" | "else" | "elif" | "do" | "while" | "until" => i += 1,
            "sudo" | "doas" | "env" | "command" | "builtin" | "exec" | "nohup" | "time"
            | "nice" | "xargs" | "stdbuf" => {
                i += 1;
                // Skip the wrapper's own options (and `-u user`-style values).
                while i < words.len() && words[i].starts_with('-') {
                    let takes_value = matches!(words[i].as_str(), "-u" | "-g" | "-n" | "-I" | "-P");
                    i += if takes_value { 2 } else { 1 };
                }
            }
            "timeout" => {
                i += 1;
                while i < words.len() && words[i].starts_with('-') {
                    i += 1;
                }
                i += 1; // duration
            }
            _ => break,
        }
    }
    &words[i.min(words.len())..]
}

/// Output redirections in a segment as (truncates, target).
fn redirections(segment: &[String]) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    for (i, word) in segment.iter().enumerate() {
        let w = word.trim_start_matches(|c: char| c.is_ascii_digit());
        if !w.starts_with('>') {
            continue;
        }
        let append = w.starts_with(">>");
        let inline = w.trim_start_matches('>').trim_start_matches('|');
        let target = if inline.is_empty() {
            segment.get(i + 1).map(String::as_str).unwrap_or("")
        } else {
            inline
        };
        if !target.is_empty() && !target.starts_with('&') {
            out.push((!append, target));
        }
    }
    out
}

/// Redirect targets whose contents nobody needs back.
fn is_scratch_target(target: &str) -> bool {
    target.starts_with("/dev/")
        || ["/tmp/", "/private/tmp/", "$TMPDIR", "${TMPDIR}"]
            .iter()
            .any(|p| target.starts_with(p))
}

fn analyze_segment(segment: &[String], cfg: &ShellConfig, depth: usize, out: &mut Findings) {
    if let Some((_, target)) = redirections(segment)
        .into_iter()
        .find(|(truncates, t)| *truncates && !is_scratch_target(t))
    {
        out.destructive(format!("`> {target}` overwrites the file"));
    }
    let words = strip_wrappers(segment);
    let Some(first) = words.first() else { return };
    let program = basename(first);
    let args = &words[1..];

    match program {
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "fish" => {
            if let Some(pos) = args.iter().position(|a| {
                a == "-c" || (a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
            }) && let Some(inner) = args.get(pos + 1)
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
        "sed" | "perl"
            if args.iter().any(|a| {
                a.starts_with("-i") || a.starts_with("-pi") || a.starts_with("--in-place")
            }) =>
        {
            out.destructive(format!("`{program} -i` edits files in place"))
        }
        "dd" => {
            if cfg.block_catastrophic
                && args
                    .iter()
                    .any(|a| a.starts_with("of=/dev/") && !a.starts_with("of=/dev/null"))
            {
                out.block("`dd` writing to a raw device".into());
            } else if args.iter().any(|a| a.starts_with("of=")) {
                out.destructive("`dd` overwrites its output file".into());
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
                    a.starts_with("erase") || a == "zerodisk" || a == "randomdisk"
                })
            {
                out.block("`diskutil` erase".into());
            }
        }
        "chmod" | "chown" => {
            let recursive = args.iter().any(|a| a == "-R" || a == "--recursive");
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
    if matches!(
        classify(command, &ShellConfig::default()),
        Verdict::Destructive(_)
    ) {
        return true;
    }
    split_segments(command).iter().any(|segment| {
        let redirects = redirections(segment)
            .iter()
            .any(|(_, t)| !t.starts_with("/dev/"));
        let words = strip_wrappers(segment);
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
                analyze_segment(&args[start..end], cfg, depth + 1, &mut payload_findings);
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
                || has_prefix(&["--force"])
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
    // A single user's home directory, e.g. /Users/alice or /home/bob.
    for prefix in ["/Users/", "/home/"] {
        if let Some(rest) = t.strip_prefix(prefix)
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
}
