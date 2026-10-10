//! Agent hook protocol: read one event, decide, answer.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::meter;
use crate::shell::{self, Verdict};
use crate::snapshot;
use crate::state::{SessionState, Store, fingerprint, now_millis, now_secs};

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    #[serde(default)]
    pub tool_response: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Let the call proceed, optionally telling the user something.
    Allow(Option<String>),
    /// Refuse this one call; the agent sees the reason and can adapt.
    Deny(String),
    /// Refuse and end the agent's run until a human resets the session.
    Stop(String),
}

/// Tools whose `command` input is a shell command line.
const SHELL_TOOLS: &[&str] = &[
    "Bash",
    "Execute",
    "Shell",
    "shell",
    "exec_command",
    "run_shell_command",
];

fn shell_command<'a>(tool: &str, input: &'a Value) -> Option<&'a str> {
    if !SHELL_TOOLS.contains(&tool) {
        return None;
    }
    match input.get("command") {
        Some(Value::String(s)) => Some(s.as_str()),
        _ => input.get("cmd").and_then(Value::as_str),
    }
}

fn label(tool: &str, input: &Value) -> String {
    let detail = shell_command(tool, input)
        .map(str::to_string)
        .or_else(|| {
            ["file_path", "path", "pattern", "url", "query"]
                .iter()
                .find_map(|k| input.get(*k).and_then(Value::as_str).map(str::to_string))
        })
        .unwrap_or_default();
    let detail: String = detail.chars().take(80).collect();
    if detail.is_empty() {
        tool.to_string()
    } else {
        format!("{tool}({detail})")
    }
}

fn reset_hint(id: &str) -> String {
    format!("A human can review and resume with `brakeline reset {id}`.")
}

pub struct Engine<'a> {
    pub cfg: &'a Config,
    pub store: &'a Store,
    /// Notice to surface to the user, such as a config problem.
    pub notice: Option<String>,
    /// The agent sends no event when a tool call fails (Droid), so a call
    /// that never reports back is counted as failed.
    pub infer_failures: bool,
}

/// How long an unreported call may stay in flight before the next call
/// counts it as failed. Parallel calls of one batch start within this window.
const PENDING_GRACE_MS: u64 = 2_000;

impl Engine<'_> {
    pub fn handle(&self, input: &HookInput) -> Outcome {
        let outcome = match input.hook_event_name.as_str() {
            "PreToolUse" => self.pre_tool_use(input),
            "PostToolUse" => self.post_tool_use(input, false),
            "PostToolUseFailure" => self.post_tool_use(input, true),
            // At the end of a turn every call has finished; any still
            // pending never succeeded.
            "Stop" if self.infer_failures && !input.session_id.is_empty() => {
                self.store.with_session(&input.session_id, |s| {
                    s.expire_pending(u64::MAX);
                    Ok(Outcome::Allow(None))
                })
            }
            _ => Ok(Outcome::Allow(None)),
        };
        let outcome = outcome.unwrap_or_else(|err| self.fallback(input, &err));
        let Some(notice) = &self.notice else {
            return outcome;
        };
        match outcome {
            Outcome::Allow(msg) => Outcome::Allow(Some(match msg {
                Some(m) => format!("{notice}\n{m}"),
                None => notice.clone(),
            })),
            Outcome::Deny(r) => Outcome::Deny(format!("{r}\n{notice}")),
            Outcome::Stop(r) => Outcome::Stop(format!("{r}\n{notice}")),
        }
    }

    /// State could not be read or written. Stateless protections still apply;
    /// everything else fails open so a broken guard never wedges the agent.
    fn fallback(&self, input: &HookInput, err: &anyhow::Error) -> Outcome {
        if input.hook_event_name == "PreToolUse" {
            let tool = input.tool_name.as_deref().unwrap_or("");
            let tool_input = input.tool_input.clone().unwrap_or(Value::Null);
            if let Some(cmd) = shell_command(tool, &tool_input)
                && let Verdict::Blocked(reason) = shell::classify(cmd, &self.cfg.shell)
            {
                return Outcome::Deny(format!("brakeline blocked this command: {reason}."));
            }
        }
        Outcome::Allow(Some(format!("brakeline error (allowing): {err:#}")))
    }

    fn pre_tool_use(&self, input: &HookInput) -> Result<Outcome> {
        let tool = input.tool_name.as_deref().unwrap_or("");
        let tool_input = input.tool_input.clone().unwrap_or(Value::Null);
        let command = shell_command(tool, &tool_input);
        let verdict = command
            .map(|c| shell::classify(c, &self.cfg.shell))
            .unwrap_or(Verdict::Safe);
        let fp = fingerprint(tool, &tool_input);
        let name = label(tool, &tool_input);
        let now_ms = now_millis();
        let now = now_ms / 1000;
        let cfg = self.cfg;
        let id = input.session_id.as_str();
        let infer = self.infer_failures;

        let (outcome, snapshot_reason) = self.store.with_session(id, |s| {
            touch(s, input, now);
            if infer {
                s.expire_pending(now_ms.saturating_sub(PENDING_GRACE_MS));
            }
            if let Some(reason) = &s.halted {
                return Ok((Outcome::Stop(format!("brakeline: this run is stopped: {reason} {}", reset_hint(id))), None));
            }
            if let Some(path) = &input.transcript_path
                && !path.is_empty()
            {
                // A metering failure must not block work; budgets just lag.
                let path = Path::new(path);
                if let Some(settings) = meter::droid_settings_path(path) {
                    if let Ok(raw) = meter::read_droid_totals(&settings, cfg) {
                        s.usage = meter::since(&raw, &s.usage_baseline);
                        s.usage_raw = raw;
                    }
                } else {
                    let _ = meter::update(path, &mut s.transcript, &mut s.usage, cfg);
                }
            }
            if let Some(reason) = budget_exceeded(s, cfg, now) {
                s.halted = Some(reason.clone());
                return Ok((Outcome::Stop(format!("brakeline: {reason} {}", reset_hint(id))), None));
            }
            if let Verdict::Blocked(reason) = &verdict {
                return Ok((deny(s, cfg, id, format!("brakeline blocked a dangerous command ({reason}). Do not retry it; find a safer way or ask the user.")), None));
            }
            let loops = &cfg.loops;
            if let Some(f) = s.failure(fp) {
                if f.epoch == s.epoch && f.consecutive >= loops.max_consecutive_failures {
                    let msg = format!(
                        "brakeline: `{}` already failed {} times in a row with no file changes in between. Retrying will fail the same way; read the error, change something, or ask the user.",
                        f.label, f.consecutive
                    );
                    return Ok((deny(s, cfg, id, msg), None));
                }
                if f.total >= loops.max_total_failures_per_call {
                    let msg = format!(
                        "brakeline: `{}` has failed {} times this session. Step back and try a different approach, or ask the user.",
                        f.label, f.total
                    );
                    return Ok((deny(s, cfg, id, msg), None));
                }
            }
            let repeats = s.identical_in_epoch(fp);
            if repeats as u32 >= loops.max_identical_calls {
                let msg = format!(
                    "brakeline: `{name}` was already called {repeats} times with identical input and no file changes in between. The result will not change; use what you have or try something different."
                );
                return Ok((deny(s, cfg, id, msg), None));
            }

            s.tool_calls += 1;
            s.consecutive_denials = 0;
            s.remember(fp, loops.window as usize);
            if infer {
                s.add_pending(fp, &name, now_ms);
            }
            let warning = budget_warning(s, cfg, now);
            let snap = match &verdict {
                Verdict::Destructive(reason) if cfg.shell.snapshot_before_destructive => {
                    s.snapshots += 1;
                    Some(reason.clone())
                }
                _ => None,
            };
            Ok((Outcome::Allow(warning), snap))
        })?;

        // Snapshot outside the session lock: it can take a while on big repos
        // and must not stall parallel tool calls of the same session.
        let Some(reason) = snapshot_reason else {
            return Ok(outcome);
        };
        let cwd = input
            .cwd
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let message = match snapshot::take(
            self.store.root(),
            &cwd,
            id,
            &reason,
            command.unwrap_or(""),
        ) {
            Ok(Some(rec)) => format!(
                "brakeline: snapshot {} saved before {reason}. Undo with `brakeline restore {}`.",
                rec.id, rec.id
            ),
            Ok(None) => format!(
                "brakeline: {reason}, and this directory is not a git repository, so no snapshot was taken."
            ),
            Err(err) => format!("brakeline: snapshot before {reason} failed: {err:#}"),
        };
        Ok(match outcome {
            Outcome::Allow(Some(w)) => Outcome::Allow(Some(format!("{w}\n{message}"))),
            Outcome::Allow(None) => Outcome::Allow(Some(message)),
            other => other,
        })
    }

    fn post_tool_use(&self, input: &HookInput, failed_event: bool) -> Result<Outcome> {
        let tool = input.tool_name.as_deref().unwrap_or("");
        let tool_input = input.tool_input.clone().unwrap_or(Value::Null);
        let fp = fingerprint(tool, &tool_input);
        let failed = failed_event || input.tool_response.as_ref().is_some_and(response_failed);
        let made_progress = !failed
            && (self.cfg.loops.progress_tools.iter().any(|t| t == tool)
                || shell_command(tool, &tool_input).is_some_and(shell::mutates));
        let name = label(tool, &tool_input);
        let now = now_secs();
        self.store.with_session(&input.session_id, |s| {
            touch(s, input, now);
            s.resolve_pending(fp);
            if failed {
                s.record_failure(fp, &name);
            } else {
                if let Some(i) = s.failures.iter().position(|f| f.fp == fp) {
                    s.failures[i].consecutive = 0;
                }
                if made_progress {
                    s.epoch += 1;
                }
            }
            Ok(Outcome::Allow(None))
        })
    }
}

fn touch(s: &mut SessionState, input: &HookInput, now: u64) {
    if s.session_id.is_empty() {
        s.session_id = input.session_id.clone();
    }
    if s.started_at == 0 {
        s.started_at = now;
    }
    s.last_seen = now;
    if let Some(cwd) = &input.cwd {
        s.cwd = cwd.clone();
    }
}

fn deny(s: &mut SessionState, cfg: &Config, id: &str, reason: String) -> Outcome {
    s.consecutive_denials += 1;
    s.total_denials += 1;
    s.last_denial = Some(reason.clone());
    if s.consecutive_denials >= cfg.loops.max_denials_before_stop {
        let why = format!(
            "{} tool calls in a row were refused, so the agent is stuck. Last refusal: {reason}",
            s.consecutive_denials
        );
        s.halted = Some(why.clone());
        return Outcome::Stop(format!(
            "brakeline stopped this run: {why} {}",
            reset_hint(id)
        ));
    }
    Outcome::Deny(reason)
}

/// Exit code from a text tool response ending in
/// `[Process exited with code N]` (Droid's Execute output).
fn text_exit_code(text: &str) -> Option<i64> {
    let start = text.rfind("[Process exited with code ")?;
    let rest = &text[start + "[Process exited with code ".len()..];
    rest[..rest.find(']')?].trim().parse().ok()
}

fn response_failed(resp: &Value) -> bool {
    if let Value::String(text) = resp {
        return text_exit_code(text).is_some_and(|c| c != 0);
    }
    let truthy = |k: &str| resp.get(k).and_then(Value::as_bool).unwrap_or(false);
    let nonzero = |k: &str| resp.get(k).and_then(Value::as_i64).is_some_and(|c| c != 0);
    truthy("is_error")
        || truthy("isError")
        || nonzero("exit_code")
        || nonzero("exitCode")
        || nonzero("returncode")
}

struct BudgetUse {
    name: &'static str,
    used: f64,
    limit: f64,
    describe: String,
}

fn budget_uses(s: &SessionState, cfg: &Config, now: u64) -> Vec<BudgetUse> {
    let b = &cfg.budget;
    let mut out = Vec::new();
    if let Some(limit) = b.max_tool_calls {
        out.push(BudgetUse {
            name: "tool calls",
            used: s.tool_calls as f64,
            limit: limit as f64,
            describe: format!("{} of {limit} tool calls", s.tool_calls),
        });
    }
    if let Some(limit) = b.max_session_minutes {
        let minutes = now.saturating_sub(s.started_at) / 60;
        out.push(BudgetUse {
            name: "session time",
            used: minutes as f64,
            limit: limit as f64,
            describe: format!("{minutes} of {limit} minutes"),
        });
    }
    if let Some(limit) = b.max_cost_usd {
        out.push(BudgetUse {
            name: "estimated cost",
            used: s.usage.cost_usd,
            limit,
            describe: format!("${:.2} of ${limit:.2} estimated spend", s.usage.cost_usd),
        });
    }
    if let Some(limit) = b.max_output_tokens {
        out.push(BudgetUse {
            name: "output tokens",
            used: s.usage.output_tokens as f64,
            limit: limit as f64,
            describe: format!("{} of {limit} output tokens", s.usage.output_tokens),
        });
    }
    if let Some(limit) = b.max_factory_credits {
        out.push(BudgetUse {
            name: "Factory credits",
            used: s.usage.factory_credits as f64,
            limit: limit as f64,
            describe: format!("{} of {limit} Factory credits", s.usage.factory_credits),
        });
    }
    out
}

fn budget_exceeded(s: &SessionState, cfg: &Config, now: u64) -> Option<String> {
    budget_uses(s, cfg, now)
        .into_iter()
        .find(|u| u.used >= u.limit)
        .map(|u| format!("{} budget reached ({}).", u.name, u.describe))
}

fn budget_warning(s: &mut SessionState, cfg: &Config, now: u64) -> Option<String> {
    let crossing: Vec<BudgetUse> = budget_uses(s, cfg, now)
        .into_iter()
        .filter(|u| u.used >= 0.8 * u.limit && !s.warned.iter().any(|w| w == u.name))
        .collect();
    if crossing.is_empty() {
        return None;
    }
    let parts: Vec<String> = crossing.iter().map(|u| u.describe.clone()).collect();
    s.warned.extend(crossing.iter().map(|u| u.name.to_string()));
    Some(format!(
        "brakeline: over 80% of budget: {}.",
        parts.join(", ")
    ))
}

pub enum Format {
    /// Claude Code JSON decisions on stdout.
    Json,
    /// Exit code 2 with the reason on stderr, for agents that only honor that.
    ExitCode,
}

/// Renders an outcome. Returns (stdout, stderr, exit code).
pub fn render(outcome: &Outcome, event: &str, format: &Format) -> (String, String, i32) {
    match format {
        Format::ExitCode => match outcome {
            Outcome::Allow(msg) => (String::new(), msg.clone().unwrap_or_default(), 0),
            Outcome::Deny(r) | Outcome::Stop(r) => (String::new(), r.clone(), 2),
        },
        Format::Json => {
            let body = match outcome {
                Outcome::Allow(None) => return (String::new(), String::new(), 0),
                Outcome::Allow(Some(msg)) => json!({ "systemMessage": msg }),
                Outcome::Deny(reason) => json!({
                    "systemMessage": reason,
                    "hookSpecificOutput": {
                        "hookEventName": event,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }),
                Outcome::Stop(reason) => json!({
                    "continue": false,
                    "stopReason": reason,
                    "hookSpecificOutput": {
                        "hookEventName": event,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }),
            };
            (body.to_string(), String::new(), 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Harness {
        _dir: tempfile::TempDir,
        store: Store,
        cfg: Config,
        infer: bool,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path().join("data")).unwrap();
            Self {
                _dir: dir,
                store,
                cfg: Config::default(),
                infer: false,
            }
        }

        fn droid() -> Self {
            Self {
                infer: true,
                ..Self::new()
            }
        }

        fn event(&self, event: &str, tool: &str, input: Value, response: Option<Value>) -> Outcome {
            let engine = Engine {
                cfg: &self.cfg,
                store: &self.store,
                notice: None,
                infer_failures: self.infer,
            };
            engine.handle(&HookInput {
                session_id: "sess".into(),
                transcript_path: None,
                cwd: Some(self._dir.path().to_string_lossy().into_owned()),
                hook_event_name: event.into(),
                tool_name: Some(tool.into()),
                tool_input: Some(input),
                tool_response: response,
            })
        }

        fn pre(&self, tool: &str, input: Value) -> Outcome {
            self.event("PreToolUse", tool, input, None)
        }
    }

    fn is_allow(o: &Outcome) -> bool {
        matches!(o, Outcome::Allow(_))
    }

    #[test]
    fn identical_calls_without_progress_are_denied_then_stopped() {
        let h = Harness::new();
        let read = json!({"file_path": "/x/a.rs"});
        for _ in 0..5 {
            assert!(is_allow(&h.pre("Read", read.clone())));
        }
        assert!(matches!(h.pre("Read", read.clone()), Outcome::Deny(_)));
        assert!(matches!(h.pre("Read", read.clone()), Outcome::Deny(_)));
        assert!(matches!(h.pre("Read", read.clone()), Outcome::Stop(_)));
        // Once stopped, everything is refused until reset.
        assert!(matches!(
            h.pre("Read", json!({"file_path": "/x/other.rs"})),
            Outcome::Stop(_)
        ));
    }

    #[test]
    fn an_edit_in_between_resets_identical_call_counting() {
        let h = Harness::new();
        let test = json!({"command": "cargo test"});
        for round in 0..4 {
            for _ in 0..4 {
                assert!(is_allow(&h.pre("Bash", test.clone())), "round {round}");
            }
            h.event(
                "PostToolUse",
                "Edit",
                json!({"file_path": format!("/x/{round}.rs")}),
                Some(json!({})),
            );
        }
    }

    #[test]
    fn repeated_failure_of_the_same_call_is_denied() {
        let h = Harness::new();
        let cmd = json!({"command": "npm run deploy"});
        for _ in 0..3 {
            assert!(is_allow(&h.pre("Bash", cmd.clone())));
            h.event("PostToolUseFailure", "Bash", cmd.clone(), None);
            // Reading around between attempts is not progress.
            assert!(is_allow(&h.pre("Grep", json!({"pattern": "deploy"}))));
        }
        match h.pre("Bash", cmd.clone()) {
            Outcome::Deny(reason) => {
                assert!(reason.contains("failed 3 times in a row"), "{reason}")
            }
            other => panic!("expected deny, got {other:?}"),
        }
        // A different command is still fine (and resets the denial streak).
        assert!(is_allow(
            &h.pre("Bash", json!({"command": "npm run build"}))
        ));
    }

    #[test]
    fn failure_detected_from_tool_response_exit_code() {
        let h = Harness::new();
        let cmd = json!({"command": "make"});
        for _ in 0..3 {
            assert!(is_allow(&h.pre("Bash", cmd.clone())));
            h.event(
                "PostToolUse",
                "Bash",
                cmd.clone(),
                Some(json!({"exit_code": 2})),
            );
        }
        assert!(matches!(h.pre("Bash", cmd), Outcome::Deny(_)));
    }

    #[test]
    fn success_resets_consecutive_failures() {
        let h = Harness::new();
        let cmd = json!({"command": "cargo build"});
        for _ in 0..2 {
            h.pre("Bash", cmd.clone());
            h.event("PostToolUseFailure", "Bash", cmd.clone(), None);
        }
        h.pre("Bash", cmd.clone());
        h.event(
            "PostToolUse",
            "Bash",
            cmd.clone(),
            Some(json!({"stdout": "ok"})),
        );
        h.pre("Bash", cmd.clone());
        h.event("PostToolUseFailure", "Bash", cmd.clone(), None);
        assert!(is_allow(&h.pre("Bash", cmd)));
    }

    #[test]
    fn catastrophic_command_is_denied() {
        let h = Harness::new();
        match h.pre("Bash", json!({"command": "rm -rf ~/"})) {
            Outcome::Deny(reason) => assert!(reason.contains("dangerous"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tool_call_budget_stops_the_run() {
        let mut h = Harness::new();
        h.cfg.budget.max_tool_calls = Some(10);
        let mut warned = false;
        for i in 0..10 {
            if let Outcome::Allow(Some(m)) = h.pre("Read", json!({"file_path": format!("/f{i}")})) {
                warned |= m.contains("80%");
            }
        }
        assert!(warned);
        match h.pre("Read", json!({"file_path": "/f99"})) {
            Outcome::Stop(r) => assert!(r.contains("tool calls budget reached"), "{r}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cost_budget_uses_transcript() {
        let mut h = Harness::new();
        h.cfg.budget.max_cost_usd = Some(1.0);
        let transcript = h._dir.path().join("t.jsonl");
        std::fs::write(
            &transcript,
            json!({"type":"assistant","message":{"id":"m","model":"claude-sonnet-5","usage":{"output_tokens":100000}}}).to_string() + "\n",
        )
        .unwrap();
        let engine = Engine {
            cfg: &h.cfg,
            store: &h.store,
            notice: None,
            infer_failures: false,
        };
        let out = engine.handle(&HookInput {
            session_id: "sess".into(),
            transcript_path: Some(transcript.to_string_lossy().into_owned()),
            cwd: None,
            hook_event_name: "PreToolUse".into(),
            tool_name: Some("Read".into()),
            tool_input: Some(json!({"file_path": "/a"})),
            tool_response: None,
        });
        match out {
            Outcome::Stop(r) => assert!(r.contains("$1.50"), "{r}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn destructive_command_outside_git_still_allowed_with_notice() {
        let h = Harness::new();
        match h.pre("Bash", json!({"command": "rm -rf build"})) {
            Outcome::Allow(Some(m)) => assert!(m.contains("not a git repository"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn droid_failures_are_inferred_from_missing_post_events() {
        let h = Harness::droid();
        // Droid's Execute carries free-text fields that vary between retries.
        let cmd = |n: u32| json!({"command": "npm run deploy", "summary": format!("try {n}"), "riskLevel": "low"});
        for n in 0..3 {
            assert!(is_allow(&h.pre("Execute", cmd(n))));
            // The command failed: Droid sends no PostToolUse, only Stop at turn end.
            h.event("Stop", "", json!({}), None);
        }
        match h.pre("Execute", cmd(9)) {
            Outcome::Deny(r) => assert!(r.contains("failed 3 times in a row"), "{r}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn droid_successes_and_parallel_calls_are_not_failures() {
        let h = Harness::droid();
        let a = json!({"command": "cargo test"});
        let b = json!({"command": "cargo clippy"});
        for _ in 0..4 {
            // A parallel batch: both start before either reports back.
            assert!(is_allow(&h.pre("Execute", a.clone())));
            assert!(is_allow(&h.pre("Execute", b.clone())));
            let ok = Some(json!("ok\n\n[Process exited with code 0]"));
            h.event("PostToolUse", "Execute", a.clone(), ok.clone());
            h.event("PostToolUse", "Execute", b.clone(), ok);
            h.event("Stop", "", json!({}), None);
        }
        let s = h.store.load("sess").unwrap().unwrap();
        assert!(s.failures.iter().all(|f| f.total == 0), "{:?}", s.failures);
        assert!(s.pending.is_empty());
    }

    #[test]
    fn droid_text_exit_code_is_parsed() {
        assert_eq!(text_exit_code("x\n[Process exited with code 0]"), Some(0));
        assert_eq!(
            text_exit_code("[Process exited with code 127]\n"),
            Some(127)
        );
        assert_eq!(text_exit_code("no marker"), None);
        assert!(response_failed(&json!(
            "boom\n[Process exited with code 1]"
        )));
    }

    #[test]
    fn droid_edit_tools_count_as_progress() {
        let h = Harness::droid();
        let test = json!({"command": "cargo test"});
        for round in 0..3 {
            for _ in 0..4 {
                assert!(is_allow(&h.pre("Execute", test.clone())), "round {round}");
                h.event(
                    "PostToolUse",
                    "Execute",
                    test.clone(),
                    Some(json!("[Process exited with code 0]")),
                );
            }
            let tool = if round % 2 == 0 {
                "ApplyPatch"
            } else {
                "Create"
            };
            h.pre(tool, json!({"input": format!("patch {round}")}));
            h.event(
                "PostToolUse",
                tool,
                json!({"input": format!("patch {round}")}),
                Some(json!({"success": true})),
            );
        }
    }

    #[test]
    fn render_formats() {
        let (out, _, code) = render(&Outcome::Stop("why".into()), "PreToolUse", &Format::Json);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["continue"], false);
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(code, 0);
        let (_, err, code) = render(&Outcome::Deny("no".into()), "PreToolUse", &Format::ExitCode);
        assert_eq!((err.as_str(), code), ("no", 2));
        assert_eq!(
            render(&Outcome::Allow(None), "PreToolUse", &Format::Json).0,
            ""
        );
    }
}
