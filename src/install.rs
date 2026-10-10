use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::state::write_atomic;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `.claude/settings.json`, hooks under a top-level `hooks` key.
    Claude,
    /// `.factory/hooks.json`, keyed directly by event name.
    Droid,
}

/// (event, timeout seconds). PreToolUse may take a snapshot, so it gets longer.
const CLAUDE_EVENTS: &[(&str, u64)] = &[
    ("PreToolUse", 120),
    ("PostToolUse", 15),
    ("PostToolUseFailure", 15),
];
/// Droid has no failure event; `Stop` lets brakeline settle unreported calls.
const DROID_EVENTS: &[(&str, u64)] = &[("PreToolUse", 120), ("PostToolUse", 15), ("Stop", 15)];

impl Target {
    fn events(self) -> &'static [(&'static str, u64)] {
        match self {
            Target::Claude => CLAUDE_EVENTS,
            Target::Droid => DROID_EVENTS,
        }
    }

    pub fn path(self, project: bool, cwd: &Path) -> Result<PathBuf> {
        let rel: &[&str] = match self {
            Target::Claude => &[".claude", "settings.json"],
            Target::Droid => &[".factory", "hooks.json"],
        };
        let base = if project {
            cwd.to_path_buf()
        } else {
            crate::config::home_dir().context("HOME is not set")?
        };
        Ok(rel.iter().fold(base, |p, part| p.join(part)))
    }

    pub fn hook_command(self, exe: &Path) -> String {
        match self {
            Target::Claude => hook_command(exe),
            Target::Droid => format!("{} --agent droid", hook_command(exe)),
        }
    }
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

pub fn hook_command(exe: &Path) -> String {
    format!("{} hook", shell_quote(&exe.to_string_lossy()))
}

/// A hook is ours if its command runs a binary named `brakeline` with the
/// `hook` subcommand, whatever flags follow.
fn is_ours(hook: &Value) -> bool {
    let Some(command) = hook.get("command").and_then(Value::as_str) else {
        return false;
    };
    let segments = crate::shell::split_segments(command);
    let Some(words) = segments.first() else {
        return false;
    };
    words
        .first()
        .is_some_and(|w| w.rsplit('/').next() == Some("brakeline"))
        && words.get(1).is_some_and(|w| w == "hook")
}

#[cfg(test)]
pub fn merge_claude_hooks(settings: Value, command: &str) -> Result<Value> {
    merge_hooks(settings, command, Target::Claude)
}

/// Adds (or replaces) brakeline's hooks in the settings object for `target`,
/// leaving every other setting and hook untouched.
pub fn merge_hooks(mut settings: Value, command: &str, target: Target) -> Result<Value> {
    if settings.is_null() {
        settings = json!({});
    }
    let Some(root) = settings.as_object_mut() else {
        bail!("settings file is not a JSON object");
    };
    let hooks = match target {
        Target::Claude => {
            let hooks = root
                .entry("hooks")
                .or_insert_with(|| Value::Object(Map::new()));
            let Some(hooks) = hooks.as_object_mut() else {
                bail!("`hooks` in settings is not an object");
            };
            hooks
        }
        Target::Droid => root,
    };
    for (event, timeout) in target.events() {
        let groups = hooks
            .entry(event.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let Some(groups) = groups.as_array_mut() else {
            bail!("`hooks.{event}` in settings is not an array");
        };
        for group in groups.iter_mut() {
            if let Some(list) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                list.retain(|h| !is_ours(h));
            }
        }
        groups.retain(|g| {
            g.get("hooks")
                .and_then(Value::as_array)
                .is_none_or(|l| !l.is_empty())
        });
        groups.push(json!({
            "matcher": "*",
            "hooks": [{ "type": "command", "command": command, "timeout": timeout }]
        }));
    }
    Ok(settings)
}

#[cfg(test)]
pub fn install_claude(path: &Path, command: &str, write: bool) -> Result<String> {
    install(path, command, Target::Claude, write)
}

/// Returns the merged settings text; writes it (with a backup) when `write`.
pub fn install(path: &Path, command: &str, target: Target, write: bool) -> Result<String> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Value::Null,
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON; fix it first", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Null,
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let had_file = !existing.is_null();
    let merged = merge_hooks(existing, command, target)?;
    let text = serde_json::to_string_pretty(&merged)? + "\n";
    if write {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if had_file {
            let backup = path.with_extension("json.brakeline-backup");
            std::fs::copy(path, &backup)
                .with_context(|| format!("cannot back up to {}", backup.display()))?;
        }
        write_atomic(path, text.as_bytes())?;
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_preserves_other_settings_and_is_idempotent() {
        let existing = json!({
            "model": "opus",
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": "/old/brakeline hook"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": "'/a b/brakeline' hook --format exit-code"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/my-brakeline-wrapper hook"}]}
                ],
                "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]
            }
        });
        let once = merge_claude_hooks(existing, "/bin/brakeline hook").unwrap();
        let twice = merge_claude_hooks(once.clone(), "/bin/brakeline hook").unwrap();
        assert_eq!(once, twice);
        assert_eq!(once["model"], "opus");
        assert_eq!(once["hooks"]["Stop"][0]["hooks"][0]["command"], "notify");
        let pre = once["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 3);
        assert_eq!(pre[0]["hooks"][0]["command"], "my-linter");
        assert_eq!(
            pre[1]["hooks"][0]["command"],
            "/opt/my-brakeline-wrapper hook"
        );
        assert_eq!(pre[2]["hooks"][0]["command"], "/bin/brakeline hook");
        assert!(once["hooks"]["PostToolUseFailure"].is_array());
    }

    #[test]
    fn droid_hooks_json_is_keyed_by_event() {
        let existing = json!({
            "PreToolUse": [{"matcher": "Execute", "hooks": [{"type": "command", "command": "audit.sh"}]}]
        });
        let cmd = Target::Droid.hook_command(Path::new("/bin/brakeline"));
        assert_eq!(cmd, "/bin/brakeline hook --agent droid");
        let merged = merge_hooks(existing, &cmd, Target::Droid).unwrap();
        assert!(merged.get("hooks").is_none());
        assert_eq!(merged["PreToolUse"].as_array().unwrap().len(), 2);
        assert_eq!(merged["Stop"][0]["hooks"][0]["command"], cmd);
        assert!(merged.get("PostToolUseFailure").is_none());
        assert_eq!(
            merge_hooks(merged.clone(), &cmd, Target::Droid).unwrap(),
            merged
        );
        let p = Target::Droid.path(true, Path::new("/repo")).unwrap();
        assert_eq!(p, Path::new("/repo/.factory/hooks.json"));
    }

    #[test]
    fn rejects_non_object_settings() {
        assert!(merge_claude_hooks(json!([1]), "x hook").is_err());
    }

    #[test]
    fn quotes_paths_with_spaces() {
        assert_eq!(
            hook_command(Path::new("/usr/bin/brakeline")),
            "/usr/bin/brakeline hook"
        );
        assert_eq!(
            hook_command(Path::new("/Users/a b/brakeline")),
            "'/Users/a b/brakeline' hook"
        );
    }

    #[test]
    fn install_writes_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{\"theme\":\"dark\"}").unwrap();
        install_claude(&path, "brakeline hook", true).unwrap();
        let backup = std::fs::read_to_string(path.with_extension("json.brakeline-backup")).unwrap();
        assert_eq!(backup, "{\"theme\":\"dark\"}");
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["theme"], "dark");
        assert!(written["hooks"]["PreToolUse"].is_array());
    }
}
