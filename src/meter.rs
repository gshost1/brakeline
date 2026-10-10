//! Incremental token metering from a Claude Code transcript (JSON Lines).
//!
//! Only new bytes since the last hook call are read. Assistant entries that
//! repeat a message id contribute only the growth in their usage numbers.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::Config;
use crate::state::{TranscriptCursor, Usage};

const MAX_SEEN_IDS: usize = 4096;
/// Very long lines are tool output, never the usage record we want; skipping
/// them keeps parsing cheap.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

pub fn update(
    path: &Path,
    cursor: &mut TranscriptCursor,
    usage: &mut Usage,
    cfg: &Config,
) -> Result<()> {
    let path_str = path.to_string_lossy().into_owned();
    if cursor.path != path_str {
        cursor.path = path_str;
        cursor.offset = 0;
    }
    let file = match File::open(path) {
        Ok(f) => f,
        // The transcript is written asynchronously and may not exist yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
    };
    let len = file.metadata()?.len();
    if len < cursor.offset {
        // Rewritten transcript: rescan; the seen-id table prevents double counting.
        cursor.offset = 0;
    }
    if len == cursor.offset {
        return Ok(());
    }

    let mut reader = BufReader::with_capacity(64 * 1024, file);
    reader.seek(SeekFrom::Start(cursor.offset))?;
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 || line.last() != Some(&b'\n') {
            // EOF or a partially written last line: pick it up next time.
            break;
        }
        cursor.offset += read as u64;
        if line.len() <= MAX_LINE_BYTES && memfind(&line, b"\"usage\"") {
            account_line(&line, cursor, usage, cfg);
        }
    }
    Ok(())
}

/// Droid keeps cumulative session totals (subagents included) in a
/// `<session>.settings.json` next to the transcript.
pub fn droid_settings_path(transcript: &Path) -> Option<std::path::PathBuf> {
    let candidate = transcript.with_extension("settings.json");
    candidate.is_file().then_some(candidate)
}

/// Reads Droid's cumulative totals. Returns them as raw usage, with the cost
/// estimated from the session's current model.
pub fn read_droid_totals(settings: &Path, cfg: &Config) -> Result<Usage> {
    let text = std::fs::read_to_string(settings)
        .with_context(|| format!("cannot read {}", settings.display()))?;
    let v: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not JSON", settings.display()))?;
    let totals = v
        .get("inclusiveTokenUsage")
        .or_else(|| v.get("tokenUsage"))
        .cloned()
        .unwrap_or(Value::Null);
    let n = |k: &str| totals.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mut usage = Usage {
        input_tokens: n("inputTokens"),
        // Thinking tokens are billed as output.
        output_tokens: n("outputTokens") + n("thinkingTokens"),
        cache_write_tokens: n("cacheCreationTokens"),
        cache_read_tokens: n("cacheReadTokens"),
        factory_credits: n("factoryCredits"),
        ..Usage::default()
    };
    let model = v.get("model").and_then(Value::as_str).unwrap_or("");
    if let Some(p) = cfg.price_for(model) {
        usage.cost_usd = (usage.input_tokens as f64 * p.input
            + usage.output_tokens as f64 * p.output
            + usage.cache_write_tokens as f64 * p.cache_write
            + usage.cache_read_tokens as f64 * p.cache_read)
            / 1_000_000.0;
    }
    Ok(usage)
}

/// `raw - baseline`, field by field, never below zero.
pub fn since(raw: &Usage, baseline: &Usage) -> Usage {
    Usage {
        input_tokens: raw.input_tokens.saturating_sub(baseline.input_tokens),
        output_tokens: raw.output_tokens.saturating_sub(baseline.output_tokens),
        cache_write_tokens: raw
            .cache_write_tokens
            .saturating_sub(baseline.cache_write_tokens),
        cache_read_tokens: raw
            .cache_read_tokens
            .saturating_sub(baseline.cache_read_tokens),
        cost_usd: (raw.cost_usd - baseline.cost_usd).max(0.0),
        messages: raw.messages.saturating_sub(baseline.messages),
        factory_credits: raw.factory_credits.saturating_sub(baseline.factory_credits),
    }
}

fn memfind(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn account_line(line: &[u8], cursor: &mut TranscriptCursor, usage: &mut Usage, cfg: &Config) {
    let Ok(entry) = serde_json::from_slice::<Value>(line) else {
        return;
    };
    if entry.get("type").and_then(Value::as_str) != Some("assistant") {
        return;
    }
    let Some(message) = entry.get("message") else {
        return;
    };
    let Some(u) = message.get("usage") else {
        return;
    };
    let n = |k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
    let now = [
        n("input_tokens"),
        n("output_tokens"),
        n("cache_creation_input_tokens"),
        n("cache_read_input_tokens"),
    ];
    let id = message
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| entry.get("uuid").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();

    let previous = if id.is_empty() {
        None
    } else {
        cursor.seen.iter_mut().find(|(seen, _)| *seen == id)
    };
    let is_new = previous.is_none();
    let delta: [u64; 4] = match previous {
        Some((_, counted)) => {
            let mut d = [0; 4];
            for i in 0..4 {
                d[i] = now[i].saturating_sub(counted[i]);
                counted[i] = counted[i].max(now[i]);
            }
            d
        }
        None => {
            if !id.is_empty() {
                if cursor.seen.len() >= MAX_SEEN_IDS {
                    cursor.seen.pop_front();
                }
                cursor.seen.push_back((id, now));
            }
            now
        }
    };
    if delta == [0; 4] {
        return;
    }
    if is_new {
        usage.messages += 1;
    }
    usage.input_tokens += delta[0];
    usage.output_tokens += delta[1];
    usage.cache_write_tokens += delta[2];
    usage.cache_read_tokens += delta[3];
    let model = message.get("model").and_then(Value::as_str).unwrap_or("");
    if let Some(p) = cfg.price_for(model) {
        usage.cost_usd += (delta[0] as f64 * p.input
            + delta[1] as f64 * p.output
            + delta[2] as f64 * p.cache_write
            + delta[3] as f64 * p.cache_read)
            / 1_000_000.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn assistant(id: &str, model: &str, input: u64, output: u64, cw: u64, cr: u64) -> String {
        serde_json::json!({
            "type": "assistant",
            "message": {
                "id": id,
                "model": model,
                "usage": {
                    "input_tokens": input,
                    "output_tokens": output,
                    "cache_creation_input_tokens": cw,
                    "cache_read_input_tokens": cr
                }
            }
        })
        .to_string()
            + "\n"
    }

    #[test]
    fn meters_incrementally_and_dedupes_repeated_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let cfg = Config::default();
        let mut cursor = TranscriptCursor::default();
        let mut usage = Usage::default();

        let mut f = File::create(&path).unwrap();
        f.write_all(b"{\"type\":\"user\",\"message\":{\"content\":\"hi\"}}\n")
            .unwrap();
        f.write_all(assistant("m1", "claude-sonnet-5", 1_000_000, 10, 0, 0).as_bytes())
            .unwrap();
        // Same message logged again with final output count: only the delta counts.
        f.write_all(assistant("m1", "claude-sonnet-5", 1_000_000, 1_000_000, 0, 0).as_bytes())
            .unwrap();
        // Partial trailing line must be left for later.
        f.write_all(b"{\"type\":\"assistant\",\"message\":{\"usage\"")
            .unwrap();
        f.flush().unwrap();

        update(&path, &mut cursor, &mut usage, &cfg).unwrap();
        assert_eq!(usage.input_tokens, 1_000_000);
        assert_eq!(usage.output_tokens, 1_000_000);
        assert_eq!(usage.messages, 1);
        assert!((usage.cost_usd - 18.0).abs() < 1e-9, "{}", usage.cost_usd);

        f.write_all(b":{\"input_tokens\":0}}}\n").unwrap();
        f.write_all(assistant("m2", "claude-opus-5", 0, 0, 0, 2_000_000).as_bytes())
            .unwrap();
        f.flush().unwrap();
        update(&path, &mut cursor, &mut usage, &cfg).unwrap();
        assert_eq!(usage.cache_read_tokens, 2_000_000);
        assert!((usage.cost_usd - 19.0).abs() < 1e-9, "{}", usage.cost_usd);

        // Re-running with no new bytes changes nothing.
        let before = usage.clone();
        update(&path, &mut cursor, &mut usage, &cfg).unwrap();
        assert_eq!(usage, before);
    }

    #[test]
    fn rewritten_transcript_does_not_double_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let cfg = Config::default();
        let mut cursor = TranscriptCursor::default();
        let mut usage = Usage::default();
        std::fs::write(&path, assistant("m1", "x", 100, 100, 0, 0).repeat(3)).unwrap();
        update(&path, &mut cursor, &mut usage, &cfg).unwrap();
        std::fs::write(&path, assistant("m1", "x", 100, 100, 0, 0)).unwrap();
        update(&path, &mut cursor, &mut usage, &cfg).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.messages, 1);
    }

    #[test]
    fn reads_droid_cumulative_totals() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("abc.jsonl");
        std::fs::write(&transcript, "").unwrap();
        assert!(droid_settings_path(&transcript).is_none());
        std::fs::write(
            dir.path().join("abc.settings.json"),
            r#"{"model":"claude-opus-5","tokenUsage":{"inputTokens":1},
               "inclusiveTokenUsage":{"inputTokens":1000000,"outputTokens":900000,
               "thinkingTokens":100000,"cacheReadTokens":0,"factoryCredits":4242}}"#,
        )
        .unwrap();
        let settings = droid_settings_path(&transcript).unwrap();
        let u = read_droid_totals(&settings, &Config::default()).unwrap();
        assert_eq!(u.output_tokens, 1_000_000);
        assert_eq!(u.factory_credits, 4242);
        assert!((u.cost_usd - 30.0).abs() < 1e-9, "{}", u.cost_usd);
        let later = Usage {
            factory_credits: 5000,
            ..u.clone()
        };
        assert_eq!(since(&later, &u).factory_credits, 758);
    }

    #[test]
    fn missing_transcript_is_not_an_error() {
        let mut cursor = TranscriptCursor::default();
        let mut usage = Usage::default();
        update(
            Path::new("/nonexistent/t.jsonl"),
            &mut cursor,
            &mut usage,
            &Config::default(),
        )
        .unwrap();
        assert_eq!(usage, Usage::default());
    }
}
