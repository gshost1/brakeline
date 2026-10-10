mod config;
mod hook;
mod install;
mod meter;
mod shell;
mod snapshot;
mod state;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use crate::hook::{Engine, Format, HookInput};
use crate::state::{Store, now_secs};

#[derive(Parser)]
#[command(
    name = "brakeline",
    version,
    about = "Stops coding-agent loops and runaway spend, blocks catastrophic commands, and snapshots work before destructive ones."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum HookFormat {
    /// Claude Code JSON decisions (default).
    Json,
    /// Exit code 2 plus stderr, for agents that only honor exit codes.
    ExitCode,
}

#[derive(Clone, Copy, ValueEnum)]
enum Agent {
    /// Claude Code.
    Claude,
    /// Factory Droid.
    Droid,
}

#[derive(Subcommand)]
enum Cmd {
    /// Handle one hook event from stdin (called by the agent).
    Hook {
        #[arg(long, value_enum, default_value = "json")]
        format: HookFormat,
        /// Which agent is calling; Droid sends no event for failed tool calls.
        #[arg(long, value_enum, default_value = "claude")]
        agent: Agent,
    },
    /// Classify a shell command the way the hook would.
    Check {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show recent sessions, or one session in detail.
    Status {
        session: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Clear a stopped session so the agent can continue.
    Reset {
        session: String,
        /// Also restart the session's budget counters (calls, time, spend).
        #[arg(long)]
        budget: bool,
    },
    /// List snapshots (for the current repository unless --all).
    Snapshots {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Restore files from a snapshot. Shows a preview unless --yes.
    Restore {
        id: String,
        #[arg(long)]
        yes: bool,
        /// Limit the restore to these paths (relative to the repository root).
        #[arg(last = true)]
        paths: Vec<String>,
    },
    /// Delete old snapshots, keeping the newest N per repository.
    Prune {
        #[arg(long, default_value_t = 50)]
        keep: usize,
    },
    /// Delete session records not seen for N days.
    Gc {
        #[arg(long, default_value_t = 14)]
        days: u64,
    },
    /// Print the effective configuration for the current directory.
    Config,
    /// Register brakeline's hooks with an agent.
    Install {
        #[arg(value_enum)]
        agent: Agent,
        /// Install into ./.claude/settings.json instead of ~/.claude/settings.json.
        #[arg(long)]
        project: bool,
        /// Write the file (a backup is kept). Without this, only print it.
        #[arg(long)]
        write: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("brakeline: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Cmd::Hook { format, agent } => run_hook(format, matches!(agent, Agent::Droid)),
        Cmd::Check { command } => {
            let cfg = config::load(Some(&cwd()))?;
            let line = command.join(" ");
            let verdict = shell::classify(&line, &cfg.shell);
            match &verdict {
                shell::Verdict::Safe => println!("safe"),
                shell::Verdict::Destructive(r) => println!("destructive: {r} (snapshot first)"),
                shell::Verdict::Blocked(r) => println!("blocked: {r}"),
            }
            Ok(if matches!(verdict, shell::Verdict::Blocked(_)) {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Status { session, json } => status(session, json),
        Cmd::Reset { session, budget } => {
            let store = Store::open_default()?;
            if !store.exists(&session) {
                bail!("no session {session}; see `brakeline status`");
            }
            store.with_session(&session, |s| {
                s.halted = None;
                s.consecutive_denials = 0;
                s.last_denial = None;
                s.failures.clear();
                s.recent.clear();
                if budget {
                    s.tool_calls = 0;
                    s.started_at = now_secs();
                    s.usage = Default::default();
                    s.usage_baseline = s.usage_raw.clone();
                    s.warned.clear();
                }
                Ok(())
            })?;
            println!("session {session} reset; tell the agent to continue.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Snapshots { all, json } => {
            let store = Store::open_default()?;
            let repo = snapshot::repo_root(&cwd()).map(|p| p.to_string_lossy().into_owned());
            let records: Vec<_> = snapshot::list(store.root())?
                .into_iter()
                .filter(|r| all || repo.as_deref() == Some(r.repo.as_str()))
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else if records.is_empty() {
                println!(
                    "no snapshots{}",
                    if all {
                        ""
                    } else {
                        " for this repository (try --all)"
                    }
                );
            } else {
                for r in records.iter().rev() {
                    println!(
                        "{}  {}  {}  {}",
                        r.id,
                        ago(r.created_at),
                        r.reason,
                        r.command.replace('\n', " ")
                    );
                    if all {
                        println!("    {}", r.repo);
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Restore { id, yes, paths } => {
            let store = Store::open_default()?;
            let record = snapshot::find(store.root(), &id)?;
            if !yes {
                println!(
                    "snapshot {} of {} ({})",
                    record.id,
                    record.repo,
                    ago(record.created_at)
                );
                println!("taken before: {}", record.command);
                let diff = snapshot::preview(store.root(), &record)?;
                if diff.is_empty() {
                    println!("the work tree already contains every file in the snapshot.");
                } else {
                    println!("restoring would write:\n{diff}");
                }
                println!(
                    "\nRe-run with --yes to write the snapshot's files back. Files created since are kept, and the current state is snapshotted first."
                );
                return Ok(ExitCode::SUCCESS);
            }
            let backup = snapshot::restore(store.root(), &record, &paths)?;
            println!("restored snapshot {} into {}", record.id, record.repo);
            if let Some(b) = backup {
                println!(
                    "previous state saved as snapshot {} (`brakeline restore {}` to undo)",
                    b.id, b.id
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Prune { keep } => {
            let store = Store::open_default()?;
            let removed = snapshot::prune(store.root(), keep)?;
            println!(
                "removed {removed} snapshot refs; run `git gc` in a repository to reclaim space."
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Gc { days } => {
            let store = Store::open_default()?;
            println!("removed {} session records", store.gc(days)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Config => {
            let cfg = config::load(Some(&cwd()))?;
            if let Some(p) = config::user_config_path() {
                println!("# user config: {}", p.display());
            }
            println!(
                "# project config: {} (can only tighten)",
                config::project_config_path(&cwd()).display()
            );
            print!("{}", toml::to_string_pretty(&cfg)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Install {
            agent,
            project,
            write,
        } => {
            let target = match agent {
                Agent::Claude => install::Target::Claude,
                Agent::Droid => install::Target::Droid,
            };
            let exe = std::env::current_exe().context("cannot locate the brakeline binary")?;
            let path = target.path(project, &cwd())?;
            let text = install::install(&path, &target.hook_command(&exe), target, write)?;
            if write {
                println!("updated {}", path.display());
                println!("start a new session (or review /hooks) to pick up the change.");
            } else {
                print!("{text}");
                eprintln!(
                    "\n# preview of {}; re-run with --write to apply",
                    path.display()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

const MAX_HOOK_INPUT: u64 = 32 * 1024 * 1024;

fn run_hook(format: HookFormat, infer_failures: bool) -> Result<ExitCode> {
    let mut raw = String::new();
    std::io::stdin()
        .take(MAX_HOOK_INPUT)
        .read_to_string(&mut raw)
        .context("cannot read hook input")?;
    let input: HookInput = serde_json::from_str(&raw).context("hook input is not valid JSON")?;
    let cwd = input.cwd.as_deref().map(Path::new);

    let (cfg, notice) = match config::load(cwd) {
        Ok(cfg) => (cfg, None),
        Err(err) => (
            config::Config::default(),
            Some(format!("brakeline config error, using defaults: {err:#}")),
        ),
    };
    let format = match format {
        HookFormat::Json => Format::Json,
        HookFormat::ExitCode => Format::ExitCode,
    };
    let outcome = match Store::open_default() {
        Ok(store) => Engine {
            cfg: &cfg,
            store: &store,
            notice,
            infer_failures,
        }
        .handle(&input),
        Err(err) => {
            // No writable state: still refuse catastrophic commands.
            let tmp =
                std::env::temp_dir().join(format!("brakeline-fallback-{}", std::process::id()));
            let store = Store::open(tmp.clone())?;
            let out = Engine {
                cfg: &cfg,
                store: &store,
                notice: Some(format!("brakeline state unavailable: {err:#}")),
                infer_failures,
            }
            .handle(&input);
            let _ = std::fs::remove_dir_all(tmp);
            out
        }
    };
    let (stdout, stderr, code) = hook::render(&outcome, &input.hook_event_name, &format);
    if !stdout.is_empty() {
        std::io::stdout().write_all(stdout.as_bytes())?;
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    Ok(ExitCode::from(code as u8))
}

fn ago(ts: u64) -> String {
    let secs = now_secs().saturating_sub(ts);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

fn status(session: Option<String>, json: bool) -> Result<ExitCode> {
    let store = Store::open_default()?;
    if let Some(id) = session {
        let s = store
            .load(&id)?
            .with_context(|| format!("no session {id}"))?;
        if json {
            println!("{}", serde_json::to_string_pretty(&s)?);
            return Ok(ExitCode::SUCCESS);
        }
        println!("session      {}", s.session_id);
        println!("cwd          {}", s.cwd);
        println!(
            "state        {}",
            s.halted
                .as_deref()
                .map(|r| format!("STOPPED: {r}"))
                .unwrap_or_else(|| "running".into())
        );
        println!("started      {}", ago(s.started_at));
        println!("last seen    {}", ago(s.last_seen));
        println!("tool calls   {}", s.tool_calls);
        println!("refusals     {} total", s.total_denials);
        if let Some(d) = &s.last_denial {
            println!("last refusal {d}");
        }
        println!("snapshots    {}", s.snapshots);
        let u = &s.usage;
        println!(
            "tokens       in {} / out {} / cache write {} / cache read {}",
            u.input_tokens, u.output_tokens, u.cache_write_tokens, u.cache_read_tokens
        );
        println!(
            "est. cost    ${:.2} over {} model calls",
            u.cost_usd, u.messages
        );
        if u.factory_credits > 0 {
            println!("credits      {} Factory credits", u.factory_credits);
        }
        let failing: Vec<_> = s.failures.iter().filter(|f| f.total > 0).collect();
        if !failing.is_empty() {
            println!("failing calls:");
            for f in failing {
                println!(
                    "  {:>3}x total, {} in a row  {}",
                    f.total, f.consecutive, f.label
                );
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    let sessions = store.list()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(ExitCode::SUCCESS);
    }
    if sessions.is_empty() {
        println!("no sessions recorded yet");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<38} {:>9} {:>6} {:>9} {:>8}  CWD",
        "SESSION", "SEEN", "CALLS", "EST.$", "STATE"
    );
    for s in sessions.iter().take(30) {
        println!(
            "{:<38} {:>9} {:>6} {:>9.2} {:>8}  {}",
            s.session_id,
            ago(s.last_seen),
            s.tool_calls,
            s.usage.cost_usd,
            if s.halted.is_some() { "STOPPED" } else { "ok" },
            s.cwd
        );
    }
    Ok(ExitCode::SUCCESS)
}
