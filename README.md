# brakeline

**A seatbelt for unattended coding agents.** brakeline is a single native binary that sits in your agent's hook pipeline and does four things on every tool call, in about 6 ms:

1. **Stops loops.** If the agent repeats the same call with no file changes in between, or retries a failing command again and again, the call is refused with an explanation the agent can act on. If it keeps getting refused, the run is stopped.
2. **Enforces budgets.** Per-session caps on estimated spend (metered from the transcript), output tokens, tool calls, and wall-clock time. You get a warning at 80% and a hard stop at 100%.
3. **Blocks catastrophic commands.** `rm -rf ~`, `rm -rf $UNSET_VAR/`, `find / -delete`, `dd of=/dev/disk2`, `mkfs`, force pushes, and your own patterns.
4. **Snapshots before destructive commands.** Before `rm`, `mv`, `> file` overwrites, `git reset --hard`, `git restore`, `git checkout -- .`, `git clean`, `sed -i`, `find -delete`/`-exec rm` and similar, it saves tracked *and untracked* files as a git object. Then `brakeline restore <id>` brings them back.

## Why

- The cost of a run is the fastest-rising complaint about coding agents. In an analysis of 66,320 Reddit complaint posts (OpenChamber, Sep 2026), "excessive token consumption" went from 9.1% to 13.7% of posts and from 9th to 3rd place.
- Agents get stuck. One public report describes Codex looping for 9 hours and using up a week of quota while redoing finished work.
- Built-in undo does not cover the shell. Claude Code checkpoints do not track files changed by `rm`, `mv` or other Bash commands. In one reported incident, an agent ran `git restore` on a repository with three days of uncommitted work, and git had nothing left to recover.

Existing tools each cover one slice: Python loop hooks, phone kill switches, or edit-only checkpoints. brakeline puts all four protections in one dependency-free binary that is fast enough to run on every call.

## Install

```sh
cargo install --git https://github.com/gshost1/brakeline   # or, from a clone: cargo install --path .
brakeline install claude          # preview the change to ~/.claude/settings.json
brakeline install claude --write  # apply it (the old file is backed up)
```

Use `--project` to install into `./.claude/settings.json` instead. The installer only adds or replaces its own `PreToolUse`, `PostToolUse` and `PostToolUseFailure` entries. Every other setting and hook is preserved.

### Factory Droid

```sh
brakeline install droid --project --write   # ./.factory/hooks.json  (omit --project for ~/.factory/hooks.json)
```

This registers `brakeline hook --agent droid` for `PreToolUse`, `PostToolUse` and `Stop`. Droid differs from Claude Code in two ways that brakeline handles:

- **Droid sends no hook event when a tool call fails.** In Droid mode, a call that never reports back is counted as failed. That happens at the turn's `Stop`, or when the next call starts more than 2 seconds later. Calls in the same parallel batch are not affected.
- **Spend comes from Droid's own counters.** brakeline reads the running session totals Droid keeps next to the transcript (`<session>.settings.json`), so subagents are included. This also enables a `max_factory_credits` budget.

Tested live with `droid exec` 0.232.0: a force push was refused, a retry loop was refused after 3 failures and then stopped, and `git reset --hard && git clean -fd` was snapshotted and fully restored. Droid shows brakeline's snapshot notice to the user, not to the model.

For agents that only understand "exit code 2 means block", use `brakeline hook --format exit-code`. It reads the same JSON event shape on stdin.

## What the agent and you see

| Situation | Agent sees | You see |
| --- | --- | --- |
| Repeated identical call | The call is refused: "already called 5 times with identical input and no file changes in between…" | A warning |
| Same command failed 3× in a row | The call is refused: "read the error, change something, or ask the user" | A warning |
| 3 refusals in a row | The run stops (`continue: false`) | A stop reason with a `brakeline reset <id>` hint |
| Budget reached | The run stops | "estimated cost budget reached ($50.12 of $50.00…)" |
| Destructive command | Allowed | "snapshot 1760000000-ab12 saved before `git reset --hard`… Undo with `brakeline restore …`" |
| Catastrophic command | The call is refused | A warning |

A stopped session stays stopped, even if you type "continue". Running `brakeline reset <session>` clears it after you've looked. Add `--budget` to also restart the spend, time and call counters.

## Commands

```text
brakeline status [SESSION] [--json]   recent sessions or one in detail (spend, refusals, failing calls)
brakeline reset SESSION [--budget]    resume a stopped session
brakeline snapshots [--all] [--json]  list snapshots for this repo
brakeline restore ID [--yes] [-- PATHS...]   preview, then restore
brakeline prune [--keep 50]           drop old snapshot refs
brakeline check -- 'rm -rf $OUT/'     classify a command the way the hook would
brakeline config                      print the effective config for this directory
brakeline gc [--days 14]              delete old session records
```

## Configuration

User config lives at `~/.config/brakeline/config.toml` (or `$BRAKELINE_CONFIG`). See [`examples/config.toml`](examples/config.toml) for every option and its default.

A repository may include `.brakeline.toml`, but **it can only tighten limits**. It can lower budgets, add blocked patterns, or turn protections on. It can never raise a budget, disable a protection, change pricing, or change `progress_tools`. A cloned repo is untrusted input, so it cannot quietly switch off your guard. Project values also have minimums (for example, at least 2 refusals before a stop, and blocked patterns of at least 4 characters), so a hostile repo can't make every session unusable.

`blocked_substrings` match the raw command text, including quoted strings. A commit message that mentions `terraform destroy` is blocked too. That errs on the safe side.

## How it works

- **Loop detection** fingerprints each call (tool name plus canonicalized input, ignoring free-text fields like a Bash `description`). Successful `Edit`/`Write` calls and file-changing shell commands advance a "progress epoch". Identical calls and failure streaks are only compared within one epoch, so the normal edit → test → edit → test cycle is never flagged.
- **Metering** reads only the new bytes of the Claude Code transcript on each call. It deduplicates repeated entries for the same message by counting only the growth in their usage numbers. Cost is an estimate from the configurable price table.
- **Snapshots** copy the real index into a temporary one, run `git add -A`, write the tree, and pin a commit under `refs/brakeline/snapshots/<id>`. Your index, working tree, branches and stash are never touched. Restore uses `git restore --overlay`, so files created after the snapshot are kept, and the current state is snapshotted first so the restore itself can be undone.
- **State** is one small JSON file per session under `~/.brakeline` (or `$BRAKELINE_HOME`), guarded by a file lock so parallel tool calls stay consistent.
- **Failure policy.** If brakeline's own state is broken, it fails open (allows the call and shows a notice) but still refuses catastrophic commands. An invalid config falls back to defaults with a visible warning.

## Limits (read these)

- **It is a guard rail, not a sandbox.** The shell checks parse the command shapes agents actually emit (quoting, `&&`, pipes, `sudo`, `xargs`, `bash -c`, `eval`). A deliberately obfuscated command can get past them. Use a real sandbox or container for hostile code.
- **Snapshots only cover git repositories, and skip ignored files** (`.env`, `node_modules`, build output). Outside git, destructive commands are allowed with a notice. Database changes, remote APIs and pushes cannot be undone by a snapshot.
- **Snapshots record file contents as they are on disk, not your staging state.** Restored files come back unstaged. Content that exists only in the index (staged, then deleted from disk) is not captured.
- **Spend is an estimate.** Prices are list prices you should verify. The transcript is written asynchronously, so the meter can lag one turn behind. Subagent transcripts are not yet metered.
- **Loop detection is a heuristic.** If a legitimate workflow trips it, raise `max_identical_calls` or add a tool to `progress_tools` in your user config.
- **Claude Code and Droid.** Both speak the same hook protocol. Other agents work if they can send the same JSON and honor either JSON decisions or exit code 2.
- **Cost estimates for non-Anthropic models use the fallback price.** Add a `[[pricing]]` entry for models such as GPT, or budget in Factory credits instead.

## Development

```sh
cargo test                 # unit tests, including real git snapshot/restore
cargo clippy --all-targets -- -D warnings
sh tests/e2e.sh            # drives the release binary with hook payloads
```

MIT licensed. See [SECURITY.md](SECURITY.md) for the threat model.
