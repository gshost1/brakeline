#!/bin/sh
# End-to-end check of the real binary using Claude Code-shaped hook payloads.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cargo build --quiet --release --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/release/brakeline"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export BRAKELINE_HOME="$WORK/home"
export BRAKELINE_CONFIG="$WORK/no-user-config.toml"
REPO="$WORK/repo"
mkdir -p "$REPO"
git -C "$REPO" init -q
printf 'v1\n' > "$REPO/app.txt"
git -C "$REPO" add app.txt
GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t \
    git -C "$REPO" commit -q -m init

fail() { echo "FAIL: $*" >&2; exit 1; }

pre() { # session, tool, tool_input-json
    printf '{"session_id":"%s","hook_event_name":"PreToolUse","cwd":"%s","tool_name":"%s","tool_input":%s}' \
        "$1" "$REPO" "$2" "$3" | "$BIN" hook
}
post_fail() {
    printf '{"session_id":"%s","hook_event_name":"PostToolUseFailure","cwd":"%s","tool_name":"%s","tool_input":%s,"error":"boom"}' \
        "$1" "$REPO" "$2" "$3" | "$BIN" hook
}

# 1. Safe call: allowed silently.
out=$(pre s1 Bash '{"command":"cargo test"}')
[ -z "$out" ] || fail "safe call produced output: $out"

# 2. Catastrophic command: denied.
out=$(pre s1 Bash '{"command":"rm -rf ~/"}')
echo "$out" | grep -q '"permissionDecision":"deny"' || fail "rm -rf ~ not denied: $out"

# 3. Destructive command: snapshot first, then the "agent" wipes uncommitted work.
printf 'v2 uncommitted\n' > "$REPO/app.txt"
printf 'brand new\n' > "$REPO/notes.txt"
out=$(pre s2 Bash '{"command":"git reset --hard && git clean -fd"}')
echo "$out" | grep -q 'snapshot' || fail "no snapshot notice: $out"
git -C "$REPO" reset -q --hard
git -C "$REPO" clean -q -fd
[ ! -e "$REPO/notes.txt" ] || fail "simulated wipe did not happen"
ID=$(cd "$REPO" && "$BIN" snapshots --json | sed -n 's/.*"id": "\([^"]*\)".*/\1/p' | head -1)
[ -n "$ID" ] || fail "snapshot not listed"
(cd "$REPO" && "$BIN" restore "$ID" --yes >/dev/null)
grep -q 'v2 uncommitted' "$REPO/app.txt" || fail "uncommitted edit not restored"
grep -q 'brand new' "$REPO/notes.txt" || fail "untracked file not restored"

# 4. Retry loop: same failing command three times, fourth is refused.
for _ in 1 2 3; do
    pre s3 Bash '{"command":"npm run deploy"}' >/dev/null
    post_fail s3 Bash '{"command":"npm run deploy"}' >/dev/null
done
out=$(pre s3 Bash '{"command":"npm run deploy"}')
echo "$out" | grep -q 'failed 3 times in a row' || fail "retry loop not caught: $out"

# 5. Stuck agent: repeated refusals end the run; reset resumes it.
pre s3 Bash '{"command":"npm run deploy"}' >/dev/null
out=$(pre s3 Bash '{"command":"npm run deploy"}')
echo "$out" | grep -q '"continue":false' || fail "run not stopped: $out"
out=$(pre s3 Read '{"file_path":"/x"}')
echo "$out" | grep -q '"continue":false' || fail "stopped run accepted new calls: $out"
"$BIN" reset s3 >/dev/null
out=$(pre s3 Read '{"file_path":"/x"}')
[ -z "$out" ] || fail "reset did not resume: $out"

# 6. Exit-code mode for agents that only honor exit status.
set +e
printf '{"session_id":"s4","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force"}}' \
    | "$BIN" hook --format exit-code 2>/dev/null
code=$?
set -e
[ "$code" = 2 ] || fail "exit-code mode returned $code"

# 7. Hostile project config cannot loosen limits.
printf '[budget]\nmax_tool_calls = 3\n[shell]\nblock_catastrophic = false\n' > "$REPO/.brakeline.toml"
(cd "$REPO" && "$BIN" config) | grep -q 'block_catastrophic = true' || fail "project disabled protection"
for i in 1 2 3; do pre s5 Read "{\"file_path\":\"/f$i\"}" >/dev/null; done
out=$(pre s5 Read '{"file_path":"/f4"}')
echo "$out" | grep -q 'tool calls budget reached' || fail "project budget not applied: $out"
rm "$REPO/.brakeline.toml"

# 8. Latency: median of 50 PreToolUse calls.
start=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
i=0
while [ $i -lt 50 ]; do
    pre "lat" Read "{\"file_path\":\"/lat$i\"}" >/dev/null
    i=$((i + 1))
done
end=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
avg=$(perl -e "printf '%.2f', ($end - $start) * 1000 / 50")
echo "average PreToolUse hook latency: ${avg} ms"

echo "e2e passed: safe, catastrophic, snapshot+restore, retry loop, stop+reset, exit-code, project config, latency"
