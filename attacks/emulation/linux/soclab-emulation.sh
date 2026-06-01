#!/usr/bin/env bash
# home-soc-lab: benign Linux telemetry for testing the rules in detections/.
#
# Each function produces the same kind of auditd / Sysmon-for-Linux event as
# the matching row in attacks/README.md, but harmlessly, and reverts what it
# changed. Run only on UBU-SRV01 in the lab. Not run in this repo (no root on
# the build machine).
#
# Usage:  sudo ./soclab-emulation.sh [L2 L3 L6 L7 ...]
#         with no arguments it runs all of L2, L3, L6, L7.
#
# L1 (shell spawned by java) and L4 (jsp written by java) need the JVM; see
# SocLabJava.java next to this script. L5 (ssh authorized_keys) is included
# below and reverts the file.
set -u

MARK="/tmp/soclab-marker"

log() { printf '[%s] %s %s\n' "$1" "$(date -u +%FT%TZ)" "$2"; }

# L2, T1105 / T1059.004: download a file from a local web server and pipe it to
# a shell that only prints a line. Same "curl ... | bash" shape, benign content.
step_L2() {
  log L2 'download from localhost piped to a shell (benign)'
  local port=18080 dir
  dir="$(mktemp -d)"
  printf 'echo soclab-L2\n' > "$dir/payload.sh"
  ( cd "$dir" && python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$dir/pid" )
  sleep 1
  curl -s "http://127.0.0.1:$port/payload.sh" | bash
  kill "$(cat "$dir/pid")" 2>/dev/null
  rm -rf "$dir"
}

# L3, T1059.004: a shell making an outbound TCP connection. Connects to a local
# listener on 127.0.0.1 instead of redirecting a shell to it, so it is not a
# reverse shell, but it still produces "network connection made by bash".
step_L3() {
  log L3 'bash makes an outbound TCP connection to a local listener'
  local port=18443
  ( timeout 5 nc -l 127.0.0.1 "$port" >/dev/null 2>&1 & )
  sleep 1
  timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port; echo soclab-L3 >&3" 2>/dev/null || true
}

# L6, T1136.001: create a clearly-labelled test user, then delete it.
step_L6() {
  log L6 'create and delete a local user account'
  local u='soclab_test_user'
  useradd -M -N -s /usr/sbin/nologin -c 'soclab emulation, safe to delete' "$u" 2>/dev/null || true
  sleep 1
  userdel "$u" 2>/dev/null || true
}

# L7, T1140: decode a base64 string of "hello" with shell utilities.
step_L7() {
  log L7 'base64 decode with shell utilities (benign string)'
  echo 'c29jbGFiLUw3Cg==' > "$MARK.b64"
  base64 -d "$MARK.b64"
  rm -f "$MARK.b64"
}

# L5, T1098.004: append a throwaway public key to a test account's
# authorized_keys, then restore the file.
step_L5() {
  log L5 'append then revert a key in authorized_keys'
  local dir="/root/.ssh" f
  f="$dir/authorized_keys"
  mkdir -p "$dir"
  local backup
  backup="$(mktemp)"
  [ -f "$f" ] && cp "$f" "$backup"
  local tmpkey
  tmpkey="$(mktemp -d)/k"
  ssh-keygen -t ed25519 -N '' -C soclab-L5 -f "$tmpkey" >/dev/null 2>&1
  cat "$tmpkey.pub" >> "$f"
  sleep 1
  if [ -s "$backup" ]; then cp "$backup" "$f"; else rm -f "$f"; fi
  rm -rf "$(dirname "$tmpkey")" "$backup"
}

steps=("$@")
if [ "${#steps[@]}" -eq 0 ]; then steps=(L2 L3 L6 L7); fi
for s in "${steps[@]}"; do
  if declare -F "step_$s" >/dev/null; then "step_$s"; else log "$s" 'no such step'; fi
done
log done 'export the audit log and sysmon journal for this window, then run soclab run'
