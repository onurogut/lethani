#!/bin/bash
# oob.sh — get an out-of-band callback endpoint (webhook / DNS / HTTP).
#
# Modes:
#   oob.sh                              one-shot: print a fresh interactsh domain
#   oob.sh --listen <log>               start a background interactsh listener,
#                                       writing JSON events to <log>; print domain + PID
#   oob.sh --user <url>                 validate and echo a user-supplied URL
#                                       (does not register anything on interactsh)
#   oob.sh --kill <log>                 stop the listener started with --listen <log>
#
# Designed to be invoked from the macOS host through the kali-ssh MCP server,
# so it runs on the Kali VM where interactsh-client is installed.
set -e

usage() {
  sed -n '2,12p' "$0"
  exit 1
}

ACTION="oneshot"
ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --listen) ACTION="listen"; ARG="$2"; shift 2 ;;
    --user)   ACTION="user";   ARG="$2"; shift 2 ;;
    --kill)   ACTION="kill";   ARG="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing binary: $1" >&2
    [[ "$1" == "interactsh-client" ]] && \
      echo "install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" >&2
    exit 1
  }
}

case "$ACTION" in

  user)
    [[ -z "$ARG" ]] && { echo "--user needs a URL" >&2; exit 1; }
    if [[ ! "$ARG" =~ ^(https?://|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) ]]; then
      echo "invalid URL/domain: $ARG" >&2
      exit 1
    fi
    echo "$ARG"
    ;;

  oneshot)
    require_bin interactsh-client
    require_bin jq
    # one-shot: register a domain, print it, then exit. The interactsh server
    # keeps the inbox for a short window — check app.interactsh.com.
    interactsh-client -json 2>/dev/null \
      | head -1 \
      | jq -r '.["full-id"] // .["protocol-host"] // empty' \
      | head -1
    ;;

  listen)
    [[ -z "$ARG" ]] && { echo "--listen needs a log path" >&2; exit 1; }
    require_bin interactsh-client
    require_bin jq
    LOG="$ARG"
    PID_FILE="${LOG}.pid"
    mkdir -p "$(dirname "$LOG")"
    : > "$LOG"
    nohup interactsh-client -json -o "$LOG" >/dev/null 2>&1 &
    LISTENER_PID=$!
    echo "$LISTENER_PID" > "$PID_FILE"
    # Wait up to 10s for the first registration line to land in the log.
    for _ in $(seq 1 10); do
      if [[ -s "$LOG" ]]; then
        DOMAIN=$(head -1 "$LOG" | jq -r '.["full-id"] // .["protocol-host"] // empty' 2>/dev/null | head -1)
        if [[ -n "$DOMAIN" ]]; then
          echo "domain: $DOMAIN"
          echo "pid:    $LISTENER_PID"
          echo "log:    $LOG"
          exit 0
        fi
      fi
      sleep 1
    done
    echo "interactsh-client did not register a domain within 10s" >&2
    kill "$LISTENER_PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
    ;;

  kill)
    [[ -z "$ARG" ]] && { echo "--kill needs the log path used with --listen" >&2; exit 1; }
    PID_FILE="${ARG}.pid"
    if [[ -f "$PID_FILE" ]]; then
      PID=$(cat "$PID_FILE")
      kill "$PID" 2>/dev/null && echo "stopped listener pid $PID" || echo "pid $PID already gone"
      rm -f "$PID_FILE"
    else
      echo "no pid file at $PID_FILE" >&2
      exit 1
    fi
    ;;

esac
