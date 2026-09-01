#!/bin/bash
#
# log_collect_supervisor.sh - keeps log_collect.sh running across crashes,
# so one bad moment doesn't silently end an overnight (12-14h) run.
#
# Usage: nohup ./log_collect_supervisor.sh FOLDER_NAME > /dev/null 2>&1 &
#        (or run it inside tmux/screen instead of nohup - either way, don't
#        run it in a plain foreground SSH session that might disconnect)
#
# Stop the whole thing (supervisor + log_collect.sh) the same way as
# always: touch FOLDER_NAME/STOP. That triggers log_collect.sh's own
# graceful shutdown, which this supervisor recognizes as intentional and
# will NOT restart from.
#
# If log_collect.sh keeps exiting within seconds of starting, that means a
# persistent problem (bad GNB_PATH, missing tool) rather than a one-off
# crash - the supervisor gives up after 5 such attempts instead of
# spinning all night, and says so in collection.log.

set -u

if [ "$#" -lt 1 ]; then
    echo "Usage: ./log_collect_supervisor.sh FOLDER_NAME"
    exit 1
fi

DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIR"
SUP_LOG="$DIR/collection.log"

sup_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') Supervisor: $*" >> "$SUP_LOG"
}

fast_failures=0

while :; do
    rm -f "$DIR/.stopped_clean"
    start_ts=$(date +%s)
    "$SCRIPT_DIR/log_collect.sh" "$DIR"
    end_ts=$(date +%s)

    if [ -f "$DIR/.stopped_clean" ]; then
        sup_log "log_collect.sh stopped cleanly, not restarting."
        break
    fi

    if [ $((end_ts - start_ts)) -lt 10 ]; then
        fast_failures=$((fast_failures + 1))
    else
        fast_failures=0
    fi

    if [ "$fast_failures" -ge 5 ]; then
        sup_log "log_collect.sh failed $fast_failures times right after starting - giving up. Check collection.log and the GNB_PATH*/tool config."
        break
    fi

    sup_log "log_collect.sh exited unexpectedly, restarting in 5s..."
    sleep 5
done
