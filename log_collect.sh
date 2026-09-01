#!/bin/bash
#
# log_collect.sh - Continuous CU/DU log collector for long gNB test runs.
#
# What it does each cycle:
#   1. rsync's only new/changed *.bin and *log* files out of the live
#      CU/DU bin dirs (and PM/KPI counters) into this run's folder -
#      already-copied, unchanged files are skipped, so a 12-14h run
#      doesn't re-read gigabytes of untouched logs every pass.
#   2. Every COMPRESS_INTERVAL_SEC, 7z's whatever has accumulated per
#      category into archives/CATEGORY_<window-start>_to_<window-end>.7z,
#      verifies the archive (7z t), then deletes the staged copies -
#      so disk usage stays bounded instead of growing for 12-14h straight.
#
# Usage:   ./log_collect.sh FOLDER_NAME
# Stop with Ctrl+C, or from another shell: touch FOLDER_NAME/STOP
# (both let the current cycle finish, do one final compress, then exit -
# there's no more "press 1 within 3 seconds", which isn't workable
# unattended for 12+ hours).
#
# Requires: rsync, 7z (p7zip).

set -u
shopt -s nullglob

# ---------------------------------------------------------------------------
# Configuration - edit for your setup
# ---------------------------------------------------------------------------
GNB_PATH1=/export/home1/users/pavan/qos_bin/5G_IPR_e2e_bin_comb_5_qat_patch1_to_16_arp_resolution_bin/gNB_SW
GNB_PATH2=/var/data/O-RAN/O-DU        # DU PM/KPI counters live under $GNB_PATH2/PM - VERIFY this path
GNB_PATH3=/var/data/O-RAN/O-CU-CP     # CU PM/KPI counters live under $GNB_PATH3/PM - VERIFY this path

COPY_INTERVAL_SEC=5          # how often to pull new/changed files
COMPRESS_INTERVAL_SEC=1800   # how often to roll up + 7z a window (1800 = 30 min)
COMPRESSION_LEVEL=9          # 7z -mx level, 0-9 (9 = ultra, matches the ~35:1 ratio already seen)

# DESTRUCTIVE, off by default: wipes GNB_PATH2/PM and GNB_PATH3/PM before
# this run starts, so leftover PM files from a previous session don't get
# swept into this run's dukpi/cukpi and misdate your first archive. Only
# turn this on if you're sure nothing else consumes those files.
CLEAR_SOURCE_PM_ON_START=false

# ---------------------------------------------------------------------------

if [ "$#" -lt 1 ]; then
    echo " enter the Log file directory name"
    echo " Ex. ./log_collect.sh FOLDER_NAME"
    echo " Edit GNB_PATH1/2/3 near the top of this script for your build/board paths."
    exit 1
fi

for tool in rsync 7z; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: '$tool' not found on PATH. Install it before running this script." >&2
        exit 1
    fi
done

RUN_DIR="$1"
mkdir -p "$RUN_DIR" || exit 1
cd "$RUN_DIR" || exit 1
mkdir -p culogs dulogs dukpi cukpi cucfg ducfg dubin cubin archives

STOP_FILE="STOP"
LOG_FILE="collection.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

stop_requested=0
trap 'stop_requested=1' INT TERM

if [ "$CLEAR_SOURCE_PM_ON_START" = true ]; then
    log "Clearing old PM files from ${GNB_PATH2:?}/PM and ${GNB_PATH3:?}/PM ..."
    rm -rf "${GNB_PATH2:?}"/PM/* "${GNB_PATH3:?}"/PM/* 2>>"$LOG_FILE"
fi

# ---------------------------------------------------------------------------
# One-time: configs + binaries/decoders (kept as plain files - these
# capture the exact build used for this session, and are never touched
# by the compress/delete cycle below).
# ---------------------------------------------------------------------------
log "Copying configs and binaries..."
cp -r "$GNB_PATH1"/gNB_CU/cfg/*.xml cucfg/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_CU/cfg/*.cfg cucfg/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_DU/cfg/*.cfg ducfg/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_DU/cfg/*.xml ducfg/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_DU/bin/gnb_du_layer2 dubin/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_DU/bin/bin_reader dubin/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_DU/bin/decode_bin_files.sh dubin/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_CU/bin/gnb_cu_pdcp cubin/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_CU/bin/bin_reader cubin/ 2>>"$LOG_FILE"
cp -r "$GNB_PATH1"/gNB_CU/bin/decode_bin_files.sh cubin/ 2>>"$LOG_FILE"

# ---------------------------------------------------------------------------
# sync_dir SRC DST PATTERN...
#   Copies files matching PATTERN(s) from SRC into DST via rsync's
#   quick-check (size+mtime), same as before - AND additionally skips any
#   file already recorded in archived_size/archived_mtime with the same
#   size+mtime, i.e. a file that was already 7z'd into a previous window
#   and deleted from staging (so the destination alone can no longer tell
#   rsync "unchanged"). Without this, every finalized log would get
#   re-copied and re-archived in *every* window for the rest of a
#   12-14h run, forever - only files that are new or still growing get
#   pulled in. A missing SRC logs one warning (not one per cycle).
# ---------------------------------------------------------------------------
declare -A warned_missing
declare -A archived_size
declare -A archived_mtime
sync_dir() {
    local src="$1" dst="$2"
    shift 2
    if [ ! -d "$src" ]; then
        if [ -z "${warned_missing[$src]:-}" ]; then
            log "WARN: source dir does not exist, skipping: $src"
            warned_missing[$src]=1
        fi
        return
    fi

    local exclude_args=() f sz mt
    for f in "$src"/*; do
        [ -f "$f" ] || continue
        read -r sz mt < <(stat -c '%s %Y' "$f" 2>/dev/null) || continue
        if [ "${archived_size[$f]:-}" = "$sz" ] && [ "${archived_mtime[$f]:-}" = "$mt" ]; then
            exclude_args+=(--exclude="$(basename "$f")")
        fi
    done

    local include_args=() pat
    for pat in "$@"; do
        include_args+=(--include="$pat")
    done
    rsync -a "${exclude_args[@]}" "${include_args[@]}" --exclude='*' "$src"/ "$dst"/ 2>>"$LOG_FILE"
}

# ---------------------------------------------------------------------------
# compress_and_clean CATEGORY SRC DIR WINDOW_START WINDOW_END
#   7z's everything currently staged in DIR into
#   archives/CATEGORY_WINDOW_START_to_WINDOW_END.7z, verifies it with
#   `7z t`, records each archived file's current (size, mtime) from SRC
#   into archived_size/archived_mtime so sync_dir won't re-pull it in
#   while it stays unchanged at the source, and only then deletes the
#   staged copies. On any failure the staged files are left in place so
#   nothing is lost - they roll into the next window's archive instead.
#   Runs sequentially (not backgrounded): it writes to the shared
#   archived_size/archived_mtime arrays, which a background subshell
#   would only update in its own copy and lose on exit.
# ---------------------------------------------------------------------------
compress_and_clean() {
    local category="$1" src="$2" dir="$3" win_start="$4" win_end="$5"
    local count
    count=$(find "$dir" -maxdepth 1 -type f -not -name '.*' | wc -l)
    if [ "$count" -eq 0 ]; then
        return
    fi
    local archive="archives/${category}_${win_start}_to_${win_end}.7z"
    if 7z a -mx="$COMPRESSION_LEVEL" -mmt=on "$archive" "$dir"/* >>"$LOG_FILE" 2>&1 \
        && 7z t "$archive" >>"$LOG_FILE" 2>&1; then
        log "Archived $count file(s) from $dir -> $archive ($(du -h "$archive" | cut -f1))"
        local f base sf sz mt
        for f in "$dir"/*; do
            [ -f "$f" ] || continue
            base=$(basename "$f")
            sf="$src/$base"
            if read -r sz mt < <(stat -c '%s %Y' "$sf" 2>/dev/null); then
                archived_size["$sf"]=$sz
                archived_mtime["$sf"]=$mt
            fi
        done
        rm -f "$dir"/*
    else
        log "ERROR: 7z failed for $category - leaving $count file(s) staged in $dir, will retry next window"
    fi
}

roll_up() {
    local win_start="$1" win_end="$2"
    compress_and_clean DULOGS "$GNB_PATH1/gNB_DU/bin" dulogs "$win_start" "$win_end"
    compress_and_clean CULOGS "$GNB_PATH1/gNB_CU/bin" culogs "$win_start" "$win_end"
    compress_and_clean DUKPI  "$GNB_PATH2/PM"          dukpi  "$win_start" "$win_end"
    compress_and_clean CUKPI  "$GNB_PATH3/PM"          cukpi  "$win_start" "$win_end"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
window_bucket=$(( $(date +%s) / COMPRESS_INTERVAL_SEC ))
window_start=$(date '+%Y%m%d_%H%M%S')
log "Collecting into $RUN_DIR (copy every ${COPY_INTERVAL_SEC}s, compress+delete every ${COMPRESS_INTERVAL_SEC}s)"
log "Stop with Ctrl+C, or: touch $RUN_DIR/$STOP_FILE"

while :; do
    sync_dir "$GNB_PATH1/gNB_DU/bin" dulogs '*.bin' '*log*'
    sync_dir "$GNB_PATH1/gNB_CU/bin" culogs '*.bin' '*log*'
    sync_dir "$GNB_PATH2/PM" dukpi '*'
    sync_dir "$GNB_PATH3/PM" cukpi '*'

    now_bucket=$(( $(date +%s) / COMPRESS_INTERVAL_SEC ))
    if [ "$now_bucket" -ne "$window_bucket" ]; then
        window_end=$(date '+%Y%m%d_%H%M%S')
        roll_up "$window_start" "$window_end"
        window_bucket=$now_bucket
        window_start=$window_end
    fi

    if [ -f "$STOP_FILE" ]; then
        log "Stop file detected."
        stop_requested=1
    fi
    [ "$stop_requested" -eq 1 ] && break

    sleep "$COPY_INTERVAL_SEC"
done

log "Stopping - final sync and flush..."
sync_dir "$GNB_PATH1/gNB_DU/bin" dulogs '*.bin' '*log*'
sync_dir "$GNB_PATH1/gNB_CU/bin" culogs '*.bin' '*log*'
sync_dir "$GNB_PATH2/PM" dukpi '*'
sync_dir "$GNB_PATH3/PM" cukpi '*'
roll_up "$window_start" "$(date '+%Y%m%d_%H%M%S')"
rm -f "$STOP_FILE"
log "Done. Archives are in $RUN_DIR/archives/"
