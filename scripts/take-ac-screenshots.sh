#!/bin/bash
# take-ac-screenshots.sh — Capture Bromure Agentic Coding's editor
# screenshots in every locale × every category.
#
# Usage: ./scripts/take-ac-screenshots.sh
#
# Prerequisites:
#   - Bromure Agentic Coding.app built at .build/.../
#       (run `./build.sh bromure-ac` first)
#   - Screen Recording + Accessibility granted to Terminal so AppleScript
#     can drive the app via System Events and screencapture can read the
#     editor window's pixels.

set -euo pipefail

APP_NAME="Bromure Agentic Coding"
APP_BUNDLE="$(pwd)/.build/arm64-apple-macosx/release/${APP_NAME}.app"
BIN="${APP_BUNDLE}/Contents/MacOS/bromure-ac"
OUTPUT_DIR="$(pwd)/Resources/ac"
PROFILE="Claude Dev"

mkdir -p "$OUTPUT_DIR"

if [ ! -x "$BIN" ]; then
    echo "ERROR: ${BIN} not found. Run ./build.sh bromure-ac first." >&2
    exit 1
fi

# Editor sidebar entries that the AppleScript bridge accepts. Order
# matches the on-screen sidebar so the loop reads top-to-bottom.
CATEGORIES=(general agent folders credentials environment mcp tracing appearance resources)

# (locale-code  filename-suffix). Locale codes are what
# `defaults write -AppleLanguages` understands; suffix is what gets
# appended to each output file.
LOCALES=(
    "en       en"
    "fr       fr"
    "de       de"
    "es       es"
    "pt       pt"
    "ja       ja"
    "zh-Hans  zh-CN"
    "zh-Hant  zh-TW"
)

# ----------------------------------------------------------------------
# Drive the app via osascript.
# ----------------------------------------------------------------------

ac_tell() {
    osascript -e "tell application \"${APP_NAME}\" to $1" 2>&1
}

# True only when the response is real data — not osascript stderr noise
# and not one of the bridge's "error: …" sentinel strings. Used to drive
# the wait loop so we don't proceed before NSApp.delegate is the
# ACAppDelegate.
ac_response_ok() {
    local s="$1"
    [ -n "$s" ] && [[ "$s" != error* ]] && [[ "$s" != *"execution error"* ]]
}

ensure_profile() {
    # Check the live profile list first; only create if missing. The
    # `create ac profile` bridge does NOT dedupe by name, so calling it
    # blindly per locale would accumulate duplicate "Screenshot"
    # profiles in the on-disk store.
    local listing
    listing=$(ac_tell "list profiles")
    if echo "$listing" | grep -q "\"name\":\"$PROFILE\""; then
        echo "  (reusing existing $PROFILE profile)"
        return
    fi
    local id
    id=$(ac_tell "create ac profile \"$PROFILE\"")
    if ! ac_response_ok "$id"; then
        echo "  ERROR creating profile: $id" >&2
        return 1
    fi
    echo "  (created $PROFILE profile: $id)"
}

editor_window_id() {
    ac_tell "get editor window id" || echo "0"
}

capture_window_id() {
    local outfile="$1"
    local wid="$2"
    [ -z "$wid" ] || [ "$wid" = "0" ] && return 1
    rm -f "$outfile"
    screencapture -x -o -l "$wid" "$outfile" 2>/dev/null
    [ -s "$outfile" ]
}

# ----------------------------------------------------------------------
# Main loop.
# ----------------------------------------------------------------------

echo "=== Bromure AC Screenshot Tool ==="
echo "Output: $OUTPUT_DIR/"
echo ""

for entry in "${LOCALES[@]}"; do
    locale=$(echo "$entry" | awk '{print $1}')
    suffix=$(echo "$entry" | awk '{print $2}')

    echo "--- Locale: $locale ---"
    pkill -x bromure-ac 2>/dev/null || true
    sleep 2

    "$BIN" -AppleLanguages "($locale)" >/dev/null 2>&1 &

    # Wait for the app to register its scripting interface AND for
    # NSApp.delegate to be the ACAppDelegate. Before that, every bridge
    # command returns "error: app not ready" — non-empty, so a naive
    # `-n "$state"` check would race past the readiness gate.
    ready=false
    for _ in $(seq 1 60); do
        sleep 0.5
        state=$(ac_tell "get app state")
        if ac_response_ok "$state"; then
            ready=true
            break
        fi
    done
    if ! $ready; then
        echo "  ERROR: app not ready after 30s — last state: $state" >&2
        continue
    fi
    sleep 0.5

    ensure_profile || continue

    # Open editor for the screenshot profile. Surface failures —
    # if the bridge can't find the profile we want the operator to see
    # it, not skip the locale with an empty Resources/ac/ directory.
    open_result=$(ac_tell "open ac profile editor \"$PROFILE\"")
    if ! ac_response_ok "$open_result"; then
        echo "  ERROR opening editor: $open_result" >&2
        continue
    fi
    sleep 1

    wid=$(editor_window_id)
    if [ -z "$wid" ] || [ "$wid" = "0" ]; then
        echo "  WARN: editor window didn't open"
        continue
    fi

    for category in "${CATEGORIES[@]}"; do
        sel=$(ac_tell "select editor category \"$category\"")
        if ! ac_response_ok "$sel"; then
            echo "  $category SKIP (select failed: $sel)" >&2
            continue
        fi
        sleep 0.6
        outfile="$OUTPUT_DIR/editor_${category}_${suffix}.png"
        if capture_window_id "$outfile" "$wid"; then
            printf "  %-12s → %s\n" "$category" "$(basename "$outfile")"
        else
            echo "  $category SKIP (capture failed)"
        fi
    done

    ac_tell "close ac profile editor" >/dev/null
    sleep 0.4
done

# Tidy: kill the app and clear the AppleLanguages override so the next
# normal launch picks the user's macOS preferred language again.
pkill -x bromure-ac 2>/dev/null || true
sleep 1
defaults delete io.bromure.agentic-coding AppleLanguages 2>/dev/null || true

echo ""
echo "=== Done ==="
count=$(find "$OUTPUT_DIR" -name "editor_*.png" -type f | wc -l | tr -d ' ')
echo "$count screenshots captured under $OUTPUT_DIR/"
