#!/usr/bin/env bash
# Converts the serial JSON audit log into a JSON Lines file

INPUT=/var/log/nginx/modsec_audit.json
OUTPUT=/var/log/nginx/modsec_audit.jsonl

# Initial run
jq -c . "$INPUT" > "$OUTPUT" 2>/dev/null || true

# Then watch for new entries
tail -n0 -F "$INPUT" | while read -r line; do
  echo "$line" | jq -c . >> "$OUTPUT" 2>/dev/null
done

