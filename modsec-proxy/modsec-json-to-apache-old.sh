#!/usr/bin/env bash
#
# /usr/local/bin/modsec-jsonl-to-apache.sh
#
INPUT=/var/log/nginx/modsec_audit.jsonl
OUTPUT=/var/log/nginx/modsec_error.log

# Ensure the output exists
touch "$OUTPUT"

tail -n0 -F "$INPUT" | while IFS= read -r json; do

  # 1) Transaction fields
  timestamp=$(jq -r '.transaction.time_stamp' <<<"$json")
  client_ip=$(jq -r '.transaction.client_ip'  <<<"$json")
  client_port=$(jq -r '.transaction.client_port' <<<"$json")
  host=$(jq -r '.transaction.request.headers.Host // "localhost"' <<<"$json")
  uri=$(jq -r '.transaction.request.uri' <<<"$json")
  txid=$(jq -r '.transaction.unique_id' <<<"$json")

  # 2) First ModSecurity message details
  match=$(jq -r '.transaction.messages[0].details.match' <<<"$json")
  file=$(jq -r '.transaction.messages[0].details.file' <<<"$json")
  line=$(jq -r '.transaction.messages[0].details.lineNumber' <<<"$json")
  rid=$(jq -r '.transaction.messages[0].details.ruleId' <<<"$json")
  rev=$(jq -r '.transaction.messages[0].details.rev // ""' <<<"$json")
  msg=$(jq -r '.transaction.messages[0].message' <<<"$json")
  data=$(jq -r '.transaction.messages[0].details.data' <<<"$json")

  # 3) Severity text mapping
  sevnum=$(jq -r '.transaction.messages[0].details.severity' <<<"$json")
  case "$sevnum" in
    "0") sevtext="EMERGENCY";;
    "1") sevtext="ALERT";;
    "2") sevtext="WARNING";;
    *)   sevtext="NOTICE";;
  esac

  # 4) Short filename for "at <file>"
  shortfile=$(basename "$file")

  # 5) Build tags list, preserving the quotes
  tags=$(jq -r '
    .transaction.messages[0].details.tags[]
    | "[tag \"" + . + "\"]"
  ' <<<"$json" | paste -sd ' ' -)

  # 6) Emit the final Apache‐style line
  printf '[%s] [:error] [pid 0] [client %s:%s] ModSecurity: %s. %s at %s. [file "%s"] [line "%s"] [id "%s"] [rev "%s"] [msg "%s"] [data "%s"] %s [hostname "%s"] [uri "%s"] [unique_id "%s"]\n' \
    "$timestamp" \
    "$client_ip" "$client_port" \
    "$sevtext" "$match" "$shortfile" \
    "$file" "$line" "$rid" "$rev" \
    "$msg" "$data" "$tags" \
    "$host" "$uri" "$txid" \
  >> "$OUTPUT"

done
