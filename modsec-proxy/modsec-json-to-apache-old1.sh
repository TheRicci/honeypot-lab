#!/usr/bin/env bash
#
# /usr/local/bin/modsec-jsonl-to-apache.sh
#
INPUT=/var/log/nginx/modsec_audit.jsonl
OUTPUT=/var/log/nginx/modsec_error.log

# Ensure the output exists
touch "$OUTPUT"

tail -n0 -F "$INPUT" | while IFS= read -r json; do

  # 1) Timestamp parts
  ts=$(jq -r '.transaction.time_stamp' <<<"$json")       # e.g. "Sat May 24 02:33:47 2025"
  us=$(jq -r '.transaction.time_stamp_ms // "000000"' <<<"$json")
  # Build "[Sat May 24 02:33:47.000000 2025]"
  timestamp=$(sed -E "s/ ([0-9]{4})$/.\${us} \1/" <<<"$ts" | sed "s/\${us}/$us/")

  # 2) Connection info
  cip=$(jq -r '.transaction.client_ip' <<<"$json")
  cport=$(jq -r '.transaction.client_port' <<<"$json")

  # 3) Host, URI, txid
  host=$(jq -r '.transaction.request.headers.Host // "localhost"' <<<"$json")
  uri=$(jq -r '.transaction.request.uri' <<<"$json")
  txid=$(jq -r '.transaction.unique_id' <<<"$json")

  # 4) ModSecurity core fields
  action="Warning."
  pattern=$(jq -r '.transaction.messages[0].details.match' <<<"$json")

  # 5) Extract variable (ARGS:...) from the `data` field
  data=$(jq -r '.transaction.messages[0].details.data' <<<"$json")
  atvar=$(jq -r '
    .transaction.messages[0].details.data
    | capture("within ([^:]+):")
    | .[0]
    // "UNKNOWN"
  ' <<<"$json")

  # 6) IDs, messages, rev, severity
  rid=$(jq -r '.transaction.messages[0].details.ruleId' <<<"$json")
  rev=$(jq -r '.transaction.messages[0].details.rev // ""' <<<"$json")
  msg=$(jq -r '.transaction.messages[0].message' <<<"$json")
  sev="CRITICAL"

  # 7) Emit in the working example format
  printf '[%s] [:error] [pid 0:tid 0] [client %s:%s] ModSecurity: %s Pattern match "%s" at %s. [id "%s"] [rev "%s"] [msg "%s"] [data "%s"] [severity "%s"] [hostname "%s"] [uri "%s"] [unique_id "%s"]\n' \
    "$timestamp" \
    "$cip" "$cport" \
    "$action" \
    "$pattern" "$atvar" \
    "$rid" "$rev" \
    "$msg" "$data" "$sev" \
    "$host" "$uri" "$txid" \
  >> "$OUTPUT"

done
