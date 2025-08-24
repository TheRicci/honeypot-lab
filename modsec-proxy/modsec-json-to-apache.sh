#!/usr/bin/env bash
INPUT=/var/log/nginx/modsec_audit.jsonl
OUTPUT=/var/log/nginx/modsec_error.log
touch "$OUTPUT"

tail -n0 -F "$INPUT" | while IFS= read -r json; do
  # Timestamp
  ts=$(jq -r '.transaction.time_stamp' <<<"$json")
  us=$(jq -r '.transaction.time_stamp_ms // "000000"' <<<"$json")
  timestamp=$(printf '%s.%s %s' "${ts% *}" "$us" "${ts##* }")

  # Conn info
  cip=$(jq -r '.transaction.client_ip' <<<"$json")
  cport=$(jq -r '.transaction.client_port' <<<"$json")

  # Host, URI, txid
  host=$(jq -r '.transaction.request.headers.Host // "localhost"' <<<"$json")
  uri=$(jq -r '.transaction.request.uri' <<<"$json")
  txid=$(jq -r '.transaction.unique_id' <<<"$json")

  # Msg details
  match=$(jq -r '.transaction.messages[0].details.match' <<<"$json")
  file=$(jq -r '.transaction.messages[0].details.file' <<<"$json")
  line=$(jq -r '.transaction.messages[0].details.lineNumber' <<<"$json")
  rid=$(jq -r '.transaction.messages[0].details.ruleId' <<<"$json")
  rev=$(jq -r '.transaction.messages[0].details.rev // ""' <<<"$json")
  msg=$(jq -r '.transaction.messages[0].message' <<<"$json")
  data=$(jq -r '.transaction.messages[0].details.data' <<<"$json")

  # Always use Warning for XSS
  action="Warning."

  # Extract the variable (ARGS:q) from data
  atvar=$(sed -n 's/.*within \([^:]*\):.*/\1/p' <<<"$data")
  atvar=${atvar:-ARGS:unknown}

  # Severity text (unused here)
  sev="CRITICAL"

  # Emit
  printf '[%s] [:error] [pid 0:tid 0] [client %s:%s] ModSecurity: %s %s at %s. [id "%s"] [rev "%s"] [msg "%s"] [data "%s"] [severity "%s"] [hostname "%s"] [uri "%s"] [unique_id "%s"]\n' \
    "$timestamp" "$cip" "$cport" \
    "$action" "$match" "$atvar" \
    "$rid" "$rev" "$msg" "$data" "$sev" \
    "$host" "$uri" "$txid" \
  >> "$OUTPUT"
done
