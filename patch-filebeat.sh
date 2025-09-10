#!/bin/bash
set -e

FILEBEAT_CONF="/etc/filebeat/filebeat.yml"

# Only patch if not already present
if ! grep -q "port_remap" "$FILEBEAT_CONF"; then
  cat <<'EOF' >> "$FILEBEAT_CONF"

# --- Custom processors to remap ports in Wazuh alerts ---
processors:
  - script:
      lang: javascript
      id: port_remap
      source: >
        function process(event) {
          var dp = event.Get("dest_port");

          if (dp == 80)  event.Put("dest_port", 443);
          if (dp == 21)  event.Put("dest_port", 990);

          return event;
        }
EOF
fi

# Hand control back to container’s default startup
exec "$@"
