#!/bin/sh
# enable any remaining modules (idempotent)
filebeat modules enable suricata

# register ingest pipelines & templates now that /etc/ssl/* is mounted
filebeat setup \
  --pipelines \
  --modules suricata

# finally, start Filebeat in foreground
exec filebeat -e -strict.perms=false \
  -c /usr/share/filebeat/filebeat.yml

