FROM docker.elastic.co/beats/filebeat:8.8.2

COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# Bring in entrypoint
COPY entrypoint.sh /usr/local/bin/docker-entrypoint

# enable module at build
RUN filebeat modules enable suricata

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
