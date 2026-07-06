# nginxwatch — minimal Lua runtime image.
FROM nickblah/lua:5.4-slim

LABEL org.opencontainers.image.title="nginxwatch" \
      org.opencontainers.image.description="nginx/Apache access-log watcher & anomaly detector" \
      org.opencontainers.image.source="https://github.com/cognis-digital/nginxwatch" \
      org.opencontainers.image.licenses="LicenseRef-COCL-1.0"

WORKDIR /app
COPY nginxwatch.lua /app/nginxwatch.lua

# Read logs from stdin or mount them read-only, e.g.:
#   docker run --rm -i nginxwatch < /var/log/nginx/access.log
#   docker run --rm -v /var/log/nginx:/logs:ro nginxwatch /logs/access.log
ENTRYPOINT ["lua", "/app/nginxwatch.lua"]
CMD ["-"]
