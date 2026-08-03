# SPEC.md §4: llm-backend is a narrow-egress reverse proxy to an
# operator-controlled remote Ollama host, not a local model server -- see
# SPEC.md §0.1's documented exception and entrypoint.sh for the mechanism.
FROM nginx:1.27-alpine
RUN apk update && apk upgrade --no-cache && apk add --no-cache iptables
COPY default.conf.template /etc/nginx/templates/default.conf.template
COPY entrypoint.sh /usr/local/bin/nw-entrypoint.sh
RUN chmod +x /usr/local/bin/nw-entrypoint.sh
EXPOSE 11434
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD wget -q --spider http://127.0.0.1:11434/api/tags || exit 1
ENTRYPOINT ["nw-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
