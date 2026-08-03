FROM nginx:1.27-alpine
# SPEC.md §0.3: patch OS packages at build time rather than trusting the
# base image tag to have been rebuilt recently.
# iptables: operator-requested Tailscale port publish requires dual-homing
# onto nw_ops (non-internal) -- see entrypoint.sh for the egress lockdown
# that keeps that dual-homing from becoming a real hole (SPEC.md §0.2).
RUN apk update && apk upgrade --no-cache && apk add --no-cache iptables
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /usr/local/bin/nw-entrypoint.sh
RUN chmod +x /usr/local/bin/nw-entrypoint.sh
EXPOSE 80
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD wget -q --spider http://127.0.0.1/health || exit 1
ENTRYPOINT ["nw-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
