FROM node:22-slim
# SPEC.md §0.3: patch OS packages and npm's own vendored deps at build time
# rather than trusting the base image tag to have been rebuilt recently.
# node:20-slim's bundled npm can't self-update past its own engine
# constraint, hence 22 (still a current LTS) rather than staying on 20.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@latest \
    && npm pack brace-expansion@latest --pack-destination /tmp \
    && find /usr/local/lib/node_modules/npm -type d -name brace-expansion | while read -r d; do \
         rm -rf "$d" && mkdir -p "$d" && tar -xzf /tmp/brace-expansion-*.tgz -C "$d" --strip-components=1; \
       done \
    && rm -f /tmp/brace-expansion-*.tgz
WORKDIR /app
COPY server.js .
EXPOSE 3000
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD node -e "require('http').get('http://localhost:3000/health', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"
CMD ["node", "server.js"]
