# Multi-stage build -- standard Next.js Docker pattern. output:'standalone'
# (next.config.js) means the runner stage ships a self-contained server
# bundle, not the full dev toolchain/node_modules tree.
FROM node:22-slim AS deps
WORKDIR /app
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY package.json .
RUN npm install

FROM node:22-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-slim AS runner
WORKDIR /app
# SPEC.md §0.3: patch OS packages at build time rather than trusting the
# base image tag to have been rebuilt recently -- same discipline as
# every other image in this range.
# npm ships bundled with the node base image, vendoring its own
# node_modules (tar/brace-expansion/picomatch/sigstore etc.) independent
# of this project's own dependencies -- apt upgrade doesn't touch it, and
# it's not reachable via this package.json's "overrides" since it isn't
# part of our dependency tree at all. Same fix as chat-web's own
# milestone-1 Dockerfile used for this exact category of finding.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@latest \
    && npm pack brace-expansion@latest --pack-destination /tmp \
    && find /usr/local/lib/node_modules/npm -type d -name brace-expansion | while read -r d; do \
         rm -rf "$d" && mkdir -p "$d" && tar -xzf /tmp/brace-expansion-*.tgz -C "$d" --strip-components=1; \
       done \
    && rm -f /tmp/brace-expansion-*.tgz
ENV NODE_ENV=production
# Next.js's standalone server.js binds to process.env.HOSTNAME, which
# Docker sets to the container ID by default -- without this override it
# only listens on the container's own IP, never 127.0.0.1/localhost,
# breaking both this Dockerfile's own HEALTHCHECK and (less obviously)
# anything reaching it in ways that resolve to a different address.
ENV HOSTNAME="0.0.0.0"
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD node -e "require('http').get('http://localhost:3000/health', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"
CMD ["node", "server.js"]
