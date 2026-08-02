FROM nginx:1.27-alpine
# SPEC.md §0.3: patch OS packages at build time rather than trusting the
# base image tag to have been rebuilt recently.
RUN apk update && apk upgrade --no-cache
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD wget -q --spider http://127.0.0.1/health || exit 1
