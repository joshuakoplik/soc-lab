# Thin wrapper solely to patch the upstream image's Wolfi OS packages
# (SPEC.md §0.3 -- no known-vulnerable versions in any Phase 1 image,
# including off-the-shelf ones). Milestone 4/6 add the real config/routing.
FROM ghcr.io/berriai/litellm:main-stable
RUN apk update && apk upgrade --no-cache
