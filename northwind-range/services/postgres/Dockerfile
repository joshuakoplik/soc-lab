# SPEC.md §0.3: the upstream image vendors gosu (privilege-drop helper) as a
# standalone Go binary, not an apt package -- `apt-get upgrade` can't patch
# it, and the project's own latest release (1.19) was itself compiled with
# an already-vulnerable Go stdlib (go1.24.6). Build it from source against a
# current Go toolchain instead, so the fix comes from the compiler, not from
# waiting on tianon/gosu to cut a new release. This stage never ships in the
# final image, so its own base image freshness doesn't factor into the scan.
FROM golang:1-bookworm AS gosu-build
RUN GOBIN=/out go install github.com/tianon/gosu@1.19

FROM pgvector/pgvector:pg16
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=gosu-build /out/gosu /usr/local/bin/gosu
COPY init/ /docker-entrypoint-initdb.d/
COPY entrypoint.sh /usr/local/bin/nw-entrypoint.sh
RUN chmod +x /usr/local/bin/nw-entrypoint.sh
ENTRYPOINT ["nw-entrypoint.sh"]
CMD ["postgres"]
