# Published to ghcr.io/secfoo-com/secfoo by .github/workflows/release.yml.
# Installs from PyPI rather than PyInstaller-bundling -- simplest, most
# robust route for a container image, since there's no cross-platform
# concern (the image itself is the platform).
#
# Note: none of the 5 agent CLIs (claude, agent/cursor, agy, gemini, codex) are
# installed in this image, and none of their auth lives here either --
# `secfoo run` needs one available on PATH inside the container (e.g. via
# a custom image built FROM this one, or a volume mount) to actually
# execute a skill. Without that, this image is still useful standalone for
# `secfoo serve` / `secfoo list` / `secfoo show` against a mounted
# ~/.secfoo store from a host-run assessment.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# git is required for --target <github-url> (secfoo shells out to
# `git clone --depth 1`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# The release workflow passes the version it just published, so the image
# tagged X.Y.Z really contains secfoo X.Y.Z -- an unpinned install could pick
# up the previous release while PyPI's index catches up. Retries cover that
# lag; a local `docker build .` without the arg installs the latest release.
ARG SECFOO_VERSION=
RUN for attempt in 1 2 3 4 5 6; do \
      pip install --no-cache-dir "secfoo${SECFOO_VERSION:+==${SECFOO_VERSION}}" && break; \
      [ "$attempt" = 6 ] && exit 1; sleep 20; \
    done \
    && secfoo --version

WORKDIR /workspace

ENTRYPOINT ["secfoo"]
CMD ["--help"]
