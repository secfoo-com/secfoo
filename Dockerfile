# Published to ghcr.io/rakfortltd/secfoo by .github/workflows/release.yml.
# Installs from PyPI rather than PyInstaller-bundling -- simplest, most
# robust route for a container image, since there's no cross-platform
# concern (the image itself is the platform).
#
# Note: none of the 4 agent CLIs (claude, agent/cursor, agy, gemini) are
# installed in this image, and none of their auth lives here either --
# `secfoo run` needs one available on PATH inside the container (e.g. via
# a custom image built FROM this one, or a volume mount) to actually
# execute a skill. Without that, this image is still useful standalone for
# `secfoo serve` / `secfoo list` / `secfoo show` against a mounted
# ~/.secfoo store from a host-run assessment.
FROM python:3.12-slim

# git is required for --target <github-url> (secfoo shells out to
# `git clone --depth 1`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir secfoo

WORKDIR /workspace

ENTRYPOINT ["secfoo"]
CMD ["--help"]
