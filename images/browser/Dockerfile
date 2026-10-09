# Browser sandbox image: Chromium driven by Playwright, plus the worker and hostile test pages.
# Build from the REPO ROOT (the worker lives in the backend package):
#   docker build -f images/browser/Dockerfile -t minilocker-browser:latest .
#
# Everything is baked in: the running container needs no host mounts at all, which is one of the
# invariants the Attack Lab checks. Rebuild after changing the worker or the fixtures.
FROM python:3.12-slim-bookworm

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pin: the browser build is tied to the Playwright version.
RUN pip install playwright==1.63.0 \
 && playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* \
 && chmod -R a+rX /ms-playwright

COPY backend/minilocker/sandbox/browser_worker.py /opt/browser_worker.py
COPY images/browser/fixtures/ /fixtures/
RUN chmod -R a+rX /opt /fixtures

# The container is also started with --user 65534, read-only rootfs and no capabilities.
USER 65534:65534
WORKDIR /tmp
CMD ["python", "-u", "/opt/browser_worker.py", "serve"]
