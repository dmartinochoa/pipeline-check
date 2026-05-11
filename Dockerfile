# syntax=docker/dockerfile:1.7
#
# Container image for the pipeline-check CLI. Multi-stage so the
# runtime layer only carries the installed wheel plus its deps. No
# build toolchain, source tree, or pip cache lingers in the final
# layer.
#
# Base ``python:3.12-slim`` is a tag (not a digest) so Dependabot /
# Renovate can offer digest pins on a regular cadence. The
# pipeline-check rule DF-001 flags floating tags in user Dockerfiles;
# this repo's own image is acceptable here because the published
# manifest is itself addressable by digest from each registry.

FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY pipeline_check ./pipeline_check
RUN pip install --no-cache-dir --upgrade pip build \
 && python -m build --wheel --outdir /wheels

FROM python:3.12-slim AS runtime
RUN useradd --create-home --uid 1000 scanner
COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
 && rm -rf /tmp/*.whl /root/.cache
USER scanner
WORKDIR /scan
ENTRYPOINT ["pipeline_check"]
CMD ["--help"]
