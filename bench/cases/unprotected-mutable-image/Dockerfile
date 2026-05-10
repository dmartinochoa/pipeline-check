# DF-001: floating-tag base image. The build pulls whatever the
# upstream registry currently serves under ``ubuntu:22.04``.
# Combined with SCM-001 (no protection rule on the default
# branch), an insider can land a tampered ``FROM`` reference
# change with no review gate, AND every subsequent build
# inherits whatever bytes the upstream registry currently
# serves. Two unrelated trust boundaries open at once.
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3
COPY app.py /app/
CMD ["python3", "/app/app.py"]
