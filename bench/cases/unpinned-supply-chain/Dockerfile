# DF-001: floating-tag base image. The build pulls whatever the
# upstream registry currently serves under ``python:3.12``; an
# upstream-account compromise on the python image propagates to
# the team's next build automatically.
FROM python:3.12

# DF-002: image runs as root by default (no USER directive). Any
# in-container RCE collapses straight to the host kernel via the
# CVE-2019-5736 / CVE-2022-0492 escape paths the rule cites.
RUN apt-get update && apt-get install -y python3-pip
COPY app.py /app/
CMD ["python3", "/app/app.py"]
