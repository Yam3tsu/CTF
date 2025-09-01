FROM ghcr.io/madrhacks/jail:latest

COPY --from=python:3.9.23-bookworm@sha256:754dbbaf5fe730bb2460efb3300293c62c222f74fbf8534ed23691c617c9609b / /srv

WORKDIR /srv/app
COPY chall chall
COPY wrapper.py run

ENV ENV_PYTHONUNBUFFERED=1
ENV ENV_PYTHONDONTWRITEBYTECODE=1

ENV ENV_PWD=/app
ENV ENV_PATH=/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV ENV_USER=root

ENV JAIL_MEM=10M