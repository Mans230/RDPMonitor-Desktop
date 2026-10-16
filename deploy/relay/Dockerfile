FROM python:3.13.7-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY relay/requirements.txt /app/relay-requirements.txt
RUN pip install --no-cache-dir -r /app/relay-requirements.txt \
    && groupadd --gid 10001 relay \
    && useradd --uid 10001 --gid relay --no-create-home --shell /usr/sbin/nologin relay \
    && mkdir /data && chown relay:relay /data
COPY --chown=relay:relay relay /app/relay
USER 10001:10001
EXPOSE 8765
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "relay"]
CMD ["--host", "0.0.0.0", "--port", "8765", "--database", "/data/relay.sqlite3", "--trusted-proxy", "172.30.0.2"]
