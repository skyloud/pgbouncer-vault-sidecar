FROM docker.io/library/ubuntu:24.04

LABEL org.opencontainers.image.source=https://github.com/skyloud/pgbouncer-vault-sidecar
LABEL org.opencontainers.image.description="Credential management for your Postgres database connections! "
LABEL org.opencontainers.image.licenses=APACHE-2.0

# Install pgbouncer, bash, and jq
RUN apt-get update && apt-get install -y pgbouncer bash jq pipx curl unzip && apt-get clean

RUN mkdir /var/secrets/ -p
RUN cd /bin/ && \
    curl -sL https://releases.hashicorp.com/vault/1.18.2/vault_1.18.2_linux_$( \
        [ $(uname -m) = "x86_64" ] && echo "amd64" || echo "arm64" \
    ).zip > vault.zip && \
    unzip vault.zip && \
    rm vault.zip && \
    chmod +x /bin/vault && \
    rm -rf /bin/README.md
RUN vault version

COPY assets/entrypoint.sh /entrypoint.sh

# Add user and group for pgbouncer to run as with a home directory
RUN groupadd -r pgbouncer && useradd -r -g pgbouncer -d /home/pgbouncer pgbouncer \
    && mkdir -p /etc/pgbouncer /var/log/pgbouncer /var/run/pgbouncer \
    && chown -R pgbouncer:pgbouncer /etc/pgbouncer /var/log/pgbouncer /var/run/pgbouncer
USER pgbouncer
STOPSIGNAL SIGINT
# Set the script as the entrypoint
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
