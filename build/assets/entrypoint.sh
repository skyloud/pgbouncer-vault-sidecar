#!/bin/sh
set -e

# This script is designed to control a pgbouncer instance with Vault Database credentials for a PostgreSQL database.
export VAULT_ADDR=${VAULT_ADDR:-"http://localhost:8200"}
VAULT_KUBERNETES_ROLE=${VAULT_KUBERNETES_ROLE:-"default"}
VAULT_PATH=${VAULT_PATH:-"db/creds/default"}

DB_NAME=${DB_NAME:-"postgres"}
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"5432"}
PGBOUNCER_LISTEN_PORT=${PGBOUNCER_LISTEN_PORT:-"5432"}
PGBOUNCER_LISTEN_ADDR=${PGBOUNCER_LISTEN_ADDR:-"127.0.0.1"}

SECRET_CHECK_INTERVAL=${SECRET_CHECK_INTERVAL:-"15"} # 10 min by default (⚠️ don't set this too low, but must be lower than the secret TTL)

VAULT_VALUE=

# Handle command error
on_error() {
    echo "Error on line $1"
    exit 1
}

trap 'on_error $LINENO' ERR

export VAULT_TOKEN_PATH=${VAULT_TOKEN_PATH:-"/tmp/vault-token"}

_get_vault_token() {
    vault write auth/kubernetes/login role=$VAULT_KUBERNETES_ROLE jwt=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) -address=$VAULT_ADDR -format=json | jq -r ".auth.client_token"
    if [ $? -ne 0 ]; then
        echo "Failed to authenticate against Vault"
        exit 1
    fi
}

echo Authenticating against Vault

export VAULT_TOKEN=$(_get_vault_token)
echo $VAULT_TOKEN > $VAULT_TOKEN_PATH

refresh_vault_token() {
    export VAULT_TOKEN=$(cat $VAULT_TOKEN_PATH)
    # If the token is expired, refresh it
    vault token lookup -format=json > /dev/null
    if [ $? -ne 0 ]; then
        echo "Token expired, refreshing" > /dev/stderr
        export VAULT_TOKEN=$(_get_vault_token)
        echo $VAULT_TOKEN > $VAULT_TOKEN_PATH
    fi
}

DATABASE_CREDS_PATH=${DATABASE_CREDS_PATH:-"/tmp/database_creds.json"}
LEASE_ID_PATH=${LEASE_ID_PATH:-"/tmp/lease_id"}

export DATABASE_CREDS=$(vault read -address=$VAULT_ADDR -format=json $VAULT_PATH)
echo $DATABASE_CREDS > $DATABASE_CREDS_PATH
NOW=$(date +%s)
EXPIRATION=$(echo $DATABASE_CREDS | jq -r '.lease_duration') # in seconds
EXPIRATION=$(($NOW + $EXPIRATION))
EXPIRATION=$(($EXPIRATION - $SECRET_CHECK_INTERVAL)) # subtract the interval to be sure the secret is refreshed before it expires
EXPIRATION=$(($EXPIRATION - 5)) # subtract 5 seconds to be sure the secret is refreshed before it expires
export SECRET_VERSION=$(echo $DATABASE_CREDS | jq -r '.lease_id')
echo $SECRET_VERSION > $LEASE_ID_PATH

load_vault_secret() {
    refresh_vault_token
    export VAULT_TOKEN=$(cat $VAULT_TOKEN_PATH)
    export DATABASE_CREDS=$(vault read -format=json $VAULT_PATH)
    echo $DATABASE_CREDS > $DATABASE_CREDS_PATH
    NOW=$(date +%s)
    EXPIRATION=$(echo $DATABASE_CREDS | jq -r '.lease_duration') # in seconds
    EXPIRATION=$(($NOW + $EXPIRATION))
    EXPIRATION=$(($EXPIRATION - $SECRET_CHECK_INTERVAL)) # subtract the interval to be sure the secret is refreshed before it expires
    EXPIRATION=$(($EXPIRATION - 5)) # subtract 5 seconds to be sure the secret is refreshed before it expires
    export SECRET_VERSION=$(echo $DATABASE_CREDS | jq -r '.lease_id')
    echo $SECRET_VERSION > $LEASE_ID_PATH
}

renew_vault_secret() {
    refresh_vault_token
    export VAULT_TOKEN=$(cat $VAULT_TOKEN_PATH)
    
    LEASE_ID=$(cat $LEASE_ID_PATH)

    if [ -z "$LEASE_ID" ]; then
        echo "No lease ID found. Exiting..." > /dev/stderr
        exit 1
    fi
    RENEW=$(vault lease renew $LEASE_ID)
    if [ $? -ne 0 ]; then
        EXPIRATION=0
        echo "Failed to renew the lease" > /dev/stderr
        echo "Renew output: $RENEW" > /dev/stderr
        echo "Reloading the secret..." > /dev/stderr
        load_vault_secret
    else
        EXPIRATION=$(date +%s)
        EXPIRATION=$(($EXPIRATION + $(echo $DATABASE_CREDS | jq -r '.lease_duration')))
        EXPIRATION=$(($EXPIRATION - $SECRET_CHECK_INTERVAL)) # subtract the interval to be sure the secret is refreshed before it expires
        EXPIRATION=$(($EXPIRATION - 5)) # subtract 5 seconds to be sure the secret is refreshed before it expires
        echo "Lease renewed successfully" > /dev/stderr
    fi
}

get_secret_version() {
    renew_vault_secret
    # If EXPIRATION is less than the current time, the secret is expired
    if [ -z "$EXPIRATION" ] || [ $EXPIRATION -lt $(date +%s) ]; then
        load_vault_secret
    fi
    echo $DATABASE_CREDS | jq -r '.lease_id'
}

write_pgbouncer_ini() {
    DATABASE_CREDS=$(cat $DATABASE_CREDS_PATH)
    if [ -z "$DATABASE_CREDS" ]; then
        echo "No database credentials found. Exiting..." > /dev/stderr
        exit 1
    fi
    local USERNAME=$(echo $DATABASE_CREDS | jq -r '.data.username')
    local PASSWORD=$(echo $DATABASE_CREDS | jq -r '.data.password')
    cat <<EOF > /etc/pgbouncer/pgbouncer.ini
[databases]
${DB_NAME} = host=${DB_HOST} port=${DB_PORT} dbname=${DB_NAME} user=${USERNAME} password=${PASSWORD}

[pgbouncer]
listen_port = ${PGBOUNCER_LISTEN_PORT}
listen_addr = ${PGBOUNCER_LISTEN_ADDR}
auth_type = any
admin_users = app_admin
pool_mode = session
max_client_conn = 500
default_pool_size = 20
server_tls_sslmode = require
logfile = /var/log/pgbouncer/pgbouncer.log
pidfile = /var/run/pgbouncer/pgbouncer.pid
min_pool_size = 2
reserve_pool_size = 0
server_tls_sslmode = ${TLS_MODE:-"prefer"}
server_tls_ca_file = ${TLS_CA_FILE:-"/etc/ssl/certs/ca-certificates.crt"}
# some Java libraries set this extra_float_digits implicitly: https://github.com/Athou/commafeed/issues/559
ignore_startup_parameters = extra_float_digits,search_path
EOF
}

PGBOUNCER_PID=
MONITOR_PID=

monitor_pgbouncer() {
    PARENT_PID=$1
    PGBOUNCER_PID=$2
    echo "Monitoring pgbouncer... (parent PID: ${PARENT_PID}, pgbouncer PID: ${PGBOUNCER_PID})"
    trap "exit 0" SIGTERM SIGINT
    while true; do
        if ! is_pgbouncer_running; then
            echo "pgbouncer is not running. Exiting..."
            kill -s 2 ${PARENT_PID}
            exit 1
        fi
        sleep 1 &
        wait $!
    done
}

is_pgbouncer_running() {
    if [ -n "${PGBOUNCER_PID}" ]; then
        if ps -p ${PGBOUNCER_PID} > /dev/null; then
            return 0
        fi
    fi
    return 1
}

start_pgbouncer() {
    if is_pgbouncer_running; then
        echo "Reloading pgbouncer..."
        pkill -HUP pgbouncer
    else
        echo "Starting pgbouncer..."
        pgbouncer -R /etc/pgbouncer/pgbouncer.ini &
        PGBOUNCER_PID=$!
        echo "pgbouncer started with PID ${PGBOUNCER_PID}"
        monitor_pgbouncer $$ $PGBOUNCER_PID &
        MONITOR_PID=$!
    fi
}

shut_down() {
    echo "Shutting down..."
    MUST_STOP=true
    if ps -p ${MONITOR_PID} > /dev/null; then
        echo "Stopping monitor..."
        kill -s 2 ${MONITOR_PID} || true
    fi
    if ps -p ${PGBOUNCER_PID} > /dev/null; then
        echo "Stopping pgbouncer..."
        kill -s 2 ${PGBOUNCER_PID} || true
        wait ${PGBOUNCER_PID} > /dev/null 2>&1 || true
    fi
    exit 0
}

force_reload() {
    EXPIRATION=0
    echo "Forcing reload... (current: ${SECRET_VERSION})"
    SECRET_VERSION=$(get_secret_version)
    echo "New version: ${SECRET_VERSION}"
    write_pgbouncer_ini
    start_pgbouncer
}

MUST_STOP=false
trap shut_down SIGTERM SIGINT
trap force_reload SIGUSR1

write_pgbouncer_ini
start_pgbouncer

while ! ${MUST_STOP}; do
    SECRET_VERSION=$(cat $LEASE_ID_PATH)
    echo "Checking for new secret version... (current: ${SECRET_VERSION})"
    if [ "${SECRET_VERSION}" != "$(get_secret_version)" ]; then
        echo "New secret version detected. Updating pgbouncer configuration..."
        write_pgbouncer_ini
        start_pgbouncer
        SECRET_VERSION=$(cat $LEASE_ID_PATH)
    fi
    echo "Waiting for the next secret version... (interval: ${SECRET_CHECK_INTERVAL}, current: ${SECRET_VERSION})"
    sleep ${SECRET_CHECK_INTERVAL} &
    wait $!
done
