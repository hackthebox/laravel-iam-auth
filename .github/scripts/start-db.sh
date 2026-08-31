#!/usr/bin/env bash
#
# Starts a database container for the driver-shapes job and exports the settings
# tests/Integration/DriverErrorShapeTest.php reads.
#
# For PostgreSQL it also maps one dedicated role to PAM authentication, which is how
# RDS implements IAM auth. Auth then fails with the same "PAM authentication failed"
# wording RDS produces, so the classifier can be tested without an AWS account.
#
# Settings are written to $GITHUB_ENV so later steps inherit them. Run locally with
# `set -a; . <(PHP=/path/to/php ./start-db.sh postgres:17); set +a` to apply them to
# your own shell; $PHP overrides the interpreter used for the readiness probe.

set -euo pipefail

IMAGE="${1:?usage: start-db.sh <docker image>}"
NAME=iam-auth-driver-shapes
PASSWORD='c0rrect-h0rse'
PAM_USERNAME=pam_probe

docker rm -f "$NAME" >/dev/null 2>&1 || true

case "$IMAGE" in
    postgres:*)
        DRIVER=pgsql PORT=5432 DATABASE=postgres USERNAME=postgres
        docker run -d --name "$NAME" -e POSTGRES_PASSWORD="$PASSWORD" -p "$PORT:5432" "$IMAGE" >/dev/null
        ;;
    mysql:*)
        DRIVER=mysql PORT=3306 DATABASE=mysql USERNAME=root
        docker run -d --name "$NAME" -e MYSQL_ROOT_PASSWORD="$PASSWORD" -p "$PORT:3306" "$IMAGE" >/dev/null
        ;;
    mariadb:*)
        DRIVER=mariadb PORT=3306 DATABASE=mysql USERNAME=root
        docker run -d --name "$NAME" -e MARIADB_ROOT_PASSWORD="$PASSWORD" -p "$PORT:3306" "$IMAGE" >/dev/null
        ;;
    *)
        echo "start-db: unsupported image '$IMAGE'" >&2
        exit 2
        ;;
esac

# Readiness means "accepts an authenticated connection", which is the state the tests
# need, so probe with the same driver they use rather than an engine-specific client.
"${PHP:-php}" -r '
    [, $dsn, $user, $pass] = $argv;
    for ($i = 0; $i < 120; $i++) {
        try {
            new PDO($dsn, $user, $pass);
            exit(0);
        } catch (PDOException $e) {
            fwrite(STDERR, "waiting: ".$e->getMessage()."\n");
            sleep(2);
        }
    }
    fwrite(STDERR, "start-db: timed out waiting for the server\n");
    exit(1);
' "$([ "$DRIVER" = pgsql ] && echo pgsql || echo mysql):host=127.0.0.1;port=$PORT;dbname=$DATABASE" "$USERNAME" "$PASSWORD"

if [ "$DRIVER" = pgsql ]; then
    docker exec "$NAME" psql -U "$USERNAME" -q -c "create role $PAM_USERNAME login"
    HBA=$(docker exec "$NAME" psql -U "$USERNAME" -tAc 'show hba_file' | tr -d '\r')
    docker exec "$NAME" sh -c "printf 'host all $PAM_USERNAME 0.0.0.0/0 pam\n' | cat - '$HBA' > /tmp/hba && cp /tmp/hba '$HBA'"
    docker exec "$NAME" psql -U "$USERNAME" -q -c 'select pg_reload_conf()' >/dev/null

    # pg_reload_conf() reports success even when the postmaster rejected the file, and
    # an image built without --with-pam rejects it. Confirm the rule is actually live,
    # otherwise the PAM test would silently assert against a scram rejection instead.
    PAM_RULES=$(docker exec "$NAME" psql -U "$USERNAME" -tAc \
        "select count(*) from pg_hba_file_rules where auth_method = 'pam' and error is null" | tr -d '[:space:]')

    if [ "${PAM_RULES:-0}" -lt 1 ]; then
        echo "start-db: $IMAGE did not accept the pam pg_hba rule; is it built --with-pam?" >&2
        docker logs "$NAME" 2>&1 | tail -20 >&2
        exit 1
    fi
fi

{
    echo "IAM_AUTH_IT_DRIVER=$DRIVER"
    echo "IAM_AUTH_IT_HOST=127.0.0.1"
    echo "IAM_AUTH_IT_PORT=$PORT"
    echo "IAM_AUTH_IT_DATABASE=$DATABASE"
    echo "IAM_AUTH_IT_USERNAME=$USERNAME"
    echo "IAM_AUTH_IT_PASSWORD=$PASSWORD"
    if [ "$DRIVER" = pgsql ]; then
        echo "IAM_AUTH_IT_PAM_USERNAME=$PAM_USERNAME"
    fi
} | tee -a "${GITHUB_ENV:-/dev/null}"
