#!/usr/bin/env bash
# Bootstrap a local Stalwart v0.16 SMTP server for integration tests.
#
# Stalwart v0.16 dropped the REST `/api/principal` endpoint and the
# auto-provisioning script that v0.15 supported. This script does the
# equivalent over the new JMAP management surface (`urn:stalwart:jmap`),
# which is not yet documented but is what the new webadmin uses.
#
# Steps:
#   1. Write a minimal `config.json` (rocksdb data store only).
#   2. Start the container with `STALWART_RECOVERY_ADMIN=admin:test` so
#      a permanent admin exists from first boot (no bootstrap wizard).
#   3. Wait for `/.well-known/jmap` to respond, then resolve the
#      admin's JMAP account id.
#   4. Provision over JMAP `POST /jmap/`:
#        - x:Domain/set     create "pimalaya.org"
#        - x:Account/set    create test user so RCPT TO has a local
#          mailbox owner
#
# Host port mapping:
#   8080 → admin HTTP (JMAP + webadmin at /admin)
#   25   → plain SMTP (Stalwart's default `smtp` listener, MTA mode)
#
# Stalwart's default `smtp` listener at container port 25 is already
# plain (no TLS, no required auth), so unlike the io-imap script we
# don't need to flip any listener or enable plain-text auth. The
# integration test uses `Auth::None` and relies on MTA-mode delivery
# from 127.0.0.1 to a local mailbox.
#
# The user password is `P!malaya-test-2026`. Stalwart's password
# strength check rejects shorter / weaker secrets like `test`. The
# test itself never authenticates, so the password only exists to
# satisfy account creation.

set -eu

NAME="io-smtp-tests"
ADMIN_PASS="test"
SMTP_PASS='P!malaya-test-2026'
ADMIN_PORT=8080
SMTP_HOST_PORT=25
IMAGE="stalwartlabs/stalwart:v0.16-alpine"

CONFIG=$(mktemp)
trap 'rm -f "$CONFIG"' EXIT
printf '{"@type":"RocksDb","path":"/var/lib/stalwart/data"}\n' > "$CONFIG"
# mktemp defaults to mode 600; the stalwart UID inside the container
# needs read access on the bind-mounted config.
chmod 644 "$CONFIG"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --rm \
    -e "STALWART_RECOVERY_ADMIN=admin:${ADMIN_PASS}" \
    -v "${CONFIG}:/etc/stalwart/config.json:ro" \
    -p "${ADMIN_PORT}:8080" \
    -p "${SMTP_HOST_PORT}:25" \
    "$IMAGE" >/dev/null

# Wait for the admin HTTP listener.
for _ in $(seq 1 30); do
    if curl -fsS -u "admin:${ADMIN_PASS}" \
        "http://localhost:${ADMIN_PORT}/.well-known/jmap" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Resolve admin's JMAP account id from the session document.
acc=$(curl -fsSL -u "admin:${ADMIN_PASS}" \
    "http://localhost:${ADMIN_PORT}/.well-known/jmap" |
    jq -r '.accounts | keys[0]')

# Batch: create domain + user.
curl -fsS -u "admin:${ADMIN_PASS}" \
    -H 'Content-Type: application/json' \
    -d "{
      \"using\":[\"urn:ietf:params:jmap:core\",\"urn:stalwart:jmap\"],
      \"methodCalls\":[
        [\"x:Domain/set\",
          {\"accountId\":\"$acc\",\"create\":{
            \"d1\":{\"name\":\"pimalaya.org\"}
          }},\"0\"],
        [\"x:Account/set\",
          {\"accountId\":\"$acc\",\"create\":{
            \"u1\":{
              \"@type\":\"User\",
              \"name\":\"test\",
              \"domainId\":\"#d1\",
              \"credentials\":{
                \"0\":{\"@type\":\"Password\",\"secret\":\"${SMTP_PASS}\"}
              }
            }
          }},\"1\"]
      ]
    }" \
    "http://localhost:${ADMIN_PORT}/jmap/" |
    jq -e '.methodResponses[] | .[1] | (.created // {}) | length > 0' >/dev/null

# Wait for the SMTP listener.
for _ in $(seq 1 30); do
    if (echo > /dev/tcp/127.0.0.1/${SMTP_HOST_PORT}) >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "stalwart ready: smtp://test@pimalaya.org@127.0.0.1:${SMTP_HOST_PORT}"
