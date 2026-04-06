#!/usr/bin/env bash

set -eu

docker run -d --name io-smtp-tests --rm -p 8080:8080 -p 25:25 stalwartlabs/stalwart:v0.15.5-alpine

sleep 2
admin_password=$(docker logs io-smtp-tests 2>&1 | grep -oP "(?<=with password ')[^']+")

curl -X POST \
     -u "admin:${admin_password}" \
     -H 'Content-Type: application/json' \
     -d '{"type":"domain","name":"pimalaya.org"}' \
     http://localhost:8080/api/principal

curl -X POST \
     -u "admin:${admin_password}" \
     -H 'Content-Type: application/json' \
     -d '{"type":"individual","name":"test","emails":["test@pimalaya.org"],"secrets":["test"],"roles":["user"]}' \
     http://localhost:8080/api/principal
