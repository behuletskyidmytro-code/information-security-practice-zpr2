#!/usr/bin/env bash
set -euo pipefail
mkdir -p nginx/certs
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx/certs/selfsigned.key -out nginx/certs/selfsigned.crt -subj '/C=UA/O=University/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
