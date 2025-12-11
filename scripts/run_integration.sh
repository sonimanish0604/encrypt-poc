#!/usr/bin/env bash
set -euo pipefail

COMPOSE="docker compose"
CURL_IMAGE="curlimages/curl:8.6.0"

cleanup() {
  $COMPOSE down -v
}
trap cleanup EXIT

echo "Ensuring clean slate..."
$COMPOSE down -v >/dev/null 2>&1 || true

echo "Building and starting stack..."
$COMPOSE up -d --build

echo "Pulling curl image for network requests..."
docker pull "$CURL_IMAGE" >/dev/null

curl_in_net() {
  docker run --rm --network encrypt-poc_default "$CURL_IMAGE" "$@"
}

echo "Waiting for API to become ready..."
for attempt in $(seq 1 60); do
  if curl_in_net -s --fail http://api:8000/ >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [[ $attempt -eq 60 ]]; then
    echo "API did not become ready in time" >&2
    docker logs enc_api || true
    exit 1
  fi
done

PAYLOAD='{"first_name":"Alice","middle_name":"M","last_name":"Doe","phone":"+15551234567","email":"alice@example.com","phone_dnc":true,"email_dnc":false}'
echo "Submitting sample payload..."
if ! curl_in_net -s --fail -X POST http://api:8000/submit \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" | grep -q '"status":"ok"'; then
  echo "API submission failed" >&2
  docker logs enc_api || true
  exit 1
fi

echo "Verifying encrypted data stored in MySQL..."
ROW_HEX=$(docker exec enc_mysql mysql -uroot -prootpassword -N -e "USE enc_poc; SELECT HEX(first_name_enc), HEX(email_enc) FROM contact_form ORDER BY id DESC LIMIT 1;")
if [[ -z "$ROW_HEX" ]]; then
  echo "No encrypted rows found in contact_form" >&2
  exit 1
fi
echo "Encrypted fields (hex): $ROW_HEX"

echo "Fetching wrapped DEK from MySQL..."
DEK_WRAPPED=$(docker exec enc_mysql mysql -uroot -prootpassword -N -e "USE enc_poc; SELECT dek_wrapped FROM encryption_keys ORDER BY id DESC LIMIT 1;")
if [[ -z "$DEK_WRAPPED" ]]; then
  echo "No wrapped DEK found in encryption_keys" >&2
  exit 1
fi

echo "Calling Vault Transit to unwrap DEK..."
VAULT_RESPONSE=$(curl_in_net -s --fail -X POST http://vault:8200/v1/transit/decrypt/pii-master \
  -H "X-Vault-Token: root" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext\":\"$DEK_WRAPPED\"}")
echo "$VAULT_RESPONSE" | python3 -c 'import json,sys; data=json.load(sys.stdin); sys.exit(0 if data.get("data", {}).get("plaintext") else 1)'

echo "Running ETL decryption job..."
ETL_OUTPUT=$($COMPOSE run --rm api python etl.py)
echo "$ETL_OUTPUT"
echo "$ETL_OUTPUT" | grep -q "First Name: Alice"

echo "Integration test completed successfully."
