#!/bin/bash

echo "=== Testing Key Generation API ==="

echo -e "\n1. Generating keys without saving to .env:"
curl -s -X POST http://localhost:8080/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"save_to_env": false}' | jq .

echo -e "\n2. Generating keys and saving to .env:"
curl -s -X POST http://localhost:8080/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"save_to_env": true}' | jq .

echo -e "\n3. Checking current keys:"
curl -s http://localhost:8080/keys/current | jq .

echo -e "\n4. Checking configuration:"
curl -s http://localhost:8080/config | jq .