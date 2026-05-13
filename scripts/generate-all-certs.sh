#!/bin/sh
set -e

CERT_DIR="/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

if [ ! -f ca.crt ]; then
    echo "Generating Root CA..."
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=Polyglot Root CA"
fi

if [ ! -f server.crt ]; then
    echo "Generating server certificate for nginx..."
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr -subj "/CN=nginx"
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
    rm -f server.csr
fi

if [ ! -f client.crt ]; then
    echo "Generating client certificate for gateway..."
    openssl genrsa -out client.key 2048
    openssl req -new -key client.key -out client.csr -subj "/CN=gateway"
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
    rm -f client.csr
fi

echo "All certificates are ready."
