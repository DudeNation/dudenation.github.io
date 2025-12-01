#!/bin/bash
# Generate SHA-256 hash for password protection
# Usage: bash tools/generate-password-hash.sh "your-password"

if [ -z "$1" ]; then
    echo "Usage: bash tools/generate-password-hash.sh \"your-password\""
    exit 1
fi

PASSWORD="$1"

# Generate SHA-256 hash using openssl
HASH=$(echo -n "$PASSWORD" | openssl dgst -sha256 | awk '{print $2}')

echo "Password: $PASSWORD"
echo "SHA-256 Hash: $HASH"
echo ""
echo "Add this to your post front matter:"
echo "password: $HASH"