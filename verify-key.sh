#!/bin/bash

# Ensure we have both the challenge and the private key file as inputs
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <challenge> <private_key_path>"
    exit 1
fi

challenge="$1"
private_key_path="$2"

# Check if the private key exists
if [ ! -f "$private_key_path" ]; then
    echo "Private key file not found: $private_key_path"
    exit 1
fi

# Sign the challenge with the private key using ssh-keygen
response=$(echo -n "$challenge" | ssh-keygen -Y sign -f "$private_key_path" -n ssh-connection)

# Check if signing was successful
if [ $? -ne 0 ]; then
    echo "Error signing the challenge with the private key"
    exit 1
fi

# Output the response
echo "$response"
