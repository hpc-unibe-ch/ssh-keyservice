#!/bin/bash

# Function to display error messages and exit
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Validate the number of arguments
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    error_exit "Usage: verify_key.sh <challenge> [<private_key_path>]"
fi

# Print all arguments
echo "All arguments: $@"

challenge="$1"
private_key_path=""

# Determine the private key path
if [ "$#" -eq 2 ]; then
    private_key_path="$2"
    # Check if the provided private key file exists
    if [ ! -f "$private_key_path" ]; then
        error_exit "Specified private key file not found: $private_key_path"
    fi
else
    # Locate private key files in $HOME/.ssh
    if [ ! -d "$HOME/.ssh" ]; then
        error_exit "SSH directory not found: $HOME/.ssh"
    fi

    private_key_files=($(find "$HOME/.ssh" -maxdepth 1 -type f -name 'id_*' -not -name "*.pub"))
    private_key_count=$(find "$HOME/.ssh" -maxdepth 1 -type f -name 'id_*' | wc -l)

    # Add custom option to the list
    private_key_files+=("Custom")

    if [ "$private_key_count" -eq 0 ]; then
        error_exit "No private key files found in $HOME/.ssh"
    elif [ "$private_key_count" -eq 1 ]; then
        private_key_path="${private_key_files[0]}"
    else
        echo "Multiple private key files found in $HOME/.ssh. Please select one:" >&2
        select file in "${private_key_files[@]}"; do
            if [ -n "$file" ]; then
                if [ "$file" == "Custom" ]; then
                    read -e -p "Enter the path to the private key file: " file
                    private_key_path="$file"
                else
                    private_key_path="$file"
                fi
                break
            else
                echo "Invalid selection. Try again." >&2
            fi
        done
    fi
fi

# Validate the selected private key file
if [ ! -f "$private_key_path" ]; then
    error_exit "Private key file not found after validation: $private_key_path"
fi

# Sign the challenge using ssh-keygen
response=$(echo -n "$challenge" | ssh-keygen -Y sign -f "$private_key_path" -n ssh-connection 2>/dev/null)
if [ $? -ne 0 ]; then
    error_exit "Failed to sign the challenge with the private key"
fi

# Output the signed response
echo "$response"
