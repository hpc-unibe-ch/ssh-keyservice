# SSH Keyservice

A flask web app for centralised management of SSH Keys designed for OpenOnDemand environments.
Users manage their SSH keys via a web portal - similar to GitHub - instead of traditionally in `~/.ssh/authorised_keys`.
On servers connected to the keyservice, the `sshd` server performs an API query using `AuthorisedKeysCommand` to retrieve the keys stored by the user. The API returns a raw response in the same format as GitHub keys.

## Authentication

This application is designed to run in OpenOnDemand environments where authentication is handled externally by the OpenOnDemand platform. The application reads OIDC tokens from a file on the web server and uses them to authenticate API requests.

### Configuration

Set the following environment variables:

- `OIDC_TOKEN_PATH` - Path to the OIDC token file (default: `/var/run/secrets/oidc/token`)
- `API_BASE_URL` - Base URL for the backend API (default: `http://localhost:8000`)
- `FLASK_SECRET_KEY` - Flask secret key for session management (auto-generated if not set)

## Background
Traditionally, users generate an SSH key and transfer the public key to a server using `ssh-copy-id` or `scp`. This process usually only requires a password or an already stored key for authentication. This approach harbours some security risks:
- It does not ensure that users actually deposit their own key. Instead, they could consciously or unconsciously use the public key of a third party to share an account.
- If the file with the stored keys is inadvertently inadequately protected, third parties could add their own keys without authorisation and thus gain access.

This app is designed to address these problems. A secure web front end allows users to manage their SSH keys, while additional security mechanisms prevent misuse:
- Authentication is handled by OpenOnDemand platform with MFA support
- Challenge-response verification to ensure that users actually have the complete key pair (private and public key) before the key is accepted.

## Repositories
[ssh-keyservice-api](https://github.com/hpc-unibe-ch/ssh-keyservice-api) - Backend API
[ssh-keyservice (this repo)](https://github.com/hpc-unibe-ch/ssh-keyservice) - Frontend Webapp

