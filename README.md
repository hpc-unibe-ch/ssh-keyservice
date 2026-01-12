# SSH Keyservice

A flask web app for centralised management of SSH Keys protected through OpenID Connect.
Users manage their SSH keys via a web portal - similar to GitHub - instead of traditionally in `~/.ssh/authorised_keys`.
On servers connected to the keyservice, the `sshd` server performs an API query using `AuthorisedKeysCommand` to retrieve the keys stored by the user. The API returns a raw response in the same format as GitHub keys.

## Authentication Modes

This application supports two authentication modes:

1. **Azure OIDC Mode** (default) - Uses Microsoft Azure Active Directory for authentication
2. **OpenOnDemand Mode** - Uses pre-authenticated OIDC tokens from files (for OpenOnDemand environments)

See [OPENONDEMAND.md](OPENONDEMAND.md) for detailed configuration instructions for running in OpenOnDemand environments.

## Background
Traditionally, users generate an SSH key and transfer the public key to a server using `ssh-copy-id` or `scp`. This process usually only requires a password or an already stored key for authentication. This approach harbours some security risks:
- It does not ensure that users actually deposit their own key. Instead, they could consciously or unconsciously use the public key of a third party to share an account.
- If the file with the stored keys is inadvertently inadequately protected, third parties could add their own keys without authorisation and thus gain access.

This app is designed to address these problems. A secure web front end allows users to manage their SSH keys, while additional security mechanisms prevent misuse:
- Possibility to enforce multi-factor authentication (MFA) when accessing the keyservice frontend. This significantly increases security.
- Challenge-response verification to ensure that users actually have the complete key pair (private and public key) before the key is accepted.

## Repositories
[ssh-keyservice-api](https://github.com/hpc-unibe-ch/ssh-keyservice-api) - Backend API
[ssh-keyservice (this repo)](https://github.com/hpc-unibe-ch/ssh-keyservice) - Frontend Webapp

