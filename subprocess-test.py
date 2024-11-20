import subprocess

def verify_challenge_response(challenge, response, public_key):
    """
    Verifies the challenge response using the provided public key.
    """
    try:
        # Remove comment from public key and keep only the key and type
        public_key = public_key.split(" ")[0] + " " + public_key.split(" ")[1]

        # Write the public key and response to temporary files
        with open("allowed_signers.tmp", "w") as pub_file, open("response.tmp", "w") as resp_file:
            pub_file.write("keyservice@localhost" + " " + public_key)
            resp_file.write(response)

        # Add newline to the challenge
        challenge += "\n"

        # Use ssh-keygen to verify the response
        # ssh-keygen -Y verify -f allowed_signers.tmp -I keyservice@localhost -n file -s signature
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", "allowed_signers.tmp", "-I", "keyservice@localhost", "-n", "file", "-s", "response.tmp"],
            input=challenge,
            text=True,
            check=True,
            capture_output=True
        )

        # Clean up temporary files
        subprocess.run(["rm", "allowed_signers.tmp", "response.tmp"])

        # Check the result
        return result.returncode == 0
    except Exception as e:
        print(f"Error during verification: {e}")
        return False

if __name__ == "__main__":

    challenge = "challenge"
    response = """-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgmUyl9oxpqEHul334T3iEyNylV/
TE0VmZbKKE9yUMwq8AAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEB7+FsFOtXWn9sGxJdJ4aZq6ehy27tt9QVGktahlRhl4fiNrBCbww8T+RQ1WSjnCd
tUJDlTMitMVxuN1u/XvXQP
-----END SSH SIGNATURE-----"""

    public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlMpfaMaahB7pd9+E94hMjcpVf0xNFZmWyihPclDMKv gunnar.jansen@id-MBP-M1-14-gjansen"
    verify_challenge_response(challenge, response, public_key)
