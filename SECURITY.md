# Security design

## Passwords
Passwords are not stored directly. The Worker derives a 256-bit value with PBKDF2-HMAC-SHA-256 using a unique 16-byte salt and 150,000 iterations.

## Dashboard sessions
Login sessions use a random 32-byte token stored in a Secure, HttpOnly, SameSite=Strict cookie. D1 stores only SHA-256(token), not the raw session token.

## WNotifier cookie and Discord webhook
They are encrypted with AES-256-GCM before being saved to D1. The encryption key is supplied through the Cloudflare Worker secret `CREDENTIAL_KEY_B64`.

The API reports only whether each credential is present. It has no endpoint that returns decrypted credentials.

## Limitation
No server-side automation system can both use a credential unattended and guarantee that an administrator who can replace the running code can never access that credential. The encryption here protects database-at-rest disclosure and accidental exposure; it does not protect against a malicious future Worker deployment by an account administrator.

## Logging
The application intentionally logs only status messages, slot IDs, durations, prices, and errors. Credential plaintext is not sent to the activity logger.
