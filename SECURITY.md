# Security Policy

TrustAI is a reference implementation for local evaluation. Run the verifier
against your own evidence and assess its fit for your environment. The bundled
example keys and records are for reproducible tests, not deployment secrets.

Report a suspected vulnerability privately through GitHub's **Report a
vulnerability** option if it is enabled for this repository. If it is not
available, contact the repository owner privately before publishing details.
Do not put exploit instructions, credentials, private evidence, or customer
data in a public issue. Include affected versions or commits, reproduction
steps with synthetic data, impact, and a safe contact method.

Maintainers will assess reports and coordinate fixes and disclosure where
possible. Generate separate signing keys for your deployment; do not reuse
the bundled example keys. Rotate any real secret that may have been exposed;
a repository edit alone does not revoke it.
