# Security Policy

## Supported Versions
We release patches for security vulnerabilities in the following versions:

| Version | Supported |
|---------|-----------|
| 1.0.1   | ✅ |
| < 1.0.1 | ❌ |

## Reporting a Vulnerability
If you discover a vulnerability in the Snake Game project:

- Please **do not open a public issue**.
- Instead, email the maintainer at: security@example.com
- Include a description of the vulnerability, steps to reproduce, and potential impact.
- You will receive a response within 72 hours.

## Known Vulnerabilities
### Unrestricted Keyboard Input (Fixed in v1.0.1)
- **Impact:** Allowed disruptive system-level keys (F5, Alt, Ctrl) to interfere with gameplay.
- **Severity:** Low
- **Patched in:** v1.0.1
- **Workaround:** Filter non-arrow keys and use `event.preventDefault()`.

## Security Best Practices
- Always run the latest version (`>= 1.0.1`).
- Avoid modifying core input handling unless you reapply sanitization.
- Deploy over HTTPS if embedding the game in a website.
- Use CSP headers (`default-src 'self'`) when hosting.

## Credits
- Vulnerability reported by **Ravi (Pratyush Raj)**, student web developer.
