# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of SOC-Copilot seriously. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Security Advisories** (Preferred)
   - Go to [Security Advisories](https://github.com/G4rb3n/SOC-Copilot/security/advisories)
   - Click "Report a vulnerability"
   - Fill in the details

2. **Email** (Alternative)
   - Send an email to the project maintainer
   - Include "SECURITY" in the subject line

### What to Include

Please include the following information:

- Type of vulnerability
- Full path of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution**: Depends on complexity, typically within 30 days

### Disclosure Policy

- We will acknowledge your email within 48 hours
- We will send a more detailed response within 7 days indicating the next steps
- We will keep you informed of the progress towards a fix
- We may ask for additional information or guidance
- We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using SOC-Copilot:

1. **Review Generated Scripts**: Always review generated response scripts before execution
2. **Test in Isolation**: Test scripts in a controlled environment first
3. **Access Control**: Restrict access to SOC-Copilot configuration and generated rules
4. **Audit Logs**: Monitor and audit SOC-Copilot activities
5. **Regular Updates**: Keep SOC-Copilot and its dependencies up to date

## Known Security Considerations

- SOC-Copilot generates scripts that can perform system modifications
- User review is required before script execution
- Generated rules and scripts should be audited regularly

Thank you for helping keep SOC-Copilot and our users safe!
