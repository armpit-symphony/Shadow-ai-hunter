# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in Shadow AI Hunter, please report it responsibly.

**Do NOT** report vulnerabilities through public GitHub issues.

### Reporting Process

1. **Private Disclosure**: Email security concerns (when available)
2. **Response**: We'll acknowledge within 48 hours
3. **Timeline**: Aim to fix within 90 days
4. **Credit**: We appreciate responsible disclosure

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |

## Security Requirements (Production)

When deploying Shadow AI Hunter in production:

- [ ] Change all default passwords and secrets
- [ ] Enable MongoDB authentication
- [ ] Enable TLS/SSL for all connections
- [ ] Run backend without privileged containers
- [ ] Use strong JWT_SECRET_KEY
- [ ] Implement network segmentation
- [ ] Enable audit logging
- [ ] Regular security scanning

## Security Scanning

This project uses:
- **pip-audit**: Python dependency vulnerability scanning
- **Trivy**: Container and configuration scanning
- **Dependabot**: Automatic dependency updates

Run security scans locally:
```bash
# Python dependencies
pip-audit -r backend/requirements.txt

# Container scan
docker build -t shadow-ai-hunter:latest .
trivy image shadow-ai-hunter:latest
```

## Authentication

- JWT-based authentication
- Role-based access control (RBAC)
- Default roles: admin, analyst, viewer, worker

**Change default credentials before production use!**
