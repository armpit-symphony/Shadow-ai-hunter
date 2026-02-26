# Shadow AI Hunter - Build Status

> Last updated: 2026-02-26

## ✅ Completed (PRs Merged)

| PR | Status | Description |
|----|--------|-------------|
| #1 | ✅ Merged | Repo hygiene + security baseline |
| #2 | ✅ Merged | JWT authentication + RBAC |
| #3 | ✅ Merged | Worker swarm + job queue |

## 🚧 In Progress / Pending

| Item | Status | Notes |
|------|--------|-------|
| Telemetry Ingestion | ⚠️ Partial | Workers exist, need API endpoint to import logs |
| Detection Engine | ⚠️ Partial | Signatures exist, need integration with event pipeline |
| Reporting | ⚠️ Partial | JSON works, PDF needs real implementation |
| CI/CD Security | ❌ Pending | GitHub Actions, Trivy, Dependabot |
| LLM Agent Layer | ❌ Pending | Phase 2 - requires security baseline first |

## 🔧 What's Missing / Needs Work

### Critical (V1)
- [ ] **Scan API → Queue integration**: Connect `/api/scan` endpoint to RQ queue
- [ ] **Telemetry import endpoint**: `/api/telemetry/import` to accept log uploads
- [ ] **Worker processes**: Need to run as separate containers/services
- [ ] **WebSocket updates**: Push scan progress to UI
- [ ] **Mongo models**: Create proper collections for events, evidence, scans

### Important (V1)
- [ ] **Real PDF generation**: Currently placeholder
- [ ] **User provisioning**: Admin UI to create users
- [ ] **Allowlist/denylist management**: UI to edit signatures
- [ ] **Baseline storage**: Store known AI domains for heuristic detection

### Nice to Have (V2+)
- [ ] LLM analysis agents
- [ ] Auto-remediation
- [ ] Multi-tenant support
- [ ] Kubernetes manifests

## 📋 Quick Start for Next Builder

```bash
# Clone and setup
git clone https://github.com/armpit-symphony/Shadow-ai-hunter.git
cd Shadow-ai-hunter

# Start services
cp .env.example .env  # Edit with real secrets
docker compose up -d

# Backend runs on :8001
# Frontend runs on :3000

# Test auth (mock users)
curl -X POST http://localhost:8001/api/v1/auth/login \
  -d "username=admin&password=admin123"
```

## 🔐 Security Notes

- Demo users hardcoded in `auth_routes.py` - replace with DB lookup
- No TLS in dev compose - add for production
- Mongo/Redis auth needs real passwords in `.env`

## 📞 Questions?

Check BUILD.md for architecture details.
