# Incident Response Guide

This guide provides incident response procedures for Kekkai Portal operations.

## Overview

This document covers:

- Incident classification
- Response procedures
- Communication templates
- Post-incident review

## Incident Classification

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **P1 - Critical** | Service unavailable, data breach | < 15 minutes | Complete outage, security breach |
| **P2 - High** | Major feature broken, performance degraded | < 1 hour | Auth broken, slow response |
| **P3 - Medium** | Minor feature broken, workaround exists | < 4 hours | Single scanner failed |
| **P4 - Low** | Cosmetic issues, enhancement requests | < 24 hours | UI glitches |

### Auto-Classification from Alerts

| Alert Type | Severity | Classification |
|------------|----------|----------------|
| `CROSS_TENANT_ATTEMPT` | Critical | P1 |
| `SAML_REPLAY` | Critical | P1 |
| `AUTH_BRUTE_FORCE` | Critical | P2 |
| `BACKUP_FAILURE` | Critical | P2 |
| `AUTH_FAILURE_SPIKE` | Warning | P3 |
| `IMPORT_FAILURE` | Warning | P3 |

## Response Procedures

### P1 - Critical Incident

**Immediate Actions (0-15 minutes)**

1. **Acknowledge alert**
2. **Assess impact**:
   - Number of affected users/tenants
   - Data exposure risk
   - Service availability
3. **Contain threat** (if security-related):
   ```bash
   # Block suspicious IP
   iptables -A INPUT -s <IP> -j DROP

   # Disable compromised account
   kekkai admin user disable --id <USER_ID>
   ```
4. **Start incident channel**
5. **Page on-call team**

**Investigation (15-60 minutes)**

1. **Gather logs**:
   ```bash
   # Get portal logs
   docker-compose logs --since 1h portal > incident_portal.log

   # Get audit logs
   tail -1000 /var/log/kekkai/audit.jsonl > incident_audit.log
   ```

2. **Check recent changes**:
   ```bash
   # Recent deployments
   git log --oneline -10

   # Config changes
   cat /var/lib/kekkai-portal/version-manifest.json
   ```

3. **Identify root cause**

**Resolution**

1. Apply fix or rollback
2. Verify service restored
3. Document timeline
4. Schedule post-mortem

### P2 - High Severity

**Response (0-1 hour)**

1. Acknowledge and assess
2. Check monitoring dashboards
3. Review recent alerts
4. Identify affected components

**Common P2 Scenarios**

**Backup Failure**
```bash
# Check backup status
./scripts/backup.sh full 2>&1 | tee backup_debug.log

# Common fixes:
# - Free disk space
# - Check database connectivity
# - Verify credentials

# Retry
./scripts/backup.sh full
```

**Authentication Issues**
```bash
# Check database
docker exec postgres pg_isready

# Check SAML config
curl http://localhost:8000/api/v1/health

# Restart auth services
docker-compose restart portal
```

### P3/P4 - Lower Severity

1. Create ticket
2. Schedule fix for next maintenance window
3. Document workaround if available

## Security Incident Response

### Suspected Breach

1. **Isolate**:
   ```bash
   # Disconnect from network
   docker network disconnect kekkai_network portal
   ```

2. **Preserve evidence**:
   ```bash
   # Snapshot logs
   cp -r /var/log/kekkai /var/log/kekkai_incident_$(date +%s)

   # Snapshot database
   ./scripts/backup.sh database
   ```

3. **Analyze**:
   ```bash
   # Check audit log for suspicious activity
   grep "cross_tenant\|auth.failure\|authz.denied" /var/log/kekkai/audit.jsonl
   ```

4. **Notify** (see communication templates)

### Cross-Tenant Access Attempt

When `CROSS_TENANT_ATTEMPT` alert triggers:

1. **Review alert details**:
   ```python
   # From monitoring
   {
       "user_id": "user123",
       "source_tenant": "tenant_a",
       "target_tenant": "tenant_b"
   }
   ```

2. **Verify if authorized**:
   - Check if user has multi-tenant access
   - Review recent permission changes

3. **If unauthorized**:
   - Disable user account
   - Review all user activity
   - Check for data access
   - Notify both tenants

### SAML Replay Attack

When `SAML_REPLAY` alert triggers:

1. **Block source IP**
2. **Invalidate affected sessions**:
   ```python
   # Clear sessions for assertion
   from portal.enterprise.saml import saml_replay_cache
   saml_replay_cache.clear()
   ```
3. **Contact IdP administrator**
4. **Review SAML configuration**

## Communication Templates

### Internal Escalation

```
INCIDENT: [TITLE]
SEVERITY: P[1-4]
TIME DETECTED: [TIMESTAMP]

IMPACT:
- [Number] users affected
- [Service] unavailable/degraded
- [Data exposure risk: Yes/No]

CURRENT STATUS:
- [Investigating/Contained/Resolving/Resolved]

ACTIONS TAKEN:
1. [Action 1]
2. [Action 2]

NEXT STEPS:
1. [Next action]

RESPONDERS:
- [Name] - [Role]
```

### Customer Notification (Outage)

```
Subject: Kekkai Portal Service Disruption

We are currently experiencing a service disruption affecting [AFFECTED SERVICE].

Impact: [DESCRIPTION]
Start time: [TIMESTAMP]
Estimated resolution: [ESTIMATE or "Under investigation"]

We are actively working to resolve this issue. Updates will be provided every [30 minutes/hour].

Current status: [STATUS PAGE URL]

We apologize for any inconvenience.
```

### Customer Notification (Security)

```
Subject: Security Notice - Action Required

We detected suspicious activity on your account/tenant.

What happened:
[BRIEF DESCRIPTION - no technical details that could help attackers]

What we did:
- [Actions taken to protect]

What you should do:
- [Required actions]

If you have questions, contact security@kademoslabs.com.
```

## Post-Incident Review

### Timeline Template

| Time | Event | Actor | Action |
|------|-------|-------|--------|
| HH:MM | Alert triggered | System | [Details] |
| HH:MM | Incident acknowledged | [Name] | [Details] |
| HH:MM | Investigation started | [Name] | [Details] |
| HH:MM | Root cause identified | [Name] | [Details] |
| HH:MM | Fix deployed | [Name] | [Details] |
| HH:MM | Service restored | System | [Details] |

### Post-Mortem Template

```markdown
# Incident Post-Mortem: [TITLE]

**Date:** [DATE]
**Duration:** [HH:MM]
**Severity:** P[1-4]
**Author:** [NAME]

## Summary
[1-2 sentence summary]

## Impact
- Users affected: [NUMBER]
- Duration: [DURATION]
- Data affected: [Yes/No - details]

## Root Cause
[Technical explanation]

## Timeline
[See timeline template above]

## Resolution
[How it was fixed]

## Lessons Learned
1. What went well:
   - [Item]
2. What went wrong:
   - [Item]
3. Where we got lucky:
   - [Item]

## Action Items
| Item | Owner | Due Date | Status |
|------|-------|----------|--------|
| [Action] | [Name] | [Date] | [Status] |

## Prevention
[How to prevent recurrence]
```

## Contacts

### Escalation Path

| Level | Contact | Method | Response Time |
|-------|---------|--------|---------------|
| L1 | On-call Engineer | PagerDuty | 15 min |
| L2 | Engineering Lead | Phone | 30 min |
| L3 | Security Team | Security channel | 15 min (P1) |
| L4 | Management | Phone | 1 hour |

### External Contacts

- **Hosting Provider**: [Contact]
- **DNS Provider**: [Contact]
- **DefectDojo Support**: [Contact]
- **Legal**: [Contact] (for breach notification)

## Tools and Resources

### Diagnostic Commands

```bash
# System overview
docker-compose ps
docker stats --no-stream

# Log analysis
journalctl -u kekkai -n 100
docker-compose logs --tail 100 portal

# Network
netstat -tlnp
ss -tlnp

# Database
docker exec postgres pg_isready
docker exec postgres psql -U defectdojo -c "SELECT count(*) FROM auth_user"
```

### Runbooks

- [Backup/Restore](./backup-restore.md)
- [Upgrade](./upgrade-runbook.md)
- [Monitoring](./monitoring.md)
