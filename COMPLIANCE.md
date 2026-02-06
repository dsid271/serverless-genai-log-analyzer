# Compliance & Security Checklist

## Overview
This checklist covers PCI-DSS (payment processing), GDPR (EU data privacy), SOC 2 Type II (auditing), and telecom/banking best practices.

---

## 1. Data Classification & PII Management

### PII Detection & Redaction
- [ ] Identify PII types: credit cards, SSNs, passwords, emails, phone numbers
- [ ] Implement detection: regex + ML (Presidio, custom classifiers)
- [ ] Redaction strategy:
  - [ ] Credit cards: `xxxx-xxxx-xxxx-1234` (last 4 visible)
  - [ ] SSNs: `xxx-xx-5678` (last 4 visible)
  - [ ] Passwords: **remove entirely**
  - [ ] Emails: `user***@domain.com`
- [ ] Classification metadata: tag all logs (public / internal / confidential / PII)
- [ ] Testing: 99%+ precision, <5% false negatives

### Data Retention & Deletion (GDPR & PCI-DSS)
- [ ] **PII data**: 90 days (right to be forgotten)
- [ ] **Financial audit logs**: 7 years (Sarbanes-Oxley)
- [ ] **Raw logs**: 30 days (cold storage after 7 days)
- [ ] **Aggregates/summaries**: 1 year
- [ ] Automated deletion jobs: run nightly, log all deletions
- [ ] Unrecoverable deletion: cryptographic erasure (not just soft-delete)
- [ ] Testing: verify data is unrecoverable after deletion

### Data Minimization
- [ ] Only collect necessary fields (logs)
- [ ] Disable field logging for PII (e.g., request body, response body)
- [ ] Aggregate data where possible (counts, aggregations)
- [ ] Document justification for each PII field (business need)

---

## 2. Encryption & Key Management

### Encryption in Transit (TLS 1.3)
- [ ] **Kafka**: SASL/SSL for producer/consumer
- [ ] **Spark → Delta Lake**: encrypted channel
- [ ] **API (FastAPI)**: HTTPS only, TLS 1.3 minimum
- [ ] **Vector DB**: encrypted connection
- [ ] **Database**: encrypted channels, no unencrypted backups
- [ ] Certificate validation: no self-signed certs in production
- [ ] Testing: SSL Labs A+ rating or equivalent

### Encryption at Rest
- [ ] **Cloud Storage (Delta Lake)**: Google Cloud KMS encryption
- [ ] **Vector DB**: encryption enabled
- [ ] **Databases**: encryption enabled
- [ ] **Kafka**: optional (depends on sensitive data)
- [ ] **Key Management**: 
  - [ ] Customer-managed keys (CMK) in Cloud KMS
  - [ ] Key rotation: annual
  - [ ] Key escrow: backup keys stored in secure location
- [ ] Testing: verify encrypted data is unreadable without key

### Key Rotation & Access
- [ ] Encryption keys: rotate annually (or per compliance policy)
- [ ] Automated rotation: use Cloud KMS auto-rotation (optional)
- [ ] Access logs: who accessed which keys, when
- [ ] Key escrow: secure backup (HSM or offline storage)
- [ ] Disaster recovery: keys accessible in failover region

---

## 3. Authentication & Authorization

### Authentication (Authn)
- [ ] **API users**: OAuth 2.0 (Google Identity) or SAML
- [ ] **Service-to-service**: API keys (auto-rotated, scoped)
- [ ] **Multi-factor authentication (MFA)**: required for admins
- [ ] **Session management**: JWT tokens, max 8-hour lifetime
- [ ] **Password policy** (if applicable):
  - [ ] Minimum 12 characters
  - [ ] Complexity: uppercase, lowercase, numbers, symbols
  - [ ] No reuse of last 5 passwords
  - [ ] Expiration: 90 days (or passwordless preferred)
- [ ] **Credential storage**: hashed (bcrypt, argon2), never plain-text
- [ ] Testing: OWASP top 10 authn tests

### Authorization (Authz) & RBAC
- [ ] **Roles defined**: admin, analyst, viewer (+ custom roles)
- [ ] **Admin**: full access, user/role management, config changes
- [ ] **Analyst**: search, analyze, cannot delete or export raw data
- [ ] **Viewer**: read-only, pre-computed reports only
- [ ] **Field-level access**: PII fields hidden from non-admin
- [ ] **Data-level access**: restrict by department, region, etc.
- [ ] **Audit trail**: log all permission changes
- [ ] Testing: attempt unauthorized access (negative tests)

### Access Control Lists (ACLs)
- [ ] **Kafka**: SASL ACLs per producer/consumer
- [ ] **Database**: least-privilege service accounts (read-only where possible)
- [ ] **Cloud Storage**: bucket policies, no public access
- [ ] **API**: API key scope restrictions (search only, no delete)
- [ ] **Secrets**: Cloud Secret Manager, no hardcoded secrets
- [ ] Testing: attempt privilege escalation (negative tests)

---

## 4. Audit Logging & Accountability

### Query Audit Trail
- [ ] **Every search logged**: user, timestamp, query, results count
- [ ] **Every analysis logged**: user, timestamp, prompt, LLM response
- [ ] **Every export logged**: user, timestamp, fields, row count
- [ ] **Data access**: all reads logged (not just modifications)
- [ ] **Sensitive operations**: user deletions, role changes, key rotations
- [ ] **Storage**: immutable, append-only (Delta Lake)
- [ ] **Retention**: 7 years minimum
- [ ] **Searchability**: query audit logs via API (with RBAC)

### Configuration Change Audit
- [ ] **Infrastructure changes**: terraform plan/apply logged
- [ ] **Policy changes**: RBAC updates logged
- [ ] **Schema changes**: Delta Lake schema evolution logged
- [ ] **Retention policy changes**: logged with approval
- [ ] **Alerting changes**: config changes tracked
- [ ] **Approval workflow**: changes require approval (for production)

### Data Access Audit
- [ ] **Who accessed what**: user, timestamp, data, duration
- [ ] **Bulk exports**: flagged for review (unusual patterns)
- [ ] **PII access**: logged separately, reviewed regularly
- [ ] **Alerts**: trigger on suspicious patterns (e.g., exporting >10K records)

### Audit Log Integrity
- [ ] **Tamper-proof**: cryptographic signing (optional)
- [ ] **Centralized**: all logs in single immutable store
- [ ] **No deletion**: audit logs cannot be deleted (only archived)
- [ ] **Backup**: audit logs replicated to secondary region

---

## 5. Network Security

### Perimeter Security
- [ ] **Private VPC**: all components in private subnets
- [ ] **Cloud NAT**: outbound internet via NAT (for API calls)
- [ ] **Cloud Armor**: DDoS protection on API
- [ ] **Firewall rules**:
  - [ ] Kafka: ingress from trusted log sources only
  - [ ] Database: ingress from Spark/API pods only
  - [ ] Vector DB: ingress from API pods only
- [ ] **VPC Flow Logs**: monitor network traffic

### API Security
- [ ] **Rate limiting**: 100 req/min per user (configurable)
- [ ] **Input validation**: all query parameters validated (SQL injection prevention)
- [ ] **CORS**: whitelist trusted origins
- [ ] **CSRF protection**: token-based (if applicable)
- [ ] **Timeout**: max query timeout 30 seconds (prevent resource exhaustion)

### Data Exfiltration Prevention
- [ ] **No public buckets**: Cloud Storage buckets require auth
- [ ] **No public databases**: databases in private subnets
- [ ] **Export restrictions**: analysts cannot export raw data (aggregates only)
- [ ] **DLP detection**: flag attempts to download >100K records
- [ ] **Network segmentation**: separate network for sensitive operations

---

## 6. Incident Response & Monitoring

### Alerting & Monitoring
- [ ] **Performance**: P99 latency, error rate, Kafka lag
- [ ] **Security**: failed auth attempts, bulk exports, permission changes
- [ ] **Data integrity**: schema validation, row count anomalies
- [ ] **Compliance**: PII access, retention policy violations, key rotations
- [ ] **PagerDuty integration**: critical alerts page on-call engineer

### Incident Response Plan
- [ ] **Runbook**: procedures for common incidents (data breach, outage, compliance violation)
- [ ] **Escalation**: severity levels (P1, P2, P3) + escalation matrix
- [ ] **Communication**: notify affected parties (customers, regulators)
- [ ] **Forensics**: preserve logs, preserve system state for investigation
- [ ] **Remediation**: steps to fix root cause + prevent recurrence
- [ ] **Post-incident review**: document lessons learned

### Data Breach Response
- [ ] **Detection**: alerts for suspicious data access patterns
- [ ] **Containment**: disable compromised user account, revoke API keys
- [ ] **Notification**: inform affected customers (if PII exposed) within 72 hours (GDPR)
- [ ] **Investigation**: forensic analysis (audit logs, network logs)
- [ ] **Remediation**: fix vulnerability, deploy patch
- [ ] **Regulatory reporting**: notify regulators if required (PCI-DSS, GDPR)

---

## 7. Compliance Certifications & Audits

### SOC 2 Type II
- [ ] **Access controls**: RBAC, MFA, least privilege
- [ ] **Audit logging**: comprehensive, tamper-proof
- [ ] **Data integrity**: validation, checksums
- [ ] **Availability**: RTO <4 hours, RPO <1 hour
- [ ] **Security**: encryption, key management, incident response
- [ ] **12-month audit**: prepare for external auditor review
- [ ] **Timeline**: collect evidence, remediate findings

### PCI-DSS (Payment Card Industry)
- [ ] **Requirement 1**: Firewall configuration (Cloud Armor, firewall rules)
- [ ] **Requirement 2**: No default credentials
- [ ] **Requirement 3**: Protect stored payment data
- [ ] **Requirement 4**: Encryption in transit (TLS 1.3)
- [ ] **Requirement 5**: Malware protection (vulnerability scanning)
- [ ] **Requirement 6**: Security patches, secure development
- [ ] **Requirement 7**: Least privilege access (RBAC)
- [ ] **Requirement 8**: User authentication (OAuth, MFA)
- [ ] **Requirement 9**: Physical security (N/A for cloud, but document assumptions)
- [ ] **Requirement 10**: Audit logging
- [ ] **Requirement 11**: Security testing (annual penetration test)
- [ ] **Requirement 12**: Information security policy

### GDPR (EU Data Protection)
- [ ] **Article 5**: Lawful processing, data minimization, accuracy
- [ ] **Article 17**: Right to erasure (implement deletion jobs)
- [ ] **Article 20**: Right to data portability (export API)
- [ ] **Article 32**: Security (encryption, access controls, audit logging)
- [ ] **Article 33**: Breach notification (within 72 hours)
- [ ] **Article 35**: Data Protection Impact Assessment (DPIA)
- [ ] **Article 37**: Data Protection Officer (assign DPO)
- [ ] **Processing Agreement**: ensure data processors are GDPR-compliant

### HIPAA (if handling health data)
- [ ] **Encryption**: data at rest + in transit
- [ ] **Access controls**: unique user IDs, role-based access
- [ ] **Audit controls**: logging of access, modifications
- [ ] **Integrity**: verify data integrity (checksums)
- [ ] **Business Associate Agreement**: with Cloud vendors
- [ ] **Breach notification**: notify individuals if PHI exposed

---

## 8. Code Security & Supply Chain

### Secure Development
- [ ] **Dependency scanning**: detect known vulnerabilities (Dependabot, Snyk)
- [ ] **Code review**: peer review, at least 2 approvals before merge
- [ ] **Static analysis**: SAST tools (CodeQL, SonarQube)
- [ ] **Dynamic analysis**: DAST (OWASP ZAP) + penetration testing
- [ ] **Secrets management**: no secrets in code, use Cloud Secret Manager
- [ ] **Signed commits**: GPG-signed commits (optional but recommended)

### Vulnerability Management
- [ ] **Dependency updates**: automatic patch updates (Dependabot)
- [ ] **Severity triage**: critical/high severity patched within 7 days
- [ ] **Penetration testing**: annual, report findings
- [ ] **Security advisories**: subscribe to vendor advisories

### Deployment Safety
- [ ] **Container scanning**: scan images for vulnerabilities (Cloud Build)
- [ ] **Image signing**: sign container images (optional)
- [ ] **Binary authorization**: only deploy signed images (optional)
- [ ] **Change approval**: production deploys require change order + approval
- [ ] **Rollback plan**: prepare rollback procedure for each deployment
- [ ] **Canary deployment**: deploy to 5% of traffic, monitor before full rollout

---

## 9. Operational Security (OpsEc)

### Access Management
- [ ] **SSH keys**: GitHub / GitLab keys, rotated annually
- [ ] **Service accounts**: minimal permissions, no human use
- [ ] **Breakglass access**: documented emergency access procedure (with logging)
- [ ] **API key rotation**: keys rotated every 90 days
- [ ] **Password manager**: use for admin credentials (not in code)

### Change Management
- [ ] **Change log**: all production changes documented
- [ ] **Change approval**: changes require approval (CAB)
- [ ] **Staging environment**: test all changes before production
- [ ] **Rollback procedure**: documented, tested (at least quarterly)
- [ ] **Maintenance windows**: communicate scheduled maintenance to users

### Disaster Recovery Drills
- [ ] **Annual DR drill**: full system restoration from backup
- [ ] **Failover drill**: test failover to secondary region (quarterly)
- [ ] **Incident simulation**: run incident response drill (quarterly)
- [ ] **Documentation**: runbooks kept up-to-date

---

## 10. Compliance Reporting & Continuous Improvement

### Regular Reviews
- [ ] **Quarterly**: review access logs, audit findings
- [ ] **Semi-annual**: security assessment, penetration test readiness
- [ ] **Annual**: full compliance audit, DPIA review, policy updates

### Documentation
- [ ] **Compliance playbook**: procedures for PCI-DSS, GDPR, SOC 2
- [ ] **Data flow diagram**: shows where PII is processed
- [ ] **Risk register**: document security risks + mitigation
- [ ] **Asset inventory**: all data, systems, dependencies

### Regulatory Reporting
- [ ] **PCI-DSS report**: annual attestation (if processing payments)
- [ ] **GDPR reports**: Data Protection Impact Assessment (if applicable)
- [ ] **Incident reports**: breach notification (within 72 hours)

---

## Quick Checklist Summary (Priority Order)

### Critical (Week 1–4)
- [ ] PII detection & redaction (99%+ precision)
- [ ] Encryption in transit (TLS 1.3) & at rest (KMS)
- [ ] RBAC (admin, analyst, viewer)
- [ ] Audit logging (all queries, data access)
- [ ] Network security (private VPC, firewall rules)

### High (Week 5–12)
- [ ] PII classification & retention enforcement (90-day deletion)
- [ ] Data breach incident response plan
- [ ] SOC 2 readiness assessment
- [ ] Penetration testing (annual)
- [ ] Compliance documentation (DPIA, playbooks)

### Medium (Week 13–24)
- [ ] PCI-DSS / GDPR certification (if applicable)
- [ ] Annual security audit
- [ ] HIPAA compliance (if handling health data)
- [ ] Disaster recovery drills (quarterly)

---

*Last Updated: 2026-02-06*
