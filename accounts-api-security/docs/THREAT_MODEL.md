# Threat Model — `accounts-api`

## Assumptions (stated, not asked)
1. Cluster runs a recent Kubernetes version with Pod Security Admission available (assume EKS 1.28+, `restricted` PSA achievable).
2. `accounts-api` terminates TLS at ALB/CloudFront; pod-to-pod traffic inside the cluster is plaintext HTTP unless stated. This is treated as an accepted gap, compensated by NetworkPolicy rather than mTLS, since no service mesh is assumed present.
3. RDS Postgres holds name, email, phone, IBAN, balance, card last-4. IBAN + audit trail is regulated PII, so it is treated as "regulated data" for scoping, though last-4 alone does not put the full PAN in scope — full PCI-DSS CDE segmentation is explicitly not claimed.
4. The third-party KYC provider is called over the public internet from inside the pod network — this is the primary egress control point.
5. GitHub Actions is the only CI/CD path into the AWS org; ~40 people can merge, only 2 are platform engineers. Controls must live in the pipeline/policy layer, not in reviewer trust.
6. No dedicated security team, so controls must be self-service, low-maintenance, and fail closed by default (deny unsigned images, deny root, etc.) rather than depend on a manual review gate.
7. AWS service names are used for scope; the control described is what actually enforces the behaviour locally. See the mapping table in `README.md`.

## Assets
| Asset | Why it matters |
|---|---|
| Customer PII + IBAN + balance (in RDS, in transit, in logs) | Regulatory data; direct fraud/privacy impact |
| KYC provider credential | Compromise lets an attacker impersonate the bank to a regulated KYC partner |
| DB credentials | Compromise gives full read/write of customer financial data |
| Container image / supply chain (source → registry → cluster) | Single choke point touched by 40 engineers; compromise here beats every downstream control |
| Cluster/namespace boundary (shared with ~12 other teams) | Blast-radius control — accounts-api must not be pivotable to or from neighbours |
| CI/CD identity (GitHub Actions → AWS) | Broadest privileged path into the org; an OIDC trust misconfiguration is an account-takeover primitive |
| Audit trail written from the event stream | Its integrity is itself something other controls get examined against |

## STRIDE-lite, scoped to what's actually in this repo

| # | Threat | STRIDE | Vector | Control built | Where |
|---|---|---|---|---|---|
| T1 | Vulnerable/malicious dependency or base image reaches prod | Tampering | 40 mergers, no security team gate | Trivy image scan + Syft SBOM in CI; fails on HIGH/CRITICAL, with a time-boxed, expiring `.trivyignore` for no-fix-available CVEs | `ci/.github/workflows/build.yml` |
| T2 | Secret committed to git (DB creds, KYC key) | Info disclosure | Fast-moving repo, 40 mergers | Gitleaks scan, blocking on push/PR | `ci/.github/workflows/build.yml` |
| T3 | Unsigned/tampered image deployed, or a neighbour's pipeline pushes into the same registry namespace | Tampering, Spoofing | Shared registry, shared cluster | Cosign keyless sign in CI + Kyverno `verifyImages` admission policy — cluster refuses any image without a valid signature from the expected CI identity | `ci/.github/workflows/build.yml`, `policies/kyverno/verify-image-signature.yaml` |
| T4 | Pod runs as root/privileged, escapes to node, pivots to a neighbour team's workload | Elevation of privilege | Shared EKS cluster | Kyverno: deny privileged/root, drop ALL capabilities, read-only root FS, deny hostPath/hostNetwork/hostPID | `policies/kyverno/restrict-pod-security.yaml` |
| T5 | East-west movement: a compromised neighbour reaches accounts-api's DB path, or accounts-api reaches something it shouldn't | Spoofing, Tampering | Shared cluster, flat network by default | Default-deny NetworkPolicy + explicit allow: ingress only from the ingress controller, egress only to RDS CIDR, KYC provider, and DNS | `k8s/networkpolicy.yaml` |
| T6 | Over-privileged pod IAM identity used for lateral movement into other AWS accounts in the org | Elevation of privilege | Multi-account org, IRSA | IRSA role in Terraform scoped to the specific RDS secret ARN, KMS key, and Secrets Manager path only — no `*` resource | `terraform/iam.tf` |
| T7 | DB/API credentials handled as plain env vars or baked into the image | Info disclosure | Regulated data | No secret material in manifests or image; pod fetches at runtime via IRSA → Secrets Manager (CSI secret-store pattern documented); CI never sees the runtime secret | `terraform/secrets.tf`, `docs/DECISIONS.md` |
| T8 | Uncontrolled egress beyond the one KYC provider (exfiltration, C2) | Info disclosure, Tampering | The public internet call is a stated requirement, so egress can't be fully denied | NetworkPolicy scopes egress to DNS + RDS CIDR + KYC provider CIDR only. Residual gap: true FQDN-based L7 egress filtering needs a mesh/Cilium not assumed present — accepted, with flow-log/GuardDuty-equivalent alerting as compensating control | `k8s/networkpolicy.yaml`, `docs/DECISIONS.md` |
| T9 | IaC drift/misconfiguration (public RDS, open SG, unencrypted storage) | Tampering | 2-person platform team, no dedicated reviewer | Checkov in CI on every `terraform plan`; blocks on HIGH | `ci/.github/workflows/build.yml` |
| T10 | Runtime anomaly after every prior control fails (shell exec, crypto-miner, unexpected outbound) | Elevation of privilege | Defense in depth | One Falco rule: alert on shell exec inside the accounts-api container and unexpected outbound to non-allowlisted ports | `falco/accounts-api-rules.yaml` |

## Explicitly out of scope, and why
- **Service mesh / mTLS** — the technically correct answer for T5 at full zero-trust maturity, but standing up a mesh from scratch is disproportionate to a 4-hour scope and to a 2-person platform team's ongoing maintenance load. NetworkPolicy is the compensating control; mesh is flagged as a follow-on in the decisions doc.
- **WAF/CloudFront rule tuning** — the edge is infrastructure outside this repo's stated boundary (the service + its pipeline + its identity/secrets); noted as an assumption, not built.
- **Full PCI-DSS CDE segmentation** — only card last-4 is stored, so full PAN scope is not claimed.
