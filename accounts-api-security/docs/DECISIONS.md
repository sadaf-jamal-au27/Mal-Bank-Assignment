# Decisions — `accounts-api`

This is the reasoning that connects the build (sections 1–6, `/terraform`, `/k8s`, `/policies`, `/ci`, `/falco`) back to the threat model in `THREAT_MODEL.md`. Each section states what was enforced, what was deliberately left un-enforced, and the compensating control behind that call.

## 1. Supply chain: one control, done properly, beats six half-wired scanners
**Enforced:** Trivy (image + filesystem) and Syft (SBOM) run on every build; Gitleaks runs on every push/PR; both are blocking, not advisory. Cosign keyless-signs the image in CI using the GitHub OIDC identity; Kyverno's `verifyImages` policy is the one control this whole chain exists to feed — the cluster will not admit an image that isn't signed by that exact identity, full stop.
**Why this one gets the most investment:** with 40 people able to merge and no security team, the registry→cluster boundary is the only chokepoint that doesn't depend on any human noticing anything. A scanner that only warns in a PR comment is advisory and gets ignored under deadline pressure; an admission controller that refuses the pod is not.
**Left un-enforced:** SAST (Semgrep) is not wired in. One-line justification: application logic vulnerabilities in an "assume it exists and is broadly competent" service are a code-review problem, not a platform-security problem, and this assessment scores infrastructure/pipeline/identity controls. If asked to extend, Semgrep would be the next addition, non-blocking initially (findings triage needs a human, and there isn't one yet).
**Compensating control for the CVE backlog problem:** `.trivyignore` entries require an expiry date and a linked ticket/reason in a comment; CI fails if an entry is past its expiry. This stops the ignore-list from becoming permanent silent risk acceptance.

## 2. Pod security: deny-by-default via Kyverno, not PodSecurityPolicy
**Enforced:** Kyverno ClusterPolicies (`restrict-pod-security.yaml`) require non-root, drop `ALL` capabilities, read-only root filesystem, disallow `hostPath`/`hostNetwork`/`hostPID`/privilege escalation, and require CPU/memory limits. `validationFailureAction: Enforce`.
**Why Kyverno over Gatekeeper/OPA:** equivalent capability here; Kyverno's policy-as-YAML (no Rego) is faster for a 2-person platform team to read, write, and hand off to the other 40 engineers to self-diagnose a denied deploy. This is a maintainability call, not a security one — justified swap per the assessment's own allowance.
**Left un-enforced:** seccomp/AppArmor profile enforcement beyond the RuntimeDefault. One-line reason: authoring a custom seccomp profile requires syscall-level knowledge of a service this exercise says to treat as opaque; RuntimeDefault is the correct floor without guessing at the app's actual syscall surface.

## 3. Secrets: never in git, never in the image, never touched by CI
**Enforced:** no secret material appears in any manifest or Dockerfile. Terraform (`secrets.tf`) provisions the KYC key and DB credential in Secrets Manager with a customer-managed KMS key (`kms.tf`); the pod's IRSA role (`iam.tf`) is the only identity permitted to read those specific ARNs. CI's own IAM role has zero permission to read secret values — it can push images and describe infra, nothing more.
**Assumption stated:** a CSI secrets-store driver (or the AWS Secrets Manager CSI provider) mounts the secret as a file at runtime; this is documented in `k8s/deployment.yaml` as a comment rather than deployed live, since the assessment doesn't require running against real AWS.
**Left un-enforced:** automatic secret rotation. One-line reason: rotation requires an app-side reload hook or restart-on-rotation behaviour that belongs to the "broadly competent, assume it exists" service, not to the platform layer being assessed here; the KMS key and Secrets Manager resource are built rotation-ready (versioned secret, no hardcoded version pin).

## 4. Identity: least privilege on the IRSA role, not on the CI role, because CI needs breadth and the pod doesn't
**Enforced:** the pod's IRSA role can only touch its own RDS secret, its own KMS key, and its own Secrets Manager path — no wildcard resource ARNs anywhere in `iam.tf`.
**Left partially un-enforced:** the GitHub Actions → AWS OIDC role is scoped by repository and branch (`terraform/oidc.tf`) but not further split by environment (dev/staging/prod use the same role in this build). One-line reason: full per-environment role separation needs an AWS Organizations SCP structure that's genuinely out of a single service repo's control — the compensating control is that the OIDC trust policy pins to `refs/heads/main` only, so no branch other than main can assume the deploy role, and that's documented as the platform team's follow-on to add environment-scoped roles.

## 5. Network: default-deny plus three explicit allows, and an honest gap on egress filtering
**Enforced:** `k8s/networkpolicy.yaml` denies all ingress/egress by default for the `accounts-api` namespace, then explicitly allows: ingress from the ingress-controller namespace only, egress to the RDS security-group CIDR, egress to DNS, and egress to the KYC provider's CIDR block.
**Left un-enforced, and why that's the honest answer rather than a gap left silent:** Kubernetes NetworkPolicy egress rules are CIDR/port based, not FQDN based — if the KYC provider sits behind a CDN with rotating IPs, the CIDR allow will be either too broad or will break. True FQDN-aware L7 egress filtering needs a service mesh or a CNI with that capability (e.g. Cilium `toFQDNs`), which isn't assumed present. The compensating control documented (not built, since it requires a running AWS account) is VPC Flow Logs plus a GuardDuty-equivalent alert on any egress destination outside the known KYC provider ASN.

## 6. Runtime: one Falco rule, not a Falco rollout
**Enforced:** a single custom rule alerting on interactive shell exec inside the `accounts-api` container, and one alerting on outbound connections to ports outside the allowlist (80/443 to the KYC CIDR, 5432 to RDS).
**Why only one control here, stated honestly:** this is explicitly the last line of defense after T1–T9 have already failed; investing heavily in tuning a full Falco ruleset ranks below getting the admission-time and supply-chain controls right, given the 4-hour scope. One rule, correctly targeted at "something got past everything else," is more honest than a large default ruleset nobody has tuned to avoid alert fatigue for a team of 2.

## Local ↔ AWS mapping used throughout
| AWS service named in the brief | Local/OSS stand-in used here | Why |
|---|---|---|
| EKS | `kind`/any local K8s (manifests are cluster-agnostic) | Pod Security Admission + Kyverno work identically |
| ECR | ghcr.io (referenced in `ci/build.yml`) | Free, OIDC-native for GitHub Actions, cosign-compatible |
| IAM (IRSA) | Terraform `aws_iam_role` + `sts:AssumeRoleWithWebIdentity` trust policy, validated with `terraform validate`/`plan` only | Same shape as real IRSA, no `apply` needed |
| KMS | Terraform `aws_kms_key`, plan-only | Encryption-at-rest for the Secrets Manager entries |
| Secrets Manager | Terraform `aws_secretsmanager_secret`, plan-only | Matches brief's AWS idiom |
| CloudTrail / GuardDuty | Documented as compensating controls for the egress gap (§5), not built | Requires a live AWS account; out of the "author + validate, don't apply" scope |
| Falco | Falco (native, not a substitute) | Open-source runtime detection, matches the brief's suggested list |

## What would come next with more time
1. Cilium (or a mesh) for FQDN-based egress filtering — closes the T8 residual gap properly.
2. Per-environment OIDC roles (dev/staging/prod) instead of one role pinned to `main`.
3. Semgrep SAST, non-blocking, once there's someone to triage findings.
4. Secret rotation Lambda + app restart hook, coordinated with the service owners.
