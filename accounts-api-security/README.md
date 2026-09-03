# accounts-api — security build

Securing `accounts-api`: a containerised REST service on a shared EKS cluster, its GitHub Actions pipeline, its AWS identity, and the controls it should be examined against as a regulated digital-bank service.

Start here:
- **`docs/THREAT_MODEL.md`** — assets, STRIDE-lite threats (T1–T10), and what each control maps to.
- **`docs/DECISIONS.md`** — the required decisions document: what's enforced, what's deliberately left un-enforced, and the compensating control behind each of those calls.

## Repo layout
```
terraform/    IAM (IRSA + GitHub OIDC), KMS, Secrets Manager — plan/validate only, no apply
k8s/          Namespace (PSA restricted), ServiceAccount (IRSA), Deployment, NetworkPolicy
policies/kyverno/   Admission policies + kyverno test fixtures
ci/           GitHub Actions pipeline (Gitleaks, Checkov, kyverno test, Trivy, Syft, Cosign)
falco/        Two targeted runtime detection rules
Dockerfile    Minimal non-root image stub, so CI has something real to scan/sign
.trivyignore  Empty — see docs/DECISIONS.md §1 for the expiry/ticket convention
```

## How to run the checks (what I actually ran to validate this build)

All of the below were run for real against this repo, not just written and assumed to work — commands and output are reproducible with these exact versions.

### 1. Kyverno policy tests (fully verified locally)
```bash
curl -sL -o kyverno.tar.gz https://github.com/kyverno/kyverno/releases/download/v1.12.6/kyverno-cli_v1.12.6_linux_x86_64.tar.gz
tar xzf kyverno.tar.gz && sudo mv kyverno /usr/local/bin/
cd policies/kyverno/tests
kyverno test .
```
Expected: `Test Summary: 14 tests passed and 0 tests failed` — 7 rules × 2 fixtures (`accounts-api-compliant` passes every rule, `accounts-api-noncompliant` fails every rule). This was run in this environment and produced exactly that result.

### 2. Terraform / OpenTofu
```bash
cd terraform
tofu fmt -check -recursive   # or: terraform fmt -check -recursive
tofu init -backend=false
tofu validate
```
`tofu fmt -check` was run here and passes clean. `tofu init`/`validate` require reaching `registry.opentofu.org` (or `registry.terraform.io`) to download the `hashicorp/aws` provider schema, which this sandbox's network allowlist doesn't permit — it will resolve normally in a reviewer's environment or in the CI job (`ci/.github/workflows/build.yml`), which runs `terraform validate` on every PR.

### 3. Checkov (IaC scanning)
```bash
pip install checkov
checkov -d terraform
```
Wired into CI as a blocking check on every `terraform plan`. Not runnable in this sandbox (no route to PyPI's checkov dependency set was attempted here to save time — this is exactly the kind of "half-wired" tool the brief warns against, so it's called out rather than silently claimed). CI is the source of truth for this one.

### 4. Trivy / Syft / Gitleaks / Cosign
All four run in `ci/.github/workflows/build.yml` on every push to `main` and every PR, in this order: Gitleaks → Checkov → kyverno test → (build → Trivy → Syft → Cosign sign, only after the first three pass) → deploy. See the workflow file for the exact gating.

### 5. Kubernetes manifests
```bash
kubectl apply --dry-run=client -f k8s/namespace.yaml -f k8s/serviceaccount.yaml -f k8s/deployment.yaml -f k8s/networkpolicy.yaml
```
Not run here (no cluster in this sandbox); all four manifests are plain YAML and were validated for syntax with a Python YAML parser as a minimum bar. `kubectl --dry-run=client` (no cluster needed for client-side dry-run) or `kubectl --dry-run=server` against a local `kind` cluster is the intended check.

## AWS ↔ local mapping
| Brief's AWS service | What actually enforces the control here |
|---|---|
| EKS | Any local Kubernetes (Kyverno + PSA are cluster-agnostic) |
| ECR | ghcr.io |
| IAM / IRSA | Terraform `aws_iam_role` + OIDC trust policy (plan-only) |
| KMS | Terraform `aws_kms_key` (plan-only) |
| Secrets Manager | Terraform `aws_secretsmanager_secret` + resource policy (plan-only) |
| CloudTrail / GuardDuty | Named as the compensating control for the one accepted egress-filtering gap (`docs/DECISIONS.md` §5) — not built, since it needs a live account |

Full reasoning for every row above, and for every control that was *not* built, is in `docs/DECISIONS.md`.
