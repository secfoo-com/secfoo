---
id: deployment-readiness
name: Deployment Readiness
description: Security and operational readiness review for production deployment.
short_name: Deployment Readiness
version: 1
---

Review this codebase for security and operational deployment readiness.

1. **CI/CD security gates.** Does the pipeline run static analysis (SAST),
   dependency vulnerability scanning, and secret scanning before merge/
   deploy? Are these gates blocking or advisory-only?

2. **Secrets management.** Are there any secrets, API keys, or credentials
   committed to the repository? Is secret retrieval done via a vault or
   parameter store rather than plaintext config or environment files
   checked into version control?

3. **Health & rollback.** Are there health-check endpoints or equivalent
   readiness/liveness signals? Is there a documented or automated rollback
   strategy if a deployment fails?

4. **Observability.** Is there structured logging, metrics, and alerting
   sufficient to detect a security incident or outage in production?

5. **Infrastructure as Code review.** If IaC is present (Terraform,
   CloudFormation, Kubernetes manifests, etc.), check for least-privilege
   IAM roles/policies, network segmentation, and publicly-exposed resources
   that shouldn't be.

6. **Rate limiting & DoS protection.** Are public-facing endpoints protected
   against abuse or denial-of-service?

7. **Backup & disaster recovery.** Is there a backup strategy for any
   persistent data, and is recovery documented or tested?

8. **Dependency hygiene.** Are dependencies pinned to specific versions? Is
   there a software bill of materials (SBOM) or equivalent?

9. **Container hardening.** If a Dockerfile or container manifest is
   present, check for a non-root user, a minimal base image, and no
   unnecessary build tools or secrets baked into the final image layer.
