# ARMO Azure deployment templates

Public, versioned ARM JSON templates + teardown scripts that ARMO's Azure onboarding / offboarding
commands fetch — the deploy command via `az deployment sub create --template-uri ...`, and the
whole-tenant deletion flow via the cleanup script below.

These are **published artifacts** mirrored from the (private) `cdr-agents` repository
(`azure/*`) — the JSON is compiled from the Bicep sources, the script is copied verbatim. `cdr-agents`
is the source of truth; do not edit here by hand. **Interim host** (public GitHub); the permanent home
is an Azure Blob container published by CI on merge.

Consumers pin a **commit-specific** raw URL so a deployed command always points at an immutable revision.

## Contents
- `cdr/single-subscription.json` — single-subscription CDR collector (`azure/main.bicep`).
  Subscription-scoped; also deployed **once** into the security subscription to create the central
  collector for a whole-tenant onboarding.
- `cdr/tenant-policy.json` — whole-tenant DINE policy (`azure/tenant-policy.bicep`).
  Management-group-scoped (`az deployment mg create`); assigns the policy that routes every in-scope
  subscription's Activity Log to the central Event Hub created above. It is the **second** half of a
  tenant onboarding, not an alternative to the first.
- `cdr/tenant-cleanup.sh` — whole-tenant teardown (`azure/tenant-cleanup.sh`): removes the DINE policy,
  remediation, the diagnostic settings it created across all in-scope subscriptions, and the collector's
  role assignments. Fetched by the tenant deletion flow.
