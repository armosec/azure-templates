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
- `cdr/tenant-cleanup.sh` — whole-tenant teardown (`azure/tenant-cleanup.sh`): removes the DINE policy,
  remediation, the diagnostic settings it created across all in-scope subscriptions, and the collector's
  role assignments. Fetched by the tenant deletion flow.
