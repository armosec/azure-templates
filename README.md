# ARMO Azure deployment templates

Public, versioned ARM JSON templates that ARMO's Azure onboarding deploy commands fetch via
`az deployment sub create --template-uri ...`.

These are **generated artifacts** — compiled from the Bicep sources in the (private) `cdr-agents`
repository (`azure/*.bicep`). Do not edit by hand; regenerate from the source.

Consumers pin a **commit-specific** raw URL so a deployed onboarding command always points at an
immutable template revision.

## Contents
- `cdr/single-subscription.json` — single-subscription CDR collector (`azure/main.bicep`).
