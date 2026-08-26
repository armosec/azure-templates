#!/usr/bin/env bash
# ARMO CDR — whole-tenant (organization-level) Activity-Log fan-in.
#
# Runs AFTER the central collector has been deployed into the security subscription (the single
# `az deployment sub create`, emitted inline by the onboarding command). This script performs the
# management-group half of onboarding: assign the DINE policy at the tenant root, grant the policy's
# remediation identity the roles it needs, and kick off remediation so every already-existing
# subscription streams its Activity Log to the central Event Hub. Subscriptions created later are
# wired automatically by the policy, with no re-run.
#
# It is the inverse of tenant-cleanup.sh and mirrors its shape (arg parsing, run() helper, honest
# exit code). Delivered as a DOWNLOADED script — curl'd to a file and run, not pasted inline — so its
# `set -euo pipefail` and any `exit` affect only this process, never the operator's interactive Cloud
# Shell (a pasted strict-mode script closes the whole shell on the first non-zero command).
#
# It deliberately does NOT block on fan-in completing. Remediation is asynchronous (~10-15 min); making
# the customer hold a Cloud Shell open that long is what let the session time out mid-run before. This
# script submits remediation and returns. Per-subscription wiring cannot be confirmed in-band:
# ReEvaluateCompliance leaves nothing observable for ~13 min, so any short poll would report zero and
# false-fail every healthy run. Authoritative per-subscription coverage is surfaced out-of-band by the
# backend (the collector's heartbeat only tells the tenant it is alive, not which subscriptions wired).
# The catastrophic cases ARE caught synchronously here: empty subscription enumeration, a failed role
# grant, and role grants that never become readable all fail closed before remediation.
#
# Idempotent: safe to re-run after a partial failure. Run it signed in with `az`, with Owner or User
# Access Administrator at the management group + the security subscription (the role grants need it).
#
# Usage:
#   tenant-onboard.sh --management-group <MG_ID> --security-subscription <SUB_ID> --location <REGION> \
#                     --eventhub-namespace <NS> --tenant-policy-template-url <URL> \
#                     [--resource-group armo-cdr] [--eventhub-name insights-activity-logs] \
#                     [--policy-name armo-cdr-activitylog] \
#                     [--dry-run] [--yes]
set -euo pipefail

MG=""            # tenant root management-group id (assignment scope + subscription enumeration)
SECURITY_SUB=""         # subscription holding the central Event Hub namespace
LOCATION=""             # region for the policy assignment identity + remediation deployment records
RESOURCE_GROUP="armo-cdr"
EVENTHUB_NAMESPACE=""    # bare namespace name (NOT the FQDN main.bicep outputs)
EVENTHUB_NAME="insights-activity-logs"
TENANT_POLICY_TEMPLATE_URL=""
POLICY_NAME="armo-cdr-activitylog"
REMEDIATION_NAME="armo-cdr-activitylog-remediation"
TENANT_POLICY_DEPLOY_NAME="armo-cdr-tenant-policy"
SEND_RULE_NAME="armo-cdr-diagnostics-send"
MONITORING_CONTRIBUTOR_ROLE_ID="749f88d5-cbae-40b8-bcfc-e573ddc772fa" # built-in; matches tenant-policy.bicep
EVENTHUB_DATA_OWNER_ROLE="Azure Event Hubs Data Owner"
DRY_RUN=false
ASSUME_YES=false

# Fail with a clear usage error (exit 2) when a valued option has no argument, rather than letting
# `set -u` abort with a cryptic "unbound variable". $1 = option name, $2 = remaining arg count.
need_val() { [[ "$2" -ge 2 ]] || { echo "error: option '$1' requires a value" >&2; exit 2; }; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --management-group) need_val "$1" "$#"; MG="$2"; shift 2 ;;
    --security-subscription) need_val "$1" "$#"; SECURITY_SUB="$2"; shift 2 ;;
    --location) need_val "$1" "$#"; LOCATION="$2"; shift 2 ;;
    --resource-group) need_val "$1" "$#"; RESOURCE_GROUP="$2"; shift 2 ;;
    --eventhub-namespace) need_val "$1" "$#"; EVENTHUB_NAMESPACE="$2"; shift 2 ;;
    --eventhub-name) need_val "$1" "$#"; EVENTHUB_NAME="$2"; shift 2 ;;
    --tenant-policy-template-url) need_val "$1" "$#"; TENANT_POLICY_TEMPLATE_URL="$2"; shift 2 ;;
    --policy-name) need_val "$1" "$#"; POLICY_NAME="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$MG" || -z "$SECURITY_SUB" || -z "$LOCATION" || -z "$EVENTHUB_NAMESPACE" || -z "$TENANT_POLICY_TEMPLATE_URL" ]]; then
  echo "error: --management-group, --security-subscription, --location, --eventhub-namespace and --tenant-policy-template-url are required" >&2
  exit 2
fi

for tool in az jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '${tool}' is required but not on PATH (both ship in Azure Cloud Shell)" >&2; exit 2; }
done

# main.bicep's `eventHubNamespace` OUTPUT is the FQDN, but a namespace resource id needs the bare name.
# A dotted value here would build a scope that matches nothing and silently skip the Event Hub grant.
if [[ "$EVENTHUB_NAMESPACE" == *.* ]]; then
  echo "error: --eventhub-namespace must be the bare namespace name, not an FQDN (got '${EVENTHUB_NAMESPACE}')." >&2
  exit 2
fi

# The policy template is fetched by `az deployment mg create --template-uri`. This script is itself
# downloaded and run, so refuse to fetch the template over anything but https — a plain-http (or other
# scheme) template URL is an insecure fetch of code Azure then deploys tenant-wide.
if [[ "$TENANT_POLICY_TEMPLATE_URL" != https://* ]]; then
  echo "error: --tenant-policy-template-url must be an https:// URL (got '${TENANT_POLICY_TEMPLATE_URL}')." >&2
  exit 2
fi

MG_SCOPE="/providers/Microsoft.Management/managementGroups/${MG}"
NS_SCOPE="/subscriptions/${SECURITY_SUB}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.EventHub/namespaces/${EVENTHUB_NAMESPACE}"
AUTH_RULE_ID="${NS_SCOPE}/authorizationRules/${SEND_RULE_NAME}"
ASSIGNMENT_ID="${MG_SCOPE}/providers/Microsoft.Authorization/policyAssignments/${POLICY_NAME}"

# run: log a command to STDERR (so it is safe inside `$(...)` — logging to stdout would pollute a
# captured value), then run it unless --dry-run. Returns the command's status, so a bare `run <cmd>`
# aborts under set -e (fail closed); steps that tolerate a per-item failure catch it explicitly
# (e.g. `run <cmd> || echo WARNING…` for best-effort provider registration, `run <cmd> || failed=…`
# to collect the failed subscriptions).
run() {
  echo "+ $*" >&2
  [[ "$DRY_RUN" == "true" ]] && return 0
  "$@"
}

if [[ "$ASSUME_YES" == "false" && "$DRY_RUN" == "false" ]]; then
  read -r -p "Assign the ARMO CDR fan-in policy at management group '${MG}' and wire its subscriptions? [y/N] " reply
  [[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "aborted."; exit 0; }
fi

# 1. Assign the DINE policy at the tenant root and capture the remediation identity's principal id.
# Not wrapped in run(): this both mutates AND returns a value we capture, so it is logged explicitly and
# the capture is guarded for --dry-run (where the deployment does not actually run).
echo "== Assigning the tenant fan-in policy at the management-group root =="
echo "+ az deployment mg create --name ${TENANT_POLICY_DEPLOY_NAME} --management-group-id ${MG} --template-uri ${TENANT_POLICY_TEMPLATE_URL} ..." >&2
if [[ "$DRY_RUN" == "true" ]]; then
  PRINCIPAL="00000000-0000-0000-0000-000000000000" # placeholder; no deployment in dry-run
else
  PRINCIPAL="$(az deployment mg create --name "$TENANT_POLICY_DEPLOY_NAME" \
    --management-group-id "$MG" --location "$LOCATION" \
    --template-uri "$TENANT_POLICY_TEMPLATE_URL" \
    --parameters location="$LOCATION" centralEventHubAuthorizationRuleId="$AUTH_RULE_ID" centralEventHubName="$EVENTHUB_NAME" \
    --query properties.outputs.policyAssignmentPrincipalId.value -o tsv)"
fi
[[ -n "$PRINCIPAL" ]] || { echo "error: could not resolve the policy assignment's identity principal id" >&2; exit 1; }
echo "policy identity: ${PRINCIPAL}"

# 2. Resolve every subscription under the tenant root. Fail closed on an empty result: a command
# substitution in a `for` list is not checked by set -e, so a silent enumeration failure (no Management
# Group Reader, wrong id, throttling) must not be mistaken for "no subscriptions".
echo "== Resolving in-scope subscriptions =="
if [[ "$DRY_RUN" == "true" ]]; then
  # Keep --dry-run fully offline: don't hit Azure for the enumeration, just show the shape of the loops.
  SUBS="<in-scope-subscription-ids>"
else
  SUBS="$(az account management-group show --name "$MG" --expand --recurse -o json \
    | jq -r '[.. | objects | select(.type == "/subscriptions") | .name] | unique[]')"
  [[ -n "$SUBS" ]] || { echo "error: no subscriptions resolved under the tenant root — check your Management Group Reader access." >&2; exit 1; }
  echo "$(printf '%s\n' "$SUBS" | grep -c .) subscription(s) in scope for Activity-Log fan-in"
fi

# 3. Register the providers remediation relies on, best-effort (one inaccessible subscription must not
# abort onboarding after the policy is assigned; a safe re-run covers any skipped).
echo "== Registering providers on in-scope subscriptions =="
for sub in $SUBS; do
  run az provider register -n microsoft.insights --subscription "$sub" || echo "  WARNING: could not register microsoft.insights on $sub (insufficient access?) — skipping" >&2
  run az provider register -n Microsoft.PolicyInsights --subscription "$sub" || echo "  WARNING: could not register Microsoft.PolicyInsights on $sub — skipping" >&2
done

# 4. Grant the remediation identity BOTH roles each per-subscription remediation deployment needs.
# Granted here, out-of-band, rather than relying on tenant-policy.bicep's in-deployment role assignment:
# a role assignment created in the same management-group deployment as the policy identity is unreliable
# (the identity's principalId may not have replicated), which intermittently leaves it with no
# Monitoring Contributor and every remediation failing PolicyAuthorizationFailed.
#
# `--assignee-object-id` + `--assignee-principal-type ServicePrincipal` skips the Graph lookup that
# `--assignee` does, which lags for a just-created policy identity. `az role assignment create` is
# idempotent on (principal, role, scope) — a re-run returns the existing assignment with exit 0 — so
# these are safe to re-run. NOT guarded with `|| true`: a genuine failure here (e.g. the operator lacks
# User Access Administrator) must abort with the clear AuthorizationFailed rather than press on into a
# 5-minute silent wait and a vague "could not start remediation" further down.
echo "== Granting the remediation identity its roles =="
run az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "$MONITORING_CONTRIBUTOR_ROLE_ID" --scope "$MG_SCOPE"
run az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "$EVENTHUB_DATA_OWNER_ROLE" --scope "$NS_SCOPE"

# 4b. Wait until BOTH grants are READABLE before remediating — each remediation deployment exercises
# them asynchronously, and RBAC propagation lags creation. Both checks are filtered by role so an
# unrelated assignment at either scope can't satisfy the wait early. Skipped under --dry-run (no grants
# were made, and the reads + sleeps would otherwise make dry-run neither offline nor quick).
if [[ "$DRY_RUN" != "true" ]]; then
  echo "== Waiting for the role grants to propagate =="
  for _ in $(seq 1 20); do
    mc="$(az role assignment list --scope "$MG_SCOPE" --assignee-object-id "$PRINCIPAL" --role "$MONITORING_CONTRIBUTOR_ROLE_ID" --query '[0].id' -o tsv 2>/dev/null || true)"
    eh="$(az role assignment list --scope "$NS_SCOPE" --assignee-object-id "$PRINCIPAL" --role "$EVENTHUB_DATA_OWNER_ROLE" --query '[0].id' -o tsv 2>/dev/null || true)"
    [[ -n "$mc" && -n "$eh" ]] && break
    sleep 15
  done
  # Fail fast if a grant never became readable: proceeding would just submit a wave of remediations that
  # all fail PolicyAuthorizationFailed and surface only as a vague warning below. A clear error here points
  # at the real cause (the operator likely lacks User Access Administrator to create the role assignments).
  [[ -n "$mc" && -n "$eh" ]] || {
    echo "error: the remediation identity's role grants (Monitoring Contributor at the management group," >&2
    echo "       Event Hubs Data Owner on the central namespace) did not become readable within the timeout." >&2
    echo "       Per-subscription remediation would fail. Verify you have User Access Administrator, then re-run." >&2
    exit 1
  }
fi

# 5. Kick off a fresh compliance evaluation + remediation PER SUBSCRIPTION. Per-subscription because
# ReEvaluateCompliance (the only way not to wait on Azure's passive evaluation cycle) is rejected at
# management-group scope but permitted at subscription scope; passing the FULL management-group
# assignment id is what binds it there. Best-effort per subscription; do NOT block on completion —
# per-subscription wiring is confirmed out-of-band (nothing is observable in-band for ~13 min).
echo "== Kicking off remediation across in-scope subscriptions =="
failed=""
for sub in $SUBS; do
  # Suppress only stdout (the success JSON); keep stderr so a per-subscription failure's az error is
  # visible next to the summary warning, not hidden.
  run az policy remediation create --name "$REMEDIATION_NAME" --subscription "$sub" \
    --policy-assignment "$ASSIGNMENT_ID" --resource-discovery-mode ReEvaluateCompliance >/dev/null \
    || failed="$failed $sub"
done
[[ -z "$failed" ]] || echo "WARNING: could not start remediation on:$failed (insufficient access?) — a re-run is safe." >&2

echo ""
echo "ARMO CDR: tenant onboarding submitted. Activity-Log fan-in completes asynchronously"
echo "(~10-15 minutes) — you do not need to keep this shell open."
