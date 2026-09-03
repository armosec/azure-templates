#!/usr/bin/env bash
# ARMO CDR — whole-tenant (organization-level) Activity-Log fan-in.
#
# Runs AFTER the central collector has been deployed into the security subscription (the single
# `az deployment sub create`, emitted inline by the onboarding command). This script performs the
# management-group half of onboarding: assign the DINE policy at the tenant root, grant the policy's
# remediation identity the roles it needs, grant the collector identity the roles its new-subscription
# reconcile loop needs, and kick off remediation so every already-existing subscription streams its
# Activity Log to the central Event Hub. Subscriptions created later are wired by the collector's
# reconcile loop (the DINE policy alone does not evaluate a new subscription promptly, nor can its
# identity register the provider a new subscription needs).
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
#                     [--diagnostic-setting-name armo-cdr-activity] \
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
DIAG_SETTING_NAME="armo-cdr-activity" # the diagnostic setting the DINE policy deploys per subscription. MUST match tenant-policy.bicep's diagnosticSettingName (its default today) — the self-heal below identifies our remediation deployments by it. Overridable via --diagnostic-setting-name so it can be kept in lockstep if the backend ever passes a non-default (as it does for --policy-name).
TENANT_POLICY_DEPLOY_NAME="armo-cdr-tenant-policy"
SEND_RULE_NAME="armo-cdr-diagnostics-send"
MONITORING_CONTRIBUTOR_ROLE_ID="749f88d5-cbae-40b8-bcfc-e573ddc772fa" # built-in; matches tenant-policy.bicep
EVENTHUB_DATA_OWNER_ROLE="Azure Event Hubs Data Owner"
COLLECTOR_IDENTITY_NAME="armo-cdr-collector"  # the collector's user-assigned identity (resources.bicep)
# Roles the collector identity's new-subscription reconcile loop needs at the management-group root.
MG_READER_ROLE_ID="ac63b705-f282-497d-ac71-919bf39d939d"                    # built-in Management Group Reader
RESOURCE_POLICY_CONTRIBUTOR_ROLE_ID="36243c78-bf99-498c-9df9-86d9f8d28608"  # built-in Resource Policy Contributor
REGISTRAR_ROLE_NAME="ARMO CDR Subscription Registrar"                       # custom role defined below
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
    --diagnostic-setting-name) need_val "$1" "$#"; DIAG_SETTING_NAME="$2"; shift 2 ;;
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
  # `|| reply=""`: without --yes on a non-interactive stdin (piped/CI), `read` hits EOF and returns
  # non-zero, which under `set -e` would abort here instead of reaching the clean "aborted." path below.
  read -r -p "Assign the ARMO CDR fan-in policy at management group '${MG}' and wire its subscriptions? [y/N] " reply || reply=""
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
    --parameters location="$LOCATION" centralEventHubAuthorizationRuleId="$AUTH_RULE_ID" centralEventHubName="$EVENTHUB_NAME" diagnosticSettingName="$DIAG_SETTING_NAME" \
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
# `--assignee` does, which lags for a just-created policy identity. When the create runs it is
# fail-closed (bare `run`, no `|| true`): a genuine failure (e.g. the operator lacks User Access
# Administrator) must abort with the clear AuthorizationFailed rather than press on into a 5-minute
# silent wait and a vague "could not start remediation" further down. Re-run safety is handled by the
# check-then-create below, NOT by the create being idempotent: `az role assignment create` is NOT safe
# to re-run on an existing management-group assignment (it crashes — see the block below).
echo "== Granting the remediation identity its roles =="
# Idempotent grants. A re-onboard reuses the same policy-assignment identity (the assignment name is
# fixed, so `az deployment mg create` keeps its system-assigned principal), which means its grants may
# already exist. `az role assignment create` is NOT safe to re-run on an existing MG-scoped assignment:
# on RoleAssignmentExists the CLI tries to return the existing one via a role-id lookup that yields
# nothing at management-group scope (the same quirk as the readback below) and crashes with
# "IndexError: list index out of range" instead of a clean no-op. So create each grant only when it's
# absent, keyed on the role it grants. (--dry-run: skip the reads — the principal is a placeholder —
# and just show the creates.)
mc_present=""; eh_present=""
if [[ "$DRY_RUN" != "true" ]]; then
  # Fail CLOSED on a read we can't complete. An empty result (exit 0) means the grant is absent and we
  # create it below; but a NON-ZERO list (throttling / missing read access) must NOT be read as "absent"
  # — that would attempt a create on an assignment that may already exist and crash with the same
  # IndexError described above. Distinguish the two by the list's exit status (not `2>/dev/null || true`,
  # which conflates them) and abort with a clear, re-runnable error.
  mc_present="$(az role assignment list --scope "$MG_SCOPE" --assignee-object-id "$PRINCIPAL" \
    --query "[?contains(roleDefinitionId, '$MONITORING_CONTRIBUTOR_ROLE_ID')].id | [0]" -o tsv)" || {
    echo "error: could not read role assignments at the management group (throttling / access?) — re-run." >&2; exit 1; }
  eh_present="$(az role assignment list --scope "$NS_SCOPE" --assignee-object-id "$PRINCIPAL" \
    --role "$EVENTHUB_DATA_OWNER_ROLE" --query '[0].id' -o tsv)" || {
    echo "error: could not read role assignments on the Event Hub namespace (throttling / access?) — re-run." >&2; exit 1; }
fi
if [[ -n "$mc_present" ]]; then
  echo "  Monitoring Contributor already granted at the management group — skipping"
else
  run az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
    --role "$MONITORING_CONTRIBUTOR_ROLE_ID" --scope "$MG_SCOPE"
fi
if [[ -n "$eh_present" ]]; then
  echo "  Azure Event Hubs Data Owner already granted on the namespace — skipping"
else
  run az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
    --role "$EVENTHUB_DATA_OWNER_ROLE" --scope "$NS_SCOPE"
fi

# 4b. Wait until BOTH grants are READABLE before remediating — each remediation deployment exercises
# them asynchronously, and RBAC propagation lags creation. Both checks are filtered by role so an
# unrelated assignment at either scope can't satisfy the wait early. Skipped under --dry-run (no grants
# were made, and the reads + sleeps would otherwise make dry-run neither offline nor quick).
if [[ "$DRY_RUN" != "true" ]]; then
  echo "== Waiting for the role grants to propagate =="
  for _ in $(seq 1 20); do
    # `az role assignment list --role <GUID>` does NOT match at management-group scope (only the role
    # NAME matches there), so this readback would never see the grant and the wait would always time out.
    # Filter client-side on roleDefinitionId instead, keyed on the same built-in GUID the grant used. The
    # Event Hub check is at resource scope and matches fine by role name.
    mc="$(az role assignment list --scope "$MG_SCOPE" --assignee-object-id "$PRINCIPAL" --query "[?contains(roleDefinitionId, '$MONITORING_CONTRIBUTOR_ROLE_ID')].id | [0]" -o tsv 2>/dev/null || true)"
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
    echo "       Per-subscription remediation would fail. Likely causes: you lack User Access Administrator" >&2
    echo "       to create the grants, or the role-assignment reads were throttled. Verify access and re-run." >&2
    exit 1
  }
fi

# 4c. Grant the COLLECTOR identity the roles its new-subscription reconcile loop needs. This is a
# DIFFERENT principal from the policy remediation identity above: the collector (a user-assigned identity
# created with the central stack) runs a loop that wires subscriptions added after onboarding — it lists
# subscriptions, registers Microsoft.Insights, clears stale remediation-deployment records, and triggers
# the policy's per-subscription remediation. The diagnostic-setting deployment is still performed by the
# policy identity (Monitoring Contributor, granted above); the collector only starts remediation.
echo "== Granting the collector identity its reconcile roles =="
if [[ "$DRY_RUN" == "true" ]]; then
  COLLECTOR_PRINCIPAL="00000000-0000-0000-0000-000000000000" # placeholder; no reads in dry-run
else
  # Resolve the collector's principal id from its user-assigned identity. Fail closed: the central-stack
  # deploy that creates it runs before this script, so a missing identity means a broken onboarding, not a
  # state to press past.
  COLLECTOR_PRINCIPAL="$(az identity show --name "$COLLECTOR_IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" \
    --subscription "$SECURITY_SUB" --query principalId -o tsv)" || {
    echo "error: could not resolve collector identity '${COLLECTOR_IDENTITY_NAME}' in resource group '${RESOURCE_GROUP}' (subscription '${SECURITY_SUB}') — is the central collector stack deployed?" >&2; exit 1; }
  [[ -n "$COLLECTOR_PRINCIPAL" ]] || {
    echo "error: collector identity '${COLLECTOR_IDENTITY_NAME}' has no principal id — is the central collector stack deployed?" >&2; exit 1; }
fi
echo "collector identity: ${COLLECTOR_PRINCIPAL}"

# Ensure the custom role exists. A narrow role — exactly the three actions the loop needs — rather than a
# built-in that includes */register/action (e.g. Contributor), which is far too broad to grant tenant-wide.
# deployments/delete is for the stale-record self-heal. Idempotent: create only when absent (a re-onboard
# reuses it). Fail closed on a read we can't complete, exactly like the grant reads below.
#
# Constraint: the role NAME is tenant-global while AssignableScopes is pinned to this MG. So if the SAME
# tenant is ever onboarded at a SECOND management group (the script permits any --management-group), the
# read below finds nothing at the new scope, this create runs, and Azure rejects it with
# RoleDefinitionWithSameNameExists — a bare run() then aborts (fail-closed, but with a non-obvious error).
# Not a concern for V1 (whole-tenant is pre-release and tenant-root-only); if MG tiers are ever exposed,
# either look the role up by name tenant-wide and extend its AssignableScopes, or make the name scope-unique.
role_present=""
if [[ "$DRY_RUN" != "true" ]]; then
  role_present="$(az role definition list --custom-role-only true --name "$REGISTRAR_ROLE_NAME" --scope "$MG_SCOPE" --query '[0].roleName' -o tsv)" || {
    echo "error: could not read custom role definitions at the management group (throttling / access?) — re-run." >&2; exit 1; }
fi
if [[ -n "$role_present" ]]; then
  echo "  custom role '${REGISTRAR_ROLE_NAME}' already defined — skipping"
else
  run az role definition create --role-definition "$(cat <<JSON
{
  "Name": "${REGISTRAR_ROLE_NAME}",
  "Description": "ARMO CDR: register Microsoft.Insights / Microsoft.PolicyInsights and delete stale policy-remediation deployment records, for the collector's new-subscription reconcile loop.",
  "Actions": [
    "Microsoft.Insights/register/action",
    "Microsoft.PolicyInsights/register/action",
    "Microsoft.Resources/deployments/delete"
  ],
  "AssignableScopes": ["${MG_SCOPE}"]
}
JSON
)"
  # A freshly-created custom role definition is not immediately assignable — wait until it is readable at
  # the assignment scope before granting it, so a first onboard doesn't need a re-run to get past this.
  # Fail fast (like the remediation-grant readback) if it never becomes readable, so the cause is clear
  # rather than surfacing below as a cryptic "role not found" role-assignment error.
  if [[ "$DRY_RUN" != "true" ]]; then
    role_ready=false
    for _ in $(seq 1 12); do
      if [[ -n "$(az role definition list --custom-role-only true --name "$REGISTRAR_ROLE_NAME" --scope "$MG_SCOPE" --query '[0].roleName' -o tsv 2>/dev/null || true)" ]]; then
        role_ready=true; break
      fi
      sleep 5
    done
    [[ "$role_ready" == "true" ]] || {
      echo "error: custom role '${REGISTRAR_ROLE_NAME}' did not become readable within the timeout (RBAC" >&2
      echo "       replication lag) — its grants below would fail with a less actionable error. The role" >&2
      echo "       definition was created and should be readable shortly; re-run." >&2
      exit 1
    }
  fi
fi

# Grant the collector its three roles at the management-group root, with the same idempotency + fail-closed
# reads as the policy-identity grants: create each only when absent (az role assignment create crashes on
# an existing MG assignment), and a NON-ZERO read (throttling / access) must abort rather than be mistaken
# for "absent". At management-group scope `--role <GUID>` does not match on reads, so the built-in roles are
# checked client-side on roleDefinitionId; the custom role matches by name.
grant_collector_mg_role() { # $1 = human name (log), $2 = present-id, $3 = role (GUID or name)
  if [[ -n "$2" ]]; then
    echo "  $1 already granted to the collector at the management group — skipping"
  else
    run az role assignment create --assignee-object-id "$COLLECTOR_PRINCIPAL" --assignee-principal-type ServicePrincipal \
      --role "$3" --scope "$MG_SCOPE"
  fi
}
reader_present=""; rpc_present=""; registrar_present=""
if [[ "$DRY_RUN" != "true" ]]; then
  reader_present="$(az role assignment list --scope "$MG_SCOPE" --assignee-object-id "$COLLECTOR_PRINCIPAL" \
    --query "[?contains(roleDefinitionId, '$MG_READER_ROLE_ID')].id | [0]" -o tsv)" || {
    echo "error: could not read the collector's role assignments at the management group (throttling / access?) — re-run." >&2; exit 1; }
  rpc_present="$(az role assignment list --scope "$MG_SCOPE" --assignee-object-id "$COLLECTOR_PRINCIPAL" \
    --query "[?contains(roleDefinitionId, '$RESOURCE_POLICY_CONTRIBUTOR_ROLE_ID')].id | [0]" -o tsv)" || {
    echo "error: could not read the collector's role assignments at the management group (throttling / access?) — re-run." >&2; exit 1; }
  registrar_present="$(az role assignment list --scope "$MG_SCOPE" --assignee-object-id "$COLLECTOR_PRINCIPAL" \
    --role "$REGISTRAR_ROLE_NAME" --query '[0].id' -o tsv)" || {
    echo "error: could not read the collector's role assignments at the management group (throttling / access?) — re-run." >&2; exit 1; }
fi
grant_collector_mg_role "Management Group Reader" "$reader_present" "$MG_READER_ROLE_ID"
grant_collector_mg_role "Resource Policy Contributor" "$rpc_present" "$RESOURCE_POLICY_CONTRIBUTOR_ROLE_ID"
grant_collector_mg_role "custom role '${REGISTRAR_ROLE_NAME}'" "$registrar_present" "$REGISTRAR_ROLE_NAME"

# 5. Kick off a fresh compliance evaluation + remediation PER SUBSCRIPTION. Per-subscription because
# ReEvaluateCompliance (the only way not to wait on Azure's passive evaluation cycle) is rejected at
# management-group scope but permitted at subscription scope; passing the FULL management-group
# assignment id is what binds it there. Best-effort per subscription; do NOT block on completion —
# per-subscription wiring is confirmed out-of-band (nothing is observable in-band for ~13 min).
echo "== Kicking off remediation across in-scope subscriptions =="
failed=""
for sub in $SUBS; do
  # Self-heal a re-onboard. Azure Policy names each remediation deployment deterministically from the
  # (fixed) policy name + subscription, so a previous onboarding of this tenant leaves a same-named
  # PolicyDeployment_* record in the subscription's deployment history. Teardown removes the diagnostic
  # setting and the assignment but NOT that history record, so on re-onboard the remediation's internal
  # "Create Deployment" hits 409 Conflict and the subscription silently never re-wires. Delete our
  # leftover record(s) first so the remediation can recreate the same-named deployment cleanly.
  #
  # One `az deployment sub list` per subscription (not a list + a show per record): DeploymentExtended
  # carries properties.parameters, so we match on the diagnostic-setting name the deployment was CREATED
  # with. That matches whether the prior remediation succeeded OR failed — a failed record has no
  # outputResources but still carries the parameters it was submitted with, and its retained name 409s
  # just the same — so this also heals the re-run-after-partial-failure case. Matching on our own
  # parameter value never touches an unrelated policy's PolicyDeployment; deleting a history record
  # affects no live resource.
  #
  # Fail CLOSED on a read we can't complete: an empty result (exit 0) means "no leftover records" and is
  # fine, but a non-zero `list` (throttling / missing read access) means we can't prove the sub is clean,
  # so we must not risk a silent 409 — flag it like a failed delete. Guarded from --dry-run (live reads).
  heal_ok=true
  if [[ "$DRY_RUN" != "true" ]]; then
    if stale="$(az deployment sub list --subscription "$sub" \
        --query "[?starts_with(name, 'PolicyDeployment_') && properties.parameters.diagnosticSettingName.value == '${DIAG_SETTING_NAME}'].name" \
        -o tsv)"; then
      for dep in $stale; do
        run az deployment sub delete --subscription "$sub" --name "$dep" || heal_ok=false
      done
    else
      heal_ok=false
    fi
  fi
  # If a conflicting record couldn't be cleared (or even confirmed absent), remediation on this sub would
  # risk a 409 and silently not re-wire — flag it via the summary warning and skip the doomed remediation,
  # rather than let a partial fan-in look like success.
  if [[ "$heal_ok" != "true" ]]; then
    failed="$failed $sub"
    continue
  fi
  # Suppress only stdout (the success JSON); keep stderr so a per-subscription failure's az error is
  # visible next to the summary warning, not hidden.
  run az policy remediation create --name "$REMEDIATION_NAME" --subscription "$sub" \
    --policy-assignment "$ASSIGNMENT_ID" --resource-discovery-mode ReEvaluateCompliance >/dev/null \
    || failed="$failed $sub"
done
# Honest exit code: if any subscription could not be healed or have remediation started, this run is
# INCOMPLETE — exit non-zero so a caller keying off the exit status (and the operator) knows to re-run,
# rather than printing the success banner over a partial fan-in. The remaining subscriptions' fan-in is
# unaffected and continues in the background; a re-run retries only the ones listed.
if [[ -n "$failed" ]]; then
  echo "" >&2
  echo "WARNING: onboarding is INCOMPLETE on:$failed" >&2
  echo "  — could not clear a conflicting deployment or start remediation there (insufficient access /" >&2
  echo "  throttling?). Re-running is safe and retries only those subscriptions." >&2
  exit 1
fi

echo ""
echo "ARMO CDR: tenant onboarding submitted. Activity-Log fan-in completes asynchronously"
echo "(~10-15 minutes) — you do not need to keep this shell open."
