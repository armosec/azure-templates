#!/usr/bin/env bash
#
# ARMO CDR — whole-tenant teardown.
#
# Removing the DINE policy assignment does NOT delete the Activity-Log diagnostic settings it
# already created in each subscription — they keep trying to push to a torn-down Event Hub. This
# script does the full cleanup, in the order that avoids orphans:
#
#   1. Resolve everything the later steps depend on — the remediation identity, its role assignments,
#      and the in-scope subscription list — BEFORE deleting anything, since the policy assignment is
#      what makes them discoverable. Abort if the subscription list can't be resolved.
#   2. Cancel + delete the remediation task, then delete the policy assignment and definition.
#      First, so nothing recreates the diagnostic settings mid-teardown: deleting the assignment does
#      NOT synchronously cancel an in-flight remediation, so a running task's deployments could still
#      recreate settings after the step-3 sweep unless we cancel it up front.
#   3. Delete the "armo-cdr-activity" diagnostic setting from every subscription under the
#      management group, plus the one main.bicep puts on the security subscription itself (which the
#      management-group sweep won't cover if the security sub sits outside the torn-down MG).
#   4. Delete the remediation identity's role assignments (Monitoring Contributor at the management
#      group; Event Hub listKeys in the security subscription) by resource ID.
#   5. Optionally delete the central collector stack (its resource group) in the security
#      subscription.
#
# It is idempotent: already-deleted resources are skipped, so a re-run after a partial failure is
# safe. Run it signed in with `az`, with the same rights used to onboard (Owner / User Access
# Administrator at the management group + the security subscription).
#
# Usage:
#   tenant-cleanup.sh --management-group <MG_ID> --security-subscription <SUB_ID> \
#                     --eventhub-namespace <NS> \
#                     [--resource-group armo-cdr] [--diagnostic-setting-name armo-cdr-activity] \
#                     [--allow-no-subscriptions] [--delete-central-stack] [--dry-run] [--yes]
# --eventhub-namespace is required: without it the central Event Hub role assignment can't be
# located, leaving an orphaned role assignment in the security subscription's IAM. Pass the bare
# namespace name, not the FQDN that main.bicep outputs.
set -euo pipefail

MG=""
SECURITY_SUB=""
RESOURCE_GROUP="armo-cdr"
EVENTHUB_NAMESPACE=""
DIAG_NAME="armo-cdr-activity"
POLICY_NAME="armo-cdr-activitylog-to-eventhub"
REMEDIATION_NAME="armo-cdr-activitylog-remediation"
DELETE_CENTRAL_STACK=false
ALLOW_NO_SUBS=false
DRY_RUN=false
ASSUME_YES=false

# Fail with a clear usage error (exit 2) when a valued option has no argument — e.g. it was the last
# token on the command line. Without this guard, `MG="$2"` under `set -u` aborts with a cryptic
# "unbound variable" instead. $1 = option name, $2 = remaining arg count ($# at the call site).
need_val() {
  [[ "$2" -ge 2 ]] || { echo "error: option '$1' requires a value" >&2; exit 2; }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --management-group) need_val "$1" "$#"; MG="$2"; shift 2 ;;
    --security-subscription) need_val "$1" "$#"; SECURITY_SUB="$2"; shift 2 ;;
    --resource-group) need_val "$1" "$#"; RESOURCE_GROUP="$2"; shift 2 ;;
    --eventhub-namespace) need_val "$1" "$#"; EVENTHUB_NAMESPACE="$2"; shift 2 ;;
    --diagnostic-setting-name) need_val "$1" "$#"; DIAG_NAME="$2"; shift 2 ;;
    --policy-name) need_val "$1" "$#"; POLICY_NAME="$2"; shift 2 ;;
    --allow-no-subscriptions) ALLOW_NO_SUBS=true; shift ;;
    --delete-central-stack) DELETE_CENTRAL_STACK=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$MG" || -z "$SECURITY_SUB" || -z "$EVENTHUB_NAMESPACE" ]]; then
  echo "error: --management-group, --security-subscription and --eventhub-namespace are required" >&2
  exit 2
fi

for tool in az jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '${tool}' is required but not on PATH" >&2; exit 2; }
done

# Event Hub namespace names can't contain dots, so a dotted value is the FQDN. main.bicep's output is
# confusingly named `eventHubNamespace` but holds the FQDN; pasting it here would build a scope that
# matches nothing and silently leave the role assignment behind.
if [[ "$EVENTHUB_NAMESPACE" == *.* ]]; then
  echo "error: --eventhub-namespace must be the bare namespace name, not an FQDN (got '${EVENTHUB_NAMESPACE}')." >&2
  echo "       Strip the '.servicebus.windows.net' suffix from main.bicep's eventHubNamespace output." >&2
  exit 2
fi

MG_SCOPE="/providers/Microsoft.Management/managementGroups/${MG}"
NS_SCOPE="/subscriptions/${SECURITY_SUB}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.EventHub/namespaces/${EVENTHUB_NAMESPACE}"

FAILURES=0

# run: echo a command, then run it unless --dry-run. An already-gone resource is tolerated (so a
# re-run after partial teardown is safe), but any other failure (permissions, throttling, bad args)
# is surfaced with its output, counted in FAILURES, AND returned as a non-zero status. A bare
# `run <cmd>` therefore aborts the script under `set -e` (fail closed); steps that must keep sweeping
# every item despite one failure use `run <cmd> || true`, which still counts it for the final exit code.
run() {
  echo "+ $*"
  [[ "$DRY_RUN" == "true" ]] && return 0
  local out rc=0
  out=$("$@" 2>&1) || rc=$?
  if [[ $rc -eq 0 ]]; then
    return 0
  fi
  # Tolerated no-op cases: "No matched assignments were found" is `az role assignment delete`'s
  # already-gone case; "not in a cancelable state" is `az policy remediation cancel` on a task that
  # has already completed (nothing to cancel — the delete that follows still cleans it up).
  if grep -qiE "not found|could not be found|does not exist|ResourceNotFound|no longer exists|No matched assignments were found|not in a cancelable state" <<<"$out"; then
    echo "  (already gone)"
    return 0
  fi
  echo "  WARNING: command failed (rc=${rc}):" >&2
  echo "${out}" >&2
  FAILURES=$((FAILURES + 1))
  # Return the failure so a bare `run <cmd>` fails closed under `set -e`. Without this, an assignment
  # is run()'s last statement and it returns 0, hiding the failure from the caller — e.g. a failed
  # remediation-cancel would let the script go on to delete the policy while a live remediation keeps
  # recreating the diagnostic settings this teardown is removing.
  return "$rc"
}

if [[ "$ASSUME_YES" == "false" && "$DRY_RUN" == "false" ]]; then
  echo "This deletes the ARMO CDR diagnostic settings across every subscription under management group '${MG}',"
  echo "removes the policy assignment/definition, and (optionally) the central stack in subscription '${SECURITY_SUB}'."
  read -r -p "Continue? [y/N] " reply
  [[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "aborted"; exit 1; }
fi

# 1. Resolve everything the later steps need BEFORE deleting anything.
echo "== Resolving the policy assignment's remediation identity =="
# The system-assigned identity is deleted along with the assignment in step 2, so capture it now.
PRINCIPAL_ID="$(az policy assignment show --name "$POLICY_NAME" --scope "$MG_SCOPE" \
  --query 'identity.principalId' -o tsv 2>/dev/null || true)"
echo "principalId: ${PRINCIPAL_ID:-<none found>}"

# Capture the identity's role assignments as resource IDs while its principal still resolves. Step 4
# deletes them with `--ids`: after step 2 the principal is gone from Entra, and `--assignee` would
# fail there ("Cannot find user or service principal in graph database") because az resolves that
# value through Microsoft Graph. Deleting by ID needs no Graph lookup at all.
ROLE_ASSIGNMENT_IDS=""
EMPTY_SCOPES=""
if [[ -n "$PRINCIPAL_ID" ]]; then
  for scope in "$MG_SCOPE" "$NS_SCOPE"; do
    if ! ids="$(az role assignment list --scope "$scope" --assignee-object-id "$PRINCIPAL_ID" \
                  --fill-principal-name false --fill-role-definition-name false \
                  --query '[].id' -o tsv 2>&1)"; then
      echo "  WARNING: could not list role assignments at ${scope}:" >&2
      echo "${ids}" >&2
      echo "  its role assignment (if any) will be left behind — check that scope's IAM by hand." >&2
      FAILURES=$((FAILURES + 1))
      continue
    fi
    if [[ -z "$ids" ]]; then
      # The assignment still exists (we resolved its principal), so it should hold a role assignment
      # at both scopes. None here usually means --resource-group / --eventhub-namespace point at the
      # wrong namespace, which would otherwise leave an orphan behind silently.
      EMPTY_SCOPES+="    ${scope}"$'\n'
      continue
    fi
    ROLE_ASSIGNMENT_IDS+="${ids}"$'\n'
  done
  if [[ -n "$EMPTY_SCOPES" ]]; then
    # Warn but don't count this as a failure: it's expected on a re-run where the role assignments
    # were already deleted while the policy assignment (and thus its resolvable identity) remains —
    # counting it would make a clean re-run exit non-zero. The likelier-to-matter cause, a wrong
    # --resource-group/--eventhub-namespace, is caught up front by the FQDN guard.
    echo "  WARNING: the remediation identity holds no role assignment at:" >&2
    printf '%s' "$EMPTY_SCOPES" >&2
    echo "  Expected if they were already removed (e.g. a re-run); otherwise check that" >&2
    echo "  --resource-group/--eventhub-namespace match the central stack before treating this as complete." >&2
  fi
fi

echo "== Resolving in-scope subscriptions =="
if ! MG_JSON="$(az account management-group show --name "$MG" --expand --recurse -o json 2>&1)"; then
  echo "error: could not enumerate subscriptions under '${MG}':" >&2
  echo "${MG_JSON}" >&2
  echo "Aborting before any deletion: removing the policy without sweeping the diagnostic settings" >&2
  echo "would leave every subscription streaming to a torn-down Event Hub, with no policy left to" >&2
  echo "identify them. Fix the management group ID / your access and re-run." >&2
  exit 1
fi
SUB_IDS="$(jq -r '[.. | objects | select(.type == "/subscriptions") | .name] | unique[]' <<<"$MG_JSON")"
if [[ -z "$SUB_IDS" ]]; then
  if [[ "$ALLOW_NO_SUBS" == "true" ]]; then
    echo "  no subscriptions under '${MG}'; continuing because --allow-no-subscriptions was passed"
  else
    echo "error: no subscriptions resolved under '${MG}' — check the management group ID and that you" >&2
    echo "have read access to the whole hierarchy. If the management group genuinely has no" >&2
    echo "subscriptions, re-run with --allow-no-subscriptions." >&2
    exit 1
  fi
else
  echo "  $(grep -c . <<<"$SUB_IDS") subscription(s) in scope"
fi

# 2. Stop anything that could recreate the diagnostic settings, then remove the policy. Cancel the
#    remediation task FIRST: deleting the assignment doesn't synchronously stop an in-flight
#    remediation, so a running task's deployments could recreate settings after the step-3 sweep.
#    Then delete the remediation task (orphaned otherwise), the assignment, and the definition.
# These run() calls are intentionally NOT `|| true`: if the remediation can't be stopped, run()
# returns non-zero and `set -e` aborts here, before the policy is deleted — leaving the policy in
# place (safe, re-runnable) rather than removing it while a live remediation recreates settings.
echo "== Cancelling and deleting the remediation task =="
run az policy remediation cancel --name "$REMEDIATION_NAME" --management-group "$MG"
run az policy remediation delete --name "$REMEDIATION_NAME" --management-group "$MG"

echo "== Deleting the policy assignment and definition =="
run az policy assignment delete --name "$POLICY_NAME" --scope "$MG_SCOPE"
run az policy definition delete --name "$POLICY_NAME" --management-group "$MG"

# 3. Delete the diagnostic setting from every subscription under the management group (recursively).
#    Safe now that the policy is gone — nothing recreates them.
echo "== Deleting diagnostic settings across in-scope subscriptions =="
# Serial by design: teardown is rare and this keeps per-subscription failure handling simple. If it
# ever needs to be faster on a very large tenant, use a bounded pool (e.g. xargs -P 8) rather than
# unbounded '&' background jobs — those would hit ARM rate limits and lose per-subscription errors.
for sub in $SUB_IDS; do
  # || true: one subscription's failure must not strand the rest still streaming to a dead hub (and
  # a re-run would keep aborting on the same sub). run() has already counted it for the final exit.
  run az monitor diagnostic-settings subscription delete \
    --name "$DIAG_NAME" --subscription "$sub" --yes || true
done

# main.bicep also puts a subscription-level diagnostic setting on the security subscription itself
# (its own Activity Log -> the central hub). It is subscription-scoped, so `az group delete` never
# removes it, and the sweep above only covers it if the security sub happens to sit under this
# management group. Delete it explicitly so it can't be orphaned pointing at a torn-down hub —
# tolerated no-op if the sweep already handled it or the security sub was onboarded by policy only.
run az monitor diagnostic-settings subscription delete \
  --name "$DIAG_NAME" --subscription "$SECURITY_SUB" --yes || true

# 4. Delete the remediation identity's role assignments, by ID (captured in step 1).
echo "== Removing remediation-identity role assignments =="
if [[ -n "${ROLE_ASSIGNMENT_IDS//[[:space:]]/}" ]]; then
  while read -r ra_id; do
    [[ -n "$ra_id" ]] || continue
    # || true: keep removing the remaining assignments even if one delete fails (counted by run()).
    run az role assignment delete --ids "$ra_id" || true
  done <<<"$ROLE_ASSIGNMENT_IDS"
elif [[ -n "$PRINCIPAL_ID" ]]; then
  echo "  none found for the remediation identity — already removed"
else
  echo "  policy assignment already gone, so no identity to clean up (expected on a re-run)"
fi

# 5. Optionally delete the central collector stack (its resource group).
if [[ "$DELETE_CENTRAL_STACK" == "true" ]]; then
  echo "== Deleting the central collector stack (resource group '${RESOURCE_GROUP}') =="
  # || true: let the run reach the final summary/exit-code path even if this last delete fails.
  run az group delete --name "$RESOURCE_GROUP" --subscription "$SECURITY_SUB" --yes || true
else
  echo "== Leaving the central collector stack in place (pass --delete-central-stack to remove it) =="
fi

if [[ "$DRY_RUN" == "false" && $FAILURES -gt 0 ]]; then
  echo "Completed with ${FAILURES} error(s) — teardown may be incomplete. Review the warnings above and re-run." >&2
  exit 1
fi

echo "Done."
