#!/usr/bin/env bash

###############################################################################
# Kubernetes Incident Diagnostic Scanner v5.7
#
# READ-ONLY / NON-MUTATING KUBERNETES RESOURCE SCANNER.
# (Not "zero side effects": see the kubectl exec note below.)
#
# This script NEVER runs: apply, create, delete, patch, edit, replace,
# scale, rollout restart/undo, cordon, drain, uncordon, taint, label,
# annotate, or any command that changes cluster state. It only uses
# get / describe / logs / top / auth can-i / get --raw for Kubernetes
# resources -- no resource is ever created, modified, or deleted.
#
# EXEC CAVEAT: optionally (OFF by default, ENABLE_POD_NETWORK_TEST=1),
# it runs read-only `kubectl exec` diagnostics (hostname / resolv.conf /
# routes) against EXISTING pods. This does not modify any Kubernetes
# resource, but `kubectl exec` does start a process inside an existing
# container -- so this mode is diagnostic execution, not purely passive
# observation, and stays off by default for that reason.
#
# ENDPOINT PROBE CAVEAT: optionally (OFF by default, ENABLE_ENDPOINT_PROBE=1),
# it issues a single HTTP GET (never POST/PUT/PATCH/DELETE) via `kubectl
# exec` into each Service endpoint's OWN container, at its own loopback
# address. Same category of caveat as above: no Kubernetes object is ever
# created, modified or deleted, but a process is executed and a real
# request is made. Off by default; see section "ENDPOINT PROBE" below.
#
# F5 / EXTERNAL LB HOOK: optionally (F5_LOG_SOURCE and/or F5_LOG_HOOK), this
# scanner can fold findings from an EXTERNAL load balancer / WAF (e.g. F5
# BIG-IP) into the same report. This scanner has no direct access to any
# appliance outside Kubernetes, so this is a pluggable, opt-in hook: you
# point it at a log file/directory you already export, or at your own
# executable that prints log lines to stdout. The scanner only READS
# whatever that hook or file produces -- it never calls out to F5 itself,
# and does not execute anything against F5. See section "F5 / EXTERNAL
# LOAD BALANCER" below.
#
# LIVE LOG VIEWER: before the scan prompts, the script offers to just
# `kubectl logs -f` one chosen pod instead of running a scan at all. Same
# read-only category as every other `logs` call here -- it only reads a
# stream, changes nothing -- and it exits (no scan, no report) once you
# stop watching. See "LIVE LOG VIEWER" below.
#
# TERMINAL SUMMARY (v5): after every scan, a per-layer table (cluster / node /
# service / pod / endpoint) is printed with severity, error message, EXPECTED root
# cause, SINCE (UTC), DURATION and owner. Also saved as terminal-summary.txt. It
# ends by pointing to index.html for the full detail. Optional env vars:
#   TERMINAL_WIDTH (default: auto)   TERMINAL_MAX_ROWS_PER_LAYER (default: 20)
#
# QUIET MODE (v5.1): while scanning, only a progress bar is shown; all detail goes to
# data/scan-console.log and the HTML report. SCAN_VERBOSE=1 prints every finding live.
#
# SEARCH-ID TRACE (v5.2): with a search value, matching log lines from every pod in scope are merged into a
# chronological trace and the summary table is ordered earliest-failure-first. Scope = chosen namespace/pods
# only; with a namespace selected, etcd/CoreDNS log scans are skipped and the ingress scan is limited to it
# (SCOPE_INCLUDE_CLUSTER_COMPONENTS=1 to include them).
#
# v5.3: init-container logs join the ID trace; with a namespace selected, node checks, events, metrics and PVC
# lookups are limited to it too; more finding types get a real start time; with a search ID the table shows
# ID-related findings plus cluster/node context (SEARCH_TABLE_ALL=1 shows everything).
#
# v5.4: READ-ONLY GUARD (every kubectl call goes through an allowlist wrapper) and a much smaller call budget:
# one read per pod, bulk reads per namespace, describe only for unhealthy objects, previous logs only after a
# restart, tail caps on every log pull. The summary prints how many kubectl calls the scan made.
#
# v5.5: FAILURE CHAINS + FIX PLAN. Findings are linked to an earlier finding that can explain them; the SUGGESTED FIX
# column gives commands (restart pod, rollback, raise limit, ...) only for the first resource of each chain. They are
# printed, never executed: the read-only guard stays on. Table headers are bold.
#
# v5.6: terminating endpoints/pods are a rollout, not a fault; platform namespaces are owned by Infra with a k3s Helm-job
# specific cause and fix; MASK_PII=1 masks long numbers in report views (credentials are always masked).
#
# v5.7: BULK PRELOAD -- pods, workloads, Services, EndpointSlices, ingresses and network policies are each read ONCE for
# the whole scope and sliced locally (v5.6 repeated those reads per namespace, Service and pod). Old per-item reads stay
# as fallbacks.
#
# It requires NO public internet access -- only connectivity to your
# Kubernetes API server via the existing kubeconfig, and writes report
# files locally.
###############################################################################

set +e

# --- v5.4: READ-ONLY GUARD + CALL ACCOUNTING ----------------------------------
# Every kubectl call in this script goes through this wrapper. It (1) refuses any verb that is not on the
# read-only allowlist, so even a future edit of this script cannot change the cluster, and (2) counts calls
# per verb in data/kubectl-calls.log, so the summary can show how many calls a scan made.
# Allowed: get, describe, logs, top, cluster-info, version, api-resources, "config current-context",
#          "auth can-i". "exec" is allowed ONLY when ENABLE_ENDPOINT_PROBE=1 or ENABLE_POD_NETWORK_TEST=1.
KCALL_LOG=""
_kblock() {
    [ -n "$KCALL_LOG" ] && echo "BLOCKED $*" >> "$KCALL_LOG"
    echo "[read-only guard] blocked: kubectl $*" >&2
    return 126
}
kubectl() {
    case "${1:-}" in
        get|describe|logs|top|cluster-info|version|api-resources) ;;
        config) [ "${2:-}" = "current-context" ] || { _kblock "$@"; return 126; } ;;
        auth)   [ "${2:-}" = "can-i" ] || { _kblock "$@"; return 126; } ;;
        exec)   if [ "${ENABLE_ENDPOINT_PROBE:-0}" != "1" ] && [ "${ENABLE_POD_NETWORK_TEST:-0}" != "1" ]; then _kblock "$@"; return 126; fi ;;
        *)      _kblock "$@"; return 126 ;;
    esac
    [ -n "$KCALL_LOG" ] && echo "$1" >> "$KCALL_LOG"
    command kubectl "$@"
}

# Startup banner, drawn once on the very first run only -- not repeated on
# every loop iteration below, and not repeated anywhere else in the script
# or its reports. Block-letter art with an orange -> yellow gradient on a
# color terminal; plain block letters when output is not a TTY.
print_first_run_banner() {
    local -A G=(
        [S]="█████/█    /█████/    █/█████"
        [H]="█   █/█   █/█████/█   █/█   █"
        [A]=" ███ /█   █/█████/█   █/█   █"
        [D]="████ /█   █/█   █/█   █/████ "
        [Y]="█   █/ █ █ /  █  /  █  /  █  "
        [G]=" ████/█    /█  ██/█   █/ ███ "
        [O]=" ███ /█   █/█   █/█   █/ ███ "
        [M]="█   █/██ ██/█ █ █/█   █/█   █"
        [_]="   /   /   /   /   "
    )
    local text="SHADY_GOMAA" colors=(202 208 208 214 220) r i ch line
    local -a rows
    local use_color=0
    [ -t 1 ] && use_color=1

    echo ""
    if [ "$use_color" -eq 1 ]; then
        printf '  \033[38;5;245mdeveloped by\033[0m\n\n'
    else
        printf '  developed by\n\n'
    fi
    for r in 0 1 2 3 4; do
        line=""
        for ((i=0; i<${#text}; i++)); do
            ch="${text:i:1}"
            IFS='/' read -ra rows <<< "${G[$ch]}"
            line+="${rows[r]} "
        done
        if [ "$use_color" -eq 1 ]; then
            printf '  \033[38;5;%sm%s\033[0m\n' "${colors[r]}" "$line"
        else
            printf '  %s\n' "$line"
        fi
    done
    echo ""
}

# Snapshot any non-interactive overrides ONCE, before the loop below. Each
# loop iteration resets its working variable to this snapshot rather than
# to whatever value the PREVIOUS iteration's interactive prompt produced --
# otherwise, from the second iteration onward, these would already be
# non-empty from the last run and every prompt would be silently skipped.
ORIG_LIVE_LOGS_POD="${LIVE_LOGS_POD:-}"
ORIG_SCAN_MINUTES="${SCAN_MINUTES:-}"
ORIG_SEARCH_VALUE="${SEARCH_VALUE:-}"
ORIG_SCAN_NAMESPACE="${SCAN_NAMESPACE:-}"
ORIG_SCAN_POD_SELECTION="${SCAN_POD_SELECTION:-}"
ORIG_REPORT_DIR="${REPORT_DIR:-}"

FIRST_RUN=1

# The script returns to the first question after every scan. That is only
# wanted in an interactive terminal. When stdin is not a terminal (cron, CI,
# `< /dev/null`) or RUN_ONCE=1 is set, the script exits after ONE run instead
# of re-running the same scan forever.
RUN_ONCE="${RUN_ONCE:-0}"
should_exit_after_run() { [ "$RUN_ONCE" = "1" ] || [ ! -t 0 ]; }

# The whole script body runs inside this loop: after a scan (or a live-log
# session) finishes, execution falls through to "done" at the very bottom
# and loops back here -- no need to relaunch the script. Ctrl+C at any
# prompt exits normally (default SIGINT handling of `read`/the running
# command), which remains the way to actually quit.
while true; do

LIVE_LOGS_POD="$ORIG_LIVE_LOGS_POD"
SCAN_MINUTES="$ORIG_SCAN_MINUTES"
SEARCH_VALUE="$ORIG_SEARCH_VALUE"
SCAN_NAMESPACE="$ORIG_SCAN_NAMESPACE"
SCAN_POD_SELECTION="$ORIG_SCAN_POD_SELECTION"
REPORT_DIR="$ORIG_REPORT_DIR"

if [ "$FIRST_RUN" = "1" ]; then
    print_first_run_banner
    FIRST_RUN=0
fi

echo "============================================================"
echo " KUBERNETES INCIDENT DIAGNOSTIC SCANNER v5.7"
echo "============================================================"
echo ""

###############################################################################
# LIVE LOG VIEWER (optional, read-only, exits after use)
#
# Before running a full scan, offer a shortcut: just tail one pod's logs
# live (kubectl logs -f) instead of a full scan. Useful when you already
# know which pod is acting up and just want to watch it right now. This
# does not run the scan or produce a report -- it exits when you stop
# watching (Ctrl+C) or the log stream ends.
#
# Still strictly read-only: `kubectl logs -f` only reads a log stream,
# same category as every other `logs` call this scanner already makes --
# it changes nothing in the cluster.
###############################################################################

LIVE_LOGS_POD="${LIVE_LOGS_POD:-}"   # optional non-interactive "namespace/podname" override
WANT_LIVE_LOGS="n"

if [ -n "$LIVE_LOGS_POD" ]; then
    WANT_LIVE_LOGS="y"
elif [ -t 0 ]; then
    read -r -p "Do you want to watch LIVE LOGS of a pod right now, instead of running a scan? [y/N]: " LIVE_LOGS_CHOICE
    case "$LIVE_LOGS_CHOICE" in
        [Yy]*) WANT_LIVE_LOGS="y" ;;
        *) WANT_LIVE_LOGS="n" ;;
    esac
fi

if [ "$WANT_LIVE_LOGS" = "y" ]; then
    if [ -n "$LIVE_LOGS_POD" ]; then
        LIVE_NS="${LIVE_LOGS_POD%%/*}"
        LIVE_POD="${LIVE_LOGS_POD#*/}"
    else
        echo ""
        echo "Discovering namespaces..."
        LIVE_NS_DISCOVERY=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
        if [ -z "$LIVE_NS_DISCOVERY" ]; then
            echo "Could not list namespaces (cluster not reachable, or kubectl unavailable)."
            echo "Continuing to the normal scan instead."
            WANT_LIVE_LOGS="n"
        else
            LIVE_NS_ARRAY=()
            while IFS= read -r live_ns; do
                [ -n "$live_ns" ] && LIVE_NS_ARRAY+=("$live_ns")
            done <<< "$LIVE_NS_DISCOVERY"
            echo ""
            for i in "${!LIVE_NS_ARRAY[@]}"; do
                printf "  %d. %s\n" "$((i+1))" "${LIVE_NS_ARRAY[$i]}"
            done
            echo ""
            read -r -p "Enter a namespace number [Enter to cancel]: " LIVE_NS_NUM
            case "$LIVE_NS_NUM" in
                ''|*[!0-9]*)
                    echo "No namespace selected -- continuing to the normal scan instead."
                    WANT_LIVE_LOGS="n"
                    ;;
                *)
                    LIVE_NS_IDX=$((LIVE_NS_NUM-1))
                    if [ "$LIVE_NS_IDX" -ge 0 ] && [ "$LIVE_NS_IDX" -lt "${#LIVE_NS_ARRAY[@]}" ]; then
                        LIVE_NS="${LIVE_NS_ARRAY[$LIVE_NS_IDX]}"
                    else
                        echo "Number out of range -- continuing to the normal scan instead."
                        WANT_LIVE_LOGS="n"
                    fi
                    ;;
            esac

            if [ "$WANT_LIVE_LOGS" = "y" ] && [ -n "${LIVE_NS:-}" ]; then
                echo ""
                echo "Discovering pods in namespace: $LIVE_NS ..."
                LIVE_POD_DISCOVERY=$(kubectl get pods -n "$LIVE_NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
                if [ -z "$LIVE_POD_DISCOVERY" ]; then
                    echo "No pods found in namespace '$LIVE_NS'. Continuing to the normal scan instead."
                    WANT_LIVE_LOGS="n"
                else
                    LIVE_POD_ARRAY=()
                    while IFS= read -r live_p; do
                        [ -n "$live_p" ] && LIVE_POD_ARRAY+=("$live_p")
                    done <<< "$LIVE_POD_DISCOVERY"
                    echo ""
                    for i in "${!LIVE_POD_ARRAY[@]}"; do
                        printf "  %d. %s\n" "$((i+1))" "${LIVE_POD_ARRAY[$i]}"
                    done
                    echo ""
                    read -r -p "Enter the number of the pod to watch [Enter to cancel]: " LIVE_POD_NUM
                    case "$LIVE_POD_NUM" in
                        ''|*[!0-9]*)
                            echo "No pod selected -- continuing to the normal scan instead."
                            WANT_LIVE_LOGS="n"
                            ;;
                        *)
                            LIVE_IDX=$((LIVE_POD_NUM-1))
                            if [ "$LIVE_IDX" -ge 0 ] && [ "$LIVE_IDX" -lt "${#LIVE_POD_ARRAY[@]}" ]; then
                                LIVE_POD="${LIVE_POD_ARRAY[$LIVE_IDX]}"
                            else
                                echo "Invalid selection -- continuing to the normal scan instead."
                                WANT_LIVE_LOGS="n"
                            fi
                            ;;
                    esac
                fi
            fi
        fi
    fi
fi

if [ "$WANT_LIVE_LOGS" = "y" ] && [ -n "${LIVE_NS:-}" ] && [ -n "${LIVE_POD:-}" ]; then
    echo ""
    echo "============================================================"
    echo " LIVE LOGS: $LIVE_NS/$LIVE_POD  (read-only: kubectl logs -f)"
    echo " Press Ctrl+C to stop watching. No scan will run."
    echo "============================================================"
    echo ""
    # NOTE: the trap does not call exit -- exit inside a trap always
    # terminates the whole process, not just this loop iteration, which
    # would defeat "return to the first question" below. It just prints
    # and returns; kubectl logs -f itself receives the same SIGINT and
    # terminates on its own, so execution naturally continues to the
    # "continue" statement right after either way (Ctrl+C or a natural
    # end of the log stream).
    trap 'echo ""; echo "Stopped watching logs."' INT
    kubectl logs -f -n "$LIVE_NS" "$LIVE_POD" --all-containers --timestamps
    trap - INT
    echo ""
    echo "Log stream ended (pod may have restarted or the container exited)."
    if should_exit_after_run; then exit 0; fi
    echo "Returning to the first question..."
    continue
fi

###############################################################################
# 0. INTERACTIVE INPUT: SCAN WINDOW + SEARCH FILTER
###############################################################################

DEFAULT_MINUTES=1440   # 24 hours

echo "------------------------------------------------------------"
echo "1. SCAN TIME WINDOW"
echo "------------------------------------------------------------"
echo "Examples: 15=15min  60=1h  180=3h  720=12h  1440=24h"
echo ""

# Allow non-interactive override via env vars (for cron / CI use)
SCAN_MINUTES="${SCAN_MINUTES:-}"
SEARCH_VALUE="${SEARCH_VALUE:-}"

if [ -t 0 ] && [ -z "$SCAN_MINUTES" ]; then
    read -r -p "Enter minutes back to scan [default: ${DEFAULT_MINUTES}]: " INPUT_MINUTES
    SCAN_MINUTES="${INPUT_MINUTES:-$DEFAULT_MINUTES}"
elif [ -z "$SCAN_MINUTES" ]; then
    SCAN_MINUTES="$DEFAULT_MINUTES"
fi

# Validate: must be a positive integer, else fall back to default
case "$SCAN_MINUTES" in
    ''|*[!0-9]*) SCAN_MINUTES="$DEFAULT_MINUTES" ;;
esac
[ "$SCAN_MINUTES" -lt 1 ] 2>/dev/null && SCAN_MINUTES="$DEFAULT_MINUTES"

echo ""
echo "------------------------------------------------------------"
echo "2. SCAN SCOPE"
echo "------------------------------------------------------------"

# Two-level picker: namespace first (with an ALL NAMESPACES option), then
# -- only if a specific namespace was chosen -- pods within that one
# namespace (with an ALL PODS option). Choosing ALL NAMESPACES scans
# everything and skips the pod-narrowing step entirely, same as the
# companion log-search tool's scope picker.
#
# Non-interactive overrides (for cron / CI use):
#   SCAN_NAMESPACE       "all"/"full", or a literal namespace name
#   SCAN_POD_SELECTION   "all", or a comma-separated list of literal pod
#                         names within that namespace (ignored when
#                         SCAN_NAMESPACE is "all"/"full")
SCAN_NAMESPACE="${SCAN_NAMESPACE:-}"
SCAN_POD_SELECTION="${SCAN_POD_SELECTION:-}"
SELECTED_NS=""
SELECTED_PODS=""
SCOPE_MODE="FULL"

if [ -n "$SCAN_NAMESPACE" ] && [ "$SCAN_NAMESPACE" != "all" ] && [ "$SCAN_NAMESPACE" != "full" ]; then
    SELECTED_NS="$SCAN_NAMESPACE"
    echo "Namespace scope set via SCAN_NAMESPACE env var: $SELECTED_NS"
elif [ -n "$SCAN_NAMESPACE" ]; then
    echo "Namespace scope set via SCAN_NAMESPACE env var: ALL NAMESPACES"
elif [ -t 0 ]; then
    echo "Discovering namespaces..."
    NS_DISCOVERY=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
    if [ -z "$NS_DISCOVERY" ]; then
        echo "Could not list namespaces (cluster not reachable yet, or kubectl unavailable)."
        echo "Defaulting to FULL SCAN -- connectivity will be verified in the next step."
    else
        NS_ARRAY=()
        while IFS= read -r ns_name; do
            [ -n "$ns_name" ] && NS_ARRAY+=("$ns_name")
        done <<< "$NS_DISCOVERY"
        echo ""
        echo "  0. ALL NAMESPACES"
        for i in "${!NS_ARRAY[@]}"; do
            printf "  %d. %s\n" "$((i+1))" "${NS_ARRAY[$i]}"
        done
        echo ""
        read -r -p "Enter a namespace number [default: 0 = ALL NAMESPACES]: " NS_CHOICE
        if [ -n "$NS_CHOICE" ] && [ "$NS_CHOICE" != "0" ]; then
            case "$NS_CHOICE" in
                *[!0-9]*)
                    echo "Invalid selection -- defaulting to ALL NAMESPACES."
                    ;;
                *)
                    if [ "$NS_CHOICE" -ge 1 ] 2>/dev/null && [ "$NS_CHOICE" -le "${#NS_ARRAY[@]}" ] 2>/dev/null; then
                        SELECTED_NS="${NS_ARRAY[$((NS_CHOICE-1))]}"
                    else
                        echo "Number out of range -- defaulting to ALL NAMESPACES."
                    fi
                    ;;
            esac
        fi
    fi
fi

if [ -n "$SELECTED_NS" ]; then
    echo ""
    echo "------------------------------------------------------------"
    echo "2b. SELECT POD(S) IN NAMESPACE: $SELECTED_NS"
    echo "------------------------------------------------------------"

    if [ -n "$SCAN_POD_SELECTION" ] && [ "$SCAN_POD_SELECTION" != "all" ]; then
        SELECTED_PODS=$(echo "$SCAN_POD_SELECTION" | tr ',' ' ')
        SCOPE_MODE="NAMESPACE_SELECTED"
        echo "Pod scope set via SCAN_POD_SELECTION env var: $SELECTED_PODS"
    elif [ -n "$SCAN_POD_SELECTION" ]; then
        SCOPE_MODE="NAMESPACE_ALL_PODS"
        echo "Pod scope set via SCAN_POD_SELECTION env var: ALL PODS in $SELECTED_NS"
    elif [ -t 0 ]; then
        POD_DISCOVERY=$(kubectl get pods -n "$SELECTED_NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
        if [ -z "$POD_DISCOVERY" ]; then
            echo "No pods found in namespace '$SELECTED_NS' (or cluster not reachable)."
            echo "Defaulting to ALL PODS in this namespace -- will simply find nothing to scan if truly empty."
            SCOPE_MODE="NAMESPACE_ALL_PODS"
        else
            POD_ARRAY=()
            while IFS= read -r pod_entry; do
                [ -n "$pod_entry" ] && POD_ARRAY+=("$pod_entry")
            done <<< "$POD_DISCOVERY"
            echo ""
            echo "  0. ALL PODS in $SELECTED_NS"
            for i in "${!POD_ARRAY[@]}"; do
                printf "  %d. %s\n" "$((i+1))" "${POD_ARRAY[$i]}"
            done
            echo ""
            read -r -p "Enter pod number(s), comma-separated, or 0 for all [default: 0 = ALL PODS]: " POD_SELECTION
            if [ -n "$POD_SELECTION" ] && [ "$POD_SELECTION" != "0" ]; then
                PICKED=""
                IFS=',' read -ra POD_NUMS <<< "$POD_SELECTION"
                for n in "${POD_NUMS[@]}"; do
                    n=$(echo "$n" | tr -d '[:space:]')
                    case "$n" in ''|*[!0-9]*) continue ;; esac
                    idx=$((n-1))
                    if [ "$idx" -ge 0 ] && [ "$idx" -lt "${#POD_ARRAY[@]}" ]; then
                        PICKED="$PICKED ${POD_ARRAY[$idx]}"
                    fi
                done
                PICKED=$(echo "$PICKED" | sed 's/^ *//')
                if [ -n "$PICKED" ]; then
                    SELECTED_PODS="$PICKED"
                    SCOPE_MODE="NAMESPACE_SELECTED"
                else
                    echo "No valid pod numbers recognized -- defaulting to ALL PODS in $SELECTED_NS."
                    SCOPE_MODE="NAMESPACE_ALL_PODS"
                fi
            else
                SCOPE_MODE="NAMESPACE_ALL_PODS"
            fi
        fi
    else
        SCOPE_MODE="NAMESPACE_ALL_PODS"
    fi
fi

echo ""
echo "------------------------------------------------------------"
echo "3. TARGETED SEARCH (optional)"
echo "------------------------------------------------------------"
echo "Enter an ID / IP / error string to search for (transaction ID,"
echo "request ID, correlation ID, user ID, IP, exception name, etc)."
echo "Leave empty for a full cluster scan."
echo ""

if [ -t 0 ] && [ -z "$SEARCH_VALUE" ]; then
    read -r -p "Enter search value [default: FULL SCAN]: " INPUT_SEARCH
    SEARCH_VALUE="$INPUT_SEARCH"
fi

# Treat the search value as literal DATA only. Never evaluate it.
SEARCH_MODE="FULL_SCAN"
if [ -n "$SEARCH_VALUE" ]; then
    SEARCH_MODE="TARGETED"
fi

SCAN_END_EPOCH=$(date +%s)
SCAN_START_EPOCH=$((SCAN_END_EPOCH - SCAN_MINUTES*60))
SCAN_START_HUMAN=$(date -d "@$SCAN_START_EPOCH" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$SCAN_START_EPOCH" '+%Y-%m-%d %H:%M:%S')
SCAN_END_HUMAN=$(date -d "@$SCAN_END_EPOCH" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$SCAN_END_EPOCH" '+%Y-%m-%d %H:%M:%S')

# Shared scope description, used everywhere (Confirm Scan, FINAL SUMMARY,
# HTML report, README) so the three scope modes are described consistently
# in exactly one place.
scope_description() {
    case "$SCOPE_MODE" in
        NAMESPACE_ALL_PODS) echo "Namespace '$SELECTED_NS', ALL pods" ;;
        NAMESPACE_SELECTED) echo "Namespace '$SELECTED_NS', pod(s):$SELECTED_PODS" ;;
        *) echo "Full infrastructure (all namespaces, all pods)" ;;
    esac
}

echo ""
echo "------------------------------------------------------------"
echo "4. CONFIRM SCAN"
echo "------------------------------------------------------------"
echo "Time range : last ${SCAN_MINUTES} minutes (${SCAN_START_HUMAN} -> ${SCAN_END_HUMAN})"
echo "Scope      : $(scope_description)"
echo "Search     : ${SEARCH_VALUE:-<none, full scan>}"
echo "Mode       : ${SEARCH_MODE}"
echo ""
echo "kubectl exec diagnostics : DISABLED by default (ENABLE_POD_NETWORK_TEST=1 to enable)"
echo "Endpoint GET probes      : ${ENABLE_ENDPOINT_PROBE:-0} (0=disabled by default; ENABLE_ENDPOINT_PROBE=1 to enable, GET only)"
echo "F5/external LB hook      : $([ -n "${F5_LOG_SOURCE:-}${F5_LOG_HOOK:-}" ] && echo "configured" || echo "not configured (F5_LOG_SOURCE / F5_LOG_HOOK)")"
echo "Kubernetes modifications : NONE (never executed by this script)"
echo ""

###############################################################################
# CONFIGURATION
###############################################################################

REPORT_DIR="${REPORT_DIR:-k8s-incident-report-$(date +%Y%m%d-%H%M%S)}"
ENABLE_POD_NETWORK_TEST="${ENABLE_POD_NETWORK_TEST:-0}"   # off by default, per safety review
ENABLE_LOG_SCAN="${ENABLE_LOG_SCAN:-1}"

# --- Endpoint probe (opt-in, off by default) ---
# Issues a live GET, via kubectl exec into each endpoint pod's OWN
# container, at 127.0.0.1:<containerPort><PROBE_PATH>. Confirms the app
# actually answers -- not just that Kubernetes reports it Ready. Still
# read-only for Kubernetes objects (no create/patch/delete); it does run
# a process inside the container and makes a real GET request, so it is
# off by default, same as ENABLE_POD_NETWORK_TEST.
ENABLE_ENDPOINT_PROBE="${ENABLE_ENDPOINT_PROBE:-0}"
PROBE_PATH="${PROBE_PATH:-/}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-3}"
PROBE_PORT_OVERRIDE="${PROBE_PORT_OVERRIDE:-}"     # force a port instead of using declared containerPorts

# --- F5 / external load balancer log hook (pluggable, off unless set) ---
# F5_LOG_SOURCE: a file or directory of already-exported F5 logs, read as-is.
# F5_LOG_HOOK:   an executable this scanner runs and captures stdout from
#                (e.g. your own wrapper around an iControl REST GET call,
#                an rsync/scp of the latest log, a Splunk/ELK query). It
#                must be read-only on the F5 side by design of the hook
#                itself -- this scanner does not and cannot enforce that,
#                it only consumes stdout.
F5_LOG_SOURCE="${F5_LOG_SOURCE:-}"
F5_LOG_HOOK="${F5_LOG_HOOK:-}"
F5_BLOCK_PATTERN="${F5_BLOCK_PATTERN:-blocking_exception_reason|support_id|violation_rating|asm.*block|tcp_rst|reset by peer|connection refused by big-?ip|no members available|pool.*monitor.*down|node.*monitor.*down|exceeded.*connection limit|irule.*(drop|reject)}"

# --- Slowness / performance triage thresholds (all opt-out via env override,
# all read-only checks -- see "API LATENCY", "ETCD HEALTH", node oversub in
# section 2, and HPA STATUS in section 4). These give circumstantial
# evidence toward common infra-side causes of "the app works but is slow";
# they cannot diagnose a slow application request path itself (that needs
# tracing/APM this scanner has no access to) -- see Coverage Limitations.
API_LATENCY_WARN_MS="${API_LATENCY_WARN_MS:-1000}"
API_LATENCY_CRIT_MS="${API_LATENCY_CRIT_MS:-3000}"
NODE_CPU_WARN_PCT="${NODE_CPU_WARN_PCT:-75}"
NODE_CPU_CRIT_PCT="${NODE_CPU_CRIT_PCT:-90}"
NODE_MEM_WARN_PCT="${NODE_MEM_WARN_PCT:-75}"
NODE_MEM_CRIT_PCT="${NODE_MEM_CRIT_PCT:-90}"
POD_CPU_WARN_PCT="${POD_CPU_WARN_PCT:-80}"
POD_CPU_CRIT_PCT="${POD_CPU_CRIT_PCT:-95}"
POD_MEM_WARN_PCT="${POD_MEM_WARN_PCT:-80}"
POD_MEM_CRIT_PCT="${POD_MEM_CRIT_PCT:-95}"

# Millisecond-resolution wall clock without shelling out to `date` (whose
# %N nanosecond format is GNU-only and silently breaks on macOS/BSD date).
# $EPOCHREALTIME is a bash 5+ builtin (seconds.microseconds); falls back to
# whole-second resolution on older bash, which is coarser but still
# functional for flagging multi-second API latency.
now_ms() {
    if [ -n "${EPOCHREALTIME:-}" ]; then
        local sec="${EPOCHREALTIME%%.*}" frac="${EPOCHREALTIME#*.}"
        echo $(( sec * 1000 + 10#${frac:0:3} ))
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

# Many Kubernetes-ecosystem components (metrics-server, controller-manager,
# kube-proxy, etc.) log via klog, whose line format is a level letter
# (I=Info, W=Warning, E=Error, F=Fatal) immediately after the timestamp,
# e.g. "...Z I0925 21:06:17.664085 1 tlsconfig.go:243] ...". Info-level
# klog lines routinely contain words like "certificate", "failed", or
# "timeout" as part of completely normal startup/retry chatter (e.g.
# "Failed probe ... no metrics to serve" while a cache warms up), which
# would otherwise false-positive against ERROR_PATTERN below. This filter
# excludes only the Info level (I) -- Warning/Error/Fatal (W/E/F) klog
# lines are never excluded. Set NOISE_EXCLUDE_PATTERN="" to disable.
#
# NOTE: the default value below is assigned via an isset-check + plain
# assignment rather than "${NOISE_EXCLUDE_PATTERN:-default}", because
# bash's ${VAR:-default} scanner treats ANY literal "}" inside default
# (even from a harmless-looking {4} regex interval) as closing the
# expansion early, silently truncating the pattern. This form also
# correctly treats an explicit NOISE_EXCLUDE_PATTERN="" as "disabled"
# rather than "unset" (":-" would have overridden an empty string back
# to the default, which is not what "set it empty to disable" should do).
if [ -z "${NOISE_EXCLUDE_PATTERN+set}" ]; then
    # v5.1: besides klog Info lines, also ignore logfmt/JSON lines whose level is INFO/DEBUG -- words like
    # 'failure_mode="none"' or 'error_count=0' in a healthy INFO line are not errors.
    NOISE_EXCLUDE_PATTERN='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[[:space:]]+I[0-9]{4}[[:space:]]|(^|[[:space:]])level="?(INFO|info|DEBUG|debug)"?([[:space:]]|$)|"level"[[:space:]]*:[[:space:]]*"(INFO|info|DEBUG|debug)"'
fi

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

mkdir -p "$REPORT_DIR/logs" "$REPORT_DIR/data" "$REPORT_DIR/raw"
KCALL_LOG="$REPORT_DIR/data/kubectl-calls.log"; : > "$KCALL_LOG"
REPORT="$REPORT_DIR/kubernetes-health-report.txt"
ERROR_REPORT="$REPORT_DIR/errors-and-warnings.txt"
FIX_REPORT="$REPORT_DIR/recommended-fixes.txt"
MATCH_REPORT="$REPORT_DIR/search-matches.txt"
TIMELINE_FILE="$REPORT_DIR/data/timeline.tsv"
FACTS_FILE="$REPORT_DIR/data/facts.tsv"
ROOTCAUSE_REPORT="$REPORT_DIR/root-cause-analysis.txt"
HTML_REPORT="$REPORT_DIR/index.html"
SEARCH_STATS_FILE="$REPORT_DIR/data/search-stats.tsv"   # occurrences per resource
PROBE_REPORT="$REPORT_DIR/endpoint-probe-results.txt"
PROBE_TSV="$REPORT_DIR/data/probe-results.tsv"
F5_REPORT="$REPORT_DIR/data/f5-external.log"

: > "$REPORT"; : > "$ERROR_REPORT"; : > "$FIX_REPORT"; : > "$MATCH_REPORT"; : > "$TIMELINE_FILE"; : > "$FACTS_FILE"; : > "$ROOTCAUSE_REPORT"; : > "$SEARCH_STATS_FILE"; : > "$PROBE_REPORT"; : > "$PROBE_TSV"; : > "$F5_REPORT"
TRACE_FILE="$REPORT_DIR/data/trace.tsv"; : > "$TRACE_FILE"

###############################################################################
# CORRELATION ENGINE: record structured facts as we find them, then at the
# end of the scan chain them into ranked root-cause candidates. This is
# heuristic/evidence-based correlation, not proof of causation -- the HTML
# report labels it "candidate", never "confirmed".
#
# Fact record (tab-separated):
#   RANK  CATEGORY  NAMESPACE  RESOURCE  OWNER  DETAIL  TIMESTAMP
#
# RANK = how "upstream" this fact typically is (lower = more likely root
# cause; higher = more likely a downstream symptom of something else):
#   10 CONTROL_PLANE   20 NODE   30 DNS   35 REDIS   38 SECURITY
#   40 NO_ENDPOINTS    45 OOM    50 RESTART   55 PENDING_SCHEDULING/PENDING_CONTAINER_ERROR/FAILED
#   60 LOG_ERROR       70 HAPROXY_5XX (almost always a symptom, not a cause)
#
# OWNER values map to a team in owner_label(): infra, network, developer,
# security, or a combined "X-or-Y" when the scanner can't tell which side
# owns the fix from API/log evidence alone.
###############################################################################
record_fact() {
    # $1 rank  $2 category  $3 namespace  $4 resource  $5 owner  $6 detail  $7 timestamp(optional)
    local ts="${7:-$(date -u '+%Y-%m-%d %H:%M:%S')*}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$ts" >> "$FACTS_FILE"
}

# Extract a leading RFC3339 timestamp from a `kubectl logs --timestamps` line,
# e.g. "2026-09-23T10:15:23.481123456Z app: connection refused". Falls back
# to empty (caller then uses "now") if the line has no such prefix.
extract_log_ts() {
    echo "$1" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1 | tr 'T' ' '
}

# --- v5 helpers: timestamps / durations used by the terminal summary table ---
# BEGIN_V5_HELPERS
# Kubernetes API timestamp (2026-09-23T10:15:23Z) -> "2026-09-23 10:15:23" (UTC).
iso_to_ts() {
    [ -z "$1" ] && return
    echo "$1" | sed -E -e 's/T/ /' -e 's/Z$//' -e 's/\.[0-9]+//'
}

# "YYYY-MM-DD HH:MM:SS[*]" (UTC) -> epoch seconds. Works with GNU and BSD date.
ts_to_epoch() {
    local t="${1%\*}"
    [ -z "$t" ] && return
    t="${t/T/ }"; t="${t%Z}"; t="${t%%.*}"
    date -u -d "$t" +%s 2>/dev/null || date -u -j -f '%Y-%m-%d %H:%M:%S' "$t" +%s 2>/dev/null
}

# seconds -> "45s" / "12m 5s" / "3h 20m" / "2d 4h"
fmt_duration() {
    local s="$1"
    case "$s" in ''|*[!0-9-]*) echo "n/a"; return ;; esac
    [ "$s" -lt 0 ] && s=0
    if   [ "$s" -ge 86400 ]; then printf '%dd %dh' $((s/86400)) $(((s%86400)/3600))
    elif [ "$s" -ge 3600 ];  then printf '%dh %dm' $((s/3600)) $(((s%3600)/60))
    elif [ "$s" -ge 60 ];    then printf '%dm %ds' $((s/60)) $((s%60))
    else printf '%ds' "$s"
    fi
}
# END_V5_HELPERS
# --- v5.4: helpers for bulk reads, sums and log caps ---------------------------
# Replace empty tab-separated fields with "-" so that `read` (tab is IFS whitespace and collapses) keeps columns.
dash_tsv() { awk -F'\t' -v OFS='\t' '{ for (i = 1; i <= NF; i++) if ($i == "") $i = "-"; print }'; }
sum_cpu() { local t s=0; for t in $1; do s=$(( s + $(cpu_to_millicores "$t") )); done; echo "$s"; }
sum_mem() { local t s=0; for t in $1; do s=$(( s + $(mem_to_mi "$t") )); done; echo "$s"; }
# Caps on how much log text one container/proxy can pull through the API server (last N lines inside the window).
LOG_TAIL_LINES="${LOG_TAIL_LINES:-$([ -n "$SEARCH_VALUE" ] && echo 20000 || echo 5000)}"
INGRESS_TAIL_LINES="${INGRESS_TAIL_LINES:-20000}"
CAPPED_LOGS_FILE="$REPORT_DIR/data/capped-logs.txt"; : > "$CAPPED_LOGS_FILE"
log_cap_check() {  # $1 file  $2 tail limit  $3 label -- remember logs that hit the cap (older lines were not scanned)
    local n; n=$(wc -l < "$1" 2>/dev/null | tr -d ' ')
    if [ -n "$n" ] && [ "$n" -ge "$2" ] 2>/dev/null; then echo "$3" >> "$CAPPED_LOGS_FILE"; fi
}
declare -A POD_OWNER_CACHE RS_OWNER_CACHE
POD_OWNER_CACHE=(); RS_OWNER_CACHE=()
# --- v5.5: data the failure-chain / fix-plan engine needs (all local files, no extra API calls) ---------------
POD_INFO_FILE="$REPORT_DIR/data/pod-info.tsv";   : > "$POD_INFO_FILE"     # ns/pod, node, ownerKind, ownerName, memLimits, cpuLimits, containers, podIP
ERR_CORPUS_FILE="$REPORT_DIR/data/error-corpus.tsv"; : > "$ERR_CORPUS_FILE"  # key, error line  (lets us see which service/pod an error message talks about)
: > "$REPORT_DIR/data/rs-owner.tsv"                                         # ns/replicaset, deployment
corpus_add() {  # $1 key (ns/pod[/container])  $2 error lines
    printf '%s\n' "$2" | head -n 30 | cut -c1-300 | redact | awk -v k="$1" 'NF { print k "\t" $0 }' >> "$ERR_CORPUS_FILE"
}
declare -A POD_READY_TRANS
POD_READY_TRANS=()
# --- v5.2: request trace for a search ID -------------------------------------
# While searching, every log line that contains the ID AND starts with a kubectl
# --timestamps prefix is collected into data/trace.tsv (ts, source, error-flag,
# message). After the scan the lines are merged and sorted by time, which gives
# a chronological trace of the ID across every pod/container in scope.
# Scope = scan scope: pick one namespace (or pods) and only those logs are read.
TRACE_MAX_LINES_PER_SOURCE="${TRACE_MAX_LINES_PER_SOURCE:-5000}"
TRACE_TERMINAL_LINES="${TRACE_TERMINAL_LINES:-20}"
TRACE_HTML_MAX_ROWS="${TRACE_HTML_MAX_ROWS:-2000}"
TERMINAL_MAX_ROWS="${TERMINAL_MAX_ROWS:-30}"
SEARCH_TABLE_RELATED_ONLY="${SEARCH_TABLE_RELATED_ONLY:-0}"
SCOPE_INCLUDE_CLUSTER_COMPONENTS="${SCOPE_INCLUDE_CLUSTER_COMPONENTS:-0}"
TRACE_ERROR_PATTERN="${TRACE_ERROR_PATTERN:-error|exception|fatal|panic|critical|timeout|timed out|refused|connection reset|broken pipe|denied|unauthorized|forbidden|failed|failure|oomkilled|outofmemory|traceback|nxdomain|servfail|(^|[^0-9])50[0-9]([^0-9]|\$)}"
trace_collect() {
    # $1 = file  $2 = label ("current logs: ns/pod/container", "ingress/proxy: ns/pod", ...)
    local f="$1" label="$2" src
    [ -z "$SEARCH_VALUE" ] && return
    [ -f "$f" ] || return
    src="${label#*: }"
    case "$label" in "previous logs:"*) src="$src (prev)" ;; esac
    grep -F -- "$SEARCH_VALUE" "$f" 2>/dev/null | head -n "$TRACE_MAX_LINES_PER_SOURCE" | awk -v src="$src" -v ws="${SCAN_START_UTC:-}" -v errpat="$TRACE_ERROR_PATTERN" '
        BEGIN { errpat = tolower(errpat) }
        {
            if (match($0, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9:.]*Z/)) {
                ts = substr($0, 1, RLENGTH)
                if (ws != "" && ts < ws) next
                msg = substr($0, RLENGTH + 1); sub(/^[ \t]+/, "", msg); gsub(/\t/, " ", msg)
                low = tolower(msg); flag = "-"
                if (low ~ errpat && low !~ /level="?(info|debug)"?/ && low !~ /"level" *: *"(info|debug)"/ && low !~ /failure_mode="?none/) flag = "!"
                printf "%s\t%s\t%s\t%s\n", ts, src, flag, substr(msg, 1, 600)
            }
        }' | redact >> "$TRACE_FILE"
}

# --- v5.1: quiet mode + progress bar -----------------------------------------
# While the scan runs, everything it would print goes to data/scan-console.log and
# only a one-line progress bar reaches the terminal (via fd 4). SCAN_VERBOSE=1 turns
# quiet mode off and prints every finding live, as v4/v5 did.
PROGRESS_FD_OPEN=0; PROGRESS_TTY=0; PROGRESS_COLS=120
NS_IDX=0; NS_TOTAL=1; POD_IDX=0; POD_N=1
progress() {
    # $1 percent  $2 label  $3 "s" = stage (also printed as a line when output is not a terminal)
    [ "$PROGRESS_FD_OPEN" = "1" ] || return 0
    local pct="$1" label="$2" kind="${3:-}" width=28 filled maxl bar el
    local full="############################" empty="----------------------------"
    case "$pct" in ''|*[!0-9]*) pct=0 ;; esac
    [ "$pct" -gt 100 ] && pct=100
    filled=$(( pct * width / 100 ))
    bar="${full:0:filled}${empty:0:width-filled}"
    el=$(( SECONDS - SCAN_RUN_START ))
    if [ "$PROGRESS_TTY" = "1" ]; then
        maxl=$(( PROGRESS_COLS - width - 20 )); [ "$maxl" -lt 10 ] && maxl=10
        printf '\r\033[K  [%s] %3d%%  %4ss  %s' "$bar" "$pct" "$el" "${label:0:maxl}" >&4
    elif [ "$kind" = "s" ]; then
        printf '  [%s] %3d%%  %4ss  %s\n' "$bar" "$pct" "$el" "$label" >&4
    fi
}
progress_pods() {
    local pct
    pct=$(( 24 + ( (NS_IDX - 1) * 1000 + POD_IDX * 1000 / POD_N ) * 56 / (NS_TOTAL * 1000) ))
    progress "$pct" "Scanning pods: $NS ($POD_IDX/$POD_N) $POD"
}


# Redact credential-shaped strings before they land in the human-facing
# report (ERROR_REPORT excerpts, search-match context, catalog details,
# root-cause evidence). Scope is deliberately narrow: Bearer tokens,
# password=/secret=/api_key= fields, JWTs, and user:pass@host connection
# strings. We do NOT attempt broad PII redaction (emails, national IDs,
# phone numbers) -- that can't be reliably regex-detected without heavy
# false positives, AND this tool's own search feature is often used to
# find a customer's ID in context, so blanket PII redaction would defeat
# its purpose. Raw log files on disk are left untouched (kept for deep
# debugging); only the aggregated report views are redacted.
# Set REDACT_SECRETS=0 to disable.
REDACT_SECRETS="${REDACT_SECRETS:-1}"
MASK_PII="${MASK_PII:-0}"   # 1 = also mask any run of 9+ digits (national IDs, card numbers) in report views; the ID you searched for stays visible
redact_creds() {
    if [ "$REDACT_SECRETS" = "0" ]; then
        cat
        return
    fi
    sed -E \
        -e 's/(Authorization:[[:space:]]*Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1[REDACTED]/gI' \
        -e 's/([Aa][Pp][Ii][_-]?[Kk][Ee][Yy]["]?[[:space:]]*[:=][[:space:]]*["]?)[A-Za-z0-9._-]{8,}/\1[REDACTED]/g' \
        -e 's/([Pp]assword["]?[[:space:]]*[:=][[:space:]]*["]?)[^[:space:]"'"'"',]+/\1[REDACTED]/g' \
        -e 's/([Ss]ecret["]?[[:space:]]*[:=][[:space:]]*["]?)[A-Za-z0-9._-]{8,}/\1[REDACTED]/g' \
        -e 's/(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/[REDACTED_JWT]/g' \
        -e 's#(://[A-Za-z0-9._-]+:)[^@/[:space:]]+(@)#\1[REDACTED]\2#g' \
        2>/dev/null
}

# v5.6: credentials are always masked; long digit runs only with MASK_PII=1
redact() { redact_creds | mask_pii; }
mask_pii() {
    if [ "$MASK_PII" != "1" ]; then cat; return; fi
    HL_KEEP="$SEARCH_VALUE" awk '
        function stars(n,   s) { s = ""; while (n-- > 0) s = s "*"; return s }
        function mask(s,   out, run, L) {
            out = ""
            while (match(s, /[0-9]+/)) {
                run = substr(s, RSTART, RLENGTH); L = RLENGTH
                out = out substr(s, 1, RSTART - 1) ((L >= 9) ? substr(run, 1, 2) stars(L - 4) substr(run, L - 1) : run)
                s = substr(s, RSTART + RLENGTH)
            }
            return out s
        }
        {
            keep = ENVIRON["HL_KEEP"]; line = $0; out = ""
            if (keep != "" && index(line, keep) > 0) {
                while ((p = index(line, keep)) > 0) { out = out mask(substr(line, 1, p - 1)) keep; line = substr(line, p + length(keep)) }
                print out mask(line)
            } else print mask(line)
        }'
}

# Extract full multi-line exception/stack-trace blocks from a
# `kubectl logs --timestamps` file, instead of a flat grep dump that can
# sever a stack trace from the line that triggered it. A block starts at
# a line matching the error pattern and continues while later lines look
# like a continuation (indented, "at ...", "Caused by:", "...", a Python
# "File \"...\"" frame, or a bare "Traceback" header) -- ending at the
# first line that looks like a new, independent log entry. Blocks are
# delimited with ===BLOCK_START===/===BLOCK_END=== markers.
extract_incident_blocks() {
    # $1 = log file  $2 = ERE pattern identifying an error/exception start
    local f="$1" pat="$2"
    [ -f "$f" ] || return
    awk -v pat="$pat" '
        BEGIN { in_block=0 }
        {
            line=$0
            rest=line
            sub(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[ \t]*/, "", rest)
            # IGNORECASE is a gawk-only feature (mawk/POSIX awk ignore it
            # silently, breaking case-insensitive matching entirely) --
            # normalize to lowercase instead, since the ERROR_PATTERN terms
            # are already all-lowercase literals.
            is_match = (tolower(line) ~ pat)
            is_continuation = (rest ~ /^[ \t]/ || rest ~ /^(at |Caused by|\.\.\.|Traceback|File ")/)
            if (is_match && !in_block) {
                in_block=1
                print "===BLOCK_START==="
                print line
                next
            }
            if (in_block && is_continuation) {
                print line
                next
            }
            if (in_block) {
                print "===BLOCK_END==="
                in_block=0
                if (is_match) { in_block=1; print "===BLOCK_START==="; print line }
            }
        }
        END { if (in_block) print "===BLOCK_END===" }
    ' "$f"
}

# Turn the marker-delimited output of extract_incident_blocks() into
# readable "Incident #N" cards with first/last-observed timestamps.
format_incident_blocks() {
    # $1 = marker output (from extract_incident_blocks)  $2 = label (pod/container)
    local raw="$1" label="$2"
    echo "$raw" | awk -v label="$label" '
        BEGIN { n=0; inb=0 }
        /^===BLOCK_START===$/ { inb=1; n++; buf=""; first=""; last=""; next }
        /^===BLOCK_END===$/ {
            inb=0
            printf "\nIncident #%d  (%s)\n", n, label
            if (first!="") printf "  First observed : %s\n", first
            if (last!="")  printf "  Last observed  : %s\n", last
            printf "  ------------------------------------------------------------\n"
            printf "%s\n", buf
            next
        }
        inb {
            ts=$0
            sub(/[ \t].*/, "", ts)
            if (first=="") first=ts
            last=ts
            buf = buf $0 "\n"
        }
    '
}

CRITICAL=0; ERRORS=0; WARNINGS=0; INFO=0; MATCHES=0; POD_TOTAL=0; POD_UNREAD=0
REDIS_STATUS="NOT DETECTED"
REDIS_STATUS_RANK=0
CONTROL_PLANE_STATUS="UNKNOWN"

# Redis health is reported as a ranked state, not a single overwritable
# string, so a later "healthy" pod doesn't quietly downgrade an earlier
# "investigation required" finding for a different Redis pod. Higher
# rank always wins:
#   1 DETECTED / UNVERIFIED           (name-only match, not confirmed Redis)
#   2 DETECTED / HEALTH EVIDENCE GOOD (confirmed Redis, running+ready, no errors)
#   3 DETECTED / INVESTIGATION REQUIRED (confirmed Redis, errors/restarts/OOM)
#   4 DETECTED / NO READY ENDPOINTS   (confirmed Redis, not Ready / no endpoints)
set_redis_status() {
    local rank="$1" label="$2"
    if [ "$rank" -gt "$REDIS_STATUS_RANK" ]; then
        REDIS_STATUS_RANK="$rank"
        REDIS_STATUS="$label"
    fi
}

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

section_header() { echo ""; echo "===================================================================="; echo "$1"; echo "===================================================================="; echo ""; }
section() {
    section_header "$1"
    case "$1" in
        "1. KUBERNETES CONTROL PLANE") progress 3  "Checking control plane and API latency" s ;;
        "1C. ETCD"*)                   progress 7  "Checking etcd" s ;;
        "2. NODE HEALTH")              progress 11 "Checking nodes" s ;;
        "3. CLUSTER EVENTS")           progress 19 "Reading cluster events" s ;;
        "NAMESPACE: "*)                NS_IDX=$((NS_IDX+1)); progress $(( 24 + (NS_IDX-1)*56/NS_TOTAL )) "Scanning namespace ${1#NAMESPACE: } ($NS_IDX/$NS_TOTAL)" s ;;
        "5. CORE DNS")                 progress 81 "Checking CoreDNS" s ;;
        "6. INGRESS"*)                 progress 85 "Checking ingress / proxies" s ;;
        "6B. F5"*)                     progress 89 "Checking external load balancer" s ;;
        "7. RESOURCE"*)                progress 91 "Checking storage and resource usage" s ;;
        "8. ROOT CAUSE"*)              progress 94 "Correlating root causes" s ;;
        "9. FINAL SUMMARY")            progress 97 "Building HTML / text reports" s ;;
    esac
}

log()      { echo "[$(timestamp)] $1" >> "$REPORT"; }
info()     { INFO=$((INFO+1)); echo -e "${CYAN}[INFO]${NC} $1"; echo "[INFO] $1" >> "$REPORT"; }
warn()     { WARNINGS=$((WARNINGS+1)); echo -e "${YELLOW}[WARNING]${NC} $1"; echo "[WARNING] $1" >> "$REPORT"; echo "[WARNING] $1" >> "$ERROR_REPORT"; echo -e "$(date -u +%H:%M:%S)\tWARNING\t$1" >> "$TIMELINE_FILE"; }
error()    { ERRORS=$((ERRORS+1)); echo -e "${RED}[ERROR]${NC} $1"; echo "[ERROR] $1" >> "$REPORT"; echo "[ERROR] $1" >> "$ERROR_REPORT"; echo -e "$(date -u +%H:%M:%S)\tERROR\t$1" >> "$TIMELINE_FILE"; }
critical() { CRITICAL=$((CRITICAL+1)); echo -e "${RED}[CRITICAL]${NC} $1"; echo "[CRITICAL] $1" >> "$REPORT"; echo "[CRITICAL] $1" >> "$ERROR_REPORT"; echo -e "$(date -u +%H:%M:%S)\tCRITICAL\t$1" >> "$TIMELINE_FILE"; }
fix()      { echo "$1" >> "$FIX_REPORT"; }

command_exists() { type -P "$1" >/dev/null 2>&1; }   # external programs only (kubectl is also a guard function)

# Safe literal search (no eval, no shell interpretation of user input).
# Tracks not just "which files matched" but occurrence counts and the
# affected resource, so the summary can report "27 occurrences across 3
# pods in 2 namespaces" instead of a misleading "3 files matched".
search_context() {
    # $1 = file to search, $2 = label for match report (e.g. "current logs: ns/pod/container")
    local f="$1" label="$2" occ
    [ -z "$SEARCH_VALUE" ] && return
    [ -f "$f" ] || return
    occ=$(grep -F -c -- "$SEARCH_VALUE" "$f" 2>/dev/null)
    if [ -n "$occ" ] && [ "$occ" -gt 0 ] 2>/dev/null; then
        MATCHES=$((MATCHES+1))
        printf '%s\t%s\n' "$occ" "$label" >> "$SEARCH_STATS_FILE"
        trace_collect "$f" "$label"
        {
            echo ""
            echo "============================================================"
            echo "MATCH: $label  (occurrences in this source: $occ)"
            echo "File:  $f"
            echo "============================================================"
            grep -F -B 20 -A 40 -- "$SEARCH_VALUE" "$f" 2>/dev/null | redact
        } >> "$MATCH_REPORT"
    fi
}

# Terminal highlight of the search keyword (black text on yellow background).
# Reads stdin, writes stdout. Literal (non-regex) match -- same semantics as
# the grep -F search itself -- and the term is passed via the environment so
# awk never interprets backslashes in it. Falls back to a plain pass-through
# when there is no search value or stdout is not a terminal, so piped/
# redirected output never gets escape codes in it.
highlight_term() {
    if [ -z "$SEARCH_VALUE" ] || [ ! -t 1 ]; then
        cat
        return
    fi
    HL_TERM="$SEARCH_VALUE" awk '
        BEGIN { term = ENVIRON["HL_TERM"]; tlen = length(term); on = "\033[30;43m"; off = "\033[0m" }
        {
            line = $0; out = ""
            if (tlen == 0) { print line; next }
            while ((i = index(line, term)) > 0) {
                out = out substr(line, 1, i-1) on substr(line, i, tlen) off
                line = substr(line, i + tlen)
            }
            print out line
        }'
}

###############################################################################
# ENDPOINT PROBE (opt-in, OFF by default: ENABLE_ENDPOINT_PROBE=1)
#
# Issues a single HTTP GET, via `kubectl exec` into the *target pod's own
# container*, to 127.0.0.1:<containerPort><PROBE_PATH>. This confirms the
# app process inside that specific pod is actually accepting and answering
# requests -- not just that Kubernetes considers it Ready -- which is
# exactly the "1 of 3 pods is silently broken while the Service still
# looks healthy overall" scenario this tool targets.
#
# Still strictly non-mutating for Kubernetes: kubectl exec creates no
# object and changes no resource. It IS a live process execution inside
# the container (same category of caveat as ENABLE_POD_NETWORK_TEST), and
# it issues a real GET -- never POST/PUT/PATCH/DELETE -- so treat it the
# same as any health-check hitting that path. Point PROBE_PATH at a safe
# health/readiness endpoint if your root path is not side-effect-free.
#
# LIMITATION: this probes from inside the pod's own network namespace
# (loopback), not from a remote client -- it proves "the app answers
# locally", not cross-node reachability, Service routing, or
# NetworkPolicy behavior. A FAIL here alongside Ready=True is a strong
# signal the app itself (not just the readiness probe) is broken; a PASS
# here alongside Ready=False points at the readiness probe/selector
# instead.
###############################################################################
probe_one() {
    # $1 ns  $2 pod  $3 container  $4 port  $5 svc  $6 label(ready/not-ready)
    local ns="$1" pod="$2" container="$3" port="$4" svc="$5" label="$6"
    local url="http://127.0.0.1:${port}${PROBE_PATH}"
    local result code

    result=$(kubectl exec "$pod" -n "$ns" -c "$container" -- \
        sh -c "if command -v curl >/dev/null 2>&1; then curl -s -o /dev/null -w '%{http_code}' -m ${PROBE_TIMEOUT} --request GET '$url'; else echo NOCURL; fi" 2>&1)

    if [ "$result" = "NOCURL" ]; then
        echo "PROBE SKIP  $ns/$pod ($container:$port, $label, svc=$svc) -- curl not present in this container image" >> "$PROBE_REPORT"
        printf 'SKIP\t%s\t%s\t%s\t%s\t%s\tno curl in image\n' "$ns" "$pod/$container" "$port" "$svc" "$label" >> "$PROBE_TSV"
        return
    fi

    code=$(echo "$result" | tail -1 | tr -dc '0-9')

    if [ -z "$code" ]; then
        error "Probe FAILED: $ns/$pod ($container:$port, $label endpoint of svc $svc) -- no HTTP response (connection refused/timeout) at $url"
        record_fact 44 PROBE_FAIL "$ns" "$pod/$container" "developer-or-network" "GET $url returned no response ($label endpoint for svc $svc) -- app not answering on this port despite current k8s state"
        echo "PROBE FAIL  $ns/$pod ($container:$port, $label, svc=$svc) -- no response at $url" >> "$PROBE_REPORT"
        printf 'FAIL\t%s\t%s\t%s\t%s\t%s\tno response\n' "$ns" "$pod/$container" "$port" "$svc" "$label" >> "$PROBE_TSV"
    elif [ "$code" -ge 500 ] 2>/dev/null; then
        error "Probe FAILED: $ns/$pod ($container:$port, $label endpoint of svc $svc) -- HTTP $code at $url"
        record_fact 44 PROBE_FAIL "$ns" "$pod/$container" "developer" "GET $url returned HTTP $code ($label endpoint for svc $svc)"
        echo "PROBE FAIL  $ns/$pod ($container:$port, $label, svc=$svc) -- HTTP $code" >> "$PROBE_REPORT"
        printf 'FAIL\t%s\t%s\t%s\t%s\t%s\tHTTP %s\n' "$ns" "$pod/$container" "$port" "$svc" "$label" "$code" >> "$PROBE_TSV"
    elif [ "$code" -ge 400 ] 2>/dev/null; then
        warn "Probe WARN: $ns/$pod ($container:$port, $label endpoint of svc $svc) -- HTTP $code at $url"
        echo "PROBE WARN  $ns/$pod ($container:$port, $label, svc=$svc) -- HTTP $code" >> "$PROBE_REPORT"
        printf 'WARN\t%s\t%s\t%s\t%s\t%s\tHTTP %s\n' "$ns" "$pod/$container" "$port" "$svc" "$label" "$code" >> "$PROBE_TSV"
    else
        echo "PROBE OK    $ns/$pod ($container:$port, $label, svc=$svc) -- HTTP $code" >> "$PROBE_REPORT"
        printf 'OK\t%s\t%s\t%s\t%s\t%s\tHTTP %s\n' "$ns" "$pod/$container" "$port" "$svc" "$label" "$code" >> "$PROBE_TSV"
    fi
}

probe_service_endpoints() {
    # $1 ns  $2 svc  $3 rows: "addr\tready\tpodname" lines (from EndpointSlice)
    local ns="$1" svc="$2" rows="$3"
    [ "$ENABLE_ENDPOINT_PROBE" = "1" ] || return
    [ -z "$rows" ] && return
    echo "$rows" | awk -F'\t' '{print $1"|"$2"|"$3}' | while IFS='|' read -r addr ready podname; do
        [ -z "$podname" ] && continue
        local label="ready"; [ "$ready" != "true" ] && label="not-ready"
        local containers found=0
        containers=$(kubectl get pod "$podname" -n "$ns" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)
        for c in $containers; do
            local cports
            if [ -n "$PROBE_PORT_OVERRIDE" ]; then
                cports="$PROBE_PORT_OVERRIDE"
            else
                cports=$(kubectl get pod "$podname" -n "$ns" -o jsonpath="{.spec.containers[?(@.name=='$c')].ports[*].containerPort}" 2>/dev/null)
            fi
            for p in $cports; do
                found=1
                probe_one "$ns" "$podname" "$c" "$p" "$svc" "$label"
            done
        done
        if [ "$found" -eq 0 ]; then
            echo "PROBE SKIP  $ns/$podname ($label, svc=$svc) -- no containerPort declared; set PROBE_PORT_OVERRIDE to force one" >> "$PROBE_REPORT"
            printf 'SKIP\t%s\t%s\t%s\t%s\t%s\tno containerPort declared\n' "$ns" "$podname/-" "-" "$svc" "$label" >> "$PROBE_TSV"
        fi
    done
}

###############################################################################
# PRECHECK
###############################################################################

section "PRECHECK"

if ! command_exists kubectl; then
    echo "ERROR: kubectl is not installed or not in PATH."
    if should_exit_after_run; then exit 1; fi
    echo "Returning to the first question -- fix this and try again, or Ctrl+C to exit."
    continue
fi

if ! CLUSTER_INFO_OUT=$(kubectl cluster-info 2>&1); then
    critical "Cannot connect to Kubernetes API server."
    fix "Check kubeconfig: kubectl config current-context"
    fix "Check connectivity: kubectl cluster-info"
    echo "Cannot connect to the Kubernetes API. Nothing was changed."
    if should_exit_after_run; then exit 1; fi
    echo "Returning to the first question -- this may be transient; try again, or Ctrl+C to exit."
    continue
fi

CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null)
log "Context: $CURRENT_CONTEXT"
log "Scan window: last ${SCAN_MINUTES} minutes ($SCAN_START_HUMAN -> $SCAN_END_HUMAN)"
log "Search mode: $SEARCH_MODE (${SEARCH_VALUE:-none})"

# v5.1: quiet mode -- from here on, scan output goes to data/scan-console.log; terminal shows progress only.
SCAN_RUN_START=$SECONDS
if [ "${SCAN_VERBOSE:-0}" != "1" ]; then
    exec 4>&1
    [ -t 1 ] && PROGRESS_TTY=1
    PROGRESS_COLS=$(tput cols 2>/dev/null); PROGRESS_COLS=${PROGRESS_COLS:-120}
    exec >> "$REPORT_DIR/data/scan-console.log" 2>&1
    PROGRESS_FD_OPEN=1
fi
progress 1 "Starting scan" s

kubectl version >> "$REPORT" 2>&1
echo "$CLUSTER_INFO_OUT" >> "$REPORT"

###############################################################################
# 1. KUBERNETES CONTROL PLANE HEALTH (not just "kubectl get pods worked")
###############################################################################

section "1. KUBERNETES CONTROL PLANE"

API_T0=$(now_ms)
READYZ_OUT=$(kubectl get --raw='/readyz?verbose' 2>&1)
READYZ_RC=$?
API_T1=$(now_ms)
READYZ_LATENCY_MS=$((API_T1 - API_T0))
echo "$READYZ_OUT" >> "$REPORT"
if [ $READYZ_RC -eq 0 ] && echo "$READYZ_OUT" | grep -qi "^readyz check passed\|ok$" ; then
    READYZ_STATE="HEALTHY"
else
    READYZ_STATE="PROBLEM"
    error "Kubernetes /readyz reports a problem."
    fix "Check: kubectl get --raw='/readyz?verbose'"
fi

API_T0=$(now_ms)
LIVEZ_OUT=$(kubectl get --raw='/livez?verbose' 2>&1)
LIVEZ_RC=$?
API_T1=$(now_ms)
LIVEZ_LATENCY_MS=$((API_T1 - API_T0))
echo "$LIVEZ_OUT" >> "$REPORT"
if [ $LIVEZ_RC -eq 0 ] && echo "$LIVEZ_OUT" | grep -qi "^livez check passed\|ok$"; then
    LIVEZ_STATE="HEALTHY"
else
    LIVEZ_STATE="PROBLEM"
    error "Kubernetes /livez reports a problem."
    fix "Check: kubectl get --raw='/livez?verbose'"
fi

# --- API server latency self-check: this scanner's own kubectl calls are
# the measurement. A slow response here (control plane or etcd overloaded)
# cascades into every controller and every app that talks to the API, and
# is one of the most common infra-wide causes of "everything feels slow"
# with no single crashing pod to point at. This is a single-sample check,
# not a trend -- a one-off blip can false-positive; corroborate with the
# etcd health check below and repeat runs before concluding this is a
# root cause.
API_LATENCY_MS=$READYZ_LATENCY_MS
[ "$LIVEZ_LATENCY_MS" -gt "$API_LATENCY_MS" ] && API_LATENCY_MS=$LIVEZ_LATENCY_MS

if [ "$API_LATENCY_MS" -ge "$API_LATENCY_CRIT_MS" ]; then
    critical "API server response time is elevated: ${API_LATENCY_MS}ms (critical threshold: ${API_LATENCY_CRIT_MS}ms) -- may indicate an overloaded control plane or slow etcd, which can cascade into slowness across the whole cluster."
    record_fact 12 API_LATENCY "-" "$CURRENT_CONTEXT" "infra" "API server /readyz-or-livez response took ${API_LATENCY_MS}ms (>= ${API_LATENCY_CRIT_MS}ms critical threshold) -- single-sample reading; corroborate with etcd health and repeat runs before treating as confirmed root cause"
elif [ "$API_LATENCY_MS" -ge "$API_LATENCY_WARN_MS" ]; then
    warn "API server response time is somewhat elevated: ${API_LATENCY_MS}ms (warning threshold: ${API_LATENCY_WARN_MS}ms)."
    record_fact 12 API_LATENCY "-" "$CURRENT_CONTEXT" "infra" "API server /readyz-or-livez response took ${API_LATENCY_MS}ms (>= ${API_LATENCY_WARN_MS}ms warning threshold)"
else
    info "API server response time: ${API_LATENCY_MS}ms (healthy, below ${API_LATENCY_WARN_MS}ms)."
fi

# CoreDNS as part of control-plane-adjacent health (checked in detail later too)
COREDNS_READY=$(kubectl get pods -n kube-system -l k8s-app=kube-dns \
    -o jsonpath='{range .items[*]}{.status.phase}{" "}{end}' 2>/dev/null)
if echo "$COREDNS_READY" | grep -q "Running" ; then
    COREDNS_STATE="HEALTHY"
else
    COREDNS_STATE="UNKNOWN/PROBLEM"
    warn "CoreDNS pods not confirmed Running via label k8s-app=kube-dns."
fi

if [ "$READYZ_STATE" = "HEALTHY" ] && [ "$LIVEZ_STATE" = "HEALTHY" ]; then
    CONTROL_PLANE_STATUS="HEALTHY"
else
    CONTROL_PLANE_STATUS="INVESTIGATION REQUIRED"
    record_fact 10 CONTROL_PLANE "-" "$CURRENT_CONTEXT" "infra" "readyz=$READYZ_STATE livez=$LIVEZ_STATE"
fi

info "Control plane: readyz=$READYZ_STATE livez=$LIVEZ_STATE coredns=$COREDNS_STATE"

###############################################################################
# 1B. ETCD HEALTH (best-effort -- only visible on kubeadm-style clusters
# where etcd runs as a static pod in kube-system; managed clusters like
# EKS/GKE/AKS run etcd outside the cluster entirely and this section will
# correctly report "not detected" rather than a false negative).
#
# Slow etcd (disk fsync latency, leader churn) is a classic, high-signal,
# purely read-only-detectable cause of cluster-wide slowness: etcd itself
# logs explicit "slow fdatasync" / "took too long" warnings when this
# happens, well before it becomes an outright outage.
###############################################################################

section "1C. ETCD HEALTH (best-effort)"

ETCD_PODS=$(kubectl get pods -n kube-system -l component=etcd -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
if [ -z "$ETCD_PODS" ]; then
    ETCD_PODS=$(kubectl get pods -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -E '^etcd(-|$)')
fi

SKIP_CLUSTER_LOGS=0
if [ -n "$SELECTED_NS" ] && [ "$SCOPE_INCLUDE_CLUSTER_COMPONENTS" != "1" ] && [ "$SELECTED_NS" != "kube-system" ]; then SKIP_CLUSTER_LOGS=1; fi
NS_ONLY=0; if [ -n "$SELECTED_NS" ] && [ "$SCOPE_INCLUDE_CLUSTER_COMPONENTS" != "1" ]; then NS_ONLY=1; fi
ETCD_SLOW_PATTERN='slow fdatasync|took too long|apply request took|waiting for readindex|failed to send out heartbeat|elected leader|lost leader|slow request'
ETCD_MATCH_COUNT=0
ETCD_POD_COUNT=0

if [ "$SKIP_CLUSTER_LOGS" = "1" ]; then
    info "etcd log scan skipped: namespace-scoped scan (set SCOPE_INCLUDE_CLUSTER_COMPONENTS=1 to include cluster components)."
elif [ -z "$ETCD_PODS" ]; then
    info "No etcd pod found in kube-system -- either this is a managed cluster (EKS/GKE/AKS) where etcd runs outside Kubernetes and is not visible here, or a non-standard etcd deployment. Not a failure of this check."
else
    for ETCD_POD in $ETCD_PODS; do
        ETCD_POD_COUNT=$((ETCD_POD_COUNT+1))
        ETCD_LOG_FILE="$REPORT_DIR/logs/etcd_${ETCD_POD}.log"
        kubectl logs "$ETCD_POD" -n kube-system --since="${SCAN_MINUTES}m" --tail="$LOG_TAIL_LINES" --timestamps > "$ETCD_LOG_FILE" 2>&1
        ETCD_MATCHES=$(grep -Ei "$ETCD_SLOW_PATTERN" "$ETCD_LOG_FILE" 2>/dev/null)
        if [ -n "$ETCD_MATCHES" ]; then
            THIS_COUNT=$(echo "$ETCD_MATCHES" | grep -c .)
            ETCD_MATCH_COUNT=$((ETCD_MATCH_COUNT + THIS_COUNT))
            error "etcd ($ETCD_POD): $THIS_COUNT slow-operation warning(s) in the last ${SCAN_MINUTES}m -- classic early signal of disk/latency-driven cluster-wide slowness."
            { echo ""; echo "ETCD SLOW: $ETCD_POD"; echo "$ETCD_MATCHES" | redact; } >> "$ERROR_REPORT"
            FIRST_ETCD_LINE=$(echo "$ETCD_MATCHES" | head -1 | cut -c1-200 | redact)
            record_fact 15 ETCD_SLOW "-" "$ETCD_POD" "infra" "$THIS_COUNT slow-operation warning(s) ($FIRST_ETCD_LINE) -- check disk I/O latency on the node hosting etcd" "$(extract_log_ts "$FIRST_ETCD_LINE")"
            fix "kubectl logs $ETCD_POD -n kube-system --since=${SCAN_MINUTES}m --timestamps | grep -Ei 'slow fdatasync|took too long'"
            fix "On the node hosting $ETCD_POD: check disk I/O latency (iostat/fio), since etcd fsyncs every write"
        fi
        search_context "$ETCD_LOG_FILE" "etcd: $ETCD_POD"
    done
    if [ "$ETCD_MATCH_COUNT" -eq 0 ]; then
        info "etcd: $ETCD_POD_COUNT pod(s) checked, no slow-operation warnings in the last ${SCAN_MINUTES}m."
    fi
fi

###############################################################################
# 2. NODES
###############################################################################

# =============================================================================================================
# v5.7 BULK PRELOAD: every kind of object is read ONCE for the whole scope (-A, or -n <selected namespace>) and
# sliced locally. v5.6 repeated these reads for every namespace, every Service and every pod; the old per-item
# reads remain only as fallbacks (a pod/Service that is missing from the bulk read is read individually).
# =============================================================================================================
POD_JP_BODY='{.status.phase}{"\n"}{.status.podIP}{"\n"}{.spec.nodeName}{"\n"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{range .status.conditions[?(@.type=="Ready")]}{.lastTransitionTime}{end}{"\n"}{.metadata.ownerReferences[0].kind}{"\n"}{.metadata.ownerReferences[0].name}{"\n"}{.spec.containers[*].readinessProbe.periodSeconds}{"\n"}{range .spec.containers[*]}{.resources.requests.cpu}{" "}{end}{"\n"}{range .spec.containers[*]}{.resources.limits.cpu}{" "}{end}{"\n"}{range .spec.containers[*]}{.resources.requests.memory}{" "}{end}{"\n"}{range .spec.containers[*]}{.resources.limits.memory}{" "}{end}{"\n"}{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{end}{"\n"}{.metadata.deletionTimestamp}{"\n"}{"@@C\n"}{range .spec.containers[*]}{.name}{"\n"}{.image}{"\n"}{.ports[*].containerPort}{"\n"}{end}{"@@S\n"}{range .status.containerStatuses[*]}{.name}{"\n"}{.restartCount}{"\n"}{.state}{"\n"}{.lastState}{"\n"}{.lastState.terminated.exitCode}{"\n"}{.lastState.terminated.reason}{"\n"}{.lastState.terminated.finishedAt}{"\n"}{end}'
BULK_DIR="$REPORT_DIR/data/bulk"; mkdir -p "$BULK_DIR/pods" "$BULK_DIR/eps"
BULK_SCOPE="-A"; [ -n "$SELECTED_NS" ] && BULK_SCOPE="-n $SELECTED_NS"
TPL_DEPLOY='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.status.readyReplicas}{"\n"}{end}'
TPL_STS='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.status.readyReplicas}{"\n"}{end}'
TPL_HPA='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.currentReplicas}{"\t"}{.spec.minReplicas}{"\t"}{.spec.maxReplicas}{"\t"}{.spec.scaleTargetRef.name}{"\t"}{range .status.conditions[?(@.type=="ScalingActive")]}{.status}{end}{"\n"}{end}'
TPL_JOBS='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.failed}{"\n"}{end}'
TPL_CRONJOBS='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.suspend}{"\t"}{.status.lastScheduleTime}{"\t"}{.status.lastSuccessfulTime}{"\n"}{end}'
TPL_SVC='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.clusterIP}{"\t"}{.spec.ports[*].port}{"\t"}{.spec.selector}{"\n"}{end}'
# bulk_read KIND TEMPLATE-VAR FILE : one read for the whole scope; FILE.ok marks that the read SUCCEEDED (an empty file then means "none exist")
bulk_read() { if kubectl get "$1" $BULK_SCOPE -o jsonpath="${!2}" > "$3" 2>/dev/null; then : > "$3.ok"; fi; }
# nsrows FILE KIND TEMPLATE-VAR : this namespace's rows (without the namespace column); if the bulk read failed, read just this namespace instead
nsrows() {
    if [ -f "$1.ok" ]; then
        awk -F'\t' -v ns="$NS" '$1 == ns { sub(/^[^\t]*\t/, ""); print }' "$1" 2>/dev/null
    else
        kubectl get "$2" -n "$NS" -o jsonpath="${!3}" 2>/dev/null | awk -F'\t' -v ns="$NS" '$1 == ns { sub(/^[^\t]*\t/, ""); print }'
    fi | dash_tsv
}

POD_JP_BULK='{range .items[*]}{"@@P "}{.metadata.namespace}{" "}{.metadata.name}{"\n"}'"$POD_JP_BODY"'{"@@END\n"}{end}'
kubectl get pods $BULK_SCOPE -o jsonpath="$POD_JP_BULK" 2>/dev/null > "$BULK_DIR/pods.txt"
POD_BULK_OK=0
if [ -s "$BULK_DIR/pods.txt" ]; then
    POD_BULK_OK=1
    awk -v dir="$BULK_DIR/pods" '
        $1 == "@@P"   { out = dir "/" $2 "__" $3 ".txt"; printf "" >> out; next }
        $1 == "@@END" { if (out != "") close(out); out = ""; next }
        out != ""     { print >> out }' "$BULK_DIR/pods.txt"
fi
bulk_read deployment TPL_DEPLOY "$BULK_DIR/deploy.tsv"
bulk_read statefulset TPL_STS "$BULK_DIR/sts.tsv"
bulk_read hpa TPL_HPA "$BULK_DIR/hpa.tsv"
bulk_read jobs TPL_JOBS "$BULK_DIR/jobs.tsv"
bulk_read cronjobs TPL_CRONJOBS "$BULK_DIR/cronjobs.tsv"
bulk_read svc TPL_SVC "$BULK_DIR/svc.tsv"
kubectl get endpointslices $BULK_SCOPE -o jsonpath='{range .items[*]}{"@@S\t"}{.metadata.namespace}{"\t"}{.metadata.labels.kubernetes\.io/service-name}{"\n"}{range .endpoints[*]}{.addresses[0]}{"\t"}{.conditions.ready}{"\t"}{.targetRef.name}{"\t"}{.conditions.terminating}{"\n"}{end}{end}' 2>/dev/null > "$BULK_DIR/eps.txt"
if [ -s "$BULK_DIR/eps.txt" ]; then
    awk -F'\t' -v dir="$BULK_DIR/eps" '
        $1 == "@@S" { if (out != "") close(out); out = dir "/" $2 "__" $3 ".txt"; printf "" >> out; next }
        out != "" && NF { print >> out }' "$BULK_DIR/eps.txt"
fi
{ echo "Ingresses:"; kubectl get ingress $BULK_SCOPE -o wide 2>&1; echo "NetworkPolicies:"; kubectl get networkpolicy $BULK_SCOPE 2>&1; } >> "$REPORT"
section "2. NODE HEALTH"

kubectl get nodes -o wide > "$REPORT_DIR/data/nodes.txt" 2>&1
cat "$REPORT_DIR/data/nodes.txt" >> "$REPORT"

if TOP_NODES_OUT=$(kubectl top nodes 2>&1); then
    echo "$TOP_NODES_OUT" >> "$REPORT"
else
    warn "kubectl top nodes unavailable (Metrics Server may not be installed)."
    fix "Check: kubectl get pods -n kube-system | grep metrics"
fi

# v5.4: ONE bulk read of every node's conditions / addresses / allocatable (v5.3 made 5 calls per node).
NODE_BULK="$REPORT_DIR/data/nodes-bulk.tsv"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[*]}{.type}={.status}{" "}{end}{"\t"}{range .status.addresses[*]}{.type}={.address}{" "}{end}{"\t"}{.status.allocatable.cpu}{"\t"}{.status.allocatable.memory}{"\n"}{end}' 2>/dev/null | dash_tsv > "$NODE_BULK"
NODE_LIST=$(cut -f1 "$NODE_BULK")
if [ "$NS_ONLY" = "1" ]; then
    # namespace-scoped: only check the node(s) that actually host pods of this namespace
    if [ "$POD_BULK_OK" = "1" ]; then
        NODE_LIST=$(awk '$1 == "@@P" { k = 0; next } { k++; if (k == 3 && $0 != "") print $0 }' "$BULK_DIR/pods.txt" | sort -u)
    else
        NODE_LIST=$(kubectl get pods -n "$SELECTED_NS" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' 2>/dev/null | awk 'NF' | sort -u)
    fi
    info "Node checks limited to the node(s) hosting pods of namespace $SELECTED_NS: $(echo $NODE_LIST)"
fi

# --- Kubernetes quantity parsing for the oversubscription check below.
# Deliberately approximate (decimal M/G treated ~= binary Mi/Gi) -- this is
# a triage signal ("is this node roughly oversubscribed?"), not a billing
# calculation, and exact byte-precision doesn't change the conclusion.
cpu_to_millicores() {
    # Kubernetes CPU quantity -> integer millicores. "500m" -> 500, "2" -> 2000,
    # "0.5" -> 500. Anything unparseable (or empty) -> 0 rather than an
    # arithmetic error, so one odd value can never abort the scan section.
    local v="$1"
    [ -z "$v" ] && { echo 0; return; }
    awk -v q="$v" 'BEGIN {
        if (q ~ /^[0-9]+m$/)                { sub(/m$/, "", q); printf "%d", q; exit }
        if (q ~ /^[0-9]+(\.[0-9]+)?$/)      { printf "%d", q * 1000; exit }
        print 0
    }'
}
mem_to_mi() {
    # Kubernetes memory quantity -> integer MiB. Handles binary (Ki/Mi/Gi/Ti)
    # and decimal (k/M/G/T) suffixes, fractions ("1.5Gi"), and bare bytes.
    # Anything unparseable (or empty) -> 0 rather than an arithmetic error.
    local v="$1"
    [ -z "$v" ] && { echo 0; return; }
    awk -v q="$v" 'BEGIN {
        if (match(q, /^[0-9]+(\.[0-9]+)?/) == 0) { print 0; exit }
        n = substr(q, 1, RLENGTH) + 0
        u = substr(q, RLENGTH + 1)
        if      (u == "Ki") m = n / 1024
        else if (u == "Mi") m = n
        else if (u == "Gi") m = n * 1024
        else if (u == "Ti") m = n * 1024 * 1024
        else if (u == "k")  m = n * 1000 / 1048576
        else if (u == "M")  m = n * 1000000 / 1048576
        else if (u == "G")  m = n * 1000000000 / 1048576
        else if (u == "T")  m = n * 1000000000000 / 1048576
        else if (u == "")   m = n / 1048576
        else { print 0; exit }
        printf "%d", m
    }'
}

# v5.4: declared CPU/memory REQUESTS per node. Full scope: ONE cluster-wide pod read (v5.3: one read per node).
# Namespace scope: one filtered read per node that hosts the namespace's pods.
NODE_REQ_RAW="$REPORT_DIR/data/node-requests-raw.txt"; : > "$NODE_REQ_RAW"
REQ_JP='{range .items[*]}{.spec.nodeName}{"|"}{.spec.containers[*].resources.requests.cpu}{"|"}{.spec.containers[*].resources.requests.memory}{"\n"}{end}'
if [ "$NS_ONLY" = "1" ]; then
    for NODE in $NODE_LIST; do
        kubectl get pods -A --field-selector spec.nodeName="$NODE" -o jsonpath="$REQ_JP" 2>/dev/null >> "$NODE_REQ_RAW"
    done
else
    if [ "$POD_BULK_OK" = "1" ] && [ -z "$SELECTED_NS" ]; then
        # whole cluster was already read: node name, CPU requests and memory requests are lines 3, 9 and 11 of each pod block
        awk '$1 == "@@P" { k = 0; n = ""; c = ""; m = ""; next } $1 == "@@END" { print n "|" c "|" m; next } { k++; if (k == 3) n = $0; if (k == 9) c = $0; if (k == 11) m = $0 }' "$BULK_DIR/pods.txt" > "$NODE_REQ_RAW"
    else
        kubectl get pods -A -o jsonpath="$REQ_JP" 2>/dev/null > "$NODE_REQ_RAW"
    fi
fi
NODE_REQ_TOT="$REPORT_DIR/data/node-requests-totals.tsv"
awk -F'|' '
    function cpu(q) { if (q ~ /^[0-9]+m$/) { sub(/m$/, "", q); return q + 0 } if (q ~ /^[0-9]+(\.[0-9]+)?$/) return q * 1000; return 0 }
    function mem(q,   n, u) {
        if (match(q, /^[0-9]+(\.[0-9]+)?/) == 0) return 0
        n = substr(q, 1, RLENGTH) + 0; u = substr(q, RLENGTH + 1)
        if (u == "Ki") return n / 1024; if (u == "Mi") return n; if (u == "Gi") return n * 1024; if (u == "Ti") return n * 1024 * 1024
        if (u == "k") return n * 1000 / 1048576; if (u == "M") return n * 1000000 / 1048576; if (u == "G") return n * 1000000000 / 1048576
        if (u == "T") return n * 1000000000000 / 1048576; if (u == "") return n / 1048576; return 0
    }
    { if ($1 == "") next; seen[$1] = 1; k = split($2, a, " "); for (i = 1; i <= k; i++) c[$1] += cpu(a[i]); k = split($3, b, " "); for (i = 1; i <= k; i++) m[$1] += mem(b[i]) }
    END { for (n in seen) printf "%s\t%d\t%d\n", n, c[n], m[n] }' "$NODE_REQ_RAW" > "$NODE_REQ_TOT"

for NODE in $NODE_LIST; do
    NODE_ROW=$(awk -F'\t' -v n="$NODE" '$1==n' "$NODE_BULK")
    COND=$(echo "$NODE_ROW" | cut -f2); IPS=$(echo "$NODE_ROW" | cut -f3)
    ALLOC_CPU_RAW=$(echo "$NODE_ROW" | cut -f4); ALLOC_MEM_RAW=$(echo "$NODE_ROW" | cut -f5)
    for _v in COND IPS ALLOC_CPU_RAW ALLOC_MEM_RAW; do [ "${!_v}" = "-" ] && printf -v "$_v" ''; done
    echo "NODE $NODE  IPs: $IPS  Conditions: $COND" >> "$REPORT"
    NODE_FLAGGED=0

    echo "$COND" | grep -q "Ready=False"          && { NODE_FLAGGED=1; critical "Node $NODE is NOT Ready. ($IPS)"; record_fact 20 NODE_NOT_READY "-" "$NODE" "infra" "Ready=False ($IPS)"; }
    echo "$COND" | grep -q "MemoryPressure=True"  && { NODE_FLAGGED=1; error "Node $NODE has MemoryPressure. ($IPS)"; record_fact 20 NODE_PRESSURE "-" "$NODE" "infra" "MemoryPressure ($IPS)"; }
    echo "$COND" | grep -q "DiskPressure=True"    && { NODE_FLAGGED=1; error "Node $NODE has DiskPressure. ($IPS)"; record_fact 20 NODE_PRESSURE "-" "$NODE" "infra" "DiskPressure ($IPS)"; }
    echo "$COND" | grep -q "PIDPressure=True"     && { NODE_FLAGGED=1; error "Node $NODE has PIDPressure. ($IPS)"; record_fact 20 NODE_PRESSURE "-" "$NODE" "infra" "PIDPressure ($IPS)"; }
    echo "$COND" | grep -q "NetworkUnavailable=True" && { NODE_FLAGGED=1; error "Node $NODE reports NetworkUnavailable. ($IPS)"; record_fact 20 NODE_NETWORK "-" "$NODE" "network" "NetworkUnavailable ($IPS)"; }

    # --- Node oversubscription: declared REQUESTS vs allocatable (invisible to `kubectl top`) ---
    ALLOC_CPU_M=$(cpu_to_millicores "$ALLOC_CPU_RAW")
    ALLOC_MEM_MI=$(mem_to_mi "$ALLOC_MEM_RAW")
    read -r REQ_CPU_TOTAL_M REQ_MEM_TOTAL_MI < <(awk -F'\t' -v n="$NODE" '$1==n {print $2 " " $3}' "$NODE_REQ_TOT")
    REQ_CPU_TOTAL_M=${REQ_CPU_TOTAL_M:-0}; REQ_MEM_TOTAL_MI=${REQ_MEM_TOTAL_MI:-0}

    if [ "$ALLOC_CPU_M" -gt 0 ] 2>/dev/null; then CPU_PCT=$(( REQ_CPU_TOTAL_M * 100 / ALLOC_CPU_M )); else CPU_PCT=0; fi
    if [ "$ALLOC_MEM_MI" -gt 0 ] 2>/dev/null; then MEM_PCT=$(( REQ_MEM_TOTAL_MI * 100 / ALLOC_MEM_MI )); else MEM_PCT=0; fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$NODE" "$REQ_CPU_TOTAL_M" "$ALLOC_CPU_M" "$CPU_PCT" "$REQ_MEM_TOTAL_MI" "$ALLOC_MEM_MI" "$MEM_PCT" >> "$REPORT_DIR/data/node-oversubscription.tsv"

    if [ "$CPU_PCT" -ge "$NODE_CPU_CRIT_PCT" ] 2>/dev/null || [ "$MEM_PCT" -ge "$NODE_MEM_CRIT_PCT" ] 2>/dev/null; then
        NODE_FLAGGED=1
        error "Node $NODE is oversubscribed by REQUESTS: CPU ${CPU_PCT}% (${REQ_CPU_TOTAL_M}m/${ALLOC_CPU_M}m), Memory ${MEM_PCT}% (${REQ_MEM_TOTAL_MI}Mi/${ALLOC_MEM_MI}Mi) of allocatable -- little scheduling headroom; likely contributor to CPU contention/slowness for pods here, even if kubectl top shows moderate live usage."
        record_fact 22 NODE_OVERSUBSCRIBED "-" "$NODE" "infra-or-developer" "Requested CPU ${CPU_PCT}% / Memory ${MEM_PCT}% of allocatable -- from declared resource requests, not live usage; reduce requests or add node capacity"
        fix "kubectl describe node $NODE   # see 'Allocated resources' section"
        fix "kubectl get pods -A --field-selector spec.nodeName=$NODE -o wide"
    elif [ "$CPU_PCT" -ge "$NODE_CPU_WARN_PCT" ] 2>/dev/null || [ "$MEM_PCT" -ge "$NODE_MEM_WARN_PCT" ] 2>/dev/null; then
        NODE_FLAGGED=1
        warn "Node $NODE requests are getting tight: CPU ${CPU_PCT}%, Memory ${MEM_PCT}% of allocatable."
        record_fact 22 NODE_OVERSUBSCRIBED "-" "$NODE" "infra-or-developer" "Requested CPU ${CPU_PCT}% / Memory ${MEM_PCT}% of allocatable -- approaching capacity"
    fi

    # `describe node` is heavy (it lists every pod on the node plus events): only for nodes with a finding.
    if [ "$NODE_FLAGGED" = "1" ] || [ "${DESCRIBE_ALL_NODES:-0}" = "1" ]; then
        NODE_DESC_FILE=$(mktemp)
        kubectl describe node "$NODE" > "$NODE_DESC_FILE" 2>&1
        cat "$NODE_DESC_FILE" >> "$REPORT"
        search_context "$NODE_DESC_FILE" "node describe: $NODE"
        rm -f "$NODE_DESC_FILE"
    fi
done

fix "Node OS-level history (kubelet/kernel/containerd journal for the last ${SCAN_MINUTES} min)"
fix "cannot be retrieved via the Kubernetes API alone. If needed, on the node itself run:"
fix "  journalctl -u kubelet --since \"${SCAN_MINUTES} minutes ago\""

###############################################################################
# 3. EVENTS -- Kubernetes Event retention is cluster-controlled, NOT tied to
# our scan window. We fetch whatever is currently retained, then separately
# report how many of those fall inside the requested window vs. outside it,
# so the HTML never implies "no events" means "nothing happened".
###############################################################################

section "3. CLUSTER EVENTS"
EVT_SCOPE="-A"; [ "$NS_ONLY" = "1" ] && EVT_SCOPE="-n $SELECTED_NS"

kubectl get events $EVT_SCOPE --sort-by=.lastTimestamp > "$REPORT_DIR/data/all-events.txt" 2>&1
cat "$REPORT_DIR/data/all-events.txt" >> "$REPORT"
search_context "$REPORT_DIR/data/all-events.txt" "cluster events"

grep -E '(^| )Warning( |$)' "$REPORT_DIR/data/all-events.txt" > "$REPORT_DIR/data/warning-events.txt" 2>/dev/null
cat "$REPORT_DIR/data/warning-events.txt" >> "$REPORT"

# Machine-parsable copy with lastTimestamp, used to compute how many of the
# currently-retained events actually fall inside [SCAN_START, SCAN_END].
kubectl get events $EVT_SCOPE -o jsonpath='{range .items[*]}{.lastTimestamp}{"\t"}{.type}{"\t"}{.involvedObject.namespace}{"\t"}{.involvedObject.name}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}' \
    > "$REPORT_DIR/data/events_raw.tsv" 2>/dev/null

SCAN_START_UTC=$(date -u -d "@$SCAN_START_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "$SCAN_START_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')
SCAN_END_UTC=$(date -u -d "@$SCAN_END_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "$SCAN_END_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')

TOTAL_RETAINED_EVENTS=$(wc -l < "$REPORT_DIR/data/events_raw.tsv" 2>/dev/null | tr -d ' ')
TOTAL_RETAINED_EVENTS=${TOTAL_RETAINED_EVENTS:-0}
EVENTS_IN_WINDOW=$(awk -F'\t' -v s="$SCAN_START_UTC" -v e="$SCAN_END_UTC" '$1!="" && $1>=s && $1<=e' "$REPORT_DIR/data/events_raw.tsv" 2>/dev/null | wc -l | tr -d ' ')
EVENTS_IN_WINDOW=${EVENTS_IN_WINDOW:-0}

# When a single namespace was selected, only that namespace's events (plus
# cluster-level events with no namespace, e.g. node events) are listed.
awk -F'\t' -v s="$SCAN_START_UTC" -v e="$SCAN_END_UTC" -v sel="$SELECTED_NS" -v OFS='\t' \
    '$1!="" && $1>=s && $1<=e && $2=="Warning" && (sel=="" || $3=="" || $3==sel)' \
    "$REPORT_DIR/data/events_raw.tsv" > "$REPORT_DIR/data/warning-events-in-window.tsv" 2>/dev/null
WARN_EVT_COUNT=$(wc -l < "$REPORT_DIR/data/warning-events-in-window.tsv" 2>/dev/null | tr -d ' ')
WARN_EVT_COUNT=${WARN_EVT_COUNT:-0}

if [ "$WARN_EVT_COUNT" -gt 0 ] 2>/dev/null; then
    warn "Found $WARN_EVT_COUNT Warning event(s) inside the requested ${SCAN_MINUTES}-minute window${SELECTED_NS:+ for namespace $SELECTED_NS (plus cluster-level events)} (of $TOTAL_RETAINED_EVENTS total events currently retained by the API server)."
    echo "    Most recent Warning events (newest first, max 15; full list in errors-and-warnings.txt):"
    sort -t$'\t' -k1,1r "$REPORT_DIR/data/warning-events-in-window.tsv" | head -15 | awk -F'\t' '{
        ts=$1; sub(/^[0-9-]+T/, "", ts); sub(/Z$/, "", ts)
        msg=$6; if (length(msg) > 160) msg=substr(msg, 1, 157) "..."
        printf "    %s  %s/%s  [%s] %s\n", ts, ($3=="" ? "-" : $3), $4, $5, msg }' | redact
    {
        echo ""
        echo "WARNING EVENTS IN WINDOW (${WARN_EVT_COUNT}), newest first:"
        sort -t$'\t' -k1,1r "$REPORT_DIR/data/warning-events-in-window.tsv" | awk -F'\t' '{
            printf "  %s  %s/%s  [%s] %s\n", $1, ($3=="" ? "-" : $3), $4, $5, $6 }' | redact
    } >> "$ERROR_REPORT"
fi

info "Events: $EVENTS_IN_WINDOW of $TOTAL_RETAINED_EVENTS currently-retained events fall inside the requested window ($SCAN_START_UTC -> $SCAN_END_UTC UTC). Kubernetes Event retention is set by the cluster, not by this scanner -- older events may already be gone, so a low count here does not prove nothing happened."

###############################################################################
# 4. NAMESPACE / WORKLOAD SCAN
###############################################################################

# --- Pod CPU/memory usage snapshot, fetched ONCE cluster-wide here (not
# per-pod in the loop below) to avoid one extra kubectl call per pod on a
# large cluster. Cross-referenced against each pod's own declared
# requests/limits during the per-pod loop below -- a raw "340Mi" number is
# meaningless without knowing whether that's near, at, or nowhere close to
# what the pod is allowed to use. Gracefully skipped if Metrics Server
# isn't installed (same condition the existing section 7 top-nodes/pods
# checks already handle).
POD_METRICS_FILE="$REPORT_DIR/data/pod-metrics-raw.tsv"
POD_METRICS_AVAILABLE=0
fetch_pod_metrics() {
    # same 4-column format (namespace pod cpu memory) in both modes
    if [ "$NS_ONLY" = "1" ]; then
        kubectl top pods -n "$SELECTED_NS" --no-headers 2>/dev/null | awk -v ns="$SELECTED_NS" 'NF {print ns " " $0}'
    else
        kubectl top pods -A --no-headers 2>/dev/null
    fi
}
if fetch_pod_metrics > "$POD_METRICS_FILE" && [ -s "$POD_METRICS_FILE" ]; then
    POD_METRICS_AVAILABLE=1
else
    : > "$POD_METRICS_FILE"
    warn "kubectl top pods unavailable (Metrics Server may not be installed) -- per-pod CPU/memory usage will not be included in this report."
    fix "Check: kubectl get pods -n kube-system | grep metrics"
fi

# When scope is SELECTED (specific pods chosen), only namespaces that
# contain at least one selected pod are visited, and within each such
# namespace only the selected pods get the deep per-pod scan (describe,
# container status, restarts, OOM check, log scan). Deployment/
# StatefulSet/Job/CronJob/Service checks still run for the WHOLE
# namespace the pod lives in, not just the selected pod's own owner --
# this is a deliberate choice: it gives real context (e.g. "is the
# Service routing to this pod healthy?") at negligible extra cost,
# without needing full ownerReference resolution up front.
selected_pods_in_ns() {
    # SELECTED_PODS is already scoped to the single chosen namespace
    # (SELECTED_NS) by construction with the namespace-first picker, so
    # this no longer needs a namespace argument or any "ns/pod" splitting.
    echo "$SELECTED_PODS" | tr ' ' '\n'
}

case "$SCOPE_MODE" in
    NAMESPACE_ALL_PODS)
        NAMESPACE_LIST="$SELECTED_NS"
        info "Scan scope restricted to namespace: $SELECTED_NS (all pods)"
        ;;
    NAMESPACE_SELECTED)
        NAMESPACE_LIST="$SELECTED_NS"
        info "Scan scope restricted to namespace: $SELECTED_NS, pod(s): $SELECTED_PODS"
        ;;
    *)
        NAMESPACE_LIST=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
        ;;
esac

REDIS_FOUND=0
NS_IDX=0; NS_TOTAL=$(echo "$NAMESPACE_LIST" | wc -w | tr -d " "); [ "${NS_TOTAL:-0}" -lt 1 ] && NS_TOTAL=1

for NS in $NAMESPACE_LIST; do
    section "NAMESPACE: $NS"

    # `get all` fans out into ~10 list calls per namespace and only feeds the text dump: opt-in (ENABLE_GET_ALL_DUMP=1).
    if [ "${ENABLE_GET_ALL_DUMP:-0}" = "1" ]; then
        kubectl get all -n "$NS" -o wide >> "$REPORT" 2>&1
    fi

    # Workloads (Deployments + StatefulSets) with desired>0 and ZERO ready replicas are complete outages of that
    # workload -> CRITICAL. If EVERY workload in the namespace is in that state it is a namespace outage.
    # v5.4: each kind is read with ONE call per namespace (v5.3 made 2-5 calls per object).
    NS_WL_TOTAL=0; NS_WL_DOWN=0

    # --- Deployments ---
    while IFS=$'\t' read -r -u 3 D DESIRED READY; do
        [ -z "$D" ] && continue
        [ "$DESIRED" = "-" ] && DESIRED=""
        [ "$READY" = "-" ] && READY=0
        NS_WL_TOTAL=$((NS_WL_TOTAL+1))
        if [ "$READY" != "$DESIRED" ]; then
            if [ "$READY" = "0" ] && [ "${DESIRED:-0}" -gt 0 ] 2>/dev/null; then
                NS_WL_DOWN=$((NS_WL_DOWN+1))
                critical "Deployment $NS/$D is DOWN: 0 of $DESIRED replicas ready (complete outage of this workload)."
            else
                error "Deployment $NS/$D READY=$READY DESIRED=$DESIRED."
            fi
            fix "kubectl describe deployment $D -n $NS"
        fi
    done 3< <(nsrows "$BULK_DIR/deploy.tsv" deployment TPL_DEPLOY)

    # --- StatefulSets (important for Redis/Kafka/DB-style workloads) ---
    while IFS=$'\t' read -r -u 3 SS SS_DESIRED SS_READY; do
        [ -z "$SS" ] && continue
        [ "$SS_DESIRED" = "-" ] && SS_DESIRED=""
        [ "$SS_READY" = "-" ] && SS_READY=0
        NS_WL_TOTAL=$((NS_WL_TOTAL+1))
        if [ "$SS_READY" != "$SS_DESIRED" ]; then
            if [ "$SS_READY" = "0" ] && [ "${SS_DESIRED:-0}" -gt 0 ] 2>/dev/null; then
                NS_WL_DOWN=$((NS_WL_DOWN+1))
                critical "StatefulSet $NS/$SS is DOWN: 0 of $SS_DESIRED replicas ready (complete outage of this workload)."
            else
                error "StatefulSet $NS/$SS READY=$SS_READY DESIRED=$SS_DESIRED."
            fi
            fix "kubectl describe statefulset $SS -n $NS"
            record_fact 55 STATEFULSET_NOT_READY "$NS" "$SS" "infra-or-developer" "StatefulSet $SS: $SS_READY/$SS_DESIRED replicas ready"
        fi
    done 3< <(nsrows "$BULK_DIR/sts.tsv" statefulset TPL_STS)

    if [ "$NS_WL_TOTAL" -gt 0 ] && [ "$NS_WL_DOWN" -eq "$NS_WL_TOTAL" ]; then
        critical "Namespace $NS: ALL $NS_WL_TOTAL workload(s) (Deployments/StatefulSets) have zero ready replicas -- complete namespace outage, not a partial degradation."
    fi

    # --- HPA: a workload can look fully Ready while the autoscaler is blind or maxed out ("works but is slow") ---
    while IFS=$'\t' read -r -u 3 HPA HPA_CUR HPA_MIN HPA_MAX HPA_TARGET HPA_SCALING_ACTIVE; do
        [ -z "$HPA" ] && continue
        for _v in HPA_CUR HPA_MIN HPA_MAX HPA_TARGET HPA_SCALING_ACTIVE; do [ "${!_v}" = "-" ] && printf -v "$_v" ''; done
        echo "HPA $NS/$HPA  target=$HPA_TARGET current=$HPA_CUR min=$HPA_MIN max=$HPA_MAX ScalingActive=$HPA_SCALING_ACTIVE" >> "$REPORT"
        if [ "$HPA_SCALING_ACTIVE" = "False" ]; then
            error "HPA $NS/$HPA (target: $HPA_TARGET) has ScalingActive=False -- it cannot read the metrics it needs to scale at all. If load is currently high, this workload will NOT scale up, which will feel like slowness/timeouts under load."
            fix "kubectl describe hpa $HPA -n $NS   # check the exact reason under Conditions"
            fix "kubectl get pods -n kube-system -l k8s-app=metrics-server   # confirm metrics-server itself is healthy"
            record_fact 43 HPA_INACTIVE "$NS" "$HPA" "infra-or-developer" "HPA for $HPA_TARGET has ScalingActive=False -- cannot obtain metrics to scale on; will not respond to load regardless of traffic"
        elif [ -n "$HPA_CUR" ] && [ -n "$HPA_MAX" ] && [ "$HPA_CUR" -ge "$HPA_MAX" ] 2>/dev/null; then
            warn "HPA $NS/$HPA (target: $HPA_TARGET) is at its maximum: $HPA_CUR/$HPA_MAX replicas. If it's still under load, this is a capacity ceiling, not a bug -- raise maxReplicas or node capacity."
            fix "kubectl describe hpa $HPA -n $NS"
            fix "kubectl top pods -n $NS -l app=$HPA_TARGET 2>/dev/null"
            record_fact 43 HPA_MAXED "$NS" "$HPA" "developer-or-infra" "HPA for $HPA_TARGET is maxed at $HPA_CUR/$HPA_MAX replicas -- likely under-provisioned for current load if traffic is still elevated"
        fi
    done 3< <(nsrows "$BULK_DIR/hpa.tsv" hpa TPL_HPA)

    # --- Jobs: any Job with failed pod attempts ---
    while IFS=$'\t' read -r -u 3 J JOB_FAILED; do
        [ -z "$J" ] && continue
        [ "$JOB_FAILED" = "-" ] && JOB_FAILED=""
        if [ -n "$JOB_FAILED" ] && [ "$JOB_FAILED" -gt 0 ] 2>/dev/null; then
            error "Job $NS/$J has $JOB_FAILED failed pod attempt(s)."
            fix "kubectl describe job $J -n $NS"
            fix "kubectl logs -n $NS -l job-name=$J --all-containers --tail=200"
            record_fact 55 JOB_FAILED "$NS" "$J" "developer" "Job $J: $JOB_FAILED failed attempt(s)"
        fi
    done 3< <(nsrows "$BULK_DIR/jobs.tsv" jobs TPL_JOBS)

    # --- CronJobs: last scheduled run without a matching successful completion (best-effort) ---
    while IFS=$'\t' read -r -u 3 CJ CJ_SUSPENDED CJ_LAST_SCHEDULE CJ_LAST_SUCCESS; do
        [ -z "$CJ" ] && continue
        for _v in CJ_SUSPENDED CJ_LAST_SCHEDULE CJ_LAST_SUCCESS; do [ "${!_v}" = "-" ] && printf -v "$_v" ''; done
        if [ "$CJ_SUSPENDED" != "true" ] && [ -n "$CJ_LAST_SCHEDULE" ] && [ "$CJ_LAST_SCHEDULE" != "$CJ_LAST_SUCCESS" ]; then
            warn "CronJob $NS/$CJ last scheduled ($CJ_LAST_SCHEDULE) does not match last successful run (${CJ_LAST_SUCCESS:-none})."
            fix "kubectl describe cronjob $CJ -n $NS"
            fix "kubectl get jobs -n $NS | grep $CJ"
            record_fact 55 CRONJOB_UNCERTAIN "$NS" "$CJ" "developer" "Last scheduled=$CJ_LAST_SCHEDULE, last successful=${CJ_LAST_SUCCESS:-none} -- most recent run may have failed"
        fi
    done 3< <(nsrows "$BULK_DIR/cronjobs.tsv" cronjobs TPL_CRONJOBS)

    echo "Services:" >> "$REPORT"
    # v5.4: ONE read for every Service (name, ClusterIP, ports, selector); v5.3 made ~5 calls per Service.
    SVC_BULK="$REPORT_DIR/data/svc-bulk-$NS.tsv"
    nsrows "$BULK_DIR/svc.tsv" svc TPL_SVC > "$SVC_BULK"
    { echo "  name / clusterIP / ports / selector:"; sed 's/^/  /' "$SVC_BULK"; } >> "$REPORT"
    while IFS=$'\t' read -r -u 3 SVC CLUSTER_IP SVC_PORT_LIST SVC_SEL_JSON; do
        [ -z "$SVC" ] && continue
        for _v in CLUSTER_IP SVC_PORT_LIST SVC_SEL_JSON; do [ "${!_v}" = "-" ] && printf -v "$_v" ''; done

        TERM_LIST=""
        EPS_KNOWN=0; EPS_FILE="$BULK_DIR/eps/${NS}__${SVC}.txt"
        if [ -f "$EPS_FILE" ]; then
            EPS_KNOWN=1; SLICE_ROWS=$(cat "$EPS_FILE")
        else
            SLICE_ROWS=$(kubectl get endpointslices -n "$NS" -l "kubernetes.io/service-name=$SVC" \
                -o jsonpath='{range .items[*]}{range .endpoints[*]}{.addresses[0]}{"\t"}{.conditions.ready}{"\t"}{.targetRef.name}{"\t"}{.conditions.terminating}{"\n"}{end}{end}' 2>/dev/null)
        fi

        if [ -z "$SLICE_ROWS" ] && [ "$EPS_KNOWN" != "1" ]; then
            # Fallback: no EndpointSlice found (older cluster / CNI) -- use legacy Endpoints
            LEGACY_READY=$(kubectl get endpoints "$SVC" -n "$NS" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)
            LEGACY_NOTREADY=$(kubectl get endpoints "$SVC" -n "$NS" -o jsonpath='{.subsets[*].notReadyAddresses[*].ip}' 2>/dev/null)
            READY_LIST="$LEGACY_READY"
            NOTREADY_LIST="$LEGACY_NOTREADY"
        else
            READY_LIST=$(echo "$SLICE_ROWS" | awk -F'\t' '$2=="true"{ if ($3=="") printf "%s ", $1; else printf "%s(%s) ", $1, $3 }')
            NOTREADY_LIST=$(echo "$SLICE_ROWS" | awk -F'\t' '$2!="true" && $4!="true"{ if ($3=="") printf "%s ", $1; else printf "%s(%s) ", $1, $3 }')
            TERM_LIST=$(echo "$SLICE_ROWS" | awk -F'\t' '$2!="true" && $4=="true"{ if ($3=="") printf "%s ", $1; else printf "%s(%s) ", $1, $3 }')
        fi

        # Optional active probe of every ready AND not-ready endpoint pod
        # for this Service (off by default -- see ENABLE_ENDPOINT_PROBE).
        # Only possible where we have per-endpoint pod names, i.e. the
        # EndpointSlice path; the legacy Endpoints fallback has IPs only.
        [ -n "$SLICE_ROWS" ] && probe_service_endpoints "$NS" "$SVC" "$SLICE_ROWS"

        echo "SERVICE $NS/$SVC  ClusterIP=$CLUSTER_IP  Ready=[$READY_LIST]  NotReady=[$NOTREADY_LIST]" >> "$REPORT"

        if [ -z "$READY_LIST" ] && [ -z "$NOTREADY_LIST" ] && [ -n "$TERM_LIST" ]; then
            warn "Service $NS/$SVC has no ready endpoints right now: every backend is terminating ($TERM_LIST) -- a rollout or scale-down in progress; re-scan in a minute before treating it as an outage."
        elif [ -z "$READY_LIST" ] && [ -z "$NOTREADY_LIST" ]; then
            # Explain WHY there are no endpoints: compare the Service's selector
            # with the pods that actually carry those labels (read-only gets).
            SVC_SELECTOR=$(echo "$SVC_SEL_JSON" | sed 's/[{}" ]//g; s/:/=/g')
            if [ -z "$SVC_SELECTOR" ]; then
                SEL_NOTE="the Service defines no selector (ExternalName or manually managed Endpoints)"
            else
                SEL_MATCH=$(kubectl get pods -n "$NS" -l "$SVC_SELECTOR" -o name 2>/dev/null | grep -c .)
                if [ "${SEL_MATCH:-0}" -eq 0 ] 2>/dev/null; then
                    SEL_NOTE="selector '$SVC_SELECTOR' matches ZERO pods in namespace $NS -- label/selector mismatch, so this Service can never route traffic regardless of pod health"
                else
                    SEL_NOTE="selector '$SVC_SELECTOR' matches $SEL_MATCH pod(s) but none are registered as endpoints -- they are likely not Running/Ready"
                fi
            fi
            error "Service $NS/$SVC (ClusterIP $CLUSTER_IP) has NO active endpoints (ready or not-ready) -- $SEL_NOTE."
            fix "kubectl describe svc $SVC -n $NS"
            fix "kubectl get svc $SVC -n $NS -o yaml   # confirm .spec.selector"
            fix "kubectl get endpointslices -n $NS -l kubernetes.io/service-name=$SVC"
            fix "kubectl get pods -n $NS --show-labels"
            record_fact 40 NO_ENDPOINTS "$NS" "$SVC" "developer-or-network" "Service $SVC ($CLUSTER_IP) has zero endpoints at all -- $SEL_NOTE"
        elif [ -z "$READY_LIST" ] && [ -n "$NOTREADY_LIST" ]; then
            error "Service $NS/$SVC (ClusterIP $CLUSTER_IP) has endpoints but NONE are Ready: $NOTREADY_LIST"
            fix "kubectl describe svc $SVC -n $NS"
            fix "kubectl get endpointslices -n $NS -l kubernetes.io/service-name=$SVC -o wide"
            record_fact 40 NO_ENDPOINTS "$NS" "$SVC" "developer-or-network" "Service $SVC ($CLUSTER_IP) has endpoints but all are NotReady: $NOTREADY_LIST -- pods exist but are failing readiness"
        elif [ -n "$NOTREADY_LIST" ]; then
            warn "Service $NS/$SVC (ClusterIP $CLUSTER_IP) is partially degraded -- ready: $READY_LIST | not-ready: $NOTREADY_LIST"
            record_fact 42 PARTIAL_NOT_READY "$NS" "$SVC" "developer" "Ready: $READY_LIST | NotReady: $NOTREADY_LIST -- some backing pods are failing readiness while others serve traffic"
        else
            info "Service $NS/$SVC ($CLUSTER_IP) all endpoints ready: $READY_LIST"
        fi

        if [ -n "$TERM_LIST" ] && [ -n "$READY_LIST" ]; then
            info "Service $NS/$SVC has terminating endpoint(s) -- rollout or scale-down in progress, not a fault: $TERM_LIST"
        fi

        # `describe svc` only for Services with a problem (or DESCRIBE_ALL_SERVICES=1)
        if [ -z "$READY_LIST" ] || [ -n "$NOTREADY_LIST" ] || [ "${DESCRIBE_ALL_SERVICES:-0}" = "1" ]; then
            kubectl describe svc "$SVC" -n "$NS" >> "$REPORT" 2>&1
        fi

        # Save for the HTML "Service Topology" section
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$NS" "$SVC" "$CLUSTER_IP" "$READY_LIST" "$NOTREADY_LIST" "$TERM_LIST" >> "$REPORT_DIR/data/service-topology.tsv"

        SVC_CONFIRMED_REDIS=0
        echo "$SVC" | grep -Eqi '(^|-)redis(-|$)' && SVC_CONFIRMED_REDIS=1
        echo "$SVC_PORT_LIST" | grep -Eq '(^|[^[:alnum:]_])(6379|6380)([^[:alnum:]_]|$)' && SVC_CONFIRMED_REDIS=1

        if [ $SVC_CONFIRMED_REDIS -eq 1 ]; then
            REDIS_FOUND=1
            if [ -z "$READY_LIST" ]; then
                set_redis_status 4 "DETECTED / NO READY ENDPOINTS (Service $SVC has none)"
            fi
        elif echo "$SVC" | grep -Eqi '(^|-)cache(-|$)|session-store'; then
            set_redis_status 1 "DETECTED / UNVERIFIED (Service name-only cache match, not confirmed Redis)"
        fi
    done 3< "$SVC_BULK"


    # --- Pods ---
    if [ "$POD_BULK_OK" = "1" ]; then
        POD_LIST=$(awk -v ns="$NS" '$1 == "@@P" && $2 == ns { print $3 }' "$BULK_DIR/pods.txt")
    else
        POD_LIST=$(kubectl get pods -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    fi
    if [ "$SCOPE_MODE" = "NAMESPACE_SELECTED" ]; then
        ALLOWED_PODS=$(selected_pods_in_ns)
        POD_LIST=$(echo "$POD_LIST" | while read -r p; do
            [ -z "$p" ] && continue
            echo "$ALLOWED_PODS" | grep -qx "$p" && echo "$p"
        done)
    fi

    POD_IDX=0; POD_N=$(echo "$POD_LIST" | grep -c .); [ "${POD_N:-0}" -lt 1 ] && POD_N=1
    for POD in $POD_LIST; do
        POD_TOTAL=$((POD_TOTAL+1))
        POD_IDX=$((POD_IDX+1)); progress_pods
        # v5.4: ONE kubectl call per pod (v5.3 made ~28). The reply is newline-delimited in this fixed order:
        #  0 phase  1 podIP  2 node  3 Ready  4 Ready-since  5 ownerKind  6 ownerName  7 readinessProbe
        #  8-11 cpu/mem requests+limits (per container, space separated)  12 waiting reasons
        #  then "@@C" + 3 lines per container (name, image, ports) and "@@S" + 7 lines per container status
        #  (name, restarts, state, lastState, exitCode, reason, finishedAt).
        PD=()
        if [ -s "$BULK_DIR/pods/${NS}__${POD}.txt" ]; then mapfile -t PD < "$BULK_DIR/pods/${NS}__${POD}.txt"; fi
        if [ "${#PD[@]}" -eq 0 ]; then   # not in the bulk read (new pod, or bulk read failed): read it individually
            mapfile -t PD < <(kubectl get pod "$POD" -n "$NS" -o jsonpath="$POD_JP_BODY" 2>/dev/null)
        fi
        POD_STATUS="${PD[0]:-}"; POD_IP="${PD[1]:-}"; NODE_NAME="${PD[2]:-}"; READY_COND="${PD[3]:-}"
        HAS_READINESS_PROBE="${PD[7]:-}"
        P_REQCPU="${PD[8]:-}"; P_LIMCPU="${PD[9]:-}"; P_REQMEM="${PD[10]:-}"; P_LIMMEM="${PD[11]:-}"; P_WAITREASONS="${PD[12]:-}"; POD_TERMINATING="${PD[13]:-}"
        if [ -z "$POD_STATUS" ]; then
            POD_UNREAD=$((POD_UNREAD+1))
            info "Pod $NS/$POD could not be read (deleted since the list was taken, or API error) -- skipped."
            continue
        fi
        POD_OWNER_CACHE["$NS/$POD"]="${PD[5]:-}|${PD[6]:-}"
        POD_READY_TRANS["$NS/$POD"]="${PD[4]:-}"
        unset CS_IMAGE CS_PORTS CS_RESTARTS CS_STATE CS_LAST CS_EXIT CS_REASON CS_FIN
        declare -A CS_IMAGE CS_PORTS CS_RESTARTS CS_STATE CS_LAST CS_EXIT CS_REASON CS_FIN
        CONTAINERS=""; _mode=""; _i=14
        while [ "$_i" -lt "${#PD[@]}" ]; do
            case "${PD[$_i]}" in
                "@@C") _mode=C; _i=$((_i+1)); continue ;;
                "@@S") _mode=S; _i=$((_i+1)); continue ;;
            esac
            if [ "$_mode" = "C" ]; then
                _cn="${PD[$_i]}"; CONTAINERS="${CONTAINERS:+$CONTAINERS$'\n'}$_cn"
                CS_IMAGE[$_cn]="${PD[$((_i+1))]:-}"; CS_PORTS[$_cn]="${PD[$((_i+2))]:-}"; _i=$((_i+3))
            elif [ "$_mode" = "S" ]; then
                _cn="${PD[$_i]}"
                CS_RESTARTS[$_cn]="${PD[$((_i+1))]:-}"; CS_STATE[$_cn]="${PD[$((_i+2))]:-}"; CS_LAST[$_cn]="${PD[$((_i+3))]:-}"
                CS_EXIT[$_cn]="${PD[$((_i+4))]:-}"; CS_REASON[$_cn]="${PD[$((_i+5))]:-}"; CS_FIN[$_cn]="${PD[$((_i+6))]:-}"; _i=$((_i+7))
            else
                _i=$((_i+1))
            fi
        done

        echo "" >> "$REPORT"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$NS/$POD" "$NODE_NAME" "${PD[5]:-}" "${PD[6]:-}" "$P_LIMMEM" "$P_LIMCPU" "$(echo $CONTAINERS)" "$POD_IP" >> "$POD_INFO_FILE"
        echo "POD: $NS/$POD  STATUS=$POD_STATUS  IP=$POD_IP  NODE=$NODE_NAME" >> "$REPORT"
        # `describe pod` is heavy (pod + its events): only when something looks wrong, or DESCRIBE_ALL_PODS=1.
        POD_UNHEALTHY=0
        if [ "$POD_STATUS" != "Running" ] && [ "$POD_STATUS" != "Succeeded" ]; then POD_UNHEALTHY=1; fi
        if [ "$POD_STATUS" = "Running" ] && [ "$READY_COND" != "True" ] && [ -z "$POD_TERMINATING" ]; then POD_UNHEALTHY=1; fi
        for _cn in "${!CS_RESTARTS[@]}"; do
            if [ "${CS_RESTARTS[$_cn]:-0}" -gt 0 ] 2>/dev/null; then POD_UNHEALTHY=1; fi
        done
        if [ "$POD_UNHEALTHY" = "1" ] || [ "${DESCRIBE_ALL_PODS:-0}" = "1" ]; then
            POD_DESC_FILE=$(mktemp)
            kubectl describe pod "$POD" -n "$NS" > "$POD_DESC_FILE" 2>&1
            cat "$POD_DESC_FILE" >> "$REPORT"
            search_context "$POD_DESC_FILE" "pod describe: $NS/$POD"
            rm -f "$POD_DESC_FILE"
        fi

        case "$POD_STATUS" in
            Running|Succeeded) ;;
            Pending)
                # A "Pending" phase means two very different things that
                # need different fixes: the pod may still be unschedulable
                # (no node fits -- resources, taints, unbound PVC), or it
                # may already be scheduled to a node and stuck because a
                # container can't start (bad image, missing ConfigMap/
                # Secret). "kubectl top nodes"/"resourcequota" only helps
                # the first case; conflating them under one PENDING
                # category pointed the wrong commands at the wrong fix.
                WAITING_REASON=$(echo "$P_WAITREASONS" | sed 's/[[:space:]]*$//')
                # The kubelet's own message names the exact missing ConfigMap /
                # Secret / key (or the failing image), e.g. 'configmap "x" not found'.
                WAITING_MESSAGE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.state.waiting.message}{" | "}{end}' 2>/dev/null | tr '\t\n' '  ' | sed -e 's/[[:space:]|]*$//')
                if [ -n "$NODE_NAME" ] && echo "$WAITING_REASON" | grep -Eqi 'ImagePullBackOff|ErrImagePull|InvalidImageName|CreateContainerConfigError|CreateContainerError'; then
                    error "Pod $NS/$POD is Pending due to a container start error on node=$NODE_NAME (reason: $WAITING_REASON). Kubelet message: ${WAITING_MESSAGE:-<none reported>}"
                    fix "kubectl describe pod $POD -n $NS   # check Events for the exact image/config/secret error"
                    fix "kubectl get pod $POD -n $NS -o jsonpath='{.status.containerStatuses[*].state.waiting.message}'"
                    record_fact 55 PENDING_CONTAINER_ERROR "$NS" "$POD" "developer" "Pending on node=$NODE_NAME due to a container start error ($WAITING_REASON) -- kubelet message: ${WAITING_MESSAGE:-none reported} -- already scheduled fine; check the image reference, ConfigMap/Secret references, or registry credentials, not node capacity"
                else
                    error "Pod $NS/$POD is Pending. (node=${NODE_NAME:-<unscheduled>})"
                    fix "kubectl describe pod $POD -n $NS"
                    fix "kubectl top nodes"
                    fix "kubectl get resourcequota -n $NS"
                    record_fact 55 PENDING_SCHEDULING "$NS" "$POD" "infra-or-developer" "Pending, unscheduled or awaiting resources (node=${NODE_NAME:-none}) -- check node capacity, PVC binding, taints/affinity, or resource requests"
                fi
                ;;
            Failed)  error "Pod $NS/$POD is Failed. (node=$NODE_NAME)"; fix "kubectl logs $POD -n $NS --all-containers"; record_fact 55 FAILED "$NS" "$POD" "developer" "Pod Failed on node=$NODE_NAME" ;;
            Unknown) error "Pod $NS/$POD status is Unknown. (node=$NODE_NAME)"; record_fact 55 UNKNOWN "$NS" "$POD" "infra" "Pod status Unknown on node=$NODE_NAME -- possible node/kubelet issue" ;;
            *) [ -n "$POD_STATUS" ] && warn "Pod $NS/$POD has status $POD_STATUS." ;;
        esac

        # (READY_COND comes from the single pod read above)
        if [ -n "$POD_TERMINATING" ]; then
            info "Pod $NS/$POD is terminating (deletion requested $POD_TERMINATING) -- not treated as a readiness failure."
        elif [ "$READY_COND" = "False" ] && [ "$POD_STATUS" = "Running" ]; then
            # Don't presume a readinessProbe exists and is "failing" -- a
            # Running-but-not-Ready pod is just as often a container that
            # hasn't finished starting, or one with NO readinessProbe at
            # all still cycling through restarts, as it is an actual probe
            # misconfiguration. Check for a defined readinessProbe on any
            # container before wording it either way.
            # (HAS_READINESS_PROBE comes from the single pod read above)
            if [ -n "$HAS_READINESS_PROBE" ]; then
                warn "Pod $NS/$POD is Running but not Ready (a readinessProbe is defined and is failing)."
                record_fact 40 READINESS_FAIL "$NS" "$POD" "developer" "Running but Ready=False with a readinessProbe defined -- the probe itself is failing; pod is excluded from Service endpoints"
            else
                warn "Pod $NS/$POD is Running but not Ready (no readinessProbe is defined -- likely still starting up or cycling through restarts, not a probe failure)."
                record_fact 40 READINESS_FAIL "$NS" "$POD" "developer" "Running but Ready=False with NO readinessProbe defined -- check container startup/restart state (e.g. CrashLoopBackOff, OOM) rather than probe config; pod is excluded from Service endpoints"
            fi
        fi

        # --- CPU/memory usage vs. requests/limits. A raw "340Mi" or "120m"
        # number means nothing on its own -- this cross-references live
        # usage (from the cluster-wide metrics snapshot fetched before this
        # loop) against what the pod itself declares it's allowed to use.
        # Usage near/at the MEMORY limit is a leading indicator of an
        # impending OOMKill; usage near/at the CPU limit is a leading
        # indicator of CPU throttling (which this scanner otherwise cannot
        # detect directly -- see Coverage Limitations). A pod with NO
        # limit set is reported as such rather than skipped, since that is
        # itself worth knowing (unbounded CPU/memory is a stability risk
        # for its neighbors, not just itself).
        if [ "$POD_METRICS_AVAILABLE" = "1" ]; then
            POD_USAGE_LINE=$(awk -v ns="$NS" -v pod="$POD" '$1==ns && $2==pod {print $3"\t"$4}' "$POD_METRICS_FILE")
            if [ -n "$POD_USAGE_LINE" ]; then
                USAGE_CPU_RAW="${POD_USAGE_LINE%%$'\t'*}"
                USAGE_MEM_RAW="${POD_USAGE_LINE##*$'\t'}"
                USAGE_CPU_M=$(cpu_to_millicores "$USAGE_CPU_RAW")
                USAGE_MEM_MI=$(mem_to_mi "$USAGE_MEM_RAW")

                REQ_CPU_M=$(sum_cpu "$P_REQCPU")
                LIM_CPU_M=$(sum_cpu "$P_LIMCPU")
                REQ_MEM_MI=$(sum_mem "$P_REQMEM")
                LIM_MEM_MI=$(sum_mem "$P_LIMMEM")

                CPU_OF_LIMIT_PCT="n/a"; MEM_OF_LIMIT_PCT="n/a"
                [ "$LIM_CPU_M" -gt 0 ] 2>/dev/null && CPU_OF_LIMIT_PCT=$(( USAGE_CPU_M * 100 / LIM_CPU_M ))
                [ "$LIM_MEM_MI" -gt 0 ] 2>/dev/null && MEM_OF_LIMIT_PCT=$(( USAGE_MEM_MI * 100 / LIM_MEM_MI ))

                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$NS" "$POD" "$USAGE_CPU_M" "$REQ_CPU_M" "$LIM_CPU_M" "$CPU_OF_LIMIT_PCT" \
                    "$USAGE_MEM_MI" "$REQ_MEM_MI" "$LIM_MEM_MI" "$MEM_OF_LIMIT_PCT" >> "$REPORT_DIR/data/pod-resource-usage.tsv"

                if [ "$CPU_OF_LIMIT_PCT" != "n/a" ] && [ "$CPU_OF_LIMIT_PCT" -ge "$POD_CPU_CRIT_PCT" ] 2>/dev/null; then
                    error "Pod $NS/$POD CPU usage is ${CPU_OF_LIMIT_PCT}% of its limit (${USAGE_CPU_M}m/${LIM_CPU_M}m) -- at high risk of CPU throttling (which this scanner cannot directly observe), a common invisible cause of app-perceived slowness."
                    record_fact 47 POD_CPU_HIGH "$NS" "$POD" "developer-or-infra" "CPU usage ${CPU_OF_LIMIT_PCT}% of limit (${USAGE_CPU_M}m/${LIM_CPU_M}m) -- likely being throttled or about to be; raise the CPU limit or reduce load"
                elif [ "$CPU_OF_LIMIT_PCT" != "n/a" ] && [ "$CPU_OF_LIMIT_PCT" -ge "$POD_CPU_WARN_PCT" ] 2>/dev/null; then
                    warn "Pod $NS/$POD CPU usage is ${CPU_OF_LIMIT_PCT}% of its limit (${USAGE_CPU_M}m/${LIM_CPU_M}m)."
                fi

                if [ "$MEM_OF_LIMIT_PCT" != "n/a" ] && [ "$MEM_OF_LIMIT_PCT" -ge "$POD_MEM_CRIT_PCT" ] 2>/dev/null; then
                    error "Pod $NS/$POD memory usage is ${MEM_OF_LIMIT_PCT}% of its limit (${USAGE_MEM_MI}Mi/${LIM_MEM_MI}Mi) -- at high risk of imminent OOMKill."
                    record_fact 46 POD_MEM_HIGH "$NS" "$POD" "developer-or-infra" "Memory usage ${MEM_OF_LIMIT_PCT}% of limit (${USAGE_MEM_MI}Mi/${LIM_MEM_MI}Mi) -- likely to be OOMKilled soon; raise the memory limit or investigate a possible leak"
                elif [ "$MEM_OF_LIMIT_PCT" != "n/a" ] && [ "$MEM_OF_LIMIT_PCT" -ge "$POD_MEM_WARN_PCT" ] 2>/dev/null; then
                    warn "Pod $NS/$POD memory usage is ${MEM_OF_LIMIT_PCT}% of its limit (${USAGE_MEM_MI}Mi/${LIM_MEM_MI}Mi)."
                fi
            fi
        fi

        # CONFIRMED_REDIS requires strong evidence (image contains redis/valkey,
        # a container literally named "redis", or the standard Redis ports).
        # POSSIBLE_CACHE is name-only ("cache", "session-store", etc.) and is
        # reported separately -- it is NOT treated as Redis for health rollup,
        # since memcached/hazelcast/valkey/app caches would otherwise get
        # mislabeled as Redis.
        CONFIRMED_REDIS=0
        POSSIBLE_CACHE=0
        echo "$POD" | grep -Eqi '(^|-)redis(-|$)' && CONFIRMED_REDIS=1
        echo "$POD" | grep -Eqi '(^|-)cache(-|$)|session-store|(^|-)data-store(-|$)' && POSSIBLE_CACHE=1

        # (CONTAINERS comes from the single pod read above)

        for CONTAINER in $CONTAINERS; do
            echo "$CONTAINER" | grep -Eqi '(^|-)redis(-|$)' && CONFIRMED_REDIS=1
            echo "$CONTAINER" | grep -Eqi '(^|-)cache(-|$)|session-store' && POSSIBLE_CACHE=1
            IMAGE="${CS_IMAGE[$CONTAINER]:-}"
            echo "$IMAGE" | grep -Eqi 'redis|valkey' && CONFIRMED_REDIS=1
            PORTS="${CS_PORTS[$CONTAINER]:-}"
            echo "$PORTS" | grep -Eq '(^|[^[:alnum:]_])(6379|6380)([^[:alnum:]_]|$)' && CONFIRMED_REDIS=1

            STATE="${CS_STATE[$CONTAINER]:-}"
            LAST_STATE="${CS_LAST[$CONTAINER]:-}"
            RESTARTS="${CS_RESTARTS[$CONTAINER]:-}"
            EXIT_CODE="${CS_EXIT[$CONTAINER]:-}"
            REASON="${CS_REASON[$CONTAINER]:-}"
            FINISHED="${CS_FIN[$CONTAINER]:-}"

            echo "CONTAINER $CONTAINER  restarts=$RESTARTS  state=$STATE  lastState=$LAST_STATE  exitCode=$EXIT_CODE reason=$REASON finishedAt=$FINISHED" >> "$REPORT"

            if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
                warn "Container $NS/$POD/$CONTAINER restarted $RESTARTS time(s). Last reason=$REASON exitCode=$EXIT_CODE finishedAt=$FINISHED"
                fix "kubectl logs $POD -n $NS -c $CONTAINER --previous --timestamps"
                record_fact 50 RESTART "$NS" "$POD/$CONTAINER" "developer" "$RESTARTS restart(s), lastReason=$REASON exitCode=$EXIT_CODE finishedAt=$FINISHED" "$(iso_to_ts "$FINISHED")"
            fi

            if echo "$LAST_STATE" | grep -qi "OOMKilled"; then
                critical "Container $NS/$POD/$CONTAINER was OOMKilled (exitCode=$EXIT_CODE, finishedAt=$FINISHED)."
                fix "kubectl top pod $POD -n $NS"
                fix "kubectl get pod $POD -n $NS -o yaml   # review resources.limits"
                record_fact 45 OOM "$NS" "$POD/$CONTAINER" "developer-or-infra" "OOMKilled at $FINISHED (exitCode=$EXIT_CODE) -- either app memory leak/spike or limits set too low" "$(iso_to_ts "$FINISHED")"
            fi

            if [ "$ENABLE_LOG_SCAN" = "1" ]; then
                LOG_FILE="$REPORT_DIR/logs/${NS}_${POD}_${CONTAINER}.log"
                kubectl logs "$POD" -n "$NS" -c "$CONTAINER" \
                    --since="${SCAN_MINUTES}m" --tail="$LOG_TAIL_LINES" --timestamps > "$LOG_FILE" 2>&1
                log_cap_check "$LOG_FILE" "$LOG_TAIL_LINES" "$NS/$POD/$CONTAINER"

                # v5.4: the previous container's log only exists (and is only worth a call) after a restart
                PREV_LOG_FILE="$REPORT_DIR/logs/${NS}_${POD}_${CONTAINER}_previous.log"
                : > "$PREV_LOG_FILE"
                if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
                    kubectl logs "$POD" -n "$NS" -c "$CONTAINER" \
                        --previous --tail="$LOG_TAIL_LINES" --timestamps > "$PREV_LOG_FILE" 2>&1
                fi

                ERROR_PATTERN='error|exception|caused by|traceback|stack trace|fatal|panic|critical|failed|failure|timeout|timed out|connection refused|connection reset|broken pipe|(^|[^[:alnum:]_])oom([^[:alnum:]_]|$)|outofmemory|segmentation fault|permission denied|(^|[^[:alnum:]_])50[234]([^[:alnum:]_]|$)|servfail|nxdomain|certificate'
                if [ -n "$NOISE_EXCLUDE_PATTERN" ]; then
                    MATCHES_TXT=$(grep -Ei "$ERROR_PATTERN" "$LOG_FILE" 2>/dev/null | grep -Ev "$NOISE_EXCLUDE_PATTERN" 2>/dev/null)
                else
                    MATCHES_TXT=$(grep -Ei "$ERROR_PATTERN" "$LOG_FILE" 2>/dev/null)
                fi

                if [ -n "$MATCHES_TXT" ]; then
                    error "Errors found in $NS/$POD/$CONTAINER logs (last ${SCAN_MINUTES}m)."
                    # Structured, multi-line-aware extraction: keeps each
                    # exception/stack-trace together as one "Incident"
                    # block instead of a flat grep dump that can sever a
                    # trace from the line that triggered it.
                    INCIDENT_BLOCKS_RAW=$(extract_incident_blocks "$LOG_FILE" "$ERROR_PATTERN")
                    if [ -n "$INCIDENT_BLOCKS_RAW" ]; then
                        format_incident_blocks "$INCIDENT_BLOCKS_RAW" "$NS/$POD/$CONTAINER" | redact >> "$ERROR_REPORT"
                    else
                        { echo ""; echo "POD: $NS/$POD  CONTAINER: $CONTAINER"; echo "$MATCHES_TXT" | redact; } >> "$ERROR_REPORT"
                    fi
                    fix "kubectl logs $POD -n $NS -c $CONTAINER --since=${SCAN_MINUTES}m --timestamps"
                    FIRST_ERR_LINE=$(echo "$MATCHES_TXT" | head -1 | cut -c1-200 | redact)
                    corpus_add "$NS/$POD/$CONTAINER" "$MATCHES_TXT"
                    LOG_TS=$(extract_log_ts "$FIRST_ERR_LINE")
                    record_fact 60 LOG_ERROR "$NS" "$POD/$CONTAINER" "developer" "$FIRST_ERR_LINE" "$LOG_TS"
                fi

                # --- Security-relevant patterns (auth, TLS/certs, RBAC) ---
                SECURITY_MATCHES=$(grep -Ei \
                    'unauthorized|forbidden|permission denied|(^|[^[:alnum:]_])40[13]([^[:alnum:]_]|$)|x509|certificate.*(expired|invalid|unknown authority)|tls handshake|ssl.*(error|fail)|no route to host.*(blocked|denied)|access denied|authentication fail|token.*(expired|invalid)' \
                    "$LOG_FILE" 2>/dev/null)
                if [ -n "$NOISE_EXCLUDE_PATTERN" ] && [ -n "$SECURITY_MATCHES" ]; then
                    SECURITY_MATCHES=$(echo "$SECURITY_MATCHES" | grep -Ev "$NOISE_EXCLUDE_PATTERN" 2>/dev/null)
                fi
                if [ -n "$SECURITY_MATCHES" ]; then
                    error "Security-relevant errors found in $NS/$POD/$CONTAINER logs (last ${SCAN_MINUTES}m)."
                    { echo ""; echo "SECURITY: $NS/$POD/$CONTAINER"; echo "$SECURITY_MATCHES" | redact; } >> "$ERROR_REPORT"
                    FIRST_SEC_LINE=$(echo "$SECURITY_MATCHES" | head -1 | cut -c1-200 | redact)
                    corpus_add "$NS/$POD/$CONTAINER" "$SECURITY_MATCHES"
                    SEC_TS=$(extract_log_ts "$FIRST_SEC_LINE")
                    record_fact 38 SECURITY "$NS" "$POD/$CONTAINER" "security" "$FIRST_SEC_LINE" "$SEC_TS"
                    fix "kubectl describe pod $POD -n $NS   # check ServiceAccount / RBAC / mounted secrets"
                    fix "kubectl logs $POD -n $NS -c $CONTAINER --since=${SCAN_MINUTES}m --timestamps"
                fi

                search_context "$LOG_FILE" "current logs: $NS/$POD/$CONTAINER"
                search_context "$PREV_LOG_FILE" "previous logs: $NS/$POD/$CONTAINER"

                if [ $CONFIRMED_REDIS -eq 1 ]; then
                    REDIS_FOUND=1
                    REDIS_MATCHES=$(grep -Ei \
                        'oom|out of memory|misconf|readonly|loading|noauth|connection refused|connection reset|timeout|timed out|broken pipe|maxmemory|evicted|master|replica|sentinel|cluster.*fail|error|exception' \
                        "$LOG_FILE" 2>/dev/null)
                    if [ -n "$REDIS_MATCHES" ]; then
                        error "Redis-related issues found in $NS/$POD/$CONTAINER."
                        { echo ""; echo "REDIS: $NS/$POD/$CONTAINER"; echo "$REDIS_MATCHES" | redact; } >> "$ERROR_REPORT"
                        FIRST_REDIS_LINE=$(echo "$REDIS_MATCHES" | head -1 | cut -c1-200 | redact)
                        corpus_add "$NS/$POD/$CONTAINER" "$REDIS_MATCHES"
                        REDIS_TS=$(extract_log_ts "$FIRST_REDIS_LINE")
                        record_fact 35 REDIS_ERROR "$NS" "$POD/$CONTAINER" "infra-or-developer" "$FIRST_REDIS_LINE" "$REDIS_TS"
                        set_redis_status 3 "DETECTED / INVESTIGATION REQUIRED"
                    fi
                    if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
                        set_redis_status 3 "DETECTED / INVESTIGATION REQUIRED"
                    fi
                    if echo "$LAST_STATE" | grep -qi "OOMKilled"; then
                        set_redis_status 4 "DETECTED / NO READY ENDPOINTS (last OOMKilled)"
                    fi
                    if [ "$READY_COND" = "False" ]; then
                        set_redis_status 4 "DETECTED / NOT READY"
                    fi
                    if [ -z "$REDIS_MATCHES" ] && [ "$READY_COND" != "False" ] && { [ -z "$RESTARTS" ] || [ "$RESTARTS" -eq 0 ] 2>/dev/null; }; then
                        set_redis_status 2 "DETECTED / HEALTH EVIDENCE GOOD"
                    fi
                elif [ $POSSIBLE_CACHE -eq 1 ]; then
                    set_redis_status 1 "DETECTED / UNVERIFIED (name-only cache match, not confirmed Redis -- could be memcached/valkey/app cache)"
                fi
            fi
        done

        # v5.3: init containers -- only when searching, and only their logs, so the ID trace also covers
        # init steps (migrations, config fetches) that run before the main containers start.
        if [ -n "$SEARCH_VALUE" ] && [ "$ENABLE_LOG_SCAN" = "1" ]; then
            INIT_CONTAINERS=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.initContainers[*]}{.name}{"\n"}{end}' 2>/dev/null)
            for ICONT in $INIT_CONTAINERS; do
                ILOG="$REPORT_DIR/logs/${NS}_${POD}_${ICONT}_init.log"
                kubectl logs "$POD" -n "$NS" -c "$ICONT" --since="${SCAN_MINUTES}m" --tail="$LOG_TAIL_LINES" --timestamps > "$ILOG" 2>&1
                search_context "$ILOG" "current logs: $NS/$POD/$ICONT (init)"
            done
        fi
        # Optional read-only network probe (off by default)
        if [ "$ENABLE_POD_NETWORK_TEST" = "1" ] && [ -n "$CONTAINERS" ]; then
            FIRST_CONTAINER=$(echo "$CONTAINERS" | head -1)
            echo "POD NETWORK INFO ($NS/$POD):" >> "$REPORT"
            kubectl exec "$POD" -n "$NS" -c "$FIRST_CONTAINER" -- \
                sh -c 'hostname; cat /etc/resolv.conf; echo "--- ROUTES ---"; (ip route || route -n) 2>/dev/null' \
                >> "$REPORT" 2>&1
        fi
    done
done

if [ $REDIS_FOUND -eq 1 ]; then
    set_redis_status 2 "DETECTED / HEALTH EVIDENCE GOOD"
fi

###############################################################################
# 5. COREDNS DETAIL
###############################################################################

section "5. CORE DNS"

kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide >> "$REPORT" 2>&1
kubectl get svc kube-dns -n kube-system -o wide >> "$REPORT" 2>&1

DNS_PODS=$(kubectl get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
if [ "$SKIP_CLUSTER_LOGS" = "1" ]; then
    DNS_PODS=""
    info "CoreDNS log scan skipped: namespace-scoped scan (set SCOPE_INCLUDE_CLUSTER_COMPONENTS=1 to include)."
fi
for DNS_POD in $DNS_PODS; do
    LOG_FILE="$REPORT_DIR/logs/coredns_${DNS_POD}.log"
    kubectl logs "$DNS_POD" -n kube-system --since="${SCAN_MINUTES}m" --tail="$LOG_TAIL_LINES" --timestamps > "$LOG_FILE" 2>&1
    DNS_MATCHES=$(grep -Ei 'error|fatal|panic|timeout|plugin/errors|servfail|refused' "$LOG_FILE" 2>/dev/null)
    if [ -n "$DNS_MATCHES" ]; then
        echo "$DNS_MATCHES" >> "$ERROR_REPORT"
        FIRST_DNS_LINE=$(echo "$DNS_MATCHES" | head -1 | cut -c1-200 | redact)
        record_fact 30 DNS_ERROR kube-system "$DNS_POD" "infra" "$FIRST_DNS_LINE" "$(extract_log_ts "$FIRST_DNS_LINE")"
    fi
    search_context "$LOG_FILE" "coredns: $DNS_POD"
done

###############################################################################
# 6. INGRESS / HAPROXY
###############################################################################

section "6. INGRESS / HAPROXY / PROXY"
HA_SCOPE_ARGS="-A"
if [ -n "$SELECTED_NS" ]; then
    HA_SCOPE_ARGS="-n $SELECTED_NS"
    info "Ingress/proxy scan limited to namespace $SELECTED_NS (namespace-scoped scan)."
fi

# Detect by pod name (broadened beyond just "haproxy|ingress") AND by
# container image, since real deployments are often named "gateway",
# "edge", "lb", "router", or use nginx/traefik/envoy under a custom name.
# v5.4: ONE pod read feeds both the name-based and the image-based proxy detection (v5.3: two full pod lists).
if [ "$POD_BULK_OK" = "1" ]; then
    HA_RAW=$(awk '
        $1 == "@@P"   { ns = $2; name = $3; mode = ""; idx = 0; imgs = ""; next }
        $1 == "@@C"   { mode = "C"; idx = 0; next }
        $1 == "@@S"   { mode = ""; next }
        $1 == "@@END" { print ns " " name " " imgs; next }
        mode == "C"   { idx++; if (idx % 3 == 2) imgs = imgs $0 "," }' "$BULK_DIR/pods.txt")
else
    HA_RAW=$(kubectl get pods $HA_SCOPE_ARGS -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' 2>/dev/null)
fi
HA_PODS_BY_NAME=$(echo "$HA_RAW" | awk 'NF {print $1" "$2}' | grep -Ei 'haproxy|ingress|nginx|traefik|envoy|gateway|controller|edge-proxy|(^|[^[:alnum:]_])lb([^[:alnum:]_]|$)|router' || true)
HA_PODS_BY_IMAGE=$(echo "$HA_RAW" | grep -Ei 'haproxy|nginx|traefik|envoyproxy|/envoy|ingress-nginx' | awk '{print $1" "$2}' || true)

HA_PODS=$(printf '%s\n%s\n' "$HA_PODS_BY_NAME" "$HA_PODS_BY_IMAGE" | awk 'NF' | sort -u)

if [ -n "$HA_PODS" ]; then
    while read -r NS POD; do
        [ -z "$POD" ] && continue
        LOG_FILE="$REPORT_DIR/logs/${NS}_${POD}_ingress.log"
        kubectl logs "$POD" -n "$NS" --all-containers --since="${SCAN_MINUTES}m" --tail="$INGRESS_TAIL_LINES" --timestamps > "$LOG_FILE" 2>&1
        HAPROXY_MATCHES=$(grep -Ei '(^|[^[:alnum:]_])50[234]([^[:alnum:]_]|$)|timeout|connection refused|connection reset|no server|backend.*down|server.*down' "$LOG_FILE" 2>/dev/null)
        if [ -n "$HAPROXY_MATCHES" ]; then
            error "Proxy/Ingress errors in $NS/$POD (last ${SCAN_MINUTES}m)."
            { echo ""; echo "INGRESS: $NS/$POD"; echo "$HAPROXY_MATCHES" | redact; } >> "$ERROR_REPORT"
            FIRST_HA_LINE=$(echo "$HAPROXY_MATCHES" | head -1 | cut -c1-200 | redact)
            corpus_add "$NS/$POD" "$HAPROXY_MATCHES"
            record_fact 70 HAPROXY_5XX "$NS" "$POD" "downstream-symptom" "$FIRST_HA_LINE" "$(extract_log_ts "$FIRST_HA_LINE")"
        fi
        search_context "$LOG_FILE" "ingress/proxy: $NS/$POD"
    done <<< "$HA_PODS"
else
    info "No Kubernetes-hosted ingress/proxy workload was detected by the available pod/image metadata. This does NOT rule out an external load balancer (cloud ALB, F5, Cloudflare, hardware LB) with no corresponding pod."
fi

###############################################################################
# 6B. F5 / EXTERNAL LOAD BALANCER (PLUGGABLE HOOK, OFF UNLESS CONFIGURED)
#
# This scanner only talks to the Kubernetes API -- it has no visibility
# into an external appliance like an F5 BIG-IP sitting in front of the
# cluster, and it makes no network calls to one. Instead this is a
# pluggable hook: point it at logs you already export, or at your own
# read-only export command, and matches are folded into the same
# correlation engine, error catalog, and HTML report as everything else.
# If neither F5_LOG_SOURCE nor F5_LOG_HOOK is set, this is skipped and
# clearly marked "not configured" rather than silently omitted.
###############################################################################

section "6B. F5 / EXTERNAL LOAD BALANCER"

F5_MATCHES_COUNT=0

if [ -z "$F5_LOG_SOURCE" ] && [ -z "$F5_LOG_HOOK" ]; then
    info "F5/external LB scanning not configured (set F5_LOG_SOURCE and/or F5_LOG_HOOK). This scanner has no direct visibility into appliance-based load balancers/WAFs -- see Coverage Limitations in the HTML report."
else
    if [ -n "$F5_LOG_HOOK" ]; then
        if [ -x "$F5_LOG_HOOK" ]; then
            info "Running F5 log hook: $F5_LOG_HOOK (must be read-only by design of the hook itself; this scanner only consumes its stdout and does not verify that)."
            if command_exists timeout; then
                timeout 30 "$F5_LOG_HOOK" >> "$F5_REPORT" 2>"$REPORT_DIR/data/f5-hook-stderr.log"
            else
                "$F5_LOG_HOOK" >> "$F5_REPORT" 2>"$REPORT_DIR/data/f5-hook-stderr.log"
            fi
        else
            warn "F5_LOG_HOOK is set to '$F5_LOG_HOOK' but is not an executable file. Skipping."
        fi
    fi

    if [ -n "$F5_LOG_SOURCE" ]; then
        if [ -f "$F5_LOG_SOURCE" ]; then
            cat "$F5_LOG_SOURCE" >> "$F5_REPORT" 2>/dev/null
        elif [ -d "$F5_LOG_SOURCE" ]; then
            find "$F5_LOG_SOURCE" -type f 2>/dev/null | while read -r f; do cat "$f" 2>/dev/null; done >> "$F5_REPORT"
        else
            warn "F5_LOG_SOURCE '$F5_LOG_SOURCE' is not a readable file or directory. Skipping."
        fi
    fi

    if [ -s "$F5_REPORT" ]; then
        F5_MATCHES_TXT=$(grep -Ei "$F5_BLOCK_PATTERN" "$F5_REPORT" 2>/dev/null)
        if [ -n "$F5_MATCHES_TXT" ]; then
            F5_MATCHES_COUNT=$(echo "$F5_MATCHES_TXT" | grep -c .)
            error "F5/external LB blocking or failure patterns found ($F5_MATCHES_COUNT line(s)) in the supplied F5 log source."
            { echo ""; echo "F5 / EXTERNAL LB (full matched lines):"; echo "$F5_MATCHES_TXT" | redact; } >> "$ERROR_REPORT"
            FIRST_F5_LINE=$(echo "$F5_MATCHES_TXT" | head -1 | cut -c1-200 | redact)
            F5_TS=$(extract_log_ts "$FIRST_F5_LINE")
            record_fact 38 F5_BLOCKED "-" "external-f5" "network" "$FIRST_F5_LINE ($F5_MATCHES_COUNT total matching line(s) in supplied F5 log source)" "$F5_TS"
            fix "Review full F5 match context in: $F5_REPORT"
            fix "On the BIG-IP: search the ASM event log using the support_id shown in the matched line"
            fix "On the BIG-IP: tmsh show ltm pool <pool> members   # check monitor status"
            fix "On the BIG-IP: tmsh show ltm virtual <vs> profiles"
            fix "On the BIG-IP: review any iRule on the affected virtual server for a drop/reject action"
        else
            info "F5 log source ingested ($(wc -l < "$F5_REPORT" 2>/dev/null | tr -d ' ') line(s)) -- no blocking/failure patterns matched F5_BLOCK_PATTERN."
        fi
        search_context "$F5_REPORT" "F5/external LB log"
    else
        warn "F5_LOG_SOURCE/F5_LOG_HOOK was configured but produced no data to scan."
    fi
fi

###############################################################################
# 7. RESOURCE USAGE / STORAGE
###############################################################################

section "7. RESOURCE USAGE AND STORAGE"

if [ "$POD_METRICS_AVAILABLE" = "1" ]; then
    # Not sorted here with `sort -h`: GNU sort's human-numeric sort does
    # not understand Kubernetes' millicore "m" suffix (e.g. "450m") and
    # would silently mis-order the CPU column. The properly unit-converted,
    # correctly sortable comparison lives in the "Pod Resource Usage"
    # section of the HTML report instead, built from the same snapshot
    # using this script's own cpu_to_millicores/mem_to_mi conversion.
    cat "$POD_METRICS_FILE" >> "$REPORT"
    info "Per-pod CPU/memory usage: see the 'Pod Resource Usage' section of the HTML report for usage cross-referenced against each pod's own requests/limits."
else
    warn "Metrics Server data unavailable."
fi

# (v5.4: the PVC list is read once below and written to the report from there)
if [ "$NS_ONLY" = "1" ]; then
    PVC_ALL=$(kubectl get pvc -n "$SELECTED_NS" --no-headers 2>/dev/null | awk -v ns="$SELECTED_NS" 'NF {print ns " " $0}')
else
    PVC_ALL=$(kubectl get pvc -A --no-headers 2>/dev/null)
fi
{ echo "PVCs (namespace name status volume capacity accessmodes storageclass age):"; echo "$PVC_ALL"; } >> "$REPORT"
PVC_PROBLEMS=$(echo "$PVC_ALL" | awk 'NF && $3!="Bound"')
if [ -n "$PVC_PROBLEMS" ]; then
    PVC_COUNT=$(echo "$PVC_PROBLEMS" | grep -c .)
    warn "$PVC_COUNT PVC(s) not in Bound state:"
    { echo ""; echo "PVCs NOT BOUND ($PVC_COUNT):"; } >> "$ERROR_REPORT"
    while read -r pvc_ns pvc_name pvc_status pvc_rest; do
        [ -z "$pvc_name" ] && continue
        PVC_SCOPE_NOTE=""
        if [ -n "$SELECTED_NS" ] && [ "$pvc_ns" != "$SELECTED_NS" ]; then
            PVC_SCOPE_NOTE="  (outside selected scope: $SELECTED_NS)"
        fi
        echo "    $pvc_ns/$pvc_name  status=$pvc_status$PVC_SCOPE_NOTE"
        echo "  $pvc_ns/$pvc_name  status=$pvc_status$PVC_SCOPE_NOTE" >> "$ERROR_REPORT"
        fix "kubectl describe pvc $pvc_name -n $pvc_ns"
        if [ -z "$PVC_SCOPE_NOTE" ]; then
            record_fact 55 PVC_NOT_BOUND "$pvc_ns" "$pvc_name" "infra" "PVC $pvc_name is $pvc_status (not Bound) -- check the StorageClass/provisioner and PV availability"
        fi
    done <<< "$PVC_PROBLEMS"
fi

###############################################################################
# 8. ROOT CAUSE CORRELATION ENGINE
#
# Groups every recorded fact by namespace (facts with namespace "-" are
# cluster/node-wide and apply to everything downstream). Within a group,
# the LOWEST rank (most "upstream" category) is presented as the root
# cause CANDIDATE; everything else in that group is shown as related
# evidence/symptoms. This is evidence-based correlation, not proof --
# the report always says "candidate", and always lists raw evidence.
###############################################################################

section "8. ROOT CAUSE ANALYSIS"

ROOTCAUSE_HTML="$REPORT_DIR/data/rootcause.html.frag"
: > "$ROOTCAUSE_HTML"

owner_label() {
    case "$1" in
        infra) echo "Infra / Platform team" ;;
        network) echo "Network team" ;;
        developer) echo "Application developer" ;;
        security) echo "Security team" ;;
        infra-or-developer) echo "Infra (limits) or Developer (memory usage) -- needs joint review" ;;
        developer-or-network) echo "Developer (readiness probe / selector) or Network team (policy) -- needs joint review" ;;
        developer-or-infra) echo "Infra or Developer" ;;
        developer-or-security) echo "Developer (auth/token handling) or Security team (cert/RBAC) -- needs joint review" ;;
        infra-or-network) echo "Infra or Network" ;;
        downstream-symptom) echo "N/A -- symptom of an upstream issue, not the root cause itself" ;;
        *) echo "Needs investigation" ;;
    esac
}

suggest_cmds() {
    # $1 category  $2 namespace  $3 resource
    local cat="$1" ns="$2" res="$3"
    case "$cat" in
        CONTROL_PLANE) echo "kubectl get --raw='/readyz?verbose'|kubectl get --raw='/livez?verbose'" ;;
        NODE_NOT_READY|NODE_PRESSURE) echo "kubectl describe node $res|kubectl top node $res|kubectl get pods -A -o wide --field-selector spec.nodeName=$res" ;;
        NODE_NETWORK) echo "kubectl describe node $res" ;;
        DNS_ERROR) echo "kubectl logs $res -n kube-system --since=${SCAN_MINUTES}m|kubectl get svc kube-dns -n kube-system" ;;
        SECURITY) echo "kubectl describe pod ${res%%/*} -n $ns   # ServiceAccount/RBAC/mounted secrets|kubectl auth can-i --list --as=system:serviceaccount:$ns:default -n $ns|kubectl get rolebinding,clusterrolebinding -n $ns|kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m" ;;
        REDIS_ERROR) echo "kubectl describe pod ${res%%/*} -n $ns|kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m|kubectl top pod ${res%%/*} -n $ns" ;;
        NO_ENDPOINTS) echo "kubectl describe svc $res -n $ns|kubectl get endpointslices -n $ns -l kubernetes.io/service-name=$res -o wide|kubectl get pods -n $ns --show-labels" ;;
        READINESS_FAIL) echo "kubectl describe pod ${res%%/*} -n $ns|kubectl logs ${res%%/*} -n $ns --since=${SCAN_MINUTES}m" ;;
        OOM) echo "kubectl top pod ${res%%/*} -n $ns|kubectl get pod ${res%%/*} -n $ns -o yaml   # check resources.limits.memory" ;;
        RESTART) echo "kubectl logs ${res%%/*} -n $ns -c ${res##*/} --previous --timestamps|kubectl describe pod ${res%%/*} -n $ns" ;;
        PENDING_SCHEDULING) echo "kubectl describe pod $res -n $ns|kubectl top nodes|kubectl get resourcequota -n $ns|kubectl get pvc -n $ns" ;;
        PENDING_CONTAINER_ERROR) echo "kubectl describe pod $res -n $ns   # check Events for the exact image/config/secret error|kubectl get pod $res -n $ns -o jsonpath='{.status.containerStatuses[*].state.waiting.message}'" ;;
        FAILED|UNKNOWN) echo "kubectl describe pod $res -n $ns|kubectl logs $res -n $ns --all-containers" ;;
        STATEFULSET_NOT_READY) echo "kubectl describe statefulset $res -n $ns|kubectl get pods -n $ns -l app=$res" ;;
        JOB_FAILED) echo "kubectl describe job $res -n $ns|kubectl logs -n $ns -l job-name=$res --all-containers --tail=200" ;;
        CRONJOB_UNCERTAIN) echo "kubectl describe cronjob $res -n $ns|kubectl get jobs -n $ns | grep $res" ;;
        LOG_ERROR) echo "kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m --timestamps" ;;
        HAPROXY_5XX) echo "kubectl logs $res -n $ns --since=${SCAN_MINUTES}m|kubectl get endpoints -n $ns   # find the backend returning 5xx" ;;
        PROBE_FAIL) echo "kubectl exec ${res%%/*} -n $ns -c ${res##*/} -- curl -v -m ${PROBE_TIMEOUT} http://127.0.0.1:<port>${PROBE_PATH}|kubectl describe pod ${res%%/*} -n $ns|kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m" ;;
        F5_BLOCKED) echo "Review full match context in the report's data/f5-external.log|On BIG-IP: search the ASM event log using the support_id in the matched line|On BIG-IP: tmsh show ltm pool <pool> members|On BIG-IP: tmsh show ltm virtual <vs> profiles|On BIG-IP: review iRules on the affected virtual server for drop/reject actions" ;;
        API_LATENCY) echo "kubectl get --raw='/readyz?verbose'|kubectl get --raw='/livez?verbose'|kubectl get componentstatuses 2>/dev/null|kubectl logs -n kube-system -l component=etcd --since=${SCAN_MINUTES}m --timestamps" ;;
        ETCD_SLOW) echo "kubectl logs $res -n kube-system --since=${SCAN_MINUTES}m --timestamps | grep -Ei 'slow fdatasync|took too long'|On the node hosting $res: check disk I/O latency (iostat/fio) -- etcd fsyncs on every write" ;;
        NODE_OVERSUBSCRIBED) echo "kubectl describe node $res   # see 'Allocated resources' section|kubectl get pods -A --field-selector spec.nodeName=$res -o wide|kubectl top pod -A --field-selector spec.nodeName=$res 2>/dev/null" ;;
        HPA_INACTIVE) echo "kubectl describe hpa $res -n $ns   # check Conditions for the exact reason|kubectl get pods -n kube-system -l k8s-app=metrics-server|kubectl top pods -n $ns" ;;
        HPA_MAXED) echo "kubectl describe hpa $res -n $ns|kubectl top pods -n $ns|kubectl describe node   # check if there is spare node capacity for more replicas" ;;
        POD_CPU_HIGH) echo "kubectl top pod $res -n $ns --containers|kubectl get pod $res -n $ns -o jsonpath='{.spec.containers[*].resources}'|kubectl describe pod $res -n $ns   # review resources.limits.cpu" ;;
        POD_MEM_HIGH) echo "kubectl top pod $res -n $ns --containers|kubectl get pod $res -n $ns -o jsonpath='{.spec.containers[*].resources}'|kubectl describe pod $res -n $ns   # review resources.limits.memory" ;;
        PVC_NOT_BOUND) echo "kubectl describe pvc $res -n $ns|kubectl get storageclass|kubectl get pv" ;;
        *) echo "kubectl describe pod $res -n $ns" ;;
    esac
}

html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

###############################################################################
# WORKLOAD RESOLUTION -- fixes namespace-level over-grouping in root-cause
# correlation. Previously, every fact in a namespace was bucketed together
# regardless of which actual Deployment/StatefulSet/Job it belonged to, so
# a namespace with several unrelated simultaneous incidents would show one
# as the "root cause" and nest the others underneath it as if related, even
# with no causal link. This resolves each pod-level fact to its real owning
# workload (via ownerReferences: Pod -> ReplicaSet -> Deployment, or Pod ->
# StatefulSet/Job/DaemonSet directly) and each service-level fact to the
# workload behind one of its actual endpoint pods -- so unrelated incidents
# in the same namespace are correctly kept in separate candidates. A
# Service with ZERO endpoints has no pod to resolve from, so it correctly
# stays its own isolated group rather than being merged into anything --
# that absence of endpoints IS the finding.
#
# Read-only: only `kubectl get` calls, cached per pod so repeat facts about
# the same pod don't re-query the API.
###############################################################################
declare -A WORKLOAD_CACHE
resolve_workload() {
    # $1 ns  $2 pod  -> prints the owning workload name (Deployment/
    # StatefulSet/Job/DaemonSet), or the pod's own name if unresolvable.
    local ns="$1" pod="$2" cache_key="${1}/${2}"
    if [ -n "${WORKLOAD_CACHE[$cache_key]+set}" ]; then
        echo "${WORKLOAD_CACHE[$cache_key]}"
        return
    fi
    local kind name result
    if [ -n "${POD_OWNER_CACHE[$cache_key]+set}" ]; then
        kind="${POD_OWNER_CACHE[$cache_key]%%|*}"; name="${POD_OWNER_CACHE[$cache_key]#*|}"
    else
        kind=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null)
        name=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null)
    fi
    if [ "$kind" = "ReplicaSet" ] && [ -n "$name" ]; then
        local deploy
        if [ -n "${RS_OWNER_CACHE[$ns/$name]+set}" ]; then
            deploy="${RS_OWNER_CACHE[$ns/$name]}"
        else
            deploy=$(kubectl get replicaset "$name" -n "$ns" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null)
        fi
        result="${deploy:-$name}"
    elif [ -n "$name" ]; then
        result="$name"
    else
        result="$pod"
    fi
    WORKLOAD_CACHE[$cache_key]="$result"
    echo "$result"
}

resolve_service_workload() {
    # $1 ns  $2 svc  -> resolves via one of the service's own endpoint pods
    # (already recorded in service-topology.tsv), so no extra selector
    # matching is needed. Falls back to an isolated "svc:<name>" group key
    # when the service has no endpoint pod to resolve from at all.
    local ns="$1" svc="$2" row podlist first_pod
    row=$(awk -F'\t' -v ns="$ns" -v svc="$svc" '$1==ns && $2==svc' "$REPORT_DIR/data/service-topology.tsv" 2>/dev/null | head -1)
    if [ -z "$row" ]; then
        echo "svc:$svc"
        return
    fi
    podlist=$(echo "$row" | awk -F'\t' '{print $4" "$5}')
    first_pod=$(echo "$podlist" | grep -oE '\([^)]+\)' | head -1 | tr -d '()')
    if [ -n "$first_pod" ]; then
        resolve_workload "$ns" "$first_pod"
    else
        echo "svc:$svc"
    fi
}

ROOT_CAUSE_COUNT=0

# --- Cluster/node-wide facts (namespace field is "-") ---
CLUSTER_FACTS=$(awk -F'\t' '$3=="-"' "$FACTS_FILE" | sort -t$'\t' -k1,1n)
if [ -n "$CLUSTER_FACTS" ]; then
    TOP=$(echo "$CLUSTER_FACTS" | head -1)
    RANK=$(echo "$TOP" | cut -f1); CAT=$(echo "$TOP" | cut -f2); RES=$(echo "$TOP" | cut -f4); OWNER=$(echo "$TOP" | cut -f5); DETAIL=$(echo "$TOP" | cut -f6)
    ROOT_CAUSE_COUNT=$((ROOT_CAUSE_COUNT+1))
    {
        echo "============================================================"
        echo "ROOT-CAUSE CANDIDATE / INVESTIGATION LEAD #$ROOT_CAUSE_COUNT  (cluster-wide)"
        echo "============================================================"
        echo "Category : $CAT"
        echo "Resource : $RES"
        echo "Owner    : $(owner_label "$OWNER")"
        echo "Evidence : $DETAIL"
        echo ""
        echo "This affects every namespace/pod scheduled on/behind it, so it is"
        echo "listed ahead of namespace-level findings."
        echo ""
        echo "Suggested investigation commands:"
        suggest_cmds "$CAT" "-" "$RES" | tr '|' '\n' | sed 's/^/  /'
        echo ""
    } >> "$ROOTCAUSE_REPORT"

    {
        echo "<div class=\"card\"><h3>Root-Cause Candidate / Investigation Lead #$ROOT_CAUSE_COUNT <span class=\"badge crit\">cluster-wide</span></h3>"
        echo "<p><b>Category:</b> $(echo "$CAT" | html_escape)<br><b>Resource:</b> $(echo "$RES" | html_escape)<br><b>Likely owner:</b> $(owner_label "$OWNER" | html_escape)</p>"
        echo "<p><b>Evidence:</b> $(echo "$DETAIL" | html_escape)</p>"
        echo "<p><b>Suggested commands (read-only):</b></p><pre>$(suggest_cmds "$CAT" "-" "$RES" | tr '|' '\n' | html_escape)</pre></div>"
    } >> "$ROOTCAUSE_HTML"
fi

# --- Per-namespace facts, grouped by resolved owning workload ---
# v5.4: one ReplicaSet->Deployment read per namespace that has findings (v5.3: one read per pod fact)
for RSNS in $(awk -F'\t' '$3!="-" {print $3}' "$FACTS_FILE" | sort -u); do
    while IFS=$'\t' read -r -u 3 _rsn _rso; do
        [ -z "$_rsn" ] && continue
        [ "$_rso" = "-" ] && _rso=""
        RS_OWNER_CACHE["$RSNS/$_rsn"]="$_rso"
        printf '%s\t%s\n' "$RSNS/$_rsn" "$_rso" >> "$REPORT_DIR/data/rs-owner.tsv"
    done 3< <(kubectl get rs -n "$RSNS" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].name}{"\n"}{end}' 2>/dev/null | dash_tsv)
done

GROUPED_FACTS="$REPORT_DIR/data/grouped_facts.tsv"
: > "$GROUPED_FACTS"

awk -F'\t' '$3!="-"' "$FACTS_FILE" | while IFS=$'\t' read -r rank cat ns res owner detail ts; do
    [ -z "$rank" ] && continue
    case "$cat" in
        NO_ENDPOINTS|PARTIAL_NOT_READY)
            GKEY=$(resolve_service_workload "$ns" "$res")
            ;;
        *)
            GKEY=$(resolve_workload "$ns" "${res%%/*}")
            ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$GKEY" "$rank" "$cat" "$ns" "$res" "$owner" "$detail" "$ts" >> "$GROUPED_FACTS"
done

NS_GROUP_PAIRS=$(awk -F'\t' '{print $4"\t"$1}' "$GROUPED_FACTS" | sort -u -t$'\t' -k1,1 -k2,2)

while IFS=$'\t' read -r NS GKEY; do
    [ -z "$NS" ] && continue
    GROUP_FACTS=$(awk -F'\t' -v ns="$NS" -v gk="$GKEY" '$4==ns && $1==gk' "$GROUPED_FACTS" | sort -t$'\t' -k2,2n)
    ROOT=$(echo "$GROUP_FACTS" | head -1)
    REST=$(echo "$GROUP_FACTS" | tail -n +2)

    RANK=$(echo "$ROOT" | cut -f2); CAT=$(echo "$ROOT" | cut -f3); RES=$(echo "$ROOT" | cut -f5); OWNER=$(echo "$ROOT" | cut -f6); DETAIL=$(echo "$ROOT" | cut -f7)
    ROOT_CAUSE_COUNT=$((ROOT_CAUSE_COUNT+1))

    {
        echo "============================================================"
        echo "ROOT-CAUSE CANDIDATE / INVESTIGATION LEAD #$ROOT_CAUSE_COUNT  (namespace: $NS, workload: $GKEY)"
        echo "============================================================"
        echo "Category : $CAT"
        echo "Resource : $NS/$RES"
        echo "Owner    : $(owner_label "$OWNER")"
        echo "Evidence : $DETAIL"
        echo ""
        if [ -n "$REST" ]; then
            echo "Related evidence for the SAME workload ($GKEY) -- likely part of the same incident:"
            echo "$REST" | while IFS=$'\t' read -r gk2 r c n res2 o d ts2; do
                echo "  - [$c] $n/$res2: $d"
            done
        fi
        echo ""
        echo "Suggested investigation commands:"
        suggest_cmds "$CAT" "$NS" "$RES" | tr '|' '\n' | sed 's/^/  /'
        echo ""
    } >> "$ROOTCAUSE_REPORT"

    {
        echo "<div class=\"card\"><h3>Root-Cause Candidate / Investigation Lead #$ROOT_CAUSE_COUNT <span class=\"badge err\">ns: $(echo "$NS" | html_escape) &middot; workload: $(echo "$GKEY" | html_escape)</span></h3>"
        echo "<p><b>Category:</b> $(echo "$CAT" | html_escape)<br><b>Resource:</b> $(echo "$NS/$RES" | html_escape)<br><b>Likely owner:</b> $(owner_label "$OWNER" | html_escape)</p>"
        echo "<p><b>Evidence:</b> $(echo "$DETAIL" | html_escape)</p>"
        if [ -n "$REST" ]; then
            echo "<p><b>Related evidence for the same workload</b> (likely part of the same incident, not a separate one):</p><pre>"
            echo "$REST" | while IFS=$'\t' read -r gk2 r c n res2 o d ts2; do
                echo "[$c] $n/$res2: $d"
            done | html_escape
            echo "</pre>"
        fi
        echo "<p><b>Suggested commands (read-only):</b></p><pre>$(suggest_cmds "$CAT" "$NS" "$RES" | tr '|' '\n' | html_escape)</pre></div>"
    } >> "$ROOTCAUSE_HTML"
done <<< "$NS_GROUP_PAIRS"

if [ "$ROOT_CAUSE_COUNT" -eq 0 ]; then
    echo "No correlated findings in this scan window -- no root-cause candidates identified." >> "$ROOTCAUSE_REPORT"
    echo "<div class=\"card\">No correlated findings in this scan window.</div>" >> "$ROOTCAUSE_HTML"
fi

echo "Root cause candidates identified: $ROOT_CAUSE_COUNT"

###############################################################################
# 8b. FULL ERROR CATALOG -- every individual detected error/finding, with
# its timestamp, exact pod/container, category, owning team, root-cause
# explanation, and suggested read-only commands. This answers "which pod,
# at what time, what's wrong, who fixes it, with what command" for EVERY
# finding -- not just the top-ranked candidate per namespace.
###############################################################################

CATALOG_REPORT="$REPORT_DIR/error-catalog.txt"
CATALOG_HTML="$REPORT_DIR/data/catalog.html.frag"
: > "$CATALOG_REPORT"
: > "$CATALOG_HTML"

echo "TIMESTAMP           | NAMESPACE/RESOURCE                | CATEGORY        | OWNER TEAM               | DETAIL" >> "$CATALOG_REPORT"
echo "--------------------+------------------------------------+-----------------+---------------------------+------------------------------------------------------------" >> "$CATALOG_REPORT"

{
echo '<table style="width:100%;border-collapse:collapse;font-size:13px">'
echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Timestamp</th><th style="padding:6px">Namespace / Pod</th><th style="padding:6px">Category</th><th style="padding:6px">Owner Team</th><th style="padding:6px">Root Cause / Detail</th><th style="padding:6px">Suggested Commands</th></tr>'
} >> "$CATALOG_HTML"

sort -t$'\t' -k7,7 "$FACTS_FILE" | while IFS=$'\t' read -r rank cat ns res owner detail ts; do
    [ -z "$rank" ] && continue
    NSRES="${ns}/${res}"
    [ "$ns" = "-" ] && NSRES="$res (cluster-wide)"
    OWNER_TXT=$(owner_label "$owner")
    CMDS=$(suggest_cmds "$cat" "$ns" "$res" | tr '|' '; ')

    printf '%-20s | %-34s | %-15s | %-25s | %s\n' "$ts" "$NSRES" "$cat" "$OWNER_TXT" "$detail" >> "$CATALOG_REPORT"
    echo "  -> fix: $CMDS" >> "$CATALOG_REPORT"

    SEV_BADGE="err"
    case "$rank" in
        1[0-9]|2[0-9]|3[0-9]) SEV_BADGE="crit" ;;
        4[0-9]|5[0-9]) SEV_BADGE="err" ;;
        *) SEV_BADGE="warn" ;;
    esac

    {
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px;white-space:nowrap\">$(echo "$ts" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$NSRES" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $SEV_BADGE\">$(echo "$cat" | html_escape)</span></td>"
        echo "<td style=\"padding:6px\">$(echo "$OWNER_TXT" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$detail" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><pre style=\"margin:0;background:none;border:none;padding:0\">$(echo "$CMDS" | tr ';' '\n' | html_escape)</pre></td>"
        echo "</tr>"
    } >> "$CATALOG_HTML"
done

echo '</table>' >> "$CATALOG_HTML"

CATALOG_COUNT=$(wc -l < "$FACTS_FILE" 2>/dev/null || echo 0)
echo "Total findings in catalog: $CATALOG_COUNT"

###############################################################################
# 8c. SEARCH STATISTICS -- occurrence-aware, not just "N files matched".
###############################################################################

SEARCH_OCCURRENCES=0
SEARCH_RESOURCES=0
SEARCH_NAMESPACES=0
if [ -n "$SEARCH_VALUE" ] && [ -s "$SEARCH_STATS_FILE" ]; then
    SEARCH_OCCURRENCES=$(awk -F'\t' '{s+=$1} END{print s+0}' "$SEARCH_STATS_FILE")
    SEARCH_RESOURCES=$(cut -f2 "$SEARCH_STATS_FILE" | sort -u | wc -l | tr -d ' ')
    # Best-effort namespace extraction: labels look like "current logs: ns/pod/container"
    SEARCH_NAMESPACES=$(cut -f2 "$SEARCH_STATS_FILE" | sed -n 's/^[^:]*: \([^/]*\)\/.*/\1/p' | sort -u | wc -l | tr -d ' ')
fi

###############################################################################
# 8e. REQUEST TRACE + RESOURCES THE SEARCH ID TOUCHED (only with a search ID)
#   data/trace-sorted.tsv  -> all collected lines, oldest first
#   search-trace.txt       -> the same as a plain-text report
#   data/search-related-pods.txt -> "namespace/pod" of every pod whose logs
#                                    (or describe output) contained the ID
###############################################################################
TRACE_SORTED="$REPORT_DIR/data/trace-sorted.tsv"
TRACE_TEXT="$REPORT_DIR/search-trace.txt"
REL_PODS_FILE="$REPORT_DIR/data/search-related-pods.txt"
TRACE_N=0; TRACE_SRC_N=0; TRACE_FIRST_TS=""; TRACE_FIRST_SRC=""; TRACE_LAST_TS=""
TRACE_ERR_N=0; TRACE_ERR_TS=""; TRACE_ERR_SRC=""
: > "$TRACE_SORTED"; : > "$REL_PODS_FILE"
if [ -n "$SEARCH_VALUE" ]; then
    progress 95 "Building the ID trace" s
    if [ -s "$SEARCH_STATS_FILE" ]; then
        cut -f2 "$SEARCH_STATS_FILE" | sed -n 's/^[^:]*: //p' | awk -F'/' 'NF>=2 {print $1"/"$2}' | sort -u > "$REL_PODS_FILE"
    fi
    if [ -s "$TRACE_FILE" ]; then
        sort -s -t$'\t' -k1,1 -k2,2 "$TRACE_FILE" | awk '!seen[$0]++' > "$TRACE_SORTED"
        TRACE_N=$(grep -c . "$TRACE_SORTED")
        TRACE_SRC_N=$(cut -f2 "$TRACE_SORTED" | sed 's/ (prev)$//' | sort -u | grep -c .)
        TRACE_FIRST_TS=$(head -1 "$TRACE_SORTED" | cut -f1)
        TRACE_FIRST_SRC=$(head -1 "$TRACE_SORTED" | cut -f2)
        TRACE_LAST_TS=$(tail -1 "$TRACE_SORTED" | cut -f1)
        TRACE_ERR_N=$(awk -F'\t' '$3=="!"' "$TRACE_SORTED" | grep -c .)
        TRACE_ERR_TS=$(awk -F'\t' '$3=="!"{print $1; exit}' "$TRACE_SORTED")
        TRACE_ERR_SRC=$(awk -F'\t' '$3=="!"{print $2; exit}' "$TRACE_SORTED")
    fi
    {
        echo "REQUEST TRACE for: $SEARCH_VALUE"
        echo "Scope : $(scope_description)"
        echo "Window: last ${SCAN_MINUTES} min ($SCAN_START_UTC -> $SCAN_END_UTC UTC)"
        if [ "$TRACE_N" -gt 0 ]; then
            echo "Lines : $TRACE_N timestamped line(s) from $TRACE_SRC_N source(s), oldest first.  '!' = line looks like an error."
            echo ""
            awk -F'\t' '{ printf "%-31s %s  %-44s  %s\n", $1, ($3=="!" ? "!" : " "), $2, $4 }' "$TRACE_SORTED"
        else
            echo "No timestamped log line contained the search value in this scope/window."
            echo "(Found in $MATCHES source(s); matches in describe/events output have no timestamp and cannot be placed on a timeline.)"
        fi
    } > "$TRACE_TEXT"
fi

###############################################################################
# 8d. TERMINAL SUMMARY TABLE (v5)
#
# After every scan (full or targeted) a compact, per-layer table is printed to
# the terminal (and saved as terminal-summary.txt):
#   CLUSTER -> NODE -> SERVICE -> POD -> ENDPOINT/EDGE
# Each row = one finding, with: severity, SINCE (when the problem started or
# was first seen, UTC), DURATION (SINCE -> now), resource, the error message,
# the EXPECTED ROOT CAUSE and the likely owner. Everything else (full logs,
# stack traces, root-cause chains, topology, usage, commands) stays in the
# HTML report -- the table ends by pointing the user to it.
#
# Read-only: the only extra API calls are `kubectl get ... -o jsonpath` lookups
# of condition/creation timestamps, used to work out how long a problem has
# existed.
#
# HONEST LIMITS (also printed under the table):
#  * "root cause" is an EXPECTED cause inferred from status/log patterns, not
#    proof -- confirm with the suggested commands in the HTML report.
#  * SINCE for log-based findings is the first matching log line INSIDE the
#    scan window, so DURATION is capped by the window you chose.
#  * A trailing * on SINCE means the start time could not be determined and
#    the scan time is shown instead (DURATION then reads "at scan").
###############################################################################
# BEGIN_V5_TERMINAL
TERM_ROWS_FILE="$REPORT_DIR/data/terminal-rows.tsv"
TERMINAL_MAX_ROWS_PER_LAYER="${TERMINAL_MAX_ROWS_PER_LAYER:-20}"

fact_layer() {
    case "$1" in
        CONTROL_PLANE|API_LATENCY|ETCD_SLOW|DNS_ERROR) echo CLUSTER ;;
        NODE_*) echo NODE ;;
        NO_ENDPOINTS) echo SERVICE ;;
        PARTIAL_NOT_READY|PROBE_FAIL|HAPROXY_5XX|F5_BLOCKED) echo ENDPOINT ;;
        *) echo POD ;;
    esac
}

fact_severity() {
    local cat="$1" detail="$2"
    case "$cat" in
        CONTROL_PLANE|NODE_NOT_READY|OOM) echo CRIT ;;
        API_LATENCY)
            case "$detail" in *"critical threshold"*) echo CRIT ;; *) echo WARN ;; esac ;;
        NODE_OVERSUBSCRIBED)
            case "$detail" in *approaching*) echo WARN ;; *) echo ERR ;; esac ;;
        PARTIAL_NOT_READY|HPA_MAXED|CRONJOB_UNCERTAIN|READINESS_FAIL|RESTART) echo WARN ;;
        *) echo ERR ;;
    esac
}

owner_short() {
    case "$1" in
        infra) echo "Infra" ;;
        network) echo "Network" ;;
        developer) echo "Developer" ;;
        security) echo "Security" ;;
        infra-or-developer) echo "Infra/Dev" ;;
        developer-or-infra) echo "Dev/Infra" ;;
        developer-or-network) echo "Dev/Net" ;;
        developer-or-security) echo "Dev/Sec" ;;
        infra-or-network) echo "Infra/Net" ;;
        downstream-symptom) echo "Symptom" ;;
        *) echo "Triage" ;;
    esac
}

# Pattern-based "expected cause" for free-text log/error lines.
classify_log_cause() {
    local m
    m=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    if printf '%s' "$m" | grep -Eq 'no repositories configured'; then
        echo "Helm job could not find a chart repository -- typical of k3s' bundled Helm jobs that ran while the node/network was still starting; they normally retry and finish on their own."
    elif printf '%s' "$m" | grep -Eq 'x509|certificate|tls handshake|ssl handshake'; then
        echo "TLS/certificate problem -- expired or untrusted certificate/CA, or hostname mismatch."
    elif printf '%s' "$m" | grep -Eq 'unauthorized|forbidden|permission denied|access denied|authentication fail|token (expired|invalid)|invalid token|noauth'; then
        echo "Authentication/authorization failure -- wrong or expired credentials/token, or missing RBAC / ServiceAccount permissions."
    elif printf '%s' "$m" | grep -Eq 'nxdomain|servfail|no such host|name resolution'; then
        echo "DNS resolution failing -- wrong host/service name, or CoreDNS / upstream resolver problem."
    elif printf '%s' "$m" | grep -Eq 'connection refused'; then
        echo "Target is not listening -- dependency down or restarting, wrong host/port, or its Service has no ready endpoints."
    elif printf '%s' "$m" | grep -Eq 'connection reset|broken pipe|reset by peer'; then
        echo "Connection dropped mid-flight -- peer crashed/restarted, idle timeout on a proxy/LB, or a network device resetting flows."
    elif printf '%s' "$m" | grep -Eq 'timeout|timed out|deadline exceeded'; then
        echo "Dependency too slow or unreachable -- overloaded backend, NetworkPolicy/firewall drop, or exhausted connection pool."
    elif printf '%s' "$m" | grep -Eq 'oom|outofmemory|out of memory|maxmemory'; then
        echo "Memory exhaustion -- leak/spike or memory limit set too low."
    elif printf '%s' "$m" | grep -Eq '(^|[^0-9])50[234]([^0-9]|$)|no server|backend.*down|server.*down'; then
        echo "Upstream backend failing or unavailable -- check backend pod health, readiness and Service endpoints."
    elif printf '%s' "$m" | grep -Eq 'segmentation fault|panic|traceback|exception|stack trace|caused by|fatal'; then
        echo "Application crash / unhandled exception -- code or config bug; see the stack trace in the HTML report."
    else
        echo "Application-reported error -- needs log review to pin down the cause."
    fi
}

# Error message shown in the table (scanner-authored details keep only the
# text before the first " -- ", since the part after it is explanation that
# belongs in the root-cause column; raw log lines are shown as-is, minus the
# leading timestamp which already has its own column).
error_text() {
    local cat="$1" d="$2" msg
    case "$cat" in
        LOG_ERROR|REDIS_ERROR|SECURITY|DNS_ERROR|HAPROXY_5XX|F5_BLOCKED)
            echo "$d" | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[[:space:]]*//' ;;
        PENDING_CONTAINER_ERROR)
            msg=$(echo "$d" | sed -n 's/.*kubelet message: \(.*\) -- already scheduled.*/\1/p')
            if [ -n "$msg" ] && [ "$msg" != "none reported" ]; then
                echo "${d%% -- *} | kubelet: $msg"
            else
                echo "${d%% -- *}"
            fi ;;
        *) echo "${d%% -- *}" ;;
    esac
}

expected_cause() {
    local cat="$1" d="$2" code hint
    case "$cat" in
        CONTROL_PLANE) echo "kube-apiserver /readyz or /livez check failing -- unhealthy API server, etcd or an admission/aggregated API; impacts every workload." ;;
        API_LATENCY) echo "Slow control-plane response -- overloaded API server or slow etcd (disk fsync latency). Single sample: re-run to confirm." ;;
        ETCD_SLOW) echo "etcd is slow to commit -- disk I/O latency or leader instability on the etcd node; degrades the whole API." ;;
        DNS_ERROR) echo "CoreDNS is logging errors -- upstream resolver unreachable/timing out, DNS loop, or CoreDNS overloaded; pods see slow or failed lookups." ;;
        NODE_NOT_READY) echo "Node stopped reporting Ready -- kubelet/container runtime down, node crashed or lost network; its pods become unavailable." ;;
        NODE_PRESSURE) echo "Node is short of memory, disk or PIDs -- kubelet will evict pods; look for a runaway pod, log/image build-up or missing limits." ;;
        NODE_NETWORK) echo "CNI has not set up networking on this node -- CNI pod crashed or node route/config problem." ;;
        NODE_OVERSUBSCRIBED) echo "Pod requests nearly fill this node -- CPU contention and scheduling failures likely; right-size requests or add nodes." ;;
        NO_ENDPOINTS)
            hint="${d#* -- }"; [ "$hint" = "$d" ] && hint=""
            echo "Service has no usable backends -- selector/label mismatch, pods down, or every pod failing readiness; all traffic to it fails.${hint:+ Scanner finding: $hint}" ;;
        PARTIAL_NOT_READY) echo "Some backends fail readiness while others serve -- one bad replica (app error, slow start or failing probe); requests may fail intermittently." ;;
        PROBE_FAIL) echo "App does not answer on its own port although Kubernetes sees the pod -- app hung/crashed inside the container, or wrong port/path." ;;
        READINESS_FAIL) echo "Pod is Running but not Ready -- readiness probe failing or app still starting; it is removed from Service endpoints." ;;
        OOM) echo "Container exceeded its memory limit and was killed -- memory leak/spike or limit set too low." ;;
        RESTART)
            code=$(echo "$d" | sed -n 's/.*exitCode=\([0-9]*\).*/\1/p')
            case "$code" in
                137) echo "Container was SIGKILLed (exit 137) -- usually OOMKill or a failing liveness probe; check memory limit and probe config." ;;
                143) echo "Container got SIGTERM (exit 143) -- rollout, eviction or node drain; only a problem if it keeps repeating." ;;
                139) echo "Segmentation fault (exit 139) -- native crash in the application or a bad base image." ;;
                0)   echo "Process exited cleanly yet keeps restarting -- it is not a long-running service, or a liveness probe is killing it." ;;
                1|2) echo "Application exited with an error (exit $code) -- startup/config/dependency failure; read the --previous logs." ;;
                *)   echo "Container keeps exiting (exit ${code:-?}) -- app crash, failing liveness probe or OOM; read the --previous logs." ;;
            esac ;;
        PENDING_SCHEDULING) echo "Scheduler cannot place the pod -- insufficient CPU/memory, unbound PVC, taints/affinity mismatch, or quota exhausted." ;;
        PENDING_CONTAINER_ERROR) echo "Pod is scheduled but its container cannot start -- bad image/tag, registry credentials, or missing ConfigMap/Secret/key." ;;
        FAILED) echo "Pod ended in Failed phase -- app exited with an error or the pod was evicted; check logs and events." ;;
        UNKNOWN) echo "Control plane lost contact with the pod's node -- kubelet/node problem rather than an app problem." ;;
        STATEFULSET_NOT_READY) echo "StatefulSet replicas not Ready -- pod crash/readiness failure, unbound PVC, or ordered rollout blocked by an earlier replica." ;;
        JOB_FAILED) echo "Job pods failed -- application error, bad config, or backoffLimit exhausted." ;;
        CRONJOB_UNCERTAIN) echo "Latest scheduled run did not complete successfully -- job failed, or is still running past its schedule." ;;
        HPA_INACTIVE) echo "Autoscaler cannot read metrics -- metrics-server unhealthy or target has no CPU/memory requests; it will not scale under load." ;;
        HPA_MAXED) echo "Autoscaler is at maxReplicas -- capacity ceiling reached; raise maxReplicas or node capacity if load is still high." ;;
        POD_CPU_HIGH) echo "CPU near the pod's limit -- likely throttling (slow responses); raise the CPU limit or reduce load." ;;
        POD_MEM_HIGH) echo "Memory near the pod's limit -- OOMKill imminent; raise the limit or investigate a leak." ;;
        PVC_NOT_BOUND) echo "No volume bound to this claim -- StorageClass/provisioner problem or no matching PV available." ;;
        F5_BLOCKED) echo "External F5/WAF blocking or failing traffic -- WAF policy violation, pool member/monitor down, or iRule drop; check the support_id on the BIG-IP." ;;
        HAPROXY_5XX) echo "Ingress/proxy saw backend failures (usually a symptom of an unhealthy backend): $(classify_log_cause "$d")" ;;
        SECURITY) echo "Security-related failure: $(classify_log_cause "$d")" ;;
        REDIS_ERROR) echo "Redis: $(classify_log_cause "$d")" ;;
        LOG_ERROR) classify_log_cause "$d" ;;
        *) echo "Needs investigation -- see the HTML report." ;;
    esac
}

# How long has this problem existed? State-based findings are resolved from the
# object's own timestamps (read-only `kubectl get`); results are cached.
declare -A SINCE_CACHE
SINCE_CACHE=()
resolve_since_ts() {
    # $1 category  $2 namespace  $3 resource  $4 detail  -> UTC ts, or nothing
    local cat="$1" ns="$2" res="$3" detail="$4" key raw="" pod ctype plist sel t best="" p
    key="$cat|$ns|$res"
    if [ -n "${SINCE_CACHE[$key]+set}" ]; then echo "${SINCE_CACHE[$key]}"; return; fi
    pod="${res%%/*}"
    case "$cat" in
        NODE_NOT_READY)
            raw=$(kubectl get node "$res" -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}' 2>/dev/null) ;;
        NODE_PRESSURE)
            ctype=$(echo "$detail" | grep -oE 'MemoryPressure|DiskPressure|PIDPressure' | head -1)
            [ -n "$ctype" ] && raw=$(kubectl get node "$res" -o jsonpath="{.status.conditions[?(@.type==\"$ctype\")].lastTransitionTime}" 2>/dev/null) ;;
        NODE_NETWORK)
            raw=$(kubectl get node "$res" -o jsonpath='{.status.conditions[?(@.type=="NetworkUnavailable")].lastTransitionTime}' 2>/dev/null) ;;
        READINESS_FAIL|FAILED|UNKNOWN)
            raw="${POD_READY_TRANS[$ns/$pod]:-}"; [ -z "$raw" ] && raw=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}' 2>/dev/null) ;;
        PENDING_SCHEDULING|PENDING_CONTAINER_ERROR)
            raw=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null) ;;
        PVC_NOT_BOUND)
            raw=$(kubectl get pvc "$res" -n "$ns" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null) ;;
        JOB_FAILED)
            raw=$(kubectl get job "$res" -n "$ns" -o jsonpath='{.status.startTime}' 2>/dev/null) ;;
        # v5.3: more finding types now get a real start time instead of "scan time *"
        NO_ENDPOINTS|PARTIAL_NOT_READY)
            # earliest moment a backing pod stopped being Ready (or was created, if it never was)
            plist=$(awk -F'\t' -v ns="$ns" -v svc="$res" '$1==ns && $2==svc {print $5}' "$REPORT_DIR/data/service-topology.tsv" 2>/dev/null | grep -oE '\([^)]+\)' | tr -d '()')
            if [ -z "$plist" ] && [ "$cat" = "NO_ENDPOINTS" ]; then
                sel=$(kubectl get svc "$res" -n "$ns" -o go-template='{{range $k,$v := .spec.selector}}{{$k}}={{$v}},{{end}}' 2>/dev/null); sel="${sel%,}"
                [ -n "$sel" ] && plist=$(kubectl get pods -n "$ns" -l "$sel" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
            fi
            for p in $plist; do
                t="${POD_READY_TRANS[$ns/$p]:-}"; [ -z "$t" ] && t=$(kubectl get pod "$p" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}' 2>/dev/null)
                [ -z "$t" ] && t=$(kubectl get pod "$p" -n "$ns" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)
                if [ -n "$t" ] && { [ -z "$best" ] || [[ "$t" < "$best" ]]; }; then best="$t"; fi
            done
            raw="$best" ;;
        PROBE_FAIL)
            case "$detail" in
                *"not-ready endpoint"*) raw="${POD_READY_TRANS[$ns/$pod]:-}"; [ -z "$raw" ] && raw=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}' 2>/dev/null) ;;
            esac ;;
        HPA_INACTIVE)
            raw=$(kubectl get hpa "$res" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="ScalingActive")].lastTransitionTime}' 2>/dev/null) ;;
        HPA_MAXED)
            raw=$(kubectl get hpa "$res" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="ScalingLimited")].lastTransitionTime}' 2>/dev/null) ;;
        CRONJOB_UNCERTAIN)
            raw=$(kubectl get cronjob "$res" -n "$ns" -o jsonpath='{.status.lastScheduleTime}' 2>/dev/null) ;;
        STATEFULSET_NOT_READY)
            raw=$(kubectl get pods -n "$ns" -o jsonpath='{range .items[*]}{.metadata.ownerReferences[0].name}{"|"}{.metadata.name}{"|"}{range .status.conditions[?(@.type=="Ready")]}{.status}{"|"}{.lastTransitionTime}{end}{"\n"}{end}' 2>/dev/null | awk -F'|' -v ss="$res" '$1==ss && $3=="False" {print $4}' | sort | head -1) ;;
    esac
    SINCE_CACHE[$key]="$(iso_to_ts "$raw")"
    echo "${SINCE_CACHE[$key]}"
}

# facts.tsv -> terminal-rows.tsv (one row per finding, sorted by severity, then time)
# columns: layer sevnum sev since duration resource error cause owner
build_terminal_rows() {
    local now_epoch rank cat ns res owner detail ts layer sev sevn since src dur ep disp nsres errtxt cause idm idmsg tl
    now_epoch=$(date +%s)
    : > "$TERM_ROWS_FILE"
    [ -s "$FACTS_FILE" ] || return
    while IFS=$'\t' read -r rank cat ns res owner detail ts; do
        [ -z "$rank" ] && continue
        case "$ns" in   # platform namespaces are not the application team's
            kube-system|kube-public|kube-node-lease)
                case "$owner" in developer|developer-or-infra) owner="infra" ;; developer-or-network) owner="infra-or-network" ;; esac ;;
        esac
        layer=$(fact_layer "$cat")
        sev=$(fact_severity "$cat" "$detail")
        case "$sev" in CRIT) sevn=0 ;; ERR) sevn=1 ;; *) sevn=2 ;; esac

        src="known"
        case "$ts" in
            *\*)
                src="scan"
                since=$(resolve_since_ts "$cat" "$ns" "$res" "$detail")
                if [ -n "$since" ]; then src="state"; else since="${ts%\*}"; fi ;;
            *) since="$ts" ;;
        esac
        idmsg=""
        if [ "$cat" = "LOG_ERROR" ] && [ -n "$SEARCH_VALUE" ] && [ -s "$TRACE_SORTED" ]; then
            tl=$(awk -F'\t' -v s="$ns/$res" '$2==s && $3=="!" {print $1 "\t" $4; exit}' "$TRACE_SORTED")
            if [ -n "$tl" ]; then
                since=$(iso_to_ts "${tl%%$'\t'*}"); src="known"
                idmsg="${tl#*$'\t'}"
            fi
        fi
        if [ "$src" = "scan" ]; then
            dur="at scan"; disp="${since:5:14}*"
        else
            ep=$(ts_to_epoch "$since")
            if [ -n "$ep" ]; then dur=$(fmt_duration $((now_epoch - ep))); else dur="n/a"; fi
            disp="${since:5:14}"
        fi

        if [ "$ns" = "-" ]; then nsres="$res"; else nsres="$ns/$res"; fi
        errtxt=$(error_text "$cat" "${idmsg:-$detail}" | tr '\t\n' '  ')
        cause=$(expected_cause "$cat" "${idmsg:-$detail}" | tr '\t\n' '  ')
        idm=$(fact_id_match "$cat" "$ns" "$res")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$layer" "$sevn" "$sev" "$disp" "$dur" "$nsres" "${errtxt:--}" "${cause:--}" "$(owner_short "$owner")" "$since" "${idm:--}" "$cat" "$ns" "$res" "$rank" >> "$TERM_ROWS_FILE"
    done < "$FACTS_FILE"
    sort -t$'\t' -k2,2n -k4,4 "$TERM_ROWS_FILE" -o "$TERM_ROWS_FILE"
    build_fix_plan
}

# --- v5.5: failure chains + fix plan ------------------------------------------------------------------------------
# Reads the findings, links each one to an EARLIER finding that can explain it (same pod, pod behind a Service,
# pod on a failing node, pods of one Deployment, or an error message that names the other service/pod), and
# writes columns 16-18: root #, fix text, own #. Fix COMMANDS go only to the first resource of each chain; the
# others just point at it. Commands are suggestions: this tool never runs them (the read-only guard blocks it).
build_fix_plan() {
    local plan_awk="$REPORT_DIR/data/fixplan.awk" tmp="$REPORT_DIR/data/terminal-rows-plan.tsv"
    [ -s "$TERM_ROWS_FILE" ] || return 0
    cat > "$plan_awk" <<'FIXPLAN_AWK_EOF'
# Failure-chain + fix-plan engine (v5.5). Input: findings sorted by SINCE (earliest first), tab separated:
#  1 layer 2 sevn 3 sev 4 since(disp) 5 duration 6 resource 7 error 8 expected-cause 9 owner 10 since(full)
#  11 idm 12 category 13 namespace 14 raw-resource 15 rank
# Output: the same 15 columns + 16 root# 17 fix text 18 own#   (commands only on the ROOT of each chain)
function ctrlof(pk,   k, o, a, d) {
    k = pkind[pk]; o = pown[pk]; if (k == "") return ""
    split(pk, a, "/")
    if (k == "ReplicaSet") { d = rsdep[a[1] "/" o]; if (d == "") { d = o; sub(/-[a-z0-9]+$/, "", d) } return "deployment/" d }
    if (k == "StatefulSet") return "statefulset/" o
    if (k == "DaemonSet") return "daemonset/" o
    if (k == "Job") return "job/" o
    return ""
}
function hasword(t, w,   L, off, p, b, a) {
    L = length(w); if (L < 4) return 0
    off = 1
    while ((p = index(substr(t, off), w)) > 0) {
        p = p + off - 1
        b = (p > 1) ? substr(t, p - 1, 1) : " "
        a = substr(t, p + L, 1); if (a == "") a = " "
        if (b !~ /[a-z0-9_-]/ && a !~ /[a-z0-9_]/) return 1
        off = p + L
    }
    return 0
}
function nm(key) { return tolower(substr(key, index(key, "/") + 1)) }
function mentions(j, i,   txt, pi, n, a, k, s, c) {
    txt = corp[pk[j]]; if (txt == "") return ""
    if (pk[i] != "") {
        pi = pk[i]
        if (hasword(txt, nm(pi))) return "its errors name pod " nm(pi)
        if (pip[pi] != "" && index(txt, pip[pi]) > 0) return "its errors name " pip[pi]
        n = split(podsvc[pi], a, " ")
        for (k = 1; k <= n; k++) {
            s = a[k]
            if (index(podsvc[pk[j]] " ", " " s " ") > 0) continue
            if (hasword(txt, nm(s))) return "its errors mention Service " nm(s)
        }
        c = ctrlof(pi)
        if (c != "" && ctrlof(pk[j]) != c && hasword(txt, nm(c))) return "its errors mention " nm(c)
    } else if (sk[i] != "") {
        if (index(podsvc[pk[j]] " ", " " sk[i] " ") > 0) return ""
        if (hasword(txt, nm(sk[i]))) return "its errors mention Service " nm(sk[i])
        if (sip[sk[i]] != "" && index(txt, sip[sk[i]]) > 0) return "its errors name " sip[sk[i]]
    }
    return ""
}
function islog(c) { return (c == "LOG_ERROR" || c == "SECURITY" || c == "REDIS_ERROR" || c == "HAPROXY_5XX") }
function causes(i, j,   ci, cj, r) {
    ci = CT[i]; cj = CT[j]
    if (ci == "ETCD_SLOW" && (cj == "API_LATENCY" || cj == "CONTROL_PLANE")) return "slow etcd commits slow the API server"
    if (ci == "DNS_ERROR" && islog(cj) && corp[pk[j]] ~ /nxdomain|servfail|no such host|name resolution/) return "DNS errors"
    if (ci ~ /^NODE_/ && pk[j] != "" && pnode[pk[j]] == RE[i]) return "it runs on this node"
    if (pk[i] != "" && pk[i] == pk[j]) return "same pod"
    if ((cj == "NO_ENDPOINTS" || cj == "PARTIAL_NOT_READY") && pk[i] != "" && NS[i] == NS[j] && index(sbacks[NS[j] "/" RE[j]] " ", " " nm(pk[i]) " ") > 0) return "its pod backs this Service"
    if (cj == "STATEFULSET_NOT_READY" && pk[i] != "" && NS[i] == NS[j] && index(nm(pk[i]), RE[j] "-") == 1) return "pod of this StatefulSet"
    if (cj == "HPA_INACTIVE" && pk[i] != "" && RE[i] ~ /metrics-server/) return "metrics-server is unhealthy"
    if (pk[i] != "" && pk[j] != "" && ctrlof(pk[i]) != "" && ctrlof(pk[i]) == ctrlof(pk[j])) return "same " ctrlof(pk[i])
    if (islog(cj)) { r = mentions(j, i); if (r != "") return r }
    return ""
}
function rollback_target(p,   c, q, own, a) {
    c = ctrlof(p); if (c !~ /^deployment\//) return ""
    split(p, a, "/"); own = pown[p]
    for (q in pkind) { if (index(q, a[1] "/") != 1) continue; if (ctrlof(q) == c && pown[q] != own && !(q in hasf)) return c }
    return ""
}
function dbl(v,   n, u) { if (match(v, /^[0-9]+/)) { n = substr(v, 1, RLENGTH) + 0; u = substr(v, RLENGTH + 1); if (u == "Mi" || u == "Gi" || u == "Ki" || u == "M" || u == "G") return (n * 2) u } return "" }
function contlimit(p, c, lims,   n, a, m, b, k) {
    n = split(lims, a, " "); m = split(pconts[p], b, " ")
    if (n == m) { for (k = 1; k <= m; k++) if (b[k] == c) return a[k] }
    if (n == 1) return a[1]
    return ""
}
function prio(i,   c) {
    c = CT[i]
    if (c == "OOM" || c == "POD_MEM_HIGH") return 9
    if (c == "RESTART" && ER[i] ~ /exitCode=137/) return 8
    if (c == "PENDING_CONTAINER_ERROR") return 8
    if (c == "PENDING_SCHEDULING") return 7
    if (c == "RESTART") return 6
    if (c == "READINESS_FAIL" || c == "PROBE_FAIL" || c == "FAILED" || c == "UNKNOWN") return 5
    if (c == "SECURITY") return 3
    if (c == "LOG_ERROR" || c == "REDIS_ERROR") return 2
    return 1
}
function add(s, label, c) { return (s == "" ? "" : s "@@") "[" label "] " c }
function fixtext(i,   cat, ns, res, p, c, ctrl, nf, s, rb, v, nv, code, q, jb) {
    cat = CT[i]; ns = NS[i]; res = RE[i]; split(res, q, "/"); p = q[1]; c = q[2]
    ctrl = (pk[i] != "") ? ctrlof(pk[i]) : ""
    nf = " -n " ns; s = ""
    rb = (pk[i] != "") ? rollback_target(pk[i]) : ""
    if (p ~ /^helm-install-/ && ns == "kube-system" && (cat == "LOG_ERROR" || cat == "RESTART" || cat == "FAILED" || cat == "READINESS_FAIL")) {
        jb = (ctrl ~ /^job\//) ? substr(ctrl, 5) : p
        s = add(s, "inspect", "kubectl logs job/" jb " -n kube-system --tail=50")
        s = add(s, "state", "kubectl get jobs,pods -n kube-system; kubectl get helmchart -A")
        s = add(s, "note", "k3s runs these Helm jobs at start-up and retries them itself; if they end Complete and Traefik works, nothing needs fixing")
        s = add(s, "only if it keeps failing once the node/network is stable", "kubectl delete job " jb " -n kube-system   (k3s recreates it)")
        return s
    }
    if (cat == "OOM" || cat == "POD_MEM_HIGH" || (cat == "RESTART" && ER[i] ~ /exitCode=137/)) {
        if (rb != "") { s = add(s, "check revisions", "kubectl rollout history " rb nf); s = add(s, "option A - quickest: roll back (a healthy older revision is running)", "kubectl rollout undo " rb nf) }
        v = contlimit(pk[i], c, plimmem[pk[i]]); nv = dbl(v)
        if (ctrl != "") s = add(s, (rb != "" ? "option B - keep this version: " : "") "raise memory limit" (v != "" ? " (now " v ")" : ""), "kubectl set resources " ctrl nf " -c " c " --limits=memory=" (nv != "" ? nv : "<HIGHER-LIMIT>"))
        else s = add(s, "raise memory limit", "bare pod without a controller: raise resources.limits.memory in its manifest and recreate it")
        s = add(s, "inspect", "kubectl logs " p nf " -c " c " --previous --tail=100")
    } else if (cat == "RESTART") {
        s = add(s, "inspect", "kubectl logs " p nf " -c " c " --previous --tail=100")
        if (rb != "") { s = add(s, "rollback - a healthy older revision is running", "kubectl rollout undo " rb nf) }
        if (ctrl != "") s = add(s, "restart pod (only after the cause above is fixed)", "kubectl delete pod " p nf)
    } else if (cat == "READINESS_FAIL" || cat == "PROBE_FAIL") {
        s = add(s, "inspect", "kubectl logs " p nf " -c " (c != "" ? c : "<container>") " --tail=100")
        if (rb != "") s = add(s, "rollback - a healthy older revision is running", "kubectl rollout undo " rb nf)
        if (ctrl != "") s = add(s, "restart pod", "kubectl delete pod " p nf)
    } else if (cat == "PENDING_SCHEDULING") {
        s = add(s, "inspect", "kubectl describe pod " p nf)
        s = add(s, "capacity", "kubectl top nodes; kubectl get resourcequota" nf)
        if (ctrl != "") s = add(s, "lower requests", "kubectl set resources " ctrl nf " --requests=cpu=<LOWER>,memory=<LOWER>")
    } else if (cat == "PENDING_CONTAINER_ERROR") {
        if (rb != "") s = add(s, "rollback - a healthy older revision is running", "kubectl rollout undo " rb nf)
        if (ctrl != "") s = add(s, "fix image", "kubectl set image " ctrl nf " <CONTAINER>=<CORRECT-IMAGE:TAG>")
        s = add(s, "pull secret / config", "kubectl get secret,configmap" nf)
        s = add(s, "inspect", "kubectl describe pod " p nf)
    } else if (cat == "FAILED" || cat == "UNKNOWN") {
        s = add(s, "inspect", "kubectl describe pod " p nf)
        if (ctrl != "") s = add(s, "reschedule", "kubectl delete pod " p nf)
    } else if (cat == "NO_ENDPOINTS") {
        s = add(s, "inspect", "kubectl get svc " res nf " -o yaml")
        s = add(s, "compare labels", "kubectl get pods" nf " --show-labels")
        s = add(s, "fix selector", "kubectl patch svc " res nf " --type merge -p '{\"spec\":{\"selector\":{\"<KEY>\":\"<VALUE-FROM-POD-LABELS>\"}}}'")
    } else if (cat == "STATEFULSET_NOT_READY") {
        s = add(s, "inspect", "kubectl describe statefulset " res nf)
        s = add(s, "rollback if caused by an update", "kubectl rollout undo statefulset/" res nf)
    } else if (cat == "JOB_FAILED") {
        s = add(s, "inspect", "kubectl logs job/" res nf " --tail=100")
        s = add(s, "re-run", "kubectl delete job " res nf "   (then recreate it from its CronJob/manifest)")
    } else if (cat == "CRONJOB_UNCERTAIN") {
        s = add(s, "inspect", "kubectl get jobs" nf)
        s = add(s, "run now", "kubectl create job --from=cronjob/" res " " res "-manual" nf)
    } else if (cat == "HPA_INACTIVE") {
        s = add(s, "inspect", "kubectl describe hpa " res nf)
        s = add(s, "metrics-server", "kubectl get pods -n kube-system -l k8s-app=metrics-server")
        s = add(s, "restart metrics-server", "kubectl rollout restart deployment/metrics-server -n kube-system")
    } else if (cat == "HPA_MAXED") {
        s = add(s, "raise maximum", "kubectl patch hpa " res nf " --type merge -p '{\"spec\":{\"maxReplicas\":<HIGHER>}}'")
    } else if (cat == "POD_CPU_HIGH") {
        if (ctrl != "") s = add(s, "raise CPU limit", "kubectl set resources " ctrl nf " -c " c " --limits=cpu=<HIGHER>")
        s = add(s, "inspect", "kubectl top pod " p nf " --containers")
    } else if (cat == "PVC_NOT_BOUND") {
        s = add(s, "inspect", "kubectl describe pvc " res nf)
        s = add(s, "storage", "kubectl get storageclass,pv")
    } else if (cat == "NODE_NOT_READY") {
        s = add(s, "inspect", "kubectl describe node " res)
        s = add(s, "on the node", "systemctl status kubelet   (k3s: systemctl status k3s or k3s-agent)")
        s = add(s, "on the node", "journalctl -u kubelet --since '30 min ago'")
        s = add(s, "restart node agent", "systemctl restart kubelet   (k3s: systemctl restart k3s or k3s-agent)")
        s = add(s, "last resort", "kubectl drain " res " --ignore-daemonsets --delete-emptydir-data")
    } else if (cat == "NODE_PRESSURE") {
        s = add(s, "inspect", "kubectl describe node " res)
        s = add(s, "find hogs", "kubectl top pods -A --sort-by=memory")
        s = add(s, "on the node", "df -h; crictl rmi --prune")
    } else if (cat == "NODE_NETWORK") {
        s = add(s, "find the CNI pod", "kubectl get pods -n kube-system -o wide | grep -Ei 'flannel|calico|cilium|weave'")
        s = add(s, "restart it", "kubectl delete pod <CNI-POD-ON-" res "> -n kube-system")
    } else if (cat == "NODE_OVERSUBSCRIBED") {
        s = add(s, "inspect", "kubectl describe node " res)
        s = add(s, "right-size", "kubectl set resources <workload> -n <ns> --requests=cpu=<LOWER>,memory=<LOWER>   (or add a node)")
    } else if (cat == "DNS_ERROR") {
        s = add(s, "inspect", "kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50")
        s = add(s, "restart CoreDNS", "kubectl rollout restart deployment/coredns -n kube-system")
    } else if (cat == "CONTROL_PLANE" || cat == "API_LATENCY" || cat == "ETCD_SLOW") {
        s = add(s, "inspect", "kubectl get --raw='/readyz?verbose'")
        s = add(s, "on the control-plane node", "journalctl -u kube-apiserver -u etcd --since '30 min ago'   (k3s: journalctl -u k3s)")
        s = add(s, "escalate", "Infra / Platform team")
    } else if (cat == "SECURITY") {
        s = add(s, "inspect", "kubectl logs " p nf " -c " c " --since=30m")
        s = add(s, "credentials / certs", "kubectl get secret" nf)
        s = add(s, "RBAC", "kubectl auth can-i --list --as=system:serviceaccount:" ns ":default" nf)
    } else if (cat == "F5_BLOCKED") {
        s = add(s, "BIG-IP", "tmsh show ltm pool <POOL> members")
        s = add(s, "BIG-IP", "search the ASM event log for the support_id in the matched line")
    } else if (cat == "HAPROXY_5XX") {
        s = add(s, "inspect", "kubectl logs " p nf " --tail=100")
        s = add(s, "backends", "kubectl get endpoints" nf)
    } else if (cat == "PARTIAL_NOT_READY") {
        s = add(s, "which backend is not ready", "kubectl get endpointslices" nf " -l kubernetes.io/service-name=" res " -o wide")
        s = add(s, "inspect the pods", "kubectl get pods" nf " -o wide")
        s = add(s, "Service", "kubectl describe svc " res nf)
    } else if (cat == "LOG_ERROR" || cat == "REDIS_ERROR") {
        s = add(s, "inspect", "kubectl logs " p nf " -c " (c != "" ? c : "<container>") " --since=30m")
        if (ctrl != "") s = add(s, "restart pod (only if the logs show a transient fault)", "kubectl delete pod " p nf)
    } else {
        s = add(s, "inspect", "see the HTML report for details and the read-only commands to confirm this finding")
    }
    return s
}
BEGIN {
    FS = OFS = "\t"
    while ((getline line < podinfo) > 0) { split(line, f, "\t"); k = f[1]; pnode[k] = f[2]; pkind[k] = f[3]; pown[k] = f[4]; plimmem[k] = f[5]; plimcpu[k] = f[6]; pconts[k] = f[7]; pip[k] = f[8] }
    while ((getline line < rsfile) > 0) { split(line, f, "\t"); rsdep[f[1]] = f[2] }
    while ((getline line < topo) > 0) {
        split(line, f, "\t"); s = f[1] "/" f[2]; sip[s] = f[3]
        n = split(f[4] " " f[5], a, " ")
        for (k = 1; k <= n; k++) if (match(a[k], /\([^)]+\)/)) { pn = substr(a[k], RSTART + 1, RLENGTH - 2); sbacks[s] = sbacks[s] " " pn; podsvc[f[1] "/" pn] = podsvc[f[1] "/" pn] " " s }
    }
    while ((getline line < corpusf) > 0) {
        split(line, f, "\t"); split(f[1], a, "/"); k = a[1] "/" a[2]
        if (length(corp[k]) < 30000) corp[k] = corp[k] " " tolower(substr(line, length(f[1]) + 2))
    }
    n = 0
}
{
    n++
    for (c = 1; c <= 15; c++) F[n, c] = $c
    CT[n] = $12; NS[n] = $13; RE[n] = $14; ER[n] = $7
    cat = CT[n]
    if (cat ~ /^(NODE_|CONTROL_PLANE|API_LATENCY|ETCD_SLOW|DNS_ERROR|F5_BLOCKED|HPA_|PVC_|JOB_|CRONJOB_|STATEFULSET_|NO_ENDPOINTS|PARTIAL_NOT_READY)/) pk[n] = ""
    else { split(RE[n], q, "/"); pk[n] = NS[n] "/" q[1]; hasf[pk[n]] = 1 }
    sk[n] = (cat == "NO_ENDPOINTS" || cat == "PARTIAL_NOT_READY") ? NS[n] "/" RE[n] : ""
}
END {
    if (n > 400) { for (j = 1; j <= n; j++) { par[j] = 0 } }
    else for (j = 1; j <= n; j++) {
        par[j] = 0
        for (i = 1; i < j; i++) { r = causes(i, j); if (r != "") { par[j] = i; why[j] = r; break } }
    }
    for (j = 1; j <= n; j++) { root[j] = (par[j] > 0) ? root[par[j]] : j; if (par[j] > 0) { kids[root[j]] = kids[root[j]] (kids[root[j]] == "" ? "" : ", ") "#" j; desc[root[j]] = desc[root[j]] " " j } }
    for (j = 1; j <= n; j++) {
        if (root[j] == j) {
            # fix for the most informative finding of the SAME pod inside this chain (e.g. the OOM kill, not just its log line)
            best = j
            if (pk[j] != "") { nd = split(desc[j], dl, " "); for (d = 1; d <= nd; d++) if (pk[dl[d]] == pk[j] && prio(dl[d]) > prio(best)) best = dl[d] }
            t = fixtext(best)
            if (kids[j] != "") t = t "@@(!) Fixing this first should also clear " kids[j] " - they are downstream of it, so they get no commands of their own."
        } else {
            t = ">> No separate fix. Expected to clear once #" root[j] " is fixed (" why[j] ") - " RE[root[j]] "."
        }
        line = ""
        for (c = 1; c <= 15; c++) line = line F[j, c] OFS
        print line root[j], t, j
    }
}
FIXPLAN_AWK_EOF
    if sort -s -t$'\t' -k10,10 -k15,15n "$TERM_ROWS_FILE" | awk -v podinfo="$POD_INFO_FILE" -v rsfile="$REPORT_DIR/data/rs-owner.tsv" -v topo="$REPORT_DIR/data/service-topology.tsv" -v corpusf="$ERR_CORPUS_FILE" -f "$plan_awk" > "$tmp" 2>"$REPORT_DIR/data/fixplan.err" && [ -s "$tmp" ]; then
        mv "$tmp" "$TERM_ROWS_FILE"
    else
        info "Fix-plan engine could not run on this system's awk (see data/fixplan.err); the table is shown without fix suggestions."
        rm -f "$tmp"
    fi
    sort -s -t$'\t' -k2,2n -k4,4 "$TERM_ROWS_FILE" -o "$TERM_ROWS_FILE"
}

# ONE renderer for every table: bold header, global # numbering, SUGGESTED FIX column.
render_findings_table() {
    # $1 rows file  $2 color  $3 terminal width  $4 layer filter ("" = all layers)  $5 show ID column (1/0)  $6 max rows
    awk -F'\t' -v color="$2" -v TW="$3" -v layer="$4" -v showid="$5" -v maxrows="$6" '
    function rep(c, n,   s, i) { s = ""; for (i = 0; i < n; i++) s = s c; return s }
    function trunc(s, n) { if (length(s) > n) return substr(s, 1, n - 3) "..."; return s }
    function cell(s, w) { return sprintf("%-" w "s", s) }
    function wrap(s, w, out,   n, words, i, line, cnt, word) {
        split("", out); cnt = 0; line = ""
        n = split(s, words, " ")
        for (i = 1; i <= n; i++) {
            word = words[i]
            while (length(word) > w) {
                if (line != "") { out[++cnt] = line; line = "" }
                out[++cnt] = substr(word, 1, w); word = substr(word, w + 1)
            }
            if (line == "") line = word
            else if (length(line) + 1 + length(word) <= w) line = line " " word
            else { out[++cnt] = line; line = word }
        }
        if (line != "" || cnt == 0) out[++cnt] = line
        return cnt
    }
    function wrapfix(s, w, out,   parts, np, p, tmp, nt, t, cnt) {
        split("", out); cnt = 0; np = split(s, parts, "@@")
        for (p = 1; p <= np; p++) { nt = wrap(parts[p], w, tmp); for (t = 1; t <= nt; t++) out[++cnt] = tmp[t] }
        if (cnt == 0) out[++cnt] = ""
        return cnt
    }
    function sep(   s) {
        s = "+" rep("-", wN+2) "+" rep("-", wS+2) "+" rep("-", wT+2) "+" rep("-", wD+2) "+" rep("-", wR+2) "+"
        if (showid == 1) s = s rep("-", wI+2) "+"
        s = s rep("-", wE+2) "+" rep("-", wC+2) "+" rep("-", wF+2) "+"
        if (showown == 1) s = s rep("-", wO+2) "+"
        print s
    }
    BEGIN {
        wN = 3; wS = 4; wT = 15; wD = 8; wR = 22; wI = 3; wO = 9
        showown = (TW >= 165) ? 1 : 0          # narrower terminals: the owner moves into the cause cell
        ncol = 8 + (showown == 1 ? 1 : 0) + (showid == 1 ? 1 : 0)
        flex = TW - (wN + wS + wT + wD + wR + (showown == 1 ? wO : 0) + (showid == 1 ? wI : 0) + ncol * 3 + 1)
        minflex = (showown == 1) ? 66 : 54; if (flex < minflex) flex = minflex
        wE = int(flex * 0.28); wC = int(flex * 0.30); wF = flex - wE - wC
        if (wE > 50) wE = 50
        if (wC > 60) wC = 60
        col["CRIT"] = "\033[1;31m"; col["ERR"] = "\033[38;5;208m"; col["WARN"] = "\033[1;33m"
        abbr["CLUSTER"] = "CLUS"; abbr["NODE"] = "NODE"; abbr["SERVICE"] = "SVC"; abbr["POD"] = "POD"; abbr["ENDPOINT"] = "EP"
        sep()
        hdr = "| " cell("#", wN) " | " cell("SEV", wS) " | " cell("SINCE (UTC)", wT) " | " cell("DURATION", wD) " | " cell("RESOURCE", wR) " | "
        if (showid == 1) hdr = hdr cell("ID", wI) " | "
        hE = (wE >= 13) ? "ERROR MESSAGE" : "ERROR"; hC = (wC >= 19) ? "EXPECTED ROOT CAUSE" : ((wC >= 10) ? "ROOT CAUSE" : "CAUSE"); hF = (wF >= 13) ? "SUGGESTED FIX" : "FIX"
        hdr = hdr cell(hE, wE) " | " cell(hC, wC) " | " cell(hF, wF) " |"
        if (showown == 1) hdr = hdr " " cell("OWNER", wO) " |"
        if (color == 1) print "\033[1m" hdr "\033[0m"; else print hdr
        sep()
    }
    {
        if (layer != "" && $1 != layer) next
        n++
        if (n > maxrows) { extra++; next }
        seq = ($18 != "") ? $18 : n
        nR = wrap($6, wR, ra); nE = wrap(trunc($7, 400), wE, ea); nC = wrap(trunc(showown == 1 ? $8 : $8 " [owner: " $9 "]", 420), wC, ca); nF = wrapfix(trunc($17, 1500), wF, fa); nO = wrap($9, wO, oa)
        m = nR; if (nE > m) m = nE; if (nC > m) m = nC; if (nF > m) m = nF; if (nO > m) m = nO; if (m < 2 && layer == "") m = 2
        down = ($17 ~ /^>>/)
        for (k = 1; k <= m; k++) {
            sv = cell((k == 1 ? $3 : (k == 2 && layer == "" ? abbr[$1] : "")), wS)
            if (color == 1 && k == 1) sv = col[$3] sv "\033[0m"
            fc = cell((k <= nF ? fa[k] : ""), wF)
            if (color == 1 && down) fc = "\033[0;36m" fc "\033[0m"
            line = "| " cell((k == 1 ? seq : ""), wN) " | " sv " | " cell((k == 1 ? $4 : ""), wT) " | " cell((k == 1 ? $5 : ""), wD) " | " cell((k <= nR ? ra[k] : ""), wR) " | "
            if (showid == 1) {
                idc = cell((k == 1 && $11 == "yes" ? "yes" : ""), wI)
                if (color == 1 && k == 1 && $11 == "yes") idc = "\033[1;36m" idc "\033[0m"
                line = line idc " | "
            }
            line = line cell((k <= nE ? ea[k] : ""), wE) " | " cell((k <= nC ? ca[k] : ""), wC) " | " fc " |"
            if (showown == 1) line = line " " cell((k <= nO ? oa[k] : ""), wO) " |"
            print line
        }
        sep()
    }
    END { if (extra > 0) printf "  ... %d more finding(s) not shown here -- see the HTML report for the full list.\n", extra }' "$1"
}
render_layer_table() { render_findings_table "$TERM_ROWS_FILE" "$3" "$4" "$1" 0 "$TERMINAL_MAX_ROWS_PER_LAYER"; }

# Fix plan for the HTML report: one card per ROOT finding, with its commands and what fixing it should also clear.
fix_plan_html() {
    sort -s -t$'\t' -k18,18n "$TERM_ROWS_FILE" | awk -F'\t' '
        function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
        NF >= 18 && $16 == $18 {
            n = split($17, parts, "@@"); cmds = ""
            for (i = 1; i <= n; i++) cmds = cmds esc(parts[i]) "\n"
            b = ($3 == "CRIT") ? "crit" : (($3 == "ERR") ? "err" : "warn")
            printf "<div class=\"card\"><h3>#%s &middot; %s <span class=\"badge %s\">%s</span></h3><p><b>Resource:</b> %s &nbsp; <b>Since:</b> %s UTC (%s) &nbsp; <b>Owner:</b> %s</p><p><b>Error:</b> %s</p><p><b>Expected root cause:</b> %s</p><pre>%s</pre></div>\n", $18, esc($12), b, $3, esc($6), $10, $5, esc($9), esc($7), esc($8), cmds
        }'
}

print_terminal_summary() {
    # $1 = 1 for ANSI colors, 0 for plain text (used for the saved .txt copy)
    local color="${1:-0}" tw="${TERMINAL_WIDTH:-}" B="" RD="" GR="" YL="" CY="" NC0=""
    local LINE layer title cnt n_crit n_err n_warn
    if [ -z "$tw" ]; then
        [ -t 1 ] && command_exists tput && tw=$(tput cols 2>/dev/null)
        tw="${tw:-160}"
    fi
    case "$tw" in ''|*[!0-9]*) tw=160 ;; esac
    if [ "$color" = "1" ]; then
        B=$'\033[1m'; RD=$'\033[1;31m'; GR=$'\033[0;32m'; YL=$'\033[1;33m'; CY=$'\033[0;36m'; NC0=$'\033[0m'
    fi
    LINE=$(printf '%*s' "$tw" '' | tr ' ' '=')

    # ---- header counts -------------------------------------------------------
    local nodes_total nodes_notready nodes_with svc_total svc_with ep_ready ep_notready pods_with
    nodes_total=$(printf '%s\n' "$NODE_LIST" | grep -c .)
    nodes_notready=$(awk -F'\t' '$2=="NODE_NOT_READY"{print $4}' "$FACTS_FILE" | sort -u | grep -c .)
    nodes_with=$(awk -F'\t' '$2 ~ /^NODE_/{print $4}' "$FACTS_FILE" | sort -u | grep -c .)
    svc_total=$(grep -c . "$REPORT_DIR/data/service-topology.tsv" 2>/dev/null); svc_total=${svc_total:-0}
    svc_with=$(awk -F'\t' '$2=="NO_ENDPOINTS"{print $3"/"$4}' "$FACTS_FILE" | sort -u | grep -c .)
    read -r ep_ready ep_notready < <(awk -F'\t' '{r+=split($4,a," "); nr+=split($5,b," ")} END{print r+0, nr+0}' "$REPORT_DIR/data/service-topology.tsv" 2>/dev/null)
    pods_with=$(awk -F'\t' '$3!="-" && $2 !~ /^(NO_ENDPOINTS|PARTIAL_NOT_READY|HPA_|PVC_|JOB_|CRONJOB_|STATEFULSET_|F5_|HAPROXY|PROBE|NODE_)/{split($4,p,"/"); print $3"/"p[1]}' "$FACTS_FILE" | sort -u | grep -c .)
    n_crit=$(awk -F'\t' '$3=="CRIT"' "$TERM_ROWS_FILE" | grep -c .)
    n_err=$(awk -F'\t' '$3=="ERR"' "$TERM_ROWS_FILE" | grep -c .)
    n_warn=$(awk -F'\t' '$3=="WARN"' "$TERM_ROWS_FILE" | grep -c .)

    echo ""
    echo "$LINE"
    echo " ${B}INCIDENT SUMMARY${NC0}  --  cluster context: $CURRENT_CONTEXT"
    echo "$LINE"
    printf ' %-10s: last %s min (%s -> %s)   scan took %s\n' "Window" "$SCAN_MINUTES" "$SCAN_START_HUMAN" "$SCAN_END_HUMAN" "$(fmt_duration $(( $(date +%s) - SCAN_END_EPOCH )))"
    printf ' %-10s: %s\n' "Scope" "$(scope_description)"
    [ -n "$SEARCH_VALUE" ] && printf ' %-10s: "%s" -> %s occurrence(s) in %s source(s); %s timestamped trace line(s) from %s source(s)\n' "Search" "$SEARCH_VALUE" "$SEARCH_OCCURRENCES" "$MATCHES" "${TRACE_N:-0}" "${TRACE_SRC_N:-0}"
    printf ' %-10s: control plane %s | CoreDNS %s | API latency %sms | etcd: %s\n' "Cluster" "$CONTROL_PLANE_STATUS" "$COREDNS_STATE" "$API_LATENCY_MS" "$ETCD_STATUS_TEXT"
    printf ' %-10s: %s total%s, %s NotReady, %s with findings\n' "Nodes" "$nodes_total" "$([ "$NS_ONLY" = "1" ] && echo " (hosting pods of this namespace)")" "$nodes_notready" "$nodes_with"
    printf ' %-10s: %s total, %s with findings\n' "Services" "$svc_total" "$svc_with"
    printf ' %-10s: %s ready, %s not-ready   (live probes: %s | F5/external LB: %s)\n' "Endpoints" "${ep_ready:-0}" "${ep_notready:-0}" "$PROBE_STATUS_TEXT" "$F5_STATUS_TEXT"
    printf ' %-10s: %s scanned, %s with findings%s\n' "Pods" "$POD_TOTAL" "$pods_with" "$([ "${POD_UNREAD:-0}" -gt 0 ] && echo ", ${POD_UNREAD} COULD NOT BE READ -- check kubectl access (results incomplete)")"
    local kc_total kc_get kc_logs kc_desc kc_top kc_exec kc_block kc_capped kc_note
    read -r kc_total kc_get kc_logs kc_desc kc_top kc_exec kc_block < <(awk '/^BLOCKED/ {b++; next} NF {n[$1]++; t++} END {print t+0, n["get"]+0, n["logs"]+0, n["describe"]+0, n["top"]+0, n["exec"]+0, b+0}' "$KCALL_LOG" 2>/dev/null)
    kc_note="all read-only"; [ "${kc_exec:-0}" -gt 0 ] && kc_note="read-only, incl. ${kc_exec} opt-in exec probe(s)"
    printf ' %-10s: %s kubectl call(s): get %s, logs %s, describe %s, top %s -- %s (guard blocked %s other attempt(s))\n' "API calls" "${kc_total:-0}" "${kc_get:-0}" "${kc_logs:-0}" "${kc_desc:-0}" "${kc_top:-0}" "$kc_note" "${kc_block:-0}"
    kc_capped=$(grep -c . "$CAPPED_LOGS_FILE" 2>/dev/null)
    [ "${kc_capped:-0}" -gt 0 ] && printf ' %-10s: %s container log(s) hit LOG_TAIL_LINES=%s -- older lines inside the window were not scanned (raise LOG_TAIL_LINES to scan them)\n' "Log cap" "$kc_capped" "$LOG_TAIL_LINES"
    echo " Findings  : ${RD}CRIT $n_crit${NC0}   ${YL}ERR $n_err${NC0}   ${CY}WARN $n_warn${NC0}"

    if [ ! -s "$TERM_ROWS_FILE" ]; then
        echo ""
        echo " ${GR}No findings in this scan window -- nothing to report.${NC0}"
    else
        if [ -n "$SEARCH_VALUE" ]; then
            print_chrono_section "$color" "$tw"
        else
        for layer in CLUSTER NODE SERVICE POD ENDPOINT; do
            case "$layer" in
                CLUSTER)  title="[ CLUSTER ]  control plane, API server, etcd, DNS" ;;
                NODE)     title="[ NODES ]" ;;
                SERVICE)  title="[ SERVICES ]  routing / Service endpoints" ;;
                POD)      title="[ PODS & WORKLOADS ]" ;;
                ENDPOINT) title="[ ENDPOINTS & EDGE ]  readiness, live probes, ingress, external LB" ;;
            esac
            cnt=$(awk -F'\t' -v l="$layer" '$1==l' "$TERM_ROWS_FILE" | grep -c .)
            if [ "$cnt" -eq 0 ]; then
                echo ""
                echo "${GR}${title}  OK -- no findings${NC0}"
            else
                echo ""
                echo "${B}${title}  -- ${cnt} finding(s)${NC0}"
                render_layer_table "$layer" "" "$color" "$tw"
            fi
        done
        fi
    fi

    [ -n "$SEARCH_VALUE" ] && print_trace_block "$color" "$tw"

    echo ""
    echo " Notes: a trailing * on SINCE = start time unknown (scan time shown). Root causes are expected causes to verify, not proof."
    echo " Fix plan: commands are only SUGGESTIONS -- this tool is read-only and never runs them. They are given to the FIRST resource of each failure chain;"
    echo "           later resources say which # to fix instead. Chains are inferred from start times + relationships (same pod, Service backends, node, Deployment, errors that name another service) -- verify before acting."
    [ "$tw" -lt 165 ] && echo " Tip: this terminal is $tw columns wide; widen it to 165+ (or set TERMINAL_WIDTH=200) for the full table layout."
    if [ "${MASK_PII:-0}" != "1" ] && awk -F'\t' '$7 ~ /[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]/ { f = 1 } END { exit !f }' "$TERM_ROWS_FILE" 2>/dev/null; then
        echo " Privacy: a long number (possible national ID / card number) appears in this output. Re-run with MASK_PII=1 before sharing it outside the team (an ID you searched for stays visible)."
    fi
    [ -n "$SEARCH_VALUE" ] && echo " With a search ID the table is ordered by SINCE (earliest failure first, all layers); ID=yes = the pod/service backend appears in the ID trail; * rows are point-in-time measurements or have an unknown start, so they sort last."
    echo ""
    echo "$LINE"
    echo " ${B}Need more details?${NC0}  Check the HTML report (full logs, stack traces, root-cause chains, topology, commands):"
    echo "   ${B}$(cd "$REPORT_DIR" 2>/dev/null && pwd)/index.html${NC0}"
    [ -n "$SEARCH_VALUE" ] && echo "   Search matches with context: $(cd "$REPORT_DIR" 2>/dev/null && pwd)/search-matches.txt"
    [ -n "$SEARCH_VALUE" ] && echo "   Chronological trace of the ID: $(cd "$REPORT_DIR" 2>/dev/null && pwd)/search-trace.txt"
    echo "$LINE"
}
# --- v5.2: search-ID aware pieces of the terminal summary ----------------------
# "yes" when this finding's pod (or, for a Service, one of its backing pods)
# appears in the search-ID trail.
fact_id_match() {
    # $1 category  $2 namespace  $3 resource
    local cat="$1" ns="$2" res="$3" row p
    [ -n "$SEARCH_VALUE" ] && [ -s "$REL_PODS_FILE" ] || return 0
    case "$cat" in
        NO_ENDPOINTS|PARTIAL_NOT_READY)
            row=$(awk -F'\t' -v ns="$ns" -v svc="$res" '$1==ns && $2==svc' "$REPORT_DIR/data/service-topology.tsv" 2>/dev/null | head -1)
            for p in $(echo "$row" | cut -f4,5 | grep -oE '\([^)]+\)' | tr -d '()'); do
                if grep -Fxq -- "$ns/$p" "$REL_PODS_FILE"; then echo yes; return 0; fi
            done ;;
        CONTROL_PLANE|API_LATENCY|ETCD_SLOW|DNS_ERROR|NODE_*|F5_BLOCKED) ;;
        *) if grep -Fxq -- "$ns/${res%%/*}" "$REL_PODS_FILE"; then echo yes; fi ;;
    esac
    return 0
}

render_chrono_table() { render_findings_table "$1" "$2" "$3" "" 1 "$TERMINAL_MAX_ROWS"; }

print_chrono_section() {
    # $1 color  $2 terminal width   (B / NC0 come from print_terminal_summary)
    # Default view: findings that involve the search ID + cluster/node-wide context (+ the root of every shown chain).
    #   SEARCH_TABLE_ALL=1 shows every finding in scope; SEARCH_TABLE_RELATED_ONLY=1 only those involving the ID.
    local color="$1" tw="$2" tmp n_all n_rel n_ctx n_shown n_hidden rel_only=0 other_lbl="cluster/node context or the first resource of a shown chain"
    tmp="$REPORT_DIR/data/terminal-rows-chrono.tsv"
    [ "$SEARCH_TABLE_RELATED_ONLY" = "1" ] && rel_only=1
    n_all=$(grep -c . "$TERM_ROWS_FILE")
    n_rel=$(awk -F'\t' '$11=="yes"' "$TERM_ROWS_FILE" | grep -c .)
    n_ctx=$(awk -F'\t' '$11!="yes" && ($1=="CLUSTER" || $1=="NODE")' "$TERM_ROWS_FILE" | grep -c .)
    if [ "$SEARCH_TABLE_ALL" = "1" ] || [ "$n_rel" -eq 0 ]; then
        sort -s -t$'\t' -k10,10 -k15,15n "$TERM_ROWS_FILE" > "$tmp"
    else
        awk -F'\t' -v rel_only="$rel_only" '
            NR == FNR { if ($11 == "yes" || (!rel_only && ($1 == "CLUSTER" || $1 == "NODE"))) { keep[$18] = 1; need[$16] = 1 } next }
            ($18 in keep) || ($18 in need)' "$TERM_ROWS_FILE" "$TERM_ROWS_FILE" | sort -s -t$'\t' -k10,10 -k15,15n > "$tmp"
    fi
    n_shown=$(grep -c . "$tmp"); n_hidden=$((n_all - n_shown))
    echo ""
    if [ "$n_rel" -eq 0 ]; then
        echo "${B}[ FAILURE SEQUENCE ]  earliest failure first -- ${n_shown} finding(s); none involve pods where the search ID appears (showing everything in scope)${NC0}"
    else
        [ "$SEARCH_TABLE_ALL" = "1" ] && other_lbl="other finding(s) in scope"
        echo "${B}[ FAILURE SEQUENCE ]  earliest failure first -- ${n_shown} finding(s): ${n_rel} involve the search ID, $((n_shown - n_rel)) ${other_lbl}${NC0}"
    fi
    [ "$n_hidden" -gt 0 ] && echo "  (${n_hidden} unrelated finding(s) hidden -- run with SEARCH_TABLE_ALL=1 to show everything)"
    render_chrono_table "$tmp" "$color" "$tw"
}

print_trace_block() {
    # $1 color  $2 terminal width
    local color="$1" tw="$2" head_n tail_n
    echo ""
    if [ "${TRACE_N:-0}" -eq 0 ]; then
        echo "${B}[ REQUEST TRACE ]  \"$SEARCH_VALUE\"${NC0}"
        if [ "${MATCHES:-0}" -eq 0 ]; then
            echo "  The ID was not found in any log in this scope/window. Try a longer window, ALL NAMESPACES, or re-check the ID and the time of the complaint."
        else
            echo "  Found in $MATCHES source(s), but not in timestamped log lines (e.g. only in describe/events), so no timeline could be built."
        fi
        return
    fi
    echo "${B}[ REQUEST TRACE ]  \"$SEARCH_VALUE\" -- ${TRACE_N} line(s) from ${TRACE_SRC_N} source(s), oldest first${NC0}"
    echo "   first seen : ${TRACE_FIRST_TS%Z}Z  in ${TRACE_FIRST_SRC}"
    if [ -n "$TRACE_ERR_TS" ]; then
        echo "   first error: ${TRACE_ERR_TS%Z}Z  in ${TRACE_ERR_SRC}   (${TRACE_ERR_N} error-like line(s) in total)"
    else
        echo "   no error-like line contains this ID (the failure may be in a pod that does not log it -- see the sequence above)"
    fi
    echo "   last seen  : ${TRACE_LAST_TS%Z}Z"
    head_n=$(( TRACE_TERMINAL_LINES * 6 / 10 )); tail_n=$(( TRACE_TERMINAL_LINES - head_n ))
    echo ""
    awk -F'\t' -v N="$TRACE_N" -v hn="$head_n" -v tn="$tail_n" -v tw="$tw" -v color="$color" '
        function trunc(s, n) { if (length(s) > n) return substr(s, 1, n - 3) "..."; return s }
        {
            if (N > hn + tn && NR > hn && NR <= N - tn) {
                if (!om) { printf "  ... %d more line(s) omitted -- full trace: search-trace.txt / HTML report ...\n", N - hn - tn; om = 1 }
                next
            }
            t = substr($1, 6, 5) " " substr($1, 12, 12)
            src = $2; if (length(src) > 34) src = ".." substr(src, length(src) - 31)
            msgw = tw - 2 - 18 - 1 - 1 - 2 - 34 - 2; if (msgw < 30) msgw = 30
            fl = " "; if ($3 == "!") fl = (color == 1 ? "\033[1;31m!\033[0m" : "!")
            printf "  %-18s %s %-34s  %s\n", t, fl, src, trunc($4, msgw)
        }' "$TRACE_SORTED"
    echo "   (! = error-like line, times are UTC)"
}
# END_V5_TERMINAL

###############################################################################
# 9. SUMMARY + HTML REPORT
###############################################################################

section "9. FINAL SUMMARY"

# --- Endpoint probe + F5 summary stats, computed before the HTML build ---
PROBE_TOTAL=0; PROBE_FAIL_COUNT=0; PROBE_OK_COUNT=0
if [ -s "$PROBE_TSV" ]; then
    PROBE_TOTAL=$(wc -l < "$PROBE_TSV" 2>/dev/null | tr -d ' ')
    PROBE_FAIL_COUNT=$(awk -F'\t' '$1=="FAIL"' "$PROBE_TSV" | wc -l | tr -d ' ')
    PROBE_OK_COUNT=$(awk -F'\t' '$1=="OK"' "$PROBE_TSV" | wc -l | tr -d ' ')
fi

if [ "$ENABLE_ENDPOINT_PROBE" != "1" ]; then
    PROBE_STATUS_TEXT="DISABLED"; PROBE_STATUS_CLASS="warn"
elif [ "$PROBE_FAIL_COUNT" -gt 0 ] 2>/dev/null; then
    PROBE_STATUS_TEXT="${PROBE_FAIL_COUNT} FAILED / ${PROBE_TOTAL} probed"; PROBE_STATUS_CLASS="err"
else
    PROBE_STATUS_TEXT="${PROBE_OK_COUNT}/${PROBE_TOTAL} OK"; PROBE_STATUS_CLASS="ok"
fi

if [ -z "$F5_LOG_SOURCE" ] && [ -z "$F5_LOG_HOOK" ]; then
    F5_STATUS_TEXT="NOT CONFIGURED"; F5_STATUS_CLASS="warn"
elif [ "$F5_MATCHES_COUNT" -gt 0 ] 2>/dev/null; then
    F5_STATUS_TEXT="${F5_MATCHES_COUNT} MATCH(ES)"; F5_STATUS_CLASS="err"
else
    F5_STATUS_TEXT="CONFIGURED / CLEAN"; F5_STATUS_CLASS="ok"
fi

# Redis badge color must reflect REDIS_STATUS_RANK, not just whether Redis
# was detected at all -- "NO READY ENDPOINTS" and "INVESTIGATION REQUIRED"
# are real problems and must not render as a green "ok" badge.
case "$REDIS_STATUS_RANK" in
    0) REDIS_STATUS_CLASS="warn" ;;   # NOT DETECTED
    1) REDIS_STATUS_CLASS="warn" ;;   # UNVERIFIED name-only match
    2) REDIS_STATUS_CLASS="ok"   ;;   # HEALTH EVIDENCE GOOD
    3) REDIS_STATUS_CLASS="err"  ;;   # INVESTIGATION REQUIRED
    4) REDIS_STATUS_CLASS="crit" ;;   # NO READY ENDPOINTS
    *) REDIS_STATUS_CLASS="warn" ;;
esac

# --- Precompute Performance / Slowness Indicators summary stats ---
if [ "$API_LATENCY_MS" -ge "$API_LATENCY_CRIT_MS" ] 2>/dev/null; then
    API_LATENCY_CLASS="crit"
elif [ "$API_LATENCY_MS" -ge "$API_LATENCY_WARN_MS" ] 2>/dev/null; then
    API_LATENCY_CLASS="warn"
else
    API_LATENCY_CLASS="ok"
fi

if [ "$SKIP_CLUSTER_LOGS" = "1" ]; then
    ETCD_STATUS_TEXT="SKIPPED (namespace-scoped scan)"; ETCD_STATUS_CLASS="warn"
elif [ -z "$ETCD_PODS" ]; then
    ETCD_STATUS_TEXT="NOT VISIBLE (managed cluster or non-standard etcd)"; ETCD_STATUS_CLASS="warn"
elif [ "$ETCD_MATCH_COUNT" -gt 0 ] 2>/dev/null; then
    ETCD_STATUS_TEXT="${ETCD_MATCH_COUNT} slow-op warning(s) across ${ETCD_POD_COUNT} pod(s)"; ETCD_STATUS_CLASS="err"
else
    ETCD_STATUS_TEXT="${ETCD_POD_COUNT} pod(s) checked, clean"; ETCD_STATUS_CLASS="ok"
fi

NODE_OVERSUB_COUNT=0
if [ -s "$REPORT_DIR/data/node-oversubscription.tsv" ]; then
    NODE_OVERSUB_COUNT=$(awk -F'\t' -v c="$NODE_CPU_WARN_PCT" -v m="$NODE_MEM_WARN_PCT" '$4>=c || $7>=m' "$REPORT_DIR/data/node-oversubscription.tsv" | wc -l | tr -d ' ')
fi
if [ "$NODE_OVERSUB_COUNT" -gt 0 ] 2>/dev/null; then
    NODE_OVERSUB_CLASS="err"; NODE_OVERSUB_TEXT="${NODE_OVERSUB_COUNT} node(s) tight on requests"
else
    NODE_OVERSUB_CLASS="ok"; NODE_OVERSUB_TEXT="within limits"
fi

HPA_ISSUE_COUNT=$(awk -F'\t' '$2=="HPA_INACTIVE" || $2=="HPA_MAXED"' "$FACTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
if [ "$HPA_ISSUE_COUNT" -gt 0 ] 2>/dev/null; then
    HPA_CLASS="err"; HPA_TEXT="${HPA_ISSUE_COUNT} HPA(s) inactive or maxed"
else
    HPA_CLASS="ok"; HPA_TEXT="no HPA issues found"
fi

POD_RES_ISSUE_COUNT=$(awk -F'\t' '$2=="POD_CPU_HIGH" || $2=="POD_MEM_HIGH"' "$FACTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
if [ "$POD_METRICS_AVAILABLE" != "1" ]; then
    POD_RES_CLASS="warn"; POD_RES_TEXT="metrics unavailable"
elif [ "$POD_RES_ISSUE_COUNT" -gt 0 ] 2>/dev/null; then
    POD_RES_CLASS="err"; POD_RES_TEXT="${POD_RES_ISSUE_COUNT} pod(s) near CPU/memory limit"
else
    POD_RES_CLASS="ok"; POD_RES_TEXT="no pods near their limits"
fi

cat >> "$REPORT" <<EOF

====================================================================
FINAL SUMMARY
====================================================================
Context        : $CURRENT_CONTEXT
Scan window    : last ${SCAN_MINUTES} min ($SCAN_START_HUMAN -> $SCAN_END_HUMAN)
Scope          : $(scope_description)
Search         : ${SEARCH_VALUE:-<full scan>}  (sources: $MATCHES, occurrences: $SEARCH_OCCURRENCES, resources: $SEARCH_RESOURCES, namespaces: $SEARCH_NAMESPACES)
Control plane  : $CONTROL_PLANE_STATUS
Redis          : $REDIS_STATUS
Critical       : $CRITICAL
Errors         : $ERRORS
Warnings       : $WARNINGS
Info           : $INFO
EOF

cat >> "$FIX_REPORT" <<'EOF'

====================================================================
GENERAL READ-ONLY TROUBLESHOOTING COMMANDS (none executed by scanner)
====================================================================
kubectl describe node <node>
kubectl describe pod <pod> -n <namespace>
kubectl logs <pod> -n <namespace> -c <container> --since=1h --timestamps
kubectl logs <pod> -n <namespace> -c <container> --previous --timestamps
kubectl describe svc <service> -n <namespace>
kubectl get endpoints <service> -n <namespace>
kubectl get endpointslices -n <namespace>
kubectl get networkpolicy -A
kubectl top nodes
kubectl top pods -A
kubectl get pvc -A
====================================================================
IMPORTANT: This scanner is diagnostic only. It never executes
remediation, restarts, scaling, or any state-changing command.
====================================================================
EOF

# --- Escape all dynamic values before they go into HTML. SEARCH_VALUE in
# particular is user-controlled input, so it must never be interpolated
# into HTML unescaped. ---
build_terminal_rows   # built once, before the HTML, so the report can include the fix plan
TERM_ROWS_BUILT=1
HTML_CONTEXT=$(printf '%s' "$CURRENT_CONTEXT" | html_escape)
HTML_SEARCH=$(printf '%s' "${SEARCH_VALUE:-Full scan}" | html_escape)
HTML_SCOPE=$(printf '%s' "$(scope_description)" | html_escape)

# --- Build a self-contained HTML report ---
{
cat <<HTML_HEAD
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>K8s Incident Report - $HTML_CONTEXT</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0f1115;color:#e6e6e6;margin:0;padding:24px;}
h1{margin-top:0} h2{border-bottom:1px solid #333;padding-bottom:6px;margin-top:32px}
.card{background:#1a1d24;border:1px solid #2a2d36;border-radius:8px;padding:16px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stat{font-size:28px;font-weight:bold} .label{color:#9aa0aa;font-size:12px;text-transform:uppercase}
.crit{color:#ff5c5c}.err{color:#ff8c42}.warn{color:#ffd166}.ok{color:#06d6a0}
pre{background:#0b0d11;border:1px solid #2a2d36;border-radius:6px;padding:12px;overflow-x:auto;white-space:pre-wrap;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;margin-left:8px}
.badge.crit{background:#3a1414}.badge.err{background:#3a2414}.badge.warn{background:#3a3414}.badge.ok{background:#123a2c}
table{font-size:13px} th{color:#9aa0aa;font-weight:600}
.timeline{position:relative;margin-left:12px;padding-left:20px;border-left:2px solid #2a2d36}
.tl-item{position:relative;margin-bottom:14px}
.tl-item::before{content:"";position:absolute;left:-26px;top:4px;width:10px;height:10px;border-radius:50%;background:#555}
.tl-item.crit::before{background:#ff5c5c} .tl-item.err::before{background:#ff8c42} .tl-item.warn::before{background:#ffd166}
.tl-time{color:#9aa0aa;font-size:12px;margin-right:8px}
</style></head><body>
<h1>Kubernetes Incident Diagnostic Report</h1>
<div class="card">
<div class="grid">
<div><div class="label">Context</div><div class="stat" style="font-size:16px">$HTML_CONTEXT</div></div>
<div><div class="label">Scan window</div><div class="stat" style="font-size:16px">${SCAN_MINUTES} min</div></div>
<div><div class="label">Scope</div><div class="stat" style="font-size:14px">$HTML_SCOPE</div></div>
<div><div class="label">From</div><div class="stat" style="font-size:14px">$SCAN_START_HUMAN</div></div>
<div><div class="label">To</div><div class="stat" style="font-size:14px">$SCAN_END_HUMAN</div></div>
<div><div class="label">Search</div><div class="stat" style="font-size:14px">$HTML_SEARCH</div></div>
<div><div class="label">Occurrences</div><div class="stat">$SEARCH_OCCURRENCES</div></div>
<div><div class="label">Resources hit</div><div class="stat" style="font-size:16px">$SEARCH_RESOURCES</div></div>
<div><div class="label">Namespaces hit</div><div class="stat" style="font-size:16px">$SEARCH_NAMESPACES</div></div>
</div>
</div>


<div class="card">
<div class="grid">
<div><div class="label">Critical</div><div class="stat crit">$CRITICAL</div></div>
<div><div class="label">Errors</div><div class="stat err">$ERRORS</div></div>
<div><div class="label">Warnings</div><div class="stat warn">$WARNINGS</div></div>
<div><div class="label">Info</div><div class="stat ok">$INFO</div></div>
</div>
</div>

<div class="card">
<h2 style="margin-top:0;border:none">Status Overview</h2>
<div class="grid">
<div>Control plane <span class="badge $([ "$CONTROL_PLANE_STATUS" = HEALTHY ] && echo ok || echo err)">$CONTROL_PLANE_STATUS</span></div>
<div>Redis <span class="badge $REDIS_STATUS_CLASS">$REDIS_STATUS</span></div>
<div>CoreDNS <span class="badge $([ "$COREDNS_STATE" = HEALTHY ] && echo ok || echo warn)">$COREDNS_STATE</span></div>
<div>Endpoint probes <span class="badge $PROBE_STATUS_CLASS">$PROBE_STATUS_TEXT</span></div>
<div>F5 / external LB <span class="badge $F5_STATUS_CLASS">$F5_STATUS_TEXT</span></div>
<div>API server latency <span class="badge $API_LATENCY_CLASS">${API_LATENCY_MS}ms</span></div>
</div>
</div>

<div class="card">
<h2 style="margin-top:0;border:none">Performance / Slowness Indicators</h2>
<p style="color:#9aa0aa;font-size:13px">Circumstantial evidence toward common INFRASTRUCTURE-side causes of "the app works but is slow". This cannot diagnose a slow application request path itself (a slow SQL query, a slow third-party call, slow app code) -- that needs distributed tracing or an APM this scanner has no access to. Treat everything here as "rule this in or out", not a confirmed diagnosis, especially the single-sample API latency reading below.</p>
<div class="grid">
<div>etcd <span class="badge $ETCD_STATUS_CLASS">$ETCD_STATUS_TEXT</span></div>
<div>Node requests vs. allocatable <span class="badge $NODE_OVERSUB_CLASS">$NODE_OVERSUB_TEXT</span></div>
<div>HPA (autoscaling) <span class="badge $HPA_CLASS">$HPA_TEXT</span></div>
<div>Pod CPU/memory vs. limits <span class="badge $POD_RES_CLASS">$POD_RES_TEXT</span></div>
<div>CPU throttling <span class="badge warn">NOT DETECTABLE (needs Prometheus)</span></div>
</div>
</div>
HTML_HEAD

if [ -n "$SEARCH_VALUE" ] && [ -s "$MATCH_REPORT" ]; then
    echo '<h2>Search Matches (with context)</h2>'
    echo '<p style="color:#9aa0aa;font-size:13px">Occurrences of your search term are highlighted <mark style="background:#ffd166;color:#0f1115;padding:0 2px;border-radius:2px;">like this</mark>.</p>'
    echo '<div class="card"><pre>'
    # Highlight is applied AFTER html-escaping, using awk's index()/substr()
    # for a purely literal (non-regex) substring replace -- the search term
    # can contain any characters (., *, [, etc.) without needing regex
    # escaping, consistent with how the search itself uses grep -F. The
    # term used for matching is escaped with the SAME html_escape() as the
    # surrounding text, so it correctly finds itself inside already-escaped
    # content (e.g. searching for "a&b" must match the "a&amp;b" that's
    # actually in the escaped stream).
    HTML_SEARCH_TERM=$(printf '%s' "$SEARCH_VALUE" | html_escape)
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$MATCH_REPORT" | \
        awk -v term="$HTML_SEARCH_TERM" '
        {
            line = $0
            tlen = length(term)
            if (tlen == 0) { print line; next }
            result = ""
            while ((idx = index(line, term)) > 0) {
                result = result substr(line, 1, idx-1) "<mark style=\"background:#ffd166;color:#0f1115;padding:0 2px;border-radius:2px;\">" substr(line, idx, tlen) "</mark>"
                line = substr(line, idx + tlen)
            }
            print result line
        }'
    echo '</pre></div>'
fi

if [ -n "$SEARCH_VALUE" ]; then
    echo "<h2>Request Trace for the search ID (chronological, oldest first)</h2>"
    if [ "${TRACE_N:-0}" -gt 0 ]; then
        echo "<p style=\"color:#9aa0aa;font-size:13px\">${TRACE_N} timestamped line(s) from ${TRACE_SRC_N} source(s) inside the scan scope, merged and sorted by time (UTC). Lines that look like errors are marked. Showing up to ${TRACE_HTML_MAX_ROWS} rows; the complete trace is in <code>search-trace.txt</code>.</p>"
        echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
        echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Time (UTC)</th><th style="padding:6px">Source (namespace/pod/container)</th><th style="padding:6px"></th><th style="padding:6px">Message</th></tr>'
        HL_TERM="$SEARCH_VALUE" awk -F'\t' -v maxrows="$TRACE_HTML_MAX_ROWS" '
            function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
            BEGIN { term = esc(ENVIRON["HL_TERM"]); tlen = length(term) }
            NR > maxrows { exit }
            {
                msg = esc($4); out = ""
                if (tlen > 0) {
                    while ((i = index(msg, term)) > 0) {
                        out = out substr(msg, 1, i - 1) "<mark style=\"background:#ffd166;color:#0f1115;padding:0 2px;border-radius:2px;\">" substr(msg, i, tlen) "</mark>"
                        msg = substr(msg, i + tlen)
                    }
                }
                msg = out msg
                flag = ($3 == "!") ? "<span class=\"badge err\">!</span>" : ""
                printf "<tr style=\"border-bottom:1px solid #2a2d36\"><td style=\"padding:6px;white-space:nowrap\">%s</td><td style=\"padding:6px\">%s</td><td style=\"padding:6px\">%s</td><td style=\"padding:6px;font-family:monospace;font-size:12px\">%s</td></tr>\n", esc($1), esc($2), flag, msg
            }' "$TRACE_SORTED"
        echo '</table></div>'
    else
        echo '<div class="card">No timestamped log line contained the search ID in this scope/window. Try a longer window or ALL NAMESPACES.</div>'
    fi
fi
if [ -s "$TERM_ROWS_FILE" ]; then
    echo "<h2>Suggested Fix Plan (commands are NOT run by this tool)</h2>"
    echo '<p style="color:#9aa0aa;font-size:13px">One card per <b>first resource of a failure chain</b> (the earliest finding that can explain the later ones). Fixing it is expected to clear the findings listed under "Fixing this first should also clear", so they get no commands of their own. Chains are inferred from start times and relationships, not proven: verify before running anything. These commands change the cluster; this scanner only prints them.</p>'
    fix_plan_html
fi

# --- Incident timeline: chronological view of everything flagged, built
# from the same warn/error/critical calls made throughout the scan. Times
# are scan-machine UTC (kubectl-reported event/log timestamps are shown
# per-item in the Error Catalog below; this view is for at-a-glance shape
# of the incident, not authoritative per-event time). ---
echo "<h2>Node Resource Requests vs. Allocatable</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Sum of declared container resource REQUESTS on each node, compared to that node'\''s allocatable capacity -- not live usage (see kubectl top for that). A node near 100% here has little scheduling headroom and is a plausible contributor to contention/slowness for everything on it, independent of what kubectl top shows at any given instant.</p>'
if [ -s "$REPORT_DIR/data/node-oversubscription.tsv" ]; then
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Node</th><th style="padding:6px">CPU requested</th><th style="padding:6px">CPU %</th><th style="padding:6px">Memory requested</th><th style="padding:6px">Memory %</th></tr>'
    while IFS=$'\t' read -r node reqcpu alloccpu cpupct reqmem allocmem mempct; do
        [ -z "$node" ] && continue
        NCLASS="ok"
        { [ "$cpupct" -ge "$NODE_CPU_WARN_PCT" ] 2>/dev/null || [ "$mempct" -ge "$NODE_MEM_WARN_PCT" ] 2>/dev/null; } && NCLASS="warn"
        { [ "$cpupct" -ge "$NODE_CPU_CRIT_PCT" ] 2>/dev/null || [ "$mempct" -ge "$NODE_MEM_CRIT_PCT" ] 2>/dev/null; } && NCLASS="err"
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\">$(echo "$node" | html_escape)</td>"
        echo "<td style=\"padding:6px\">${reqcpu}m / ${alloccpu}m</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $NCLASS\">${cpupct}%</span></td>"
        echo "<td style=\"padding:6px\">${reqmem}Mi / ${allocmem}Mi</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $NCLASS\">${mempct}%</span></td>"
        echo "</tr>"
    done < "$REPORT_DIR/data/node-oversubscription.tsv"
    echo '</table></div>'
else
    echo '<div class="card">No node resource data collected.</div>'
fi

echo "<h2>Pod Resource Usage (CPU / Memory)</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Live usage (from Metrics Server) for every pod covered by this scan, cross-referenced against that pod'\''s own declared requests and limits -- a raw usage number means little without knowing what the pod is actually allowed to use. "no limit" means the container has none set: it cannot be throttled/OOMKilled by its own limit, but it is also an unbounded stability risk for its node neighbors.</p>'
if [ "$POD_METRICS_AVAILABLE" != "1" ]; then
    echo '<div class="card">Metrics Server data unavailable for this run -- per-pod usage could not be collected.</div>'
elif [ -s "$REPORT_DIR/data/pod-resource-usage.tsv" ]; then
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Namespace / Pod</th><th style="padding:6px">CPU usage</th><th style="padding:6px">CPU request / limit</th><th style="padding:6px">CPU % of limit</th><th style="padding:6px">Mem usage</th><th style="padding:6px">Mem request / limit</th><th style="padding:6px">Mem % of limit</th></tr>'
    while IFS=$'\t' read -r ns pod usagecpu reqcpu limcpu cpupct usagemem reqmem limmem mempct; do
        [ -z "$pod" ] && continue
        CCLASS="ok"
        [ "$cpupct" != "n/a" ] && [ "$cpupct" -ge "$POD_CPU_WARN_PCT" ] 2>/dev/null && CCLASS="warn"
        [ "$cpupct" != "n/a" ] && [ "$cpupct" -ge "$POD_CPU_CRIT_PCT" ] 2>/dev/null && CCLASS="err"
        MCLASS="ok"
        [ "$mempct" != "n/a" ] && [ "$mempct" -ge "$POD_MEM_WARN_PCT" ] 2>/dev/null && MCLASS="warn"
        [ "$mempct" != "n/a" ] && [ "$mempct" -ge "$POD_MEM_CRIT_PCT" ] 2>/dev/null && MCLASS="err"
        LIMCPU_DISP="${limcpu}m"; [ "$limcpu" = "0" ] && LIMCPU_DISP="no limit"
        LIMMEM_DISP="${limmem}Mi"; [ "$limmem" = "0" ] && LIMMEM_DISP="no limit"
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\">$(echo "$ns/$pod" | html_escape)</td>"
        echo "<td style=\"padding:6px\">${usagecpu}m</td>"
        echo "<td style=\"padding:6px\">${reqcpu}m / $(echo "$LIMCPU_DISP" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $CCLASS\">$(echo "$cpupct" | html_escape)$([ "$cpupct" != "n/a" ] && echo "%")</span></td>"
        echo "<td style=\"padding:6px\">${usagemem}Mi</td>"
        echo "<td style=\"padding:6px\">${reqmem}Mi / $(echo "$LIMMEM_DISP" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $MCLASS\">$(echo "$mempct" | html_escape)$([ "$mempct" != "n/a" ] && echo "%")</span></td>"
        echo "</tr>"
    done < "$REPORT_DIR/data/pod-resource-usage.tsv"
    echo '</table></div>'
else
    echo '<div class="card">No pods with matching metrics data were found in this scan'\''s scope.</div>'
fi

echo "<h2>Service Topology -- Service &rarr; ClusterIP &rarr; Endpoints (Ready / Not-Ready)</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Built from EndpointSlices (falls back to legacy Endpoints if no slice exists). Each endpoint shows the backing pod name from targetRef, so you can see exactly which pod is or is not serving traffic for a service.</p>'
if [ -s "$REPORT_DIR/data/service-topology.tsv" ]; then
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Namespace</th><th style="padding:6px">Service</th><th style="padding:6px">ClusterIP</th><th style="padding:6px">Ready endpoints</th><th style="padding:6px">Not-Ready endpoints</th></tr>'
    while IFS='|' read -r ns svc cip ready notready; do
        [ -z "$svc" ] && continue
        RCLASS="ok"; [ -z "$ready" ] && RCLASS="crit"
        NCLASS=""; [ -n "$notready" ] && NCLASS="warn"
        if [ -n "$notready" ]; then
            NOTREADY_CELL="<span class=\"badge $NCLASS\">$(echo "$notready" | html_escape)</span>"
        else
            NOTREADY_CELL="--"
        fi
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\">$(echo "$ns" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$svc" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$cip" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $RCLASS\">$([ -n "$ready" ] && echo "$ready" | html_escape || echo NONE)</span></td>"
        echo "<td style=\"padding:6px\">$NOTREADY_CELL</td>"
        echo "</tr>"
    done < <(awk -F'\t' '{print $1"|"$2"|"$3"|"$4"|"$5}' "$REPORT_DIR/data/service-topology.tsv")
    echo '</table></div>'
else
    echo '<div class="card">No services found in scanned namespaces.</div>'
fi

echo "<h2>Active Endpoint Probes (opt-in live GET check)</h2>"
if [ "$ENABLE_ENDPOINT_PROBE" != "1" ]; then
    echo '<div class="card">Disabled for this run. Set <code>ENABLE_ENDPOINT_PROBE=1</code> (optionally with <code>PROBE_PATH</code>, <code>PROBE_TIMEOUT</code>, <code>PROBE_PORT_OVERRIDE</code>) to have the scanner issue a live GET -- via <code>kubectl exec</code> into each endpoint pod'\''s own container -- at <code>127.0.0.1:&lt;port&gt;PROBE_PATH</code>. This confirms the app actually answers, not just that Kubernetes reports it Ready. It proves local responsiveness only, not cross-node/NetworkPolicy reachability, and issues GET requests only -- no Kubernetes object is ever changed.</div>'
elif [ -s "$PROBE_TSV" ]; then
    echo '<p style="color:#9aa0aa;font-size:13px">Each row is one live GET issued from inside that pod'\''s own container to its own loopback address -- it proves the app process answers locally, not that other pods can reach it over the network.</p>'
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Result</th><th style="padding:6px">Namespace</th><th style="padding:6px">Pod/Container</th><th style="padding:6px">Port</th><th style="padding:6px">Service</th><th style="padding:6px">Endpoint state</th><th style="padding:6px">Detail</th></tr>'
    while IFS=$'\t' read -r st ns podc port svc label detail; do
        [ -z "$st" ] && continue
        CLASS="ok"
        case "$st" in FAIL) CLASS="crit" ;; WARN) CLASS="warn" ;; SKIP) CLASS="warn" ;; OK) CLASS="ok" ;; esac
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\"><span class=\"badge $CLASS\">$(echo "$st" | html_escape)</span></td>"
        echo "<td style=\"padding:6px\">$(echo "$ns" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$podc" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$port" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$svc" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$label" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$detail" | html_escape)</td>"
        echo "</tr>"
    done < "$PROBE_TSV"
    echo '</table></div>'
else
    echo '<div class="card">Enabled, but nothing was probed this run (no EndpointSlice-backed services with resolvable pods were found).</div>'
fi

echo "<h2>F5 / External Load Balancer</h2>"
if [ -z "$F5_LOG_SOURCE" ] && [ -z "$F5_LOG_HOOK" ]; then
    echo '<div class="card">Not configured for this run. Set <code>F5_LOG_SOURCE</code> (a file or directory of already-exported F5 logs) and/or <code>F5_LOG_HOOK</code> (an executable this scanner runs and reads stdout from) to fold F5/WAF findings -- blocked requests, pool member down, expired monitors, iRule drops, etc -- into this report. This scanner has no direct network access to any external appliance; it only reads what you point it at.</div>'
elif [ "$F5_MATCHES_COUNT" -gt 0 ] 2>/dev/null; then
    echo "<div class=\"card\"><p><b>$F5_MATCHES_COUNT matching line(s)</b> found against the configured F5_BLOCK_PATTERN. Full matched lines (redacted) are included in the Errors and Warnings section below, and the top match is folded into Root Cause Analysis and the Error Catalog as category <b>F5_BLOCKED</b>, owner <b>Network team</b>.</p></div>"
else
    echo '<div class="card">F5 log source configured and ingested -- no lines matched F5_BLOCK_PATTERN in this scan window.</div>'
fi

echo "<h2>Incident Timeline (scan order, UTC)</h2>"
if [ -s "$TIMELINE_FILE" ]; then
    echo '<div class="card"><div class="timeline">'
    sort -t$'\t' -k1,1 "$TIMELINE_FILE" | while IFS=$'\t' read -r ttime tsev tmsg; do
        [ -z "$ttime" ] && continue
        CLASS="warn"
        case "$tsev" in CRITICAL) CLASS="crit" ;; ERROR) CLASS="err" ;; WARNING) CLASS="warn" ;; esac
        echo "<div class=\"tl-item $CLASS\"><span class=\"tl-time\">$(echo "$ttime" | html_escape) UTC</span><span class=\"badge $CLASS\">$(echo "$tsev" | html_escape)</span> $(echo "$tmsg" | html_escape)</div>"
    done
    echo '</div></div>'
else
    echo '<div class="card">No warnings/errors were flagged during this scan window.</div>'
fi

echo "<h2>Root Cause Analysis ($ROOT_CAUSE_COUNT candidate(s))</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Evidence-based correlation across the resources touched during this scan. These are ranked "investigation leads" based on how upstream a finding typically is -- not proven causation. Always confirm with the suggested read-only commands before acting.</p>'
cat "$ROOTCAUSE_HTML"

echo "<h2>Error Catalog -- every finding ($CATALOG_COUNT), by pod &amp; timestamp</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Every individual error/warning detected in this scan window, with the exact pod/container, when it happened (log timestamp when available, else scan time marked with *; all times UTC), which team likely owns the fix, and the read-only command(s) to confirm before acting.</p>'
echo '<div class="card" style="overflow-x:auto">'
cat "$CATALOG_HTML"
echo '</div>'

ERROR_REPORT_LINES=$(wc -l < "$ERROR_REPORT" 2>/dev/null | tr -d ' ')
echo "<h2>Errors and Warnings -- full, untruncated (${ERROR_REPORT_LINES:-0} lines)</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">This is the complete content matched during the scan -- not an excerpt -- so nothing needed for debugging is cut. Also available as a plain text file at errors-and-warnings.txt inside the report directory.</p>'
echo '<div class="card"><pre>'
sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$ERROR_REPORT"
echo '</pre></div>'

echo '<h2>Recommended Investigation Commands (none executed)</h2><div class="card"><pre>'
sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$FIX_REPORT"
echo '</pre></div>'

cat <<HTML_TAIL
<h2>Safety Confirmation</h2>
<div class="card"><pre>
Kubernetes resources modified/created/deleted : NO
Pods restarted / nodes drained or cordoned    : NO
kubectl exec diagnostics enabled              : $([ "$ENABLE_POD_NETWORK_TEST" = "1" ] && echo YES || echo "NO (default off)")
Endpoint GET probes issued (opt-in)           : $([ "$ENABLE_ENDPOINT_PROBE" = "1" ] && echo "YES ($PROBE_TOTAL probe(s), GET only, no Kubernetes object changed)" || echo "NO (default off)")
F5/external log hook executed (opt-in)        : $([ -n "$F5_LOG_HOOK" ] && echo "YES ($F5_LOG_HOOK -- must be read-only by design of the hook itself; this scanner only reads its stdout)" || echo "NO")
Automatic remediation                         : NEVER
Public internet access required               : NO (still requires connectivity to the Kubernetes API server via kubeconfig)
Report written locally to                     : $REPORT_DIR/
</pre></div>

<h2>Coverage Limitations</h2>
<div class="card"><pre>
24h application/container logs   : available via --since=${SCAN_MINUTES}m
Kubernetes Events                : subject to cluster's event retention window
24h kubelet / kernel / node logs : NOT available via Kubernetes API alone (needs node/SSH or external logging)
Network blocking (NetworkPolicy) : evidence only (endpoints/logs), not packet-level proof
F5 / external LB / WAF           : NOT visible to this scanner directly -- only via the pluggable F5_LOG_SOURCE / F5_LOG_HOOK hook (opt-in, off unless configured)
Endpoint probe reachability      : when enabled, probes are loopback-only (inside the pod's own container) -- proves the app answers locally, not that other pods/nodes/NetworkPolicy allow reaching it
Snapshot timing                  : each check is a separate live kubectl call made a moment apart, not one atomic snapshot -- during a rapidly changing/flapping incident, two different checks can in principle reflect slightly different instants. When two sections disagree, trust the most specific, most recent evidence (a pod's own Ready condition, live logs) over aggregate summaries.
Root-cause grouping               : candidates are grouped by the resolved owning workload (Deployment/StatefulSet/Job, via ownerReferences), not just by namespace, so unrelated incidents in the same namespace are kept as separate candidates. Remaining edge cases: a bare pod with no owner reference is its own group; a Service with endpoints is grouped with the workload behind those endpoints; a Service with ZERO endpoints has no pod to resolve from and is intentionally left isolated (that absence is itself the finding). Two genuinely distinct workloads that happen to share an identical name across different resource kinds in the same namespace are a residual, unlikely edge case not disambiguated further.
"App works but is slow" diagnosis : this scanner can only rule common INFRASTRUCTURE-side causes in or out (control plane/etcd latency, node oversubscription, HPA capacity) -- it cannot diagnose a slow application request path (slow SQL, slow third-party call, slow app code), since Kubernetes exposes no per-request latency data and this scanner has no tracing/APM access. If all four Performance indicators are clean, the slowness is very likely inside the application or a dependency it calls, not the cluster.
API server latency                : a SINGLE-SAMPLE reading taken once during this run, not a trend -- a one-off network blip can false-positive and a real but intermittent slowdown can be missed entirely if it isn't happening at the exact moment this scan runs. Corroborate with the etcd check and repeat runs before treating as a confirmed root cause.
etcd health                       : best-effort and visible ONLY on kubeadm-style clusters running etcd as a static pod in kube-system. Managed clusters (EKS, GKE, AKS) run etcd outside Kubernetes entirely -- "not detected" there is expected, not a failed check.
Node oversubscription             : computed from declared resource REQUESTS, not live usage -- a node can show high % here while kubectl top shows it mostly idle (over-requested but under-used), or vice versa (under-requested but a burst of real usage). Both readings are meaningful; neither alone is the full picture.
CPU throttling                    : NOT detectable by this scanner. A container hitting its CPU limit and being throttled is invisible to both 'kubectl top' and the metrics-server API -- that data (container_cpu_cfs_throttled_*) only exists in cAdvisor/Prometheus, which this scanner does not query. This is the single most common invisible-to-this-tool cause of "slow but not crashing".
Pod CPU/memory usage              : a SINGLE-SAMPLE reading from Metrics Server at scan time, not a trend -- a pod that briefly spikes to 95% of its limit moments before or after this scan runs will not be caught, and a pod caught mid-spike may look worse than its typical behavior. High usage vs. limit is a leading indicator, not a confirmed diagnosis; corroborate with repeat runs, or run 'kubectl top pod --containers' several times a few seconds apart, or use a monitoring system for a real trend.
</pre></div>

</body></html>
HTML_TAIL
} > "$HTML_REPORT"

cat > "$REPORT_DIR/README.txt" <<EOF
Kubernetes Incident Diagnostic Report
Context   : $CURRENT_CONTEXT
Generated : $(timestamp)
Window    : last ${SCAN_MINUTES} min ($SCAN_START_HUMAN -> $SCAN_END_HUMAN)
Scope     : $(scope_description)
Search    : ${SEARCH_VALUE:-<full scan>}  (sources: $MATCHES, occurrences: $SEARCH_OCCURRENCES, resources: $SEARCH_RESOURCES, namespaces: $SEARCH_NAMESPACES)

Open index.html in a browser for the visual report (fully offline, no
network access needed).

Text reports:
  $REPORT
  $ERROR_REPORT
  $FIX_REPORT
  $MATCH_REPORT       (only populated if a search value was given)
  $ROOTCAUSE_REPORT   (ranked root-cause candidates with evidence + commands)
  $REPORT_DIR/terminal-summary.txt   (the per-layer table printed at the end of the scan)
  $REPORT_DIR/search-trace.txt   (chronological trace of the search ID; only with a search value)

Summary:
  Critical           : $CRITICAL
  Errors             : $ERRORS
  Warnings           : $WARNINGS
  Info               : $INFO
  Root-cause candidates : $ROOT_CAUSE_COUNT

Optional capabilities (all OFF unless explicitly enabled):
  Endpoint probes (ENABLE_ENDPOINT_PROBE=1) : $([ "$ENABLE_ENDPOINT_PROBE" = "1" ] && echo "ON -- $PROBE_TOTAL probed, $PROBE_FAIL_COUNT failed" || echo "off")
  F5/external LB hook (F5_LOG_SOURCE/F5_LOG_HOOK) : $([ -n "$F5_LOG_SOURCE$F5_LOG_HOOK" ] && echo "configured -- $F5_MATCHES_COUNT match(es)" || echo "not configured")

THIS SCAN IS READ-ONLY with respect to Kubernetes objects. Endpoint probes
(if enabled) issue GET requests only; the F5 hook (if configured) only
reads data you point it at. No Kubernetes resource was modified.
EOF

# v5.1: leave quiet mode, then show only the summary table and one pointer sentence.
if [ "$PROGRESS_FD_OPEN" = "1" ]; then
    progress 100 "Scan complete" s
    [ "$PROGRESS_TTY" = "1" ] && printf '\n' >&4
    exec 1>&4 2>&4 4>&-
    PROGRESS_FD_OPEN=0
fi
[ "${TERM_ROWS_BUILT:-0}" = "1" ] || build_terminal_rows
print_terminal_summary 0 > "$REPORT_DIR/terminal-summary.txt"
if [ -t 1 ]; then print_terminal_summary 1; else print_terminal_summary 0; fi
echo " No Kubernetes resource was modified by this scan."

if should_exit_after_run; then
    echo ""
    echo "Done (non-interactive or RUN_ONCE=1 run -- not returning to the prompt)."
    exit 0
fi

echo ""
echo "Returning to the first question... (Ctrl+C to exit)"

done