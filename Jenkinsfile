pipeline {
  agent {
    label 'bondi-u20'
  }

  options {
    timestamps()
    disableConcurrentBuilds()
    skipDefaultCheckout(true)
    timeout(time: 120, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  triggers {
    upstream(upstreamProjects: 'NIOS-CVE/NIOS-CVE-Analyser/NIOS-CVE-Build/NIOS-CVE-Repo', threshold: hudson.model.Result.SUCCESS)
  }

  parameters {
    string(name: 'REPOSITORY_URL', defaultValue: 'git@github.com:Infoblox-CTO/nios.git', description: 'Git URL of the repository to index/analyze on the backend VM.')
    string(name: 'BRANCH', defaultValue: '', description: 'Optional manual override. If empty, branch is auto-resolved from upstream Jenkins console and falls back to develop/9.2.')
    string(name: 'VULNERABILITIES_FILE_PATH', defaultValue: '', description: 'Optional manual override. If empty, auto-generated delta CSV from latest S3 upload is used.')
    string(name: 'EXISTING_INDEX_ID', defaultValue: '', description: 'Optional: existing index id on backend VM (if provided and found, /index/build is skipped).')
    string(name: 'API_BASE_URL', defaultValue: 'http://10.120.23.89:8088', description: 'Backend API base URL reachable from Jenkins.')
    string(name: 'AUTOMATION_CONFIG_PATH', defaultValue: 'configs/jenkins_automation.json', description: 'Config file for branch/S3 automation settings.')
    string(name: 'JENKINS_API_CREDENTIALS_ID', defaultValue: 'jenkins-api-user-token', description: 'Credentials ID (username/password or username/token) for upstream Jenkins API auth.')
    string(name: 'AWS_S3_CREDENTIALS_ID', defaultValue: 'aws-s3-access-key-secret', description: 'Credentials ID (username=AWS access key, password=AWS secret key) for S3 read/list access.')
    choice(name: 'ANALYSIS_MODE', choices: ['standard', 'urgent', 'ad_hoc'], description: 'Workflow D analysis mode.')
    string(name: 'SEVERITIES', defaultValue: 'CRITICAL,HIGH', description: 'Comma-separated severities for filtering findings.')
    string(name: 'LIMIT', defaultValue: '0', description: 'Maximum CVEs to analyze. Use 0 for no cap.')
    string(name: 'WORKERS', defaultValue: '4', description: 'Parallel CVE workers for /runs/start.')
    string(name: 'OUTPUT_DIR', defaultValue: '.jenkins_work/output', description: 'Where Jenkins stores downloaded XLSX and API logs.')
  }

  environment {
    RUN_ROOT = "${WORKSPACE}/.jenkins_work"
    LOG_DIR = "${WORKSPACE}/.jenkins_work/logs"
    PYTHON_BIN = 'python3'
  }

  stages {
    stage('Checkout Pipeline Repo') {
      steps {
        checkout(scm)
      }
    }

    stage('Validate Parameters') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          mkdir -p "$RUN_ROOT" "$LOG_DIR"

          trim_spaces() {
            local s="$1"
            s="${s#"${s%%[![:space:]]*}"}"
            s="${s%"${s##*[![:space:]]}"}"
            printf '%s' "$s"
          }

          sanitize_param() {
            local v
            v="$(trim_spaces "$1")"
            if [[ ${#v} -ge 2 ]]; then
              if [[ "${v:0:1}" == '"' && "${v: -1}" == '"' ]]; then
                v="${v:1:${#v}-2}"
              elif [[ "${v:0:1}" == "'" && "${v: -1}" == "'" ]]; then
                v="${v:1:${#v}-2}"
              fi
            fi
            printf '%s' "$(trim_spaces "$v")"
          }

          REPOSITORY_URL_CLEAN="$(sanitize_param "${REPOSITORY_URL:-git@github.com:Infoblox-CTO/nios.git}")"
          BRANCH_CLEAN="$(sanitize_param "${BRANCH:-}")"
          VULNERABILITIES_FILE_PATH_CLEAN="$(sanitize_param "${VULNERABILITIES_FILE_PATH:-}")"
          EXISTING_INDEX_ID_CLEAN="$(sanitize_param "${EXISTING_INDEX_ID:-}")"
          API_BASE_URL_CLEAN="$(sanitize_param "${API_BASE_URL:-}")"
          AUTOMATION_CONFIG_PATH_CLEAN="$(sanitize_param "${AUTOMATION_CONFIG_PATH:-configs/jenkins_automation.json}")"

          if [[ -z "$REPOSITORY_URL_CLEAN" ]]; then
            echo "ERROR: REPOSITORY_URL is required" >&2
            exit 1
          fi
          if [[ -n "$VULNERABILITIES_FILE_PATH_CLEAN" ]]; then
            if [[ "$VULNERABILITIES_FILE_PATH_CLEAN" != /* ]]; then
              echo "ERROR: VULNERABILITIES_FILE_PATH must be an absolute path when manually supplied" >&2
              exit 1
            fi
            EXT_LOWER="$(echo "${VULNERABILITIES_FILE_PATH_CLEAN##*.}" | tr '[:upper:]' '[:lower:]')"
            case "$EXT_LOWER" in
              json|csv|xlsx|xlsm) ;;
              *)
                echo "ERROR: VULNERABILITIES_FILE_PATH extension must be .json/.csv/.xlsx/.xlsm (got: $VULNERABILITIES_FILE_PATH_CLEAN)" >&2
                exit 1
                ;;
            esac
          fi

          if [[ -z "$API_BASE_URL_CLEAN" ]]; then
            echo "ERROR: API_BASE_URL is required" >&2
            exit 1
          fi
          if [[ ! "$API_BASE_URL_CLEAN" =~ ^https?:// ]]; then
            echo "ERROR: API_BASE_URL must start with http:// or https://" >&2
            exit 1
          fi

          if [[ ! "${LIMIT:-}" =~ ^[0-9]+$ ]]; then
            echo "ERROR: LIMIT must be a non-negative integer" >&2
            exit 1
          fi

          if [[ ! "${WORKERS:-}" =~ ^[0-9]+$ || "${WORKERS:-}" -le 0 ]]; then
            echo "ERROR: WORKERS must be a positive integer" >&2
            exit 1
          fi

          RUN_DIR="$RUN_ROOT/run-${BUILD_NUMBER}"
          API_BASE="${API_BASE_URL_CLEAN%/}"
          PROJECT_NAME="$(basename "$REPOSITORY_URL_CLEAN")"
          PROJECT_NAME="${PROJECT_NAME%.git}"
          PROJECT_NAME="$(printf '%s' "$PROJECT_NAME" | tr -cs 'A-Za-z0-9._-' '-')"
          PROJECT_NAME="${PROJECT_NAME#-}"
          PROJECT_NAME="${PROJECT_NAME%-}"

          if [[ -n "${OUTPUT_DIR:-}" ]]; then
            if [[ "${OUTPUT_DIR}" = /* ]]; then
              OUTPUT_DIR_ABS="$OUTPUT_DIR"
            else
              OUTPUT_DIR_ABS="$WORKSPACE/$OUTPUT_DIR"
            fi
          else
            OUTPUT_DIR_ABS="$RUN_DIR/output"
          fi

          mkdir -p "$RUN_DIR" "$OUTPUT_DIR_ABS" "$LOG_DIR"

          cat > "$RUN_ROOT/run.env" <<EOF
export RUN_DIR="$RUN_DIR"
export OUTPUT_DIR_ABS="$OUTPUT_DIR_ABS"
export API_BASE="$API_BASE"
export PROJECT_NAME="$PROJECT_NAME"
export REPOSITORY_URL_CLEAN="$REPOSITORY_URL_CLEAN"
export BRANCH_CLEAN="$BRANCH_CLEAN"
export VULNERABILITIES_FILE_PATH_CLEAN="$VULNERABILITIES_FILE_PATH_CLEAN"
export EXISTING_INDEX_ID_CLEAN="$EXISTING_INDEX_ID_CLEAN"
export AUTOMATION_CONFIG_PATH_CLEAN="$AUTOMATION_CONFIG_PATH_CLEAN"
EOF

          echo "RUN_DIR=$RUN_DIR"
          echo "OUTPUT_DIR_ABS=$OUTPUT_DIR_ABS"
          echo "API_BASE=$API_BASE"
          echo "PROJECT_NAME=$PROJECT_NAME"
          echo "BRANCH(initial)=$BRANCH_CLEAN"
          echo "VULNERABILITIES_FILE_PATH=$VULNERABILITIES_FILE_PATH_CLEAN"
          echo "EXISTING_INDEX_ID=$EXISTING_INDEX_ID_CLEAN"
          echo "AUTOMATION_CONFIG_PATH=$AUTOMATION_CONFIG_PATH_CLEAN"
        '''
      }
    }

    stage('Resolve Automated Inputs') {
      steps {
        script {
          withCredentials([
            usernamePassword(credentialsId: params.JENKINS_API_CREDENTIALS_ID, usernameVariable: 'JENKINS_API_USER', passwordVariable: 'JENKINS_API_TOKEN'),
            usernamePassword(credentialsId: params.AWS_S3_CREDENTIALS_ID, usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')
          ]) {
            sh '''#!/usr/bin/env bash
              set -euo pipefail
              source "$RUN_ROOT/run.env"

              if [[ ! -f "$AUTOMATION_CONFIG_PATH_CLEAN" ]]; then
                echo "ERROR: automation config not found: $AUTOMATION_CONFIG_PATH_CLEAN" >&2
                exit 1
              fi

              echo "Checking Python dependencies for automation resolver..."
              if ! "$PYTHON_BIN" -c 'import boto3, botocore' >/dev/null 2>&1; then
                echo "boto3/botocore not found. Installing in user site-packages..."
                "$PYTHON_BIN" -m pip install --user --upgrade boto3 botocore
              fi

              AUTO_ENV_FILE="$RUN_DIR/auto_inputs.env"

              "$PYTHON_BIN" scripts/resolve_automation_inputs.py \
                --config "$AUTOMATION_CONFIG_PATH_CLEAN" \
                --workspace "$WORKSPACE" \
                --run-root "$RUN_ROOT" \
                --output-env "$AUTO_ENV_FILE" \
                --repository-override "$REPOSITORY_URL_CLEAN" \
                --branch-override "$BRANCH_CLEAN" \
                --vulnerabilities-path-override "$VULNERABILITIES_FILE_PATH_CLEAN"

              source "$AUTO_ENV_FILE"

              if [[ -z "$AUTO_BRANCH" ]]; then
                echo "ERROR: branch resolution produced an empty value" >&2
                exit 1
              fi
              if [[ -z "$AUTO_VULNERABILITIES_FILE_PATH" ]]; then
                echo "ERROR: vulnerabilities path resolution produced an empty value" >&2
                exit 1
              fi
              if [[ "$AUTO_VULNERABILITIES_FILE_PATH" != /* ]]; then
                echo "ERROR: resolved vulnerabilities file path must be absolute: $AUTO_VULNERABILITIES_FILE_PATH" >&2
                exit 1
              fi

              EXT_LOWER="$(echo "${AUTO_VULNERABILITIES_FILE_PATH##*.}" | tr '[:upper:]' '[:lower:]')"
              case "$EXT_LOWER" in
                json|csv|xlsx|xlsm) ;;
                *)
                  echo "ERROR: resolved vulnerabilities file extension is invalid: $AUTO_VULNERABILITIES_FILE_PATH" >&2
                  exit 1
                  ;;
              esac

              cat >> "$RUN_ROOT/run.env" <<EOF
export REPOSITORY_URL_CLEAN="$AUTO_REPOSITORY_URL"
export BRANCH_CLEAN="$AUTO_BRANCH"
export VULNERABILITIES_FILE_PATH_CLEAN="$AUTO_VULNERABILITIES_FILE_PATH"
export AUTO_BRANCH_SOURCE="$AUTO_BRANCH_SOURCE"
export AUTO_VULNERABILITIES_FILE_PATH_SOURCE="$AUTO_VULNERABILITIES_FILE_PATH_SOURCE"
EOF

              echo "Resolved BRANCH=$AUTO_BRANCH (source=$AUTO_BRANCH_SOURCE)"
              echo "Resolved VULNERABILITIES_FILE_PATH=$AUTO_VULNERABILITIES_FILE_PATH (source=$AUTO_VULNERABILITIES_FILE_PATH_SOURCE)"
            '''
          }
        }
      }
    }

    stage('Check API Health') {
      options { timeout(time: 5, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"
          curl --fail --silent --show-error "$API_BASE/health" \
            | tee "$LOG_DIR/api_health.json" >/dev/null
          echo "Backend health endpoint reachable: $API_BASE/health"
        '''
      }
    }

    stage('Build Code Index (API)') {
      options { timeout(time: 240, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          curl --fail --silent --show-error "$API_BASE/indexes" -o "$RUN_DIR/indexes.json"

            # Reuse an existing VM index when possible: explicit id takes priority.
            # If explicit id is not found, fall back to project+branch matching.
          IDX_SELECT="$($PYTHON_BIN - <<PY
import json
import re
import sys
from pathlib import Path

target = "${EXISTING_INDEX_ID_CLEAN}".strip()
project = "${PROJECT_NAME}".strip()
branch = "${BRANCH_CLEAN}".strip()
repo_url = "${REPOSITORY_URL_CLEAN}".strip()
data = json.loads(Path("$RUN_DIR/indexes.json").read_text(encoding="utf-8"))
indexes = data.get("indexes") or []

picked = None
reason = ""

def norm(s: str) -> str:
  return re.sub(r"[^A-Za-z0-9._-]+", "-", (s or "")).strip("-").lower()

def idx_id(item: dict) -> str:
  return (item.get("id") or item.get("index_id") or "").strip()

def norm_git(u: str) -> str:
  s = (u or "").strip().lower()
  if not s:
    return ""
  s = re.sub(r"^(ssh://)", "", s)
  m = re.match(r"^(?:[^@]+@)?([^:/]+)[:/](.+)$", s)
  if m:
    host = m.group(1)
    path = m.group(2)
  else:
    m = re.match(r"^https?://([^/]+)/(.+)$", s)
    if m:
      host = m.group(1)
      path = m.group(2)
    else:
      return s[:-4] if s.endswith(".git") else s
  path = path.strip("/")
  if path.endswith(".git"):
    path = path[:-4]
  return f"{host}/{path}"

target_norm = norm(target)
project_norm = norm(project)
branch_norm = norm(branch)

if target:
  picked = next((i for i in indexes if idx_id(i) == target), None)
  if picked is None and target_norm:
    picked = next((i for i in indexes if norm(idx_id(i)) == target_norm), None)
  if picked is None:
    print(f"WARNING: Requested EXISTING_INDEX_ID not found on backend VM: {target}", file=sys.stderr)
    print("Known indexes from /indexes:", file=sys.stderr)
    for i in indexes:
      print(f"  - {idx_id(i)}", file=sys.stderr)
    reason = "provided_missing"
  else:
    reason = "provided"

if picked is None:
  # Primary auto-match: exact project+branch metadata.
  repo_norm = norm_git(repo_url)
  def repo_match(i: dict) -> bool:
    g = norm_git(i.get("git_url") or "")
    return (not repo_norm) or (g == repo_norm)

  matches = [
    i for i in indexes
    if (
      ((i.get("project") or project) == project) and
      ((i.get("branch") or "") == branch) and
      repo_match(i)
    )
  ]
  if not matches:
    # Fallback: normalized metadata match for branch naming differences.
    matches = [
      i for i in indexes
      if (
        (norm(i.get("project") or project) == project_norm) and
        (norm(i.get("branch") or "") == branch_norm) and
        repo_match(i)
      )
    ]
  if not matches and project_norm and branch_norm:
    # Final fallback: infer from index id pattern when branch metadata is absent/inconsistent.
    matches = [
      i for i in indexes
      if (
        norm(idx_id(i)).startswith(f"{project_norm}__") and
        branch_norm in norm(idx_id(i)) and
        repo_match(i)
      )
    ]
  if matches:
    matches.sort(key=lambda i: float(i.get("updated_at") or 0.0), reverse=True)
    picked = matches[0]
    reason = "auto"

if picked:
  print("true")
  print(idx_id(picked))
  print(picked.get("repo_root") or "")
  print(reason)
else:
  print("false")
  print("")
  print("")
  print("none")
  print(f"DEBUG: no index matched project={project!r} branch={branch!r} repo_norm={norm_git(repo_url)!r}", file=sys.stderr)
  print("DEBUG: known indexes on backend VM:", file=sys.stderr)
  for i in indexes:
    print(f"  id={idx_id(i)!r} project={i.get('project')!r} branch={i.get('branch')!r} git_url_norm={norm_git(i.get('git_url') or '')!r}", file=sys.stderr)
PY
)"

          REUSE_EXISTING="$(printf '%s\n' "$IDX_SELECT" | sed -n '1p')"
          INDEX_ID="$(printf '%s\n' "$IDX_SELECT" | sed -n '2p')"
          REPO_ROOT="$(printf '%s\n' "$IDX_SELECT" | sed -n '3p')"
          REUSE_REASON="$(printf '%s\n' "$IDX_SELECT" | sed -n '4p')"

            if [[ "$REUSE_EXISTING" == "true" ]]; then
            if [[ -z "$INDEX_ID" ]]; then
              echo "ERROR: existing index selection returned empty index id" >&2
              exit 1
            fi
            cat >> "$RUN_ROOT/run.env" <<EOF
export INDEX_ID="$INDEX_ID"
export REPO_ROOT="$REPO_ROOT"
EOF

            if [[ "$REUSE_REASON" == "provided" ]]; then
              echo "Using existing index from backend VM: INDEX_ID=$INDEX_ID"
              echo "Skipping /index/build because EXISTING_INDEX_ID was provided."
            else
              echo "Using existing index from backend VM: INDEX_ID=$INDEX_ID"
              echo "Skipping /index/build because project+branch index already exists."
            fi
            echo "REPO_ROOT=$REPO_ROOT"
            exit 0
          fi

          INDEX_BUILD_PAYLOAD="$RUN_DIR/index_build_payload.json"
          "$PYTHON_BIN" - <<PY
import json
import re

raw_url = "${REPOSITORY_URL_CLEAN}".strip()

def ssh_to_https(u: str) -> str:
    """Convert git@github.com:org/repo.git to https://github.com/org/repo.git"""
    m = re.match(r'^(?:[^@]+@)?([^:/]+):(.+)$', u)
    if m and not u.startswith('http'):
        host = m.group(1)
        path = m.group(2).lstrip('/')
        return f'https://{host}/{path}'
    return u

git_url = ssh_to_https(raw_url)
print(f"index/build git_url: {git_url}")

payload = {
        "git_url": git_url,
        "branch": "${BRANCH_CLEAN}",
    "mode": "full",
    "project": "${PROJECT_NAME}",
        "name": "${PROJECT_NAME} · ${BRANCH_CLEAN}",
}
with open("$INDEX_BUILD_PAYLOAD", "w", encoding="utf-8") as f:
    json.dump(payload, f)
PY

          INDEX_BUILD_BODY="$RUN_DIR/index_build_response.json"
          HTTP_CODE="$(curl --silent --show-error \
            -X POST "$API_BASE/index/build" \
            -H 'Content-Type: application/json' \
            --data-binary "@$INDEX_BUILD_PAYLOAD" \
            -o "$INDEX_BUILD_BODY" \
            -w '%{http_code}')"

          if [[ "$HTTP_CODE" != "202" && "$HTTP_CODE" != "200" ]]; then
            echo "ERROR: /index/build failed with HTTP $HTTP_CODE" >&2
            cat "$INDEX_BUILD_BODY" >&2 || true
            exit 1
          fi

          echo "Index build accepted. Polling /index/status..."
          INDEX_STATE=""
          for _ in $(seq 1 300); do
            curl --fail --silent --show-error "$API_BASE/index/status" \
              -o "$RUN_DIR/index_status.json"

            INDEX_STATE="$($PYTHON_BIN - <<PY
import json
from pathlib import Path
p = Path("$RUN_DIR/index_status.json")
d = json.loads(p.read_text(encoding="utf-8"))
print(((d.get("last") or {}).get("state") or "unknown").strip())
PY
)"

            echo "index_state=$INDEX_STATE"

            if [[ "$INDEX_STATE" == "ok" ]]; then
              break
            fi
            if [[ "$INDEX_STATE" == "failed" ]]; then
              echo "ERROR: Index build failed. See $RUN_DIR/index_status.json" >&2
              exit 1
            fi
            sleep 10
          done

          if [[ "$INDEX_STATE" != "ok" ]]; then
            echo "ERROR: Timed out waiting for /index/status to reach ok" >&2
            exit 1
          fi

          IDX_AND_ROOT="$($PYTHON_BIN - <<PY
import json
import re
from pathlib import Path

def norm(s: str) -> str:
  return re.sub(r"[^A-Za-z0-9._-]+", "-", (s or "")).strip("-").lower()

def idx_id(item: dict) -> str:
  return (item.get("id") or item.get("index_id") or "").strip()

def norm_git(u: str) -> str:
  s = (u or "").strip().lower()
  if not s:
    return ""
  s = re.sub(r"^(ssh://)", "", s)
  m = re.match(r"^(?:[^@]+@)?([^:/]+)[:/](.+)$", s)
  if m:
    host = m.group(1)
    path = m.group(2)
  else:
    m = re.match(r"^https?://([^/]+)/(.+)$", s)
    if m:
      host = m.group(1)
      path = m.group(2)
    else:
      return s[:-4] if s.endswith(".git") else s
  path = path.strip("/")
  if path.endswith(".git"):
    path = path[:-4]
  return f"{host}/{path}"

data = json.loads(Path("$RUN_DIR/indexes.json").read_text(encoding="utf-8"))
indexes = data.get("indexes") or []
project = "${PROJECT_NAME}"
branch = "${BRANCH_CLEAN}"
repo_norm = norm_git("${REPOSITORY_URL_CLEAN}")

def repo_match(i: dict) -> bool:
  g = norm_git(i.get("git_url") or "")
  return (not repo_norm) or (g == repo_norm)

matches = [
  i for i in indexes
  if (
    ((i.get("project") or project) == project) and
    ((i.get("branch") or "") == branch) and
    repo_match(i)
  )
]
if not matches:
  project_norm = norm(project)
  branch_norm = norm(branch)
  matches = [
    i for i in indexes
    if (
      (norm(i.get("project") or project) == project_norm) and
      (norm(i.get("branch") or "") == branch_norm) and
      repo_match(i)
    )
  ]
if not matches:
    raise SystemExit("No index found for requested project/branch after build")
matches.sort(key=lambda i: float(i.get("updated_at") or 0.0), reverse=True)
picked = matches[0]
print(idx_id(picked) + "\t" + (picked.get("repo_root") or ""))
PY
)"

          INDEX_ID="${IDX_AND_ROOT%%$'\t'*}"
          REPO_ROOT="${IDX_AND_ROOT#*$'\t'}"

          if [[ -z "$INDEX_ID" ]]; then
            echo "ERROR: Could not determine INDEX_ID from /indexes" >&2
            exit 1
          fi

          cat >> "$RUN_ROOT/run.env" <<EOF
export INDEX_ID="$INDEX_ID"
export REPO_ROOT="$REPO_ROOT"
EOF

          echo "INDEX_ID=$INDEX_ID"
          echo "REPO_ROOT=$REPO_ROOT"
        '''
      }
    }

    stage('Run Vulnerability Analysis (API)') {
      options { timeout(time: 240, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          RUN_START_PAYLOAD="$RUN_DIR/run_start_payload.json"
          "$PYTHON_BIN" - <<PY
import json
severities = [s.strip() for s in "${SEVERITIES}".split(",") if s.strip()]
payload = {
  "vulns_path": "${VULNERABILITIES_FILE_PATH_CLEAN}",
    "severities": severities or ["CRITICAL", "HIGH"],
    "limit": int("${LIMIT}"),
    "mode": "${ANALYSIS_MODE}",
    "workers": int("${WORKERS}"),
    "index_id": "${INDEX_ID}",
}
if "${REPO_ROOT}".strip():
    payload["repo_root"] = "${REPO_ROOT}"
with open("$RUN_START_PAYLOAD", "w", encoding="utf-8") as f:
    json.dump(payload, f)
PY

          RUN_START_BODY="$RUN_DIR/run_start_response.json"
          HTTP_CODE="$(curl --silent --show-error \
            -X POST "$API_BASE/runs/start" \
            -H 'Content-Type: application/json' \
            --data-binary "@$RUN_START_PAYLOAD" \
            -o "$RUN_START_BODY" \
            -w '%{http_code}')"

          if [[ "$HTTP_CODE" != "202" && "$HTTP_CODE" != "200" ]]; then
            echo "ERROR: /runs/start failed with HTTP $HTTP_CODE" >&2
            cat "$RUN_START_BODY" >&2 || true
            exit 1
          fi

          RUN_ID="$($PYTHON_BIN - <<PY
import json
from pathlib import Path
data = json.loads(Path("$RUN_START_BODY").read_text(encoding="utf-8"))
print((data.get("run_id") or "").strip())
PY
)"

          if [[ -z "$RUN_ID" ]]; then
            echo "ERROR: run_id missing in /runs/start response" >&2
            exit 1
          fi

          cat >> "$RUN_ROOT/run.env" <<EOF
export RUN_ID="$RUN_ID"
EOF

          echo "RUN_ID=$RUN_ID"
          echo "Polling /runs/$RUN_ID ..."

          RUN_STATE=""
          for _ in $(seq 1 360); do
            curl --fail --silent --show-error "$API_BASE/runs/$RUN_ID" \
              -o "$RUN_DIR/run_status.json"

            RUN_STATE="$($PYTHON_BIN - <<PY
import json
from pathlib import Path
d = json.loads(Path("$RUN_DIR/run_status.json").read_text(encoding="utf-8"))
status = d.get("status") or {}
print((status.get("state") or "unknown").strip())
PY
)"

            echo "run_state=$RUN_STATE"

            if [[ "$RUN_STATE" == "ok" || "$RUN_STATE" == "failed" || "$RUN_STATE" == "cancelled" ]]; then
              break
            fi
            sleep 15
          done

          if [[ "$RUN_STATE" != "ok" ]]; then
            echo "ERROR: analysis run ended with state=$RUN_STATE" >&2
            exit 1
          fi
        '''
      }
    }

    stage('Download Excel Report (API)') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          XLSX_PATH="$OUTPUT_DIR_ABS/${RUN_ID}.xlsx"

          HTTP_CODE="$(curl --silent --show-error \
            "$API_BASE/runs/$RUN_ID/report.xlsx" \
            -o "$XLSX_PATH" \
            -w '%{http_code}')"

          if [[ "$HTTP_CODE" != "200" ]]; then
            echo "ERROR: /runs/$RUN_ID/report.xlsx failed with HTTP $HTTP_CODE" >&2
            if [[ -f "$XLSX_PATH" ]]; then
              cat "$XLSX_PATH" >&2 || true
              rm -f "$XLSX_PATH"
            fi
            exit 1
          fi

          if [[ ! -s "$XLSX_PATH" ]]; then
            echo "ERROR: Downloaded XLSX is empty: $XLSX_PATH" >&2
            exit 1
          fi

          cat >> "$RUN_ROOT/run.env" <<EOF
export XLSX_PATH="$XLSX_PATH"
EOF

          echo "RUN_ID=$RUN_ID"
          echo "XLSX_PATH=$XLSX_PATH"
        '''
      }
    }

    stage('Summarize Results') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"
          "$PYTHON_BIN" - <<PY
import json
from pathlib import Path

run_status = json.loads(Path("$RUN_DIR/run_status.json").read_text(encoding="utf-8"))
status = run_status.get("status") or {}
artifact = run_status.get("artifact") or {}
results = artifact.get("results") or []

print("Final analysis summary")
print(f"run_id: {'$RUN_ID'}")
print(f"analysis_id: {status.get('analysis_id')}")
print(f"state: {status.get('state')}")
print(f"results: {len(results)}")
print(f"xlsx: {'$XLSX_PATH'}")
PY
        '''
      }
    }
  }

  post {
    always {
      script {
        if (fileExists('.jenkins_work')) {
          archiveArtifacts artifacts: '.jenkins_work/**', fingerprint: true, onlyIfSuccessful: false
        } else {
          echo 'No .jenkins_work directory found; skipping artifact archive.'
        }
      }
    }
    failure {
      echo 'Pipeline failed. Inspect archived API payloads/responses and logs under .jenkins_work/.'
    }
    success {
      echo 'Pipeline completed successfully via backend API endpoints. XLSX and API traces are archived under .jenkins_work/**.'
    }
  }
}