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

  parameters {
    string(name: 'INPUT_PATH', defaultValue: '.jenkins_work/run_20/input', description: 'Existing input file or directory on the Jenkins agent. Directory mode auto-picks newest .json/.csv/.xlsx/.xlsm file.')
    string(name: 'WORKFLOW_D_API_BASE', defaultValue: 'http://localhost:8088', description: 'Workflow D API base URL used by the frontend and this pipeline.')
    choice(name: 'ANALYSIS_MODE', choices: ['standard', 'urgent', 'ad_hoc'], description: 'Workflow D analysis mode.')
    string(name: 'SEVERITIES', defaultValue: 'CRITICAL,HIGH', description: 'Comma-separated severities for filtering findings.')
    string(name: 'LIMIT', defaultValue: '0', description: 'Maximum CVEs to analyze. Use 0 for no cap.')
    string(name: 'WORKERS', defaultValue: '4', description: 'Parallel CVE workers for analysis.')
    string(name: 'POLL_INTERVAL_SECONDS', defaultValue: '5', description: 'Polling interval for run status.')
    string(name: 'POLL_TIMEOUT_SECONDS', defaultValue: '7200', description: 'Maximum time to wait for completion.')
  }

  environment {
    PYTHON_BIN = 'python3'
    RUN_ID = ''
    VULNS_PATH = ''
  }

  stages {
    stage('Resolve Input File') {
      steps {
        script {
          env.VULNS_PATH = sh(
            returnStdout: true,
            script: '''#!/usr/bin/env bash
              set -euo pipefail

              if [[ ! "${LIMIT:-}" =~ ^[0-9]+$ ]]; then
                echo "ERROR: LIMIT must be a non-negative integer" >&2
                exit 1
              fi
              if [[ ! "${WORKERS:-}" =~ ^[0-9]+$ || "${WORKERS:-}" -le 0 ]]; then
                echo "ERROR: WORKERS must be a positive integer" >&2
                exit 1
              fi
              if [[ ! "${POLL_INTERVAL_SECONDS:-}" =~ ^[0-9]+$ || "${POLL_INTERVAL_SECONDS:-}" -le 0 ]]; then
                echo "ERROR: POLL_INTERVAL_SECONDS must be a positive integer" >&2
                exit 1
              fi
              if [[ ! "${POLL_TIMEOUT_SECONDS:-}" =~ ^[0-9]+$ || "${POLL_TIMEOUT_SECONDS:-}" -le 0 ]]; then
                echo "ERROR: POLL_TIMEOUT_SECONDS must be a positive integer" >&2
                exit 1
              fi

              CANDIDATE="$INPUT_PATH"
              if [[ "$CANDIDATE" != /* ]]; then
                CANDIDATE="$WORKSPACE/$CANDIDATE"
              fi

              if [[ ! -e "$CANDIDATE" ]]; then
                echo "ERROR: INPUT_PATH not found: $CANDIDATE" >&2
                exit 1
              fi

              if [[ -d "$CANDIDATE" ]]; then
                PICKED="$(
                  find "$CANDIDATE" -maxdepth 1 -type f -print0 \
                    | xargs -0 ls -1t 2>/dev/null \
                    | while IFS= read -r f; do
                        low="$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')"
                        case "$low" in
                          *.json|*.csv|*.xlsx|*.xlsm)
                            printf '%s\n' "$f"
                            break
                            ;;
                        esac
                      done
                )"
                if [[ -z "$PICKED" ]]; then
                  echo "ERROR: No supported input file in directory: $CANDIDATE" >&2
                  exit 1
                fi
                CANDIDATE="$PICKED"
              fi

              EXT_LOWER="$(echo "${CANDIDATE##*.}" | tr '[:upper:]' '[:lower:]')"
              case "$EXT_LOWER" in
                json|csv|xlsx|xlsm) ;;
                *)
                  echo "ERROR: INPUT_PATH file extension must be .json/.csv/.xlsx/.xlsm" >&2
                  exit 1
                  ;;
              esac

              if [[ ! -s "$CANDIDATE" ]]; then
                echo "ERROR: Input file is empty: $CANDIDATE" >&2
                exit 1
              fi

              printf '%s' "$CANDIDATE"
            '''
          ).trim()

          echo "Resolved input file: ${env.VULNS_PATH}"
        }
      }
    }

    stage('Start Workflow D Run') {
      steps {
        script {
          env.RUN_ID = sh(
            returnStdout: true,
            script: '''#!/usr/bin/env bash
              set -euo pipefail

              PAYLOAD="$($PYTHON_BIN - <<'PY'
import json
import os

sevs = [x.strip().upper() for x in os.environ.get("SEVERITIES", "CRITICAL,HIGH").split(",") if x.strip()]
payload = {
    "vulns_path": os.environ["VULNS_PATH"],
    "severities": sevs or ["CRITICAL", "HIGH"],
    "limit": int(os.environ.get("LIMIT", "0") or "0"),
    "mode": os.environ.get("ANALYSIS_MODE", "standard"),
    "workers": int(os.environ.get("WORKERS", "4") or "4"),
}
print(json.dumps(payload))
PY
              )"

              RESP="$(curl --fail --silent --show-error \
                -H 'Content-Type: application/json' \
                -X POST \
                --data "$PAYLOAD" \
                "$WORKFLOW_D_API_BASE/runs/start")"

              export RESP
              "$PYTHON_BIN" - <<'PY'
import json
import os

obj = json.loads(os.environ["RESP"])
rid = obj.get("run_id")
if not rid:
    raise SystemExit("run_id missing in /runs/start response")
print(rid)
PY
            '''
          ).trim()

          echo "Started run_id: ${env.RUN_ID}"
          echo "Frontend/API run URL: ${params.WORKFLOW_D_API_BASE}/runs/${env.RUN_ID}"
        }
      }
    }

    stage('Wait For Completion') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail

          start_ts="$(date +%s)"
          timeout_sec="$POLL_TIMEOUT_SECONDS"
          interval_sec="$POLL_INTERVAL_SECONDS"

          while true; do
            RESP="$(curl --silent --show-error "$WORKFLOW_D_API_BASE/runs/$RUN_ID")"

            export RESP
            STATE="$($PYTHON_BIN - <<'PY'
import json
import os

obj = json.loads(os.environ["RESP"])
status = obj.get("status") or {}
state = status.get("state")
if not state and obj.get("artifact"):
    state = "completed"
print(state or "")
PY
            )"

            ANALYSIS_ID="$($PYTHON_BIN - <<'PY'
import json
import os

obj = json.loads(os.environ["RESP"])
status = obj.get("status") or {}
print(status.get("analysis_id") or "")
PY
            )"

            echo "run_id=$RUN_ID state=${STATE:-unknown} analysis_id=${ANALYSIS_ID:-n/a}"

            if [[ "$STATE" == "ok" || "$STATE" == "completed" ]]; then
              echo "Run completed successfully."
              echo "View in frontend/API: $WORKFLOW_D_API_BASE/runs/$RUN_ID"
              break
            fi
            if [[ "$STATE" == "failed" || "$STATE" == "cancelled" || "$STATE" == "rejected" ]]; then
              echo "Run finished with state=$STATE" >&2
              exit 1
            fi

            now_ts="$(date +%s)"
            elapsed="$((now_ts - start_ts))"
            if (( elapsed >= timeout_sec )); then
              echo "Timed out waiting for run completion after ${elapsed}s" >&2
              exit 1
            fi

            sleep "$interval_sec"
          done
        '''
      }
    }
  }

  post {
    always {
      echo 'Pipeline finished without workspace cleanup, cloning, checkout, or local artifact staging.'
    }
    failure {
      echo 'Pipeline failed. Inspect Workflow D status via /runs/{run_id} on the configured API.'
    }
    success {
      echo 'Pipeline completed successfully. Results are available via Workflow D and visible in the frontend run views.'
    }
  }
}
