pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    timeout(time: 120, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  parameters {
    string(
      name: 'SBOM_UPLOAD_URL',
      defaultValue: '',
      description: 'Required: backend-generated SBOM URL for Jenkins handoff.'
    )
  }

  environment {
    RUN_ROOT = "${WORKSPACE}/.jenkins_work"
    LOG_DIR = "${WORKSPACE}/.jenkins_work/logs"
    PYTHON_BIN = 'python3'
    DTRACK_URL = 'http://localhost:8081'
    DTRACK_CREDENTIALS_ID = 'dtrack-api-key'
    WAIT_MINUTES = '30'
    SECOND_SERVICE_API_URL = 'http://10.120.23.89:8088'
    WORKFLOW_MODE = 'standard'
    SEVERITIES = 'CRITICAL,HIGH'
  }

  stages {
    stage('Validate Parameters') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          mkdir -p "$RUN_ROOT" "$LOG_DIR"

          if [[ -z "${WAIT_MINUTES:-}" || ! "$WAIT_MINUTES" =~ ^[0-9]+$ || "$WAIT_MINUTES" -le 0 ]]; then
            echo "ERROR: WAIT_MINUTES must be a positive integer" >&2
            exit 1
          fi
          if [[ -z "${SBOM_UPLOAD_URL:-}" ]]; then
            echo "ERROR: SBOM_UPLOAD_URL is required" >&2
            exit 1
          fi
          if [[ -z "${DTRACK_URL:-}" ]]; then
            echo "ERROR: DTRACK_URL is required" >&2
            exit 1
          fi
          if [[ -z "${SECOND_SERVICE_API_URL:-}" ]]; then
            echo "ERROR: SECOND_SERVICE_API_URL is required" >&2
            exit 1
          fi
          if [[ -z "${DTRACK_CREDENTIALS_ID:-}" ]]; then
            echo "ERROR: DTRACK_CREDENTIALS_ID is required" >&2
            exit 1
          fi

          RUN_DIR="$RUN_ROOT/run-${BUILD_NUMBER}"
          SBOM_LOCAL_PATH="$RUN_DIR/input/sbom.yaml"
          FINDINGS_JSON="$RUN_DIR/output/findings.json"
          NORMALIZED_JSON="$RUN_DIR/output/normalized_payload.json"
          FINAL_ANALYSIS_JSON="$RUN_DIR/output/final_analysis.json"

          mkdir -p "$RUN_DIR/input" "$RUN_DIR/output" "$LOG_DIR"

          cat > "$RUN_ROOT/run.env" <<EOF
export RUN_DIR="$RUN_DIR"
export SBOM_LOCAL_PATH="$SBOM_LOCAL_PATH"
export FINDINGS_JSON="$FINDINGS_JSON"
export NORMALIZED_JSON="$NORMALIZED_JSON"
export FINAL_ANALYSIS_JSON="$FINAL_ANALYSIS_JSON"
EOF

          echo "RUN_DIR=$RUN_DIR"
          echo "SBOM_LOCAL_PATH=$SBOM_LOCAL_PATH"
        '''
      }
    }

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Acquire SBOM') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          echo "Downloading uploaded SBOM from backend handoff URL"
          curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
            "$SBOM_UPLOAD_URL" -o "$SBOM_LOCAL_PATH"

          if [[ ! -s "$SBOM_LOCAL_PATH" ]]; then
            echo "ERROR: SBOM file is empty or missing: $SBOM_LOCAL_PATH" >&2
            exit 1
          fi
          echo "SBOM ready: $SBOM_LOCAL_PATH"
        '''
      }
    }

    stage('Install Python Dependencies') {
      options { timeout(time: 20, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"
          "$PYTHON_BIN" -m pip install --upgrade pip
          "$PYTHON_BIN" -m pip install -r requirements.txt
        '''
      }
    }

    stage('Run Dependency-Track Ingestion') {
      options { timeout(time: 80, unit: 'MINUTES') }
      steps {
        withCredentials([
          string(credentialsId: env.DTRACK_CREDENTIALS_ID, variable: 'DTRACK_API_KEY')
        ]) {
          sh '''#!/usr/bin/env bash
            set -euo pipefail
            source "$RUN_ROOT/run.env"

            "$PYTHON_BIN" Dependency_Track_Final_2.py \
              --sbom-file "$SBOM_LOCAL_PATH" \
              --dtrack-url "$DTRACK_URL" \
              --dtrack-api-key "$DTRACK_API_KEY" \
              --wait-minutes "$WAIT_MINUTES" \
              --output-findings-json "$FINDINGS_JSON" \
              2>&1 | tee "$LOG_DIR/dependency_track.log"
          '''
        }
      }
    }

    stage('Validate Findings JSON') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"
          "$PYTHON_BIN" - <<PY
import json
from pathlib import Path

p = Path("$FINDINGS_JSON")
if not p.exists() or p.stat().st_size == 0:
    raise SystemExit(f"Findings JSON missing or empty: {p}")

obj = json.loads(p.read_text(encoding="utf-8"))
if not isinstance(obj, dict):
    raise SystemExit("Findings JSON must be an object")

findings = obj.get("findings")
if not isinstance(findings, list) or not findings:
    raise SystemExit("Findings JSON must contain a non-empty 'findings' array")

for i, row in enumerate(findings[:3]):
    if not isinstance(row, dict):
        raise SystemExit(f"findings[{i}] is not an object")
    if "vulnerability" not in row or "component" not in row:
        raise SystemExit(f"findings[{i}] missing vulnerability/component keys")

print(f"Validated findings JSON with {len(findings)} entries")
PY
        '''
      }
    }

    stage('Submit Findings To Workflow D') {
      options { timeout(time: 30, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          "$PYTHON_BIN" scripts/submit_findings_to_workflow_d.py \
            --vulns "$FINDINGS_JSON" \
            --api "$SECOND_SERVICE_API_URL" \
            --mode "$WORKFLOW_MODE" \
            --severities "$SEVERITIES" \
            --out "$FINAL_ANALYSIS_JSON" \
            --normalized-out "$NORMALIZED_JSON" \
            2>&1 | tee "$LOG_DIR/workflow_submit.log"
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

p = Path("$FINAL_ANALYSIS_JSON")
if not p.exists():
    raise SystemExit(f"Final analysis output missing: {p}")
obj = json.loads(p.read_text(encoding="utf-8"))
analysis_id = obj.get("analysis_id")
results = obj.get("results") or []
print("Final analysis summary")
print(f"analysis_id: {analysis_id}")
print(f"results: {len(results)}")
PY
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: '.jenkins_work/**', fingerprint: true, onlyIfSuccessful: false
    }
    failure {
      echo 'Pipeline failed. Inspect archived logs under .jenkins_work/logs/.'
    }
    success {
      echo 'Pipeline completed successfully. Final output is archived under .jenkins_work/**.'
    }
  }
}
