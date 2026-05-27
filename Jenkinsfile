pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    timeout(time: 120, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  parameters {
    choice(
      name: 'SBOM_SOURCE',
      choices: ['UPLOAD_URL', 'HTTP_URL', 'WORKSPACE_PATH'],
      description: 'How Jenkins should load the SBOM file.'
    )
    string(
      name: 'SBOM_UPLOAD_URL',
      defaultValue: '',
      description: 'Backend-generated SBOM URL for Jenkins handoff (preferred).'
    )
    password(
      name: 'SBOM_UPLOAD_TOKEN',
      defaultValue: '',
      description: 'Optional bearer token if your upload endpoint requires Authorization header.'
    )
    string(
      name: 'SBOM_HTTP_URL',
      defaultValue: '',
      description: 'Remote SBOM URL when SBOM_SOURCE=HTTP_URL.'
    )
    string(
      name: 'SBOM_WORKSPACE_PATH',
      defaultValue: '',
      description: 'Existing file path on Jenkins node when SBOM_SOURCE=WORKSPACE_PATH.'
    )
    string(
      name: 'SBOM_FILENAME',
      defaultValue: 'sbom.yaml',
      description: 'Filename used in workspace for downloaded/copied SBOM.'
    )

    string(
      name: 'DTRACK_URL',
      defaultValue: 'http://10.120.23.60:8081',
      description: 'Dependency-Track base URL.'
    )
    string(
      name: 'DTRACK_API_KEY_CREDENTIALS_ID',
      defaultValue: 'dtrack-api-key',
      description: 'Jenkins secret-text credentials ID containing Dependency-Track API key.'
    )
    booleanParam(
      name: 'DTRACK_VERIFY_SSL',
      defaultValue: false,
      description: 'Enable SSL verification for Dependency-Track requests.'
    )
    string(
      name: 'WAIT_MINUTES',
      defaultValue: '30',
      description: 'Minutes to wait for DT enrichment before findings export.'
    )

    string(
      name: 'SECOND_SERVICE_API_URL',
      defaultValue: 'http://10.120.23.89:8088',
      description: 'Workflow D backend API base URL (not the frontend :5173 URL).'
    )
    string(
      name: 'ANALYSIS_REPO_ROOT',
      defaultValue: '',
      description: 'Optional repo root used by Workflow D context retrieval.'
    )
    choice(
      name: 'WORKFLOW_MODE',
      choices: ['standard', 'urgent', 'ad_hoc'],
      description: 'Workflow D run mode used for /analyze.'
    )
    string(
      name: 'SEVERITIES',
      defaultValue: 'CRITICAL,HIGH',
      description: 'Comma-separated severities to analyze.'
    )
    string(
      name: 'LIMIT',
      defaultValue: '',
      description: 'Optional max number of CVEs to analyze.'
    )

    string(
      name: 'PYTHON_BIN',
      defaultValue: 'python3',
      description: 'Python executable on Jenkins agent.'
    )
    string(
      name: 'OUTPUT_SUBDIR',
      defaultValue: '',
      description: 'Optional run folder name under .jenkins_work; blank => build-specific default.'
    )
  }

  environment {
    RUN_ROOT = "${WORKSPACE}/.jenkins_work"
    LOG_DIR = "${WORKSPACE}/.jenkins_work/logs"
  }

  stages {
    stage('Validate Parameters') {
      steps {
        script {
          def waitInt = params.WAIT_MINUTES?.trim() ? params.WAIT_MINUTES.toInteger() : 0
          if (waitInt <= 0) {
            error('WAIT_MINUTES must be a positive integer.')
          }
          if (!params.DTRACK_URL?.trim()) {
            error('DTRACK_URL is required.')
          }
          if (!params.SECOND_SERVICE_API_URL?.trim()) {
            error('SECOND_SERVICE_API_URL is required.')
          }
          if (!params.DTRACK_API_KEY_CREDENTIALS_ID?.trim()) {
            error('DTRACK_API_KEY_CREDENTIALS_ID is required.')
          }
          if (params.SBOM_SOURCE == 'UPLOAD_URL' && !params.SBOM_UPLOAD_URL?.trim()) {
            error('SBOM_UPLOAD_URL is required when SBOM_SOURCE=UPLOAD_URL.')
          }
          if (params.SBOM_SOURCE == 'HTTP_URL' && !params.SBOM_HTTP_URL?.trim()) {
            error('SBOM_HTTP_URL is required when SBOM_SOURCE=HTTP_URL.')
          }
          if (params.SBOM_SOURCE == 'WORKSPACE_PATH' && !params.SBOM_WORKSPACE_PATH?.trim()) {
            error('SBOM_WORKSPACE_PATH is required when SBOM_SOURCE=WORKSPACE_PATH.')
          }

          def outDir = params.OUTPUT_SUBDIR?.trim() ? params.OUTPUT_SUBDIR.trim() : "run-${env.BUILD_NUMBER}"
          env.RUN_DIR = "${env.RUN_ROOT}/${outDir}"
          env.SBOM_LOCAL_PATH = "${env.RUN_DIR}/input/${params.SBOM_FILENAME ?: 'sbom.yaml'}"
          env.FINDINGS_JSON = "${env.RUN_DIR}/output/findings.json"
          env.NORMALIZED_JSON = "${env.RUN_DIR}/output/normalized_payload.json"
          env.FINAL_ANALYSIS_JSON = "${env.RUN_DIR}/output/final_analysis.json"
        }
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          mkdir -p "$RUN_DIR/input" "$RUN_DIR/output" "$LOG_DIR"
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

          case "$SBOM_SOURCE" in
            UPLOAD_URL)
              echo "Downloading uploaded SBOM from backend handoff URL"
              if [[ -n "$SBOM_UPLOAD_TOKEN" ]]; then
                curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
                  -H "Authorization: Bearer $SBOM_UPLOAD_TOKEN" \
                  "$SBOM_UPLOAD_URL" -o "$SBOM_LOCAL_PATH"
              else
                curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
                  "$SBOM_UPLOAD_URL" -o "$SBOM_LOCAL_PATH"
              fi
              ;;
            HTTP_URL)
              echo "Downloading SBOM from HTTP URL"
              curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
                "$SBOM_HTTP_URL" -o "$SBOM_LOCAL_PATH"
              ;;
            WORKSPACE_PATH)
              echo "Copying SBOM from agent path"
              if [[ ! -f "$SBOM_WORKSPACE_PATH" ]]; then
                echo "ERROR: SBOM_WORKSPACE_PATH does not exist: $SBOM_WORKSPACE_PATH" >&2
                exit 1
              fi
              cp "$SBOM_WORKSPACE_PATH" "$SBOM_LOCAL_PATH"
              ;;
            *)
              echo "ERROR: unsupported SBOM_SOURCE=$SBOM_SOURCE" >&2
              exit 1
              ;;
          esac

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
          "$PYTHON_BIN" -m pip install --upgrade pip
          "$PYTHON_BIN" -m pip install -r requirements.txt
        '''
      }
    }

    stage('Run Dependency-Track Ingestion') {
      options { timeout(time: 80, unit: 'MINUTES') }
      steps {
        withCredentials([
          string(credentialsId: params.DTRACK_API_KEY_CREDENTIALS_ID, variable: 'DTRACK_API_KEY')
        ]) {
          sh '''#!/usr/bin/env bash
            set -euo pipefail
            VERIFY_SSL_FLAG=""
            if [[ "$DTRACK_VERIFY_SSL" == "true" ]]; then
              VERIFY_SSL_FLAG="--verify-ssl"
            fi

            "$PYTHON_BIN" Dependency_Track_Final_2.py \
              --sbom-file "$SBOM_LOCAL_PATH" \
              --dtrack-url "$DTRACK_URL" \
              --dtrack-api-key "$DTRACK_API_KEY" \
              --wait-minutes "$WAIT_MINUTES" \
              --output-findings-json "$FINDINGS_JSON" \
              $VERIFY_SSL_FLAG \
              2>&1 | tee "$LOG_DIR/dependency_track.log"
          '''
        }
      }
    }

    stage('Validate Findings JSON') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
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

          LIMIT_ARG=""
          if [[ -n "${LIMIT:-}" ]]; then
            LIMIT_ARG="--limit $LIMIT"
          fi

          REPO_ARG=""
          if [[ -n "${ANALYSIS_REPO_ROOT:-}" ]]; then
            REPO_ARG="--repo-root $ANALYSIS_REPO_ROOT"
          fi

          "$PYTHON_BIN" scripts/submit_findings_to_workflow_d.py \
            --vulns "$FINDINGS_JSON" \
            --api "$SECOND_SERVICE_API_URL" \
            --mode "$WORKFLOW_MODE" \
            --severities "$SEVERITIES" \
            --out "$FINAL_ANALYSIS_JSON" \
            --normalized-out "$NORMALIZED_JSON" \
            $LIMIT_ARG $REPO_ARG \
            2>&1 | tee "$LOG_DIR/workflow_submit.log"
        '''
      }
    }

    stage('Summarize Results') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
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
