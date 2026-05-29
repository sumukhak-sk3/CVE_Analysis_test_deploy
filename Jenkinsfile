pipeline {
  agent {
    label 'ubuntu_bin2'
  }

  options {
    timestamps()
    disableConcurrentBuilds()
    skipDefaultCheckout(true)
    timeout(time: 120, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  parameters {
    string(name: 'REPOSITORY_URL', defaultValue: '', description: 'Required: Git URL of the repository to index/analyze.')
    string(name: 'BRANCH', defaultValue: 'main', description: 'Git branch to checkout from REPOSITORY_URL.')
    string(name: 'VULNERABILITIES_FILE_URL', defaultValue: '', description: 'Optional: HTTP/HTTPS URL Jenkins can download (.json/.csv/.xlsx).')
    string(name: 'VULNERABILITIES_FILE_PATH', defaultValue: '', description: 'Optional: file path available on the Jenkins agent (workspace/shared mount).')
    string(name: 'INDEX_NAME', defaultValue: '', description: 'Optional: custom index folder name. Auto-generated if empty.')
    choice(name: 'INDEX_MODE', choices: ['full', 'incremental'], description: 'Index build mode for scripts/build_index.py.')
    choice(name: 'ANALYSIS_MODE', choices: ['standard', 'urgent', 'ad_hoc'], description: 'Workflow D analysis mode.')
    string(name: 'SEVERITIES', defaultValue: 'CRITICAL,HIGH', description: 'Comma-separated severities for filtering findings.')
    string(name: 'LIMIT', defaultValue: '0', description: 'Maximum CVEs to analyze. Use 0 for no cap.')
    string(name: 'WORKERS', defaultValue: '4', description: 'Parallel CVE workers for run_pipeline.')
    string(name: 'OUTPUT_DIR', defaultValue: '.jenkins_work/output', description: 'Output directory (absolute or workspace-relative).')
  }

  environment {
    RUN_ROOT = "${WORKSPACE}/.jenkins_work"
    LOG_DIR = "${WORKSPACE}/.jenkins_work/logs"
    PYTHON_BIN = 'python3'
  }

  stages {
    stage('Validate Parameters') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          mkdir -p "$RUN_ROOT" "$LOG_DIR"

          if [[ -z "${REPOSITORY_URL:-}" ]]; then
            echo "ERROR: REPOSITORY_URL is required" >&2
            exit 1
          fi
          if [[ -z "${BRANCH:-}" ]]; then
            echo "ERROR: BRANCH is required" >&2
            exit 1
          fi
          if [[ -z "${VULNERABILITIES_FILE_URL:-}" && -z "${VULNERABILITIES_FILE_PATH:-}" ]]; then
            echo "ERROR: Provide either VULNERABILITIES_FILE_URL or VULNERABILITIES_FILE_PATH" >&2
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
          INPUT_DIR="$RUN_DIR/input"
          TARGET_REPO_DIR="$RUN_DIR/target_repo"
          RUNS_DIR="$RUN_DIR/runs"
          INDEXES_DIR="$RUN_DIR/indexes"

          if [[ -n "${OUTPUT_DIR:-}" ]]; then
            if [[ "${OUTPUT_DIR}" = /* ]]; then
              OUTPUT_DIR_ABS="$OUTPUT_DIR"
            else
              OUTPUT_DIR_ABS="$WORKSPACE/$OUTPUT_DIR"
            fi
          else
            OUTPUT_DIR_ABS="$RUN_DIR/output"
          fi

          mkdir -p "$INPUT_DIR" "$TARGET_REPO_DIR" "$RUNS_DIR" "$INDEXES_DIR" "$OUTPUT_DIR_ABS" "$LOG_DIR"

          cat > "$RUN_ROOT/run.env" <<EOF
export RUN_DIR="$RUN_DIR"
export INPUT_DIR="$INPUT_DIR"
export TARGET_REPO_DIR="$TARGET_REPO_DIR"
export RUNS_DIR="$RUNS_DIR"
export INDEXES_DIR="$INDEXES_DIR"
export OUTPUT_DIR_ABS="$OUTPUT_DIR_ABS"
EOF

          echo "RUN_DIR=$RUN_DIR"
          echo "OUTPUT_DIR_ABS=$OUTPUT_DIR_ABS"
        '''
      }
    }

    stage('Checkout Pipeline Repo') {
      steps {
        checkout(scm)
      }
    }

    stage('Acquire Vulnerabilities File') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          SRC_NAME=""

          if [[ -n "${VULNERABILITIES_FILE_URL:-}" ]]; then
            echo "Downloading vulnerabilities file from URL"
            CLEAN_URL="$(printf '%s' "$VULNERABILITIES_FILE_URL" | cut -d'?' -f1)"
            SRC_NAME="$(basename "$CLEAN_URL")"
            [[ -n "$SRC_NAME" ]] || SRC_NAME="vulnerabilities.json"
            EXT_LOWER="$(echo "${SRC_NAME##*.}" | tr '[:upper:]' '[:lower:]')"
            VULNS_LOCAL_PATH="$INPUT_DIR/vulnerabilities.${EXT_LOWER}"
            curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
              "$VULNERABILITIES_FILE_URL" -o "$VULNS_LOCAL_PATH"
          else
            SRC_PATH="$VULNERABILITIES_FILE_PATH"
            if [[ "$SRC_PATH" != /* ]]; then
              SRC_PATH="$WORKSPACE/$SRC_PATH"
            fi
            if [[ ! -f "$SRC_PATH" ]]; then
              echo "ERROR: VULNERABILITIES_FILE_PATH does not exist on Jenkins agent: $SRC_PATH" >&2
              exit 1
            fi
            SRC_NAME="$(basename "$SRC_PATH")"
            EXT_LOWER="$(echo "${SRC_NAME##*.}" | tr '[:upper:]' '[:lower:]')"
            VULNS_LOCAL_PATH="$INPUT_DIR/vulnerabilities.${EXT_LOWER}"
            cp "$SRC_PATH" "$VULNS_LOCAL_PATH"
          fi

          if [[ ! -s "$VULNS_LOCAL_PATH" ]]; then
            echo "ERROR: Vulnerabilities file is empty or missing: $VULNS_LOCAL_PATH" >&2
            exit 1
          fi

          case "$EXT_LOWER" in
            json|csv|xlsx|xlsm) ;;
            *)
              echo "ERROR: vulnerabilities file extension must be .json/.csv/.xlsx/.xlsm" >&2
              exit 1
              ;;
          esac

          cat >> "$RUN_ROOT/run.env" <<EOF
export VULNS_LOCAL_PATH="$VULNS_LOCAL_PATH"
EOF

          echo "VULNS_LOCAL_PATH=$VULNS_LOCAL_PATH"
        '''
      }
    }

    stage('Clone Target Repository') {
      options { timeout(time: 20, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          if [[ -d "$TARGET_REPO_DIR/.git" ]]; then
            rm -rf "$TARGET_REPO_DIR"
          fi

          echo "Cloning target repository: ${REPOSITORY_URL} (branch: ${BRANCH})"
          git clone --depth 1 --branch "$BRANCH" -- "$REPOSITORY_URL" "$TARGET_REPO_DIR" \
            2>&1 | tee "$LOG_DIR/git_clone.log"

          if [[ ! -d "$TARGET_REPO_DIR/.git" ]]; then
            echo "ERROR: target repository clone failed" >&2
            exit 1
          fi
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
          "$PYTHON_BIN" -m pip install -r requirements.txt 2>&1 | tee "$LOG_DIR/pip_install.log"
        '''
      }
    }

    stage('Build Code Index') {
      options { timeout(time: 40, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          if [[ -n "${INDEX_NAME:-}" ]]; then
            SAFE_INDEX_NAME="$(echo "$INDEX_NAME" | tr -cs 'A-Za-z0-9._-' '-')"
          else
            REPO_BASE="$(basename "$REPOSITORY_URL")"
            REPO_BASE="${REPO_BASE%.git}"
            SAFE_INDEX_NAME="$(echo "${REPO_BASE}-${BRANCH}-${BUILD_NUMBER}" | tr -cs 'A-Za-z0-9._-' '-')"
          fi
          INDEX_DIR="$INDEXES_DIR/$SAFE_INDEX_NAME"
          mkdir -p "$INDEX_DIR"

          "$PYTHON_BIN" scripts/build_index.py \
            --repo "$TARGET_REPO_DIR" \
            --out "$INDEX_DIR" \
            --mode "$INDEX_MODE" \
            2>&1 | tee "$LOG_DIR/index_build.log"

          if [[ ! -s "$INDEX_DIR/meta.json" ]]; then
            echo "ERROR: index build did not produce meta.json in $INDEX_DIR" >&2
            exit 1
          fi

          cat >> "$RUN_ROOT/run.env" <<EOF
export INDEX_DIR="$INDEX_DIR"
EOF

          echo "INDEX_DIR=$INDEX_DIR"
        '''
      }
    }

    stage('Run Vulnerability Analysis') {
      options { timeout(time: 90, unit: 'MINUTES') }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          SEV_ARGS=()
          IFS=',' read -r -a RAW_SEVS <<< "${SEVERITIES:-CRITICAL,HIGH}"
          for s in "${RAW_SEVS[@]}"; do
            v="$(echo "$s" | xargs)"
            if [[ -n "$v" ]]; then
              SEV_ARGS+=("$v")
            fi
          done

          "$PYTHON_BIN" scripts/run_pipeline.py \
            --repo-root "$TARGET_REPO_DIR" \
            --vulns "$VULNS_LOCAL_PATH" \
            --index-dir "$INDEX_DIR" \
            --force-all \
            --hitl-mode non_interactive \
            --mode "$ANALYSIS_MODE" \
            --limit "$LIMIT" \
            --workers "$WORKERS" \
            --runs-dir "$RUNS_DIR" \
            --severities "${SEV_ARGS[@]}" \
            2>&1 | tee "$LOG_DIR/run_pipeline.log"
        '''
      }
    }

    stage('Generate Excel Report') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          source "$RUN_ROOT/run.env"

          FULL_REPORT="$(ls -1t "$RUNS_DIR"/run-*.full.json 2>/dev/null | head -n 1 || true)"
          if [[ -z "$FULL_REPORT" ]]; then
            echo "ERROR: No run-*.full.json found in $RUNS_DIR" >&2
            exit 1
          fi

          RUN_ID="$(basename "$FULL_REPORT" .full.json)"
          XLSX_PATH="$OUTPUT_DIR_ABS/${RUN_ID}.xlsx"

          "$PYTHON_BIN" scripts/export_report_xlsx.py \
            --report "$FULL_REPORT" \
            --out "$XLSX_PATH" \
            2>&1 | tee "$LOG_DIR/export_xlsx.log"

          cat >> "$RUN_ROOT/run.env" <<EOF
export RUN_ID="$RUN_ID"
export FULL_REPORT="$FULL_REPORT"
export XLSX_PATH="$XLSX_PATH"
EOF

          echo "RUN_ID=$RUN_ID"
          echo "FULL_REPORT=$FULL_REPORT"
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

p = Path("$FULL_REPORT")
if not p.exists() or p.stat().st_size == 0:
    raise SystemExit(f"Full report missing or empty: {p}")

obj = json.loads(p.read_text(encoding="utf-8"))
analysis = obj.get("analysis_result") or {}
analysis_id = obj.get("analysis_id") or analysis.get("analysis_id")
results = analysis.get("results") or []

print("Final analysis summary")
print(f"run_id: {'$RUN_ID'}")
print(f"analysis_id: {analysis_id}")
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
        node('ubuntu_bin2') {
          if (fileExists('.jenkins_work')) {
            archiveArtifacts artifacts: '.jenkins_work/**', fingerprint: true, onlyIfSuccessful: false
          } else {
            echo 'No .jenkins_work directory found; skipping artifact archive.'
          }
        }
      }
    }
    failure {
      echo 'Pipeline failed. Inspect archived logs under .jenkins_work/logs/ and run artifacts under .jenkins_work/run-*/.'
    }
    success {
      echo 'Pipeline completed successfully. Index, run reports, and XLSX are archived under .jenkins_work/**.'
    }
  }
}
