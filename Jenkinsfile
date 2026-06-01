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
    RUN_ID = ''
    VULNS_PATH = ''
  }

  stages {
    stage('Resolve Input File') {
      steps {
        script {
          int limit = params.LIMIT?.trim()?.isInteger() ? params.LIMIT.toInteger() : -1
          int workers = params.WORKERS?.trim()?.isInteger() ? params.WORKERS.toInteger() : -1
          int pollInterval = params.POLL_INTERVAL_SECONDS?.trim()?.isInteger() ? params.POLL_INTERVAL_SECONDS.toInteger() : -1
          int pollTimeout = params.POLL_TIMEOUT_SECONDS?.trim()?.isInteger() ? params.POLL_TIMEOUT_SECONDS.toInteger() : -1

          if (limit < 0) {
            error('LIMIT must be a non-negative integer')
          }
          if (workers <= 0) {
            error('WORKERS must be a positive integer')
          }
          if (pollInterval <= 0) {
            error('POLL_INTERVAL_SECONDS must be a positive integer')
          }
          if (pollTimeout <= 0) {
            error('POLL_TIMEOUT_SECONDS must be a positive integer')
          }

          def supported = ['json', 'csv', 'xlsx', 'xlsm']
          File candidate = new File(params.INPUT_PATH)
          if (!candidate.isAbsolute()) {
            candidate = new File(env.WORKSPACE, params.INPUT_PATH)
          }

          if (!candidate.exists()) {
            error("INPUT_PATH not found: ${candidate.absolutePath}")
          }

          if (candidate.isDirectory()) {
            List<File> files = candidate
              .listFiles()
              ?.findAll { it.isFile() }
              ?.findAll {
                String n = it.name.toLowerCase(java.util.Locale.ROOT)
                supported.any { ext -> n.endsWith('.' + ext) }
              }
              ?.sort { a, b -> b.lastModified() <=> a.lastModified() } ?: []

            if (files.isEmpty()) {
              error("No supported input file in directory: ${candidate.absolutePath}")
            }
            candidate = files[0]
          }

          String name = candidate.name.toLowerCase(java.util.Locale.ROOT)
          boolean extOk = supported.any { ext -> name.endsWith('.' + ext) }
          if (!extOk) {
            error('INPUT_PATH file extension must be .json/.csv/.xlsx/.xlsm')
          }
          if (candidate.length() <= 0) {
            error("Input file is empty: ${candidate.absolutePath}")
          }

          env.VULNS_PATH = candidate.absolutePath
          echo "Resolved input file: ${env.VULNS_PATH}"
        }
      }
    }

    stage('Start Workflow D Run') {
      steps {
        script {
          List<String> severities = (params.SEVERITIES ?: 'CRITICAL,HIGH')
            .split(',')
            .collect { it.trim().toUpperCase(java.util.Locale.ROOT) }
            .findAll { it }
          if (severities.isEmpty()) {
            severities = ['CRITICAL', 'HIGH']
          }

          def payload = [
            vulns_path: env.VULNS_PATH,
            severities: severities,
            limit: params.LIMIT.toInteger(),
            mode: params.ANALYSIS_MODE,
            workers: params.WORKERS.toInteger(),
          ]

          String base = (params.WORKFLOW_D_API_BASE ?: '').trim().replaceAll('/+$', '')
          if (!base) {
            error('WORKFLOW_D_API_BASE is required')
          }

          URL url = new URL(base + '/runs/start')
          HttpURLConnection conn = (HttpURLConnection) url.openConnection()
          conn.setRequestMethod('POST')
          conn.setConnectTimeout(30000)
          conn.setReadTimeout(120000)
          conn.setRequestProperty('Content-Type', 'application/json')
          conn.setDoOutput(true)
          conn.outputStream.withWriter('UTF-8') { w ->
            w << groovy.json.JsonOutput.toJson(payload)
          }

          int code = conn.responseCode
          String body
          if (code >= 200 && code < 300) {
            body = conn.inputStream.getText('UTF-8')
          } else {
            body = conn.errorStream ? conn.errorStream.getText('UTF-8') : ''
            error("Failed to start run: HTTP ${code} ${body}")
          }

          def obj = new groovy.json.JsonSlurperClassic().parseText(body)
          if (!(obj instanceof Map) || !obj.run_id) {
            error("run_id missing in /runs/start response: ${body}")
          }
          env.RUN_ID = String.valueOf(obj.run_id)

          echo "Started run_id: ${env.RUN_ID}"
          echo "Frontend/API run URL: ${params.WORKFLOW_D_API_BASE}/runs/${env.RUN_ID}"
        }
      }
    }

    stage('Wait For Completion') {
      steps {
        script {
          String base = (params.WORKFLOW_D_API_BASE ?: '').trim().replaceAll('/+$', '')
          int intervalSec = params.POLL_INTERVAL_SECONDS.toInteger()
          int timeoutSec = params.POLL_TIMEOUT_SECONDS.toInteger()
          long deadline = System.currentTimeMillis() + (timeoutSec * 1000L)

          while (true) {
            URL url = new URL(base + '/runs/' + env.RUN_ID)
            HttpURLConnection conn = (HttpURLConnection) url.openConnection()
            conn.setRequestMethod('GET')
            conn.setConnectTimeout(30000)
            conn.setReadTimeout(120000)

            int code = conn.responseCode
            String body = (code >= 200 && code < 300) ?
              conn.inputStream.getText('UTF-8') :
              (conn.errorStream ? conn.errorStream.getText('UTF-8') : '')

            if (code < 200 || code >= 300) {
              error("Failed polling run status: HTTP ${code} ${body}")
            }

            def obj = new groovy.json.JsonSlurperClassic().parseText(body)
            def statusObj = (obj instanceof Map && obj.status instanceof Map) ? obj.status : [:]
            String state = statusObj.state ? String.valueOf(statusObj.state) : ''
            String analysisId = statusObj.analysis_id ? String.valueOf(statusObj.analysis_id) : 'n/a'

            if (!state && obj instanceof Map && obj.artifact) {
              state = 'completed'
            }

            echo "run_id=${env.RUN_ID} state=${state ?: 'unknown'} analysis_id=${analysisId}"

            if (state == 'ok' || state == 'completed') {
              echo 'Run completed successfully.'
              echo "View in frontend/API: ${base}/runs/${env.RUN_ID}"
              break
            }

            if (state == 'failed' || state == 'cancelled' || state == 'rejected') {
              error("Run finished with state=${state}")
            }

            if (System.currentTimeMillis() >= deadline) {
              error("Timed out waiting for run completion after ${timeoutSec}s")
            }

            sleep(time: intervalSec, unit: 'SECONDS')
          }
        }
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
