pipeline {
    agent any

    environment {
        SONAR_HOST_URL   = 'http://localhost:9000'
        SENTINEL_API_KEY = credentials('sentinel-api-key')
        SENTINEL_URL     = 'http://localhost:8000'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "📦 Checked out: ${GIT_COMMIT?.take(8)} on ${GIT_BRANCH}"
            }
        }

        stage('Setup Python') {
            steps {
                sh '''
                    python3 -m pip install --user --quiet \
                        pytest pytest-cov PyJWT requests
                '''
            }
        }

        stage('Run Tests') {
            steps {
                script {
                    try {
                        sh '''
                            python3 -m pytest tests/ -v \
                                --junitxml=test-results.xml \
                                --cov=. \
                                --cov-report=xml:coverage.xml \
                                --cov-report=term-missing
                        '''
                    } catch (Exception e) {
                        echo "⚠️ Some tests failed — continuing"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'test-results.xml'
                }
            }
        }

        stage('SENTINEL Security Scan') {
            steps {
                script {
                    echo "🛡️ Running SENTINEL RAG security scan..."

                    def changedFiles = sh(
                        script: '''
                            git diff --name-only HEAD~1 HEAD 2>/dev/null | grep "\\.py$" \
                            || git ls-files "*.py"
                        ''',
                        returnStdout: true
                    ).trim().split('\n').findAll { it?.trim() }
                        .findAll { f ->
                            !f.contains('test_') &&
                            !f.contains('__init__') &&
                            !f.startsWith('_sentinel') &&
                            !f.contains('/tests/')
                        }

                    echo "Files to scan: ${changedFiles}"

                    def overallVerdict   = 'CLEAN'
                    def totalCritical    = 0
                    def totalHigh        = 0
                    def totalFindings    = 0
                    // ── KEY FIX: accumulate the full findings list ──────────
                    def allFindingsJson  = '[]'

                    changedFiles.each { filePath ->
                        filePath = filePath.trim()
                        if (!filePath || !fileExists(filePath)) return

                        writeFile file: '_sentinel_scan.py', text: """
import json, urllib.request, sys, os

file_path    = sys.argv[1]
sentinel_url = sys.argv[2]
api_key      = sys.argv[3] if len(sys.argv) > 3 else ""

with open(file_path, 'r', errors='replace') as f:
    code = f.read()

payload = json.dumps({
    "code":      code,
    "filename":  file_path,
    "provider":  "deepseek",
    "api_key":   api_key if api_key and api_key not in ("null","") else None,
    "scan_mode": "full",
    "kb_layers": ["owasp", "mifid", "sebi", "cve", "pci", "dora"]
}).encode('utf-8')

req = urllib.request.Request(
    sentinel_url + '/scan',
    data=payload,
    headers={'Content-Type': 'application/json'},
    method='POST'
)
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode('utf-8')
        parsed = json.loads(raw)
        findings = parsed.get('findings', [])
        counts = {}
        for fnd in findings:
            s = fnd.get('severity','LOW')
            counts[s] = counts.get(s,0)+1
        print(f"[SENTINEL] {file_path}: {len(findings)} findings — {counts}", flush=True)
        for fnd in findings:
            print(f"[SENTINEL]   [{fnd.get('severity','?')}] {fnd.get('title','?')}", flush=True)
        # ── Print the full JSON as the last line so Groovy can capture it ──
        print(raw, flush=True)
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8')
    print(f"[SENTINEL] HTTP ERROR {e.code}: {body[:400]}", flush=True)
    print(json.dumps({"findings": [], "error": f"HTTP {e.code}"}))
except Exception as e:
    print(f"[SENTINEL] ERROR: {e}", flush=True)
    print(json.dumps({"findings": [], "error": str(e)}))
"""
                        def fullOutput = sh(
                            script: "python3 _sentinel_scan.py '${filePath}' '${SENTINEL_URL}' '${SENTINEL_API_KEY}'",
                            returnStdout: true
                        ).trim()

                        // Last line starting with { is the JSON response
                        def jsonLine = fullOutput.split('\n').findAll { it.startsWith('{') }.last() ?: '{}'

                        def parsed
                        try {
                            parsed = new groovy.json.JsonSlurper().parseText(jsonLine)
                        } catch (Exception e) {
                            parsed = [findings: []]
                        }

                        def findings     = parsed.findings ?: []
                        def criticalCount = findings.count { it.severity == 'CRITICAL' }
                        def highCount     = findings.count { it.severity == 'HIGH' }
                        def fileFindings  = findings.size()

                        totalCritical += criticalCount
                        totalHigh     += highCount
                        totalFindings += fileFindings

                        // ── Accumulate findings for webhook ─────────────────
                        def existing = new groovy.json.JsonSlurper().parseText(allFindingsJson)
                        existing.addAll(findings)
                        allFindingsJson = groovy.json.JsonOutput.toJson(existing)

                        echo "  ${filePath}: ${fileFindings} findings — CRITICAL:${criticalCount} HIGH:${highCount}"
                    }

                    if (totalCritical > 0)  overallVerdict = 'BLOCKED'
                    else if (totalHigh > 3) overallVerdict = 'HIGH_RISK'

                    echo "🛡️ SENTINEL verdict: ${overallVerdict} — total:${totalFindings} critical:${totalCritical} high:${totalHigh}"

                    env.SENTINEL_VERDICT       = overallVerdict
                    env.SENTINEL_CRITICAL      = totalCritical.toString()
                    env.SENTINEL_HIGH          = totalHigh.toString()
                    env.SENTINEL_TOTAL         = totalFindings.toString()
                    // ── Store full findings JSON in env for webhook ─────────
                    env.SENTINEL_FINDINGS_JSON = allFindingsJson

                    // ── KEY FIX: do NOT call error() here ──────────────────
                    // We mark the result but let SonarQube run first.
                    // error() is called AFTER post{always} in the next stage.
                    if (overallVerdict == 'BLOCKED') {
                        currentBuild.result = 'FAILURE'
                        // Do NOT error() here — fall through to SonarQube
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            // ── KEY FIX: run even when build is FAILURE ─────────────────────
            when { expression { true } }
            steps {
                script {
                    def sonarAvailable = sh(
                        script: "export PATH=\$PATH:/opt/homebrew/bin:/usr/local/bin && which sonar-scanner 2>/dev/null && echo yes || echo no",
                        returnStdout: true
                    ).trim().readLines().last()

                    if (sonarAvailable == 'yes') {
                        try {
                            withSonarQubeEnv('SonarQube-Local') {
                                sh '''
                                    export PATH=$PATH:/opt/homebrew/bin:/usr/local/bin
                                    sonar-scanner \
                                        -Dsonar.projectKey=sentinel-capital-markets \
                                        -Dsonar.projectName="SENTINEL Capital Markets" \
                                        -Dsonar.sources=. \
                                        -Dsonar.exclusions=**/tests/**,**/__pycache__/** \
                                        -Dsonar.python.coverage.reportPaths=coverage.xml \
                                        -Dsonar.python.xunit.reportPath=test-results.xml
                                '''
                            }
                        } catch (Exception e) {
                            echo "⚠️ SonarQube failed: ${e.message} — continuing"
                        }
                    } else {
                        echo "⚠️ sonar-scanner not found — skipping"
                    }
                }
            }
        }

        stage('Quality Gate') {
            when { expression { true } }
            steps {
                script {
                    try {
                        timeout(time: 5, unit: 'MINUTES') {
                            def qg = waitForQualityGate()
                            env.SONAR_GATE_STATUS = qg.status
                            echo "SonarQube Quality Gate: ${qg.status}"
                        }
                    } catch (Exception e) {
                        echo "⚠️ Quality Gate skipped: ${e.message}"
                        env.SONAR_GATE_STATUS = ''
                    }
                }
            }
        }

    }

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult ?: 'UNKNOWN'
                def verdict     = env.SENTINEL_VERDICT       ?: 'UNKNOWN'
                def critical    = env.SENTINEL_CRITICAL      ?: '0'
                def high        = env.SENTINEL_HIGH          ?: '0'
                def total       = env.SENTINEL_TOTAL         ?: '0'
                def author      = env.GIT_COMMITTER_NAME     ?: 'unknown'
                def sonarStatus = env.SONAR_GATE_STATUS      ?: ''
                // ── KEY FIX: pass the real findings array ──────────────────
                def findingsJson = env.SENTINEL_FINDINGS_JSON ?: '[]'

                writeFile file: '_sentinel_webhook.py', text: """
import json, urllib.request, os, base64

sonar_url_val  = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
sonar_proj     = "sentinel-capital-markets"
sonar_token_val = os.environ.get("SONAR_AUTH_TOKEN", "")

# Fetch live SonarQube measures
sonar_data = {}
try:
    headers_sq = {}
    if sonar_token_val:
        headers_sq["Authorization"] = "Basic " + base64.b64encode(
            f"{sonar_token_val}:".encode()
        ).decode()
    metrics = "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density"
    _req = urllib.request.Request(
        f"{sonar_url_val}/api/measures/component?component={sonar_proj}&metricKeys={metrics}",
        headers=headers_sq
    )
    with urllib.request.urlopen(_req, timeout=5) as _r:
        _d = json.loads(_r.read())
        for m in _d.get("component", {}).get("measures", []):
            sonar_data[m["metric"]] = m.get("value")
except Exception as e:
    print(f"SonarQube metrics fetch skipped: {e}")

# ── KEY FIX: include the full findings array ───────────────────────────────
findings_raw = '''${findingsJson}'''
try:
    findings_list = json.loads(findings_raw)
except Exception:
    findings_list = []

payload = json.dumps({
    "event":        "build_complete",
    "build_number": ${BUILD_NUMBER},
    "build_url":    "${BUILD_URL}",
    "repo_url":     "${GIT_URL}",
    "branch":       "${GIT_BRANCH}",
    "commit_hash":  "${GIT_COMMIT}",
    "author":       "${author}",
    "status":       "${buildStatus}",
    "verdict":      "${verdict}",
    "sentinel": {
        "total_findings": ${total},
        "critical":       ${critical},
        "high":           ${high}
    },
    # ── The full findings array — this is what was missing ─────────────────
    "findings": findings_list,
    "sonarqube": {
        "status":      "${sonarStatus}",
        "project_key": sonar_proj,
        "url":         f"{sonar_url_val}/dashboard?id={sonar_proj}",
        "bugs":        int(sonar_data.get("bugs") or 0),
        "vulnerabilities": int(sonar_data.get("vulnerabilities") or 0),
        "code_smells": int(sonar_data.get("code_smells") or 0),
        "coverage":    float(sonar_data.get("coverage") or 0),
        "duplication": float(sonar_data.get("duplicated_lines_density") or 0),
    }
}).encode("utf-8")

req = urllib.request.Request(
    "${SENTINEL_URL}/ci/webhook",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST"
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        print("SENTINEL webhook:", resp.read().decode())
except Exception as e:
    print("SENTINEL webhook failed (non-critical):", e)
"""
                sh 'python3 _sentinel_webhook.py || true'
                echo "📊 Result posted to SENTINEL — verdict: ${verdict}"

                // ── KEY FIX: NOW raise the error after SonarQube has run ───
                if (verdict == 'BLOCKED') {
                    error("🚫 SENTINEL blocked: ${critical} CRITICAL vulnerabilities found")
                }
            }
        }
        failure  { echo "❌ Pipeline FAILED" }
        success  { echo "✅ Pipeline PASSED" }
        unstable { echo "⚠️ Pipeline UNSTABLE" }
    }
}
