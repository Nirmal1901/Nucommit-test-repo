pipeline {
    agent any

    environment {
        SONAR_HOST_URL   = 'http://localhost:9000'
        // SONAR_TOKEN intentionally NOT set here — withSonarQubeEnv injects it automatically.
        // Setting it manually AND using withSonarQubeEnv causes a sonar.login conflict → auth failure.
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
                            // Skip test files, __init__.py and helper scripts
                            !f.contains('test_') &&
                            !f.contains('__init__') &&
                            !f.startsWith('_sentinel') &&
                            !f.contains('/tests/')
                        }

                    echo "Files to scan: ${changedFiles}"

                    def overallVerdict = 'CLEAN'
                    def totalCritical  = 0
                    def totalHigh      = 0
                    def totalFindings  = 0

                    changedFiles.each { filePath ->
                        filePath = filePath.trim()
                        if (!filePath || !fileExists(filePath)) return

                        // Use a Python helper script to POST the file to SENTINEL.
                        // This completely avoids shell escaping issues with special chars.
                        writeFile file: '_sentinel_scan.py', text: """
import json, urllib.request, sys, os

file_path    = sys.argv[1]
sentinel_url = sys.argv[2]
api_key      = sys.argv[3] if len(sys.argv) > 3 else ""

print(f"[SENTINEL] Scanning  : {file_path}", flush=True)
print(f"[SENTINEL] Backend   : {sentinel_url}/scan", flush=True)
key_status = ('SET (' + str(len(api_key)) + ' chars)') if api_key and api_key not in ('null','') else 'NOT SET — using .env DEEPSEEK_API_KEY'
print(f"[SENTINEL] API key   : {key_status}", flush=True)

with open(file_path, 'r', errors='replace') as f:
    code = f.read()
print(f"[SENTINEL] Code size : {len(code)} chars", flush=True)

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
    print("[SENTINEL] Posting to backend...", flush=True)
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode('utf-8')
        print(f"[SENTINEL] HTTP 200 — {len(raw)} chars received", flush=True)
        try:
            parsed = json.loads(raw)
            findings = parsed.get('findings', [])
            counts = {}
            for fnd in findings:
                s = fnd.get('severity','LOW')
                counts[s] = counts.get(s,0)+1
            print(f"[SENTINEL] Findings  : {len(findings)} — {counts}", flush=True)
            for fnd in findings:
                print(f"[SENTINEL]   [{fnd.get('severity','?')}] {fnd.get('title','?')}", flush=True)
            if parsed.get('error'):
                print(f"[SENTINEL] ERROR: {parsed['error']}", flush=True)
        except Exception as pe:
            print(f"[SENTINEL] Parse error: {pe}", flush=True)
        print(raw)
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8')
    print(f"[SENTINEL] HTTP ERROR {e.code}: {body[:400]}", flush=True)
    print(json.dumps({"findings": [], "error": f"HTTP {e.code}"}))
except urllib.error.URLError as e:
    print(f"[SENTINEL] CONNECTION FAILED: {e.reason}", flush=True)
    print(f"[SENTINEL] Is uvicorn running at {sentinel_url}?", flush=True)
    print(json.dumps({"findings": [], "error": str(e)}))
except Exception as e:
    print(f"[SENTINEL] ERROR: {e}", flush=True)
    print(json.dumps({"findings": [], "error": str(e)}))
"""
                        def fullOutput = sh(
                            script: "python3 _sentinel_scan.py '${filePath}' '${SENTINEL_URL}' '${SENTINEL_API_KEY}'",
                            returnStdout: true
                        ).trim()

                        // Logs go to console; JSON is the last line starting with {
                        def response = fullOutput.split('\n').findAll { it.startsWith('{') }.last() ?: '{}'

                        def criticalCount = response.count('"CRITICAL"')
                        def highCount     = response.count('"HIGH"')
                        def mediumCount   = response.count('"MEDIUM"')
                        def lowCount      = response.count('"LOW"')
                        def fileFindings  = criticalCount + highCount + mediumCount + lowCount

                        totalCritical += criticalCount
                        totalHigh     += highCount
                        totalFindings += fileFindings

                        echo "  ${filePath}: ${fileFindings} findings — CRITICAL:${criticalCount} HIGH:${highCount} MEDIUM:${mediumCount} LOW:${lowCount}"
                    }

                    if (totalCritical > 0)  overallVerdict = 'BLOCKED'
                    else if (totalHigh > 3) overallVerdict = 'HIGH_RISK'

                    echo "🛡️ SENTINEL verdict: ${overallVerdict} — total:${totalFindings} critical:${totalCritical} high:${totalHigh}"

                    env.SENTINEL_VERDICT  = overallVerdict
                    env.SENTINEL_CRITICAL = totalCritical.toString()
                    env.SENTINEL_HIGH     = totalHigh.toString()
                    env.SENTINEL_TOTAL    = totalFindings.toString()

                    if (overallVerdict == 'BLOCKED') {
                        currentBuild.result = 'FAILURE'
                        error("🚫 SENTINEL blocked: ${totalCritical} CRITICAL vulnerabilities found")
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                script {
                    // Homebrew installs to /opt/homebrew/bin on Apple Silicon Macs.
                    // Jenkins runs in a minimal shell that doesn't source ~/.zshrc,
                    // so /opt/homebrew/bin is not on PATH. Set it explicitly here.
                    def sonarAvailable = sh(
                        script: "export PATH=$PATH:/opt/homebrew/bin:/usr/local/bin && which sonar-scanner 2>/dev/null && echo yes || echo no",
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
                            currentBuild.result = 'UNSTABLE'
                        }
                    } else {
                        echo "⚠️ sonar-scanner not found at /opt/homebrew/bin or /usr/local/bin — skipping"
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    try {
                        timeout(time: 5, unit: 'MINUTES') {
                            waitForQualityGate abortPipeline: false
                        }
                    } catch (Exception e) {
                        echo "⚠️ Quality Gate skipped: ${e.message}"
                    }
                }
            }
        }

    }

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult ?: 'UNKNOWN'
                def verdict     = env.SENTINEL_VERDICT  ?: 'UNKNOWN'
                def critical    = env.SENTINEL_CRITICAL ?: '0'
                def high        = env.SENTINEL_HIGH     ?: '0'
                def total       = env.SENTINEL_TOTAL    ?: '0'
                def author      = env.GIT_COMMITTER_NAME ?: 'unknown'

                // Python webhook poster — no shell escaping issues
                writeFile file: '_sentinel_webhook.py', text: """
import json, urllib.request, os

# Fetch SonarQube measures if available
sonar_data = {}
sonar_url_val = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
sonar_proj    = "sentinel-capital-markets"
try:
    import urllib.request as _ur
    sonar_token_val = os.environ.get("SONAR_AUTH_TOKEN","")
    headers_sq = {}
    if sonar_token_val:
        import base64 as _b64
        headers_sq["Authorization"] = "Basic " + _b64.b64encode(f"{sonar_token_val}:".encode()).decode()
    metrics = "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density"
    _req = _ur.Request(
        f"{sonar_url_val}/api/measures/component?component={sonar_proj}&metricKeys={metrics}",
        headers=headers_sq
    )
    with _ur.urlopen(_req, timeout=5) as _r:
        _d = json.loads(_r.read())
        for m in _d.get("component",{}).get("measures",[]):
            sonar_data[m["metric"]] = m.get("value")
except Exception:
    pass

payload = json.dumps({
    "event":        "build_complete",
    "build_number": ${BUILD_NUMBER},
    "build_url":    "${BUILD_URL}",
    "repo_url":     "${GIT_URL}",
    "repo_name":    "${GIT_URL}".split("/")[-1].replace(".git",""),
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
    "sonarqube": {
        "status":      os.environ.get("SONAR_GATE_STATUS",""),
        "project_key": sonar_proj,
        "url":         f"{sonar_url_val}/dashboard?id={sonar_proj}",
        "bugs":        int(sonar_data.get("bugs") or 0),
        "vulnerabilities": int(sonar_data.get("vulnerabilities") or 0),
        "code_smells": int(sonar_data.get("code_smells") or 0),
        "coverage":    float(sonar_data.get("coverage") or 0),
        "duplication": float(sonar_data.get("duplicated_lines_density") or 0),
    }
}).encode('utf-8')

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
            }
        }
        failure  { echo "❌ Pipeline FAILED" }
        success  { echo "✅ Pipeline PASSED" }
        unstable { echo "⚠️ Pipeline UNSTABLE" }
    }
}
