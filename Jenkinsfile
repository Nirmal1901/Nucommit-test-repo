// pipeline {
//     agent any

//     environment {
//         SONAR_HOST_URL   = 'http://localhost:9000'
//         SENTINEL_API_KEY = credentials('sentinel-api-key')
//         SENTINEL_URL     = 'http://localhost:8000'
//         SONAR_AUTH_TOKEN = credentials('sonarqube-token')   // ← FIX: expose token for webhook
//     }

//     stages {

//         stage('Checkout') {
//             steps {
//                 checkout scm
//                 echo "📦 Checked out: ${GIT_COMMIT?.take(8)} on ${GIT_BRANCH}"
//             }
//         }

//         stage('Setup Python') {
//             steps {
//                 sh 'python3 -m pip install --user --quiet pytest pytest-cov PyJWT requests'
//             }
//         }

//         stage('Run Tests') {
//             steps {
//                 script {
//                     try {
//                         sh '''
//                             python3 -m pytest tests/ -v \
//                                 --junitxml=test-results.xml \
//                                 --cov=. \
//                                 --cov-report=xml:coverage.xml \
//                                 --cov-report=term-missing
//                         '''
//                     } catch (Exception e) {
//                         echo "⚠️ Some tests failed — continuing"
//                         currentBuild.result = 'UNSTABLE'
//                     }
//                 }
//             }
//             post {
//                 always {
//                     junit allowEmptyResults: true, testResults: 'test-results.xml'
//                 }
//             }
//         }

//         stage('SENTINEL Security Scan') {
//             steps {
//                 script {
//                     echo "🛡️ Running SENTINEL RAG security scan..."

//                     def changedFiles = sh(
//                         script: '''
//                             git diff --name-only HEAD~1 HEAD 2>/dev/null | grep "\\.py$" \
//                             || git diff --name-only HEAD 2>/dev/null | grep "\\.py$" \
//                             || git ls-files "*.py"
//                         ''',
//                         returnStdout: true
//                     ).trim().split('\n').findAll { it?.trim() }
//                         .findAll { f ->
//                             !f.contains('test_') &&
//                             !f.contains('__init__') &&
//                             !f.startsWith('_sentinel') &&
//                             !f.contains('/tests/')
//                         }

//                     echo "Files to scan: ${changedFiles}"

//                     writeFile file: '_sentinel_scan.py', text: '''
// import json, urllib.request, sys, os

// file_path    = sys.argv[1]
// sentinel_url = sys.argv[2]
// api_key      = sys.argv[3] if len(sys.argv) > 3 else ""
// accum_file   = "sentinel_findings.json"

// with open(file_path, "r", errors="replace") as f:
//     code = f.read()

// payload = json.dumps({
//     "code":      code,
//     "filename":  file_path,
//     "provider":  "deepseek",
//     "api_key":   api_key if api_key and api_key not in ("null", "") else None,
//     "scan_mode": "full",
//     "kb_layers": ["owasp", "mifid", "sebi", "cve", "pci", "dora"]
// }).encode("utf-8")

// req = urllib.request.Request(
//     sentinel_url + "/scan",
//     data=payload,
//     headers={"Content-Type": "application/json"},
//     method="POST"
// )
// try:
//     with urllib.request.urlopen(req, timeout=120) as resp:
//         raw      = resp.read().decode("utf-8")
//         data     = json.loads(raw)
//         findings = data.get("findings", [])

//         counts = {}
//         for fnd in findings:
//             s = fnd.get("severity", "LOW")
//             counts[s] = counts.get(s, 0) + 1

//         existing = []
//         if os.path.exists(accum_file):
//             try:
//                 with open(accum_file, "r") as af:
//                     existing = json.load(af)
//             except Exception:
//                 existing = []
//         existing.extend(findings)
//         with open(accum_file, "w") as af:
//             json.dump(existing, af)

//         crit  = counts.get("CRITICAL", 0)
//         high  = counts.get("HIGH", 0)
//         med   = counts.get("MEDIUM", 0)
//         low   = counts.get("LOW", 0)
//         total = len(findings)

//         print(f"[SENTINEL] {file_path}: {total} findings — CRITICAL:{crit} HIGH:{high} MEDIUM:{med} LOW:{low}", flush=True)
//         for fnd in findings:
//             print(f"[SENTINEL]   [{fnd.get('severity','?')}] {fnd.get('title','?')}", flush=True)

//         print(f"SENTINEL_COUNTS critical={crit} high={high} total={total}", flush=True)

// except urllib.error.HTTPError as e:
//     body = e.read().decode("utf-8")
//     print(f"[SENTINEL] HTTP ERROR {e.code}: {body[:400]}", flush=True)
//     print("SENTINEL_COUNTS critical=0 high=0 total=0", flush=True)
// except Exception as e:
//     print(f"[SENTINEL] ERROR: {e}", flush=True)
//     print("SENTINEL_COUNTS critical=0 high=0 total=0", flush=True)
// '''

//                     sh 'printf "[]" > sentinel_findings.json'

//                     def overallVerdict = 'CLEAN'
//                     def totalCritical  = 0
//                     def totalHigh      = 0
//                     def totalFindings  = 0

//                     changedFiles.each { filePath ->
//                         filePath = filePath.trim()
//                         if (!filePath || !fileExists(filePath)) return

//                         def fullOutput = sh(
//                             script: "python3 _sentinel_scan.py '${filePath}' '${SENTINEL_URL}' '${SENTINEL_API_KEY}'",
//                             returnStdout: true
//                         ).trim()

//                         echo fullOutput

//                         def summaryLine = fullOutput.split('\n').find { it.startsWith('SENTINEL_COUNTS') } ?: 'SENTINEL_COUNTS critical=0 high=0 total=0'
//                         def tokens      = summaryLine.tokenize(' ')
//                         def criticalCount = tokens.find { it.startsWith('critical=') }?.tokenize('=')?.last()?.toInteger() ?: 0
//                         def highCount     = tokens.find { it.startsWith('high=') }?.tokenize('=')?.last()?.toInteger() ?: 0
//                         def fileFindings  = tokens.find { it.startsWith('total=') }?.tokenize('=')?.last()?.toInteger() ?: 0

//                         totalCritical += criticalCount
//                         totalHigh     += highCount
//                         totalFindings += fileFindings

//                         echo "  ${filePath}: ${fileFindings} findings — CRITICAL:${criticalCount} HIGH:${highCount}"
//                     }

//                     if (totalCritical > 0)  overallVerdict = 'BLOCKED'
//                     else if (totalHigh > 3) overallVerdict = 'HIGH_RISK'

//                     echo "🛡️ SENTINEL verdict: ${overallVerdict} — total:${totalFindings} critical:${totalCritical} high:${totalHigh}"

//                     env.SENTINEL_VERDICT  = overallVerdict
//                     env.SENTINEL_CRITICAL = totalCritical.toString()
//                     env.SENTINEL_HIGH     = totalHigh.toString()
//                     env.SENTINEL_TOTAL    = totalFindings.toString()

//                     if (overallVerdict == 'BLOCKED') {
//                         currentBuild.result = 'FAILURE'
//                     }
//                 }
//             }
//         }

//         stage('SonarQube Analysis') {
//             steps {
//                 catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
//                     script {
//                         def sonarAvailable = sh(
//                             script: "export PATH=\$PATH:/opt/homebrew/bin:/usr/local/bin && which sonar-scanner 2>/dev/null && echo yes || echo no",
//                             returnStdout: true
//                         ).trim().readLines().last()

//                         if (sonarAvailable == 'yes') {
//                             withSonarQubeEnv('SonarQube-Local') {
//                                 sh '''
//                                     export PATH=$PATH:/opt/homebrew/bin:/usr/local/bin
//                                     sonar-scanner \
//                                         -Dsonar.projectKey=sentinel-capital-markets \
//                                         -Dsonar.projectName="SENTINEL Capital Markets" \
//                                         -Dsonar.sources=. \
//                                         -Dsonar.exclusions=**/tests/**,**/__pycache__/** \
//                                         -Dsonar.python.coverage.reportPaths=coverage.xml \
//                                         -Dsonar.python.xunit.reportPath=test-results.xml
//                                 '''
//                             }
//                         } else {
//                             echo "⚠️ sonar-scanner not found — skipping"
//                         }
//                     }
//                 }
//             }
//         }

//         stage('Quality Gate') {
//             steps {
//                 catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
//                     script {
//                         try {
//                             timeout(time: 5, unit: 'MINUTES') {
//                                 def qg = waitForQualityGate()
//                                 env.SONAR_GATE_STATUS = qg.status
//                                 echo "SonarQube Quality Gate: ${qg.status}"
//                             }
//                         } catch (Exception e) {
//                             echo "⚠️ Quality Gate skipped: ${e.message}"
//                             env.SONAR_GATE_STATUS = ''
//                         }
//                     }
//                 }
//             }
//         }

//     }

//     post {
//         always {
//             script {
//                 def buildStatus = currentBuild.currentResult ?: 'UNKNOWN'
//                 def verdict     = env.SENTINEL_VERDICT       ?: 'UNKNOWN'
//                 def critical    = env.SENTINEL_CRITICAL      ?: '0'
//                 def high        = env.SENTINEL_HIGH          ?: '0'
//                 def total       = env.SENTINEL_TOTAL         ?: '0'
//                 def author      = env.GIT_COMMITTER_NAME     ?: 'unknown'
//                 def sonarStatus = env.SONAR_GATE_STATUS      ?: ''

//                 writeFile file: '_sentinel_webhook.py', text: """
// import json, urllib.request, os, base64

// sonar_url_val   = os.environ.get("SONAR_HOST_URL", "http://localhost:9000")
// sonar_proj      = "sentinel-capital-markets"
// sonar_token_val = os.environ.get("SONAR_AUTH_TOKEN", "")   # ← now populated from credentials

// # credentials('sonarqube-token') returns just the token if stored as StringCredentials.
// # If it was stored as UsernamePassword (fallback), it returns "sonarqube-token:<token>".
// # Strip the username prefix so Basic auth works either way.
// if ":" in sonar_token_val:
//     sonar_token_val = sonar_token_val.split(":", 1)[1]

// sonar_data = {}
// try:
//     headers_sq = {}
//     if sonar_token_val:
//         headers_sq["Authorization"] = "Basic " + base64.b64encode(
//             f"{sonar_token_val}:".encode()
//         ).decode()
//     metrics = "bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density"
//     _req = urllib.request.Request(
//         f"{sonar_url_val}/api/measures/component?component={sonar_proj}&metricKeys={metrics}",
//         headers=headers_sq
//     )
//     with urllib.request.urlopen(_req, timeout=5) as _r:
//         _d = json.loads(_r.read())
//         for m in _d.get("component", {}).get("measures", []):
//             sonar_data[m["metric"]] = m.get("value")
//     print(f"SonarQube metrics fetched: {sonar_data}")
// except Exception as e:
//     print(f"SonarQube metrics fetch skipped: {e}")

// # ── Coverage fallback: parse coverage.xml if SonarQube didn't return it ───
// if "coverage" not in sonar_data and os.path.exists("coverage.xml"):
//     try:
//         import xml.etree.ElementTree as ET
//         tree = ET.parse("coverage.xml")
//         root = tree.getroot()
//         line_rate = float(root.attrib.get("line-rate", 0))
//         sonar_data["coverage"] = round(line_rate * 100, 1)
//         print(f"Coverage from coverage.xml: {sonar_data['coverage']}%")
//     except Exception as e:
//         print(f"coverage.xml parse failed: {e}")

// findings_list = []
// try:
//     with open("sentinel_findings.json", "r") as f:
//         findings_list = json.load(f)
//     print(f"Loaded {len(findings_list)} findings from sentinel_findings.json")
// except Exception as e:
//     print(f"Could not read sentinel_findings.json: {e}")

// payload = json.dumps({
//     "event":        "build_complete",
//     "build_number": ${BUILD_NUMBER},
//     "build_url":    "${BUILD_URL}",
//     "repo_url":     "${GIT_URL}",
//     "branch":       "${GIT_BRANCH}",
//     "commit_hash":  "${GIT_COMMIT}",
//     "author":       "${author}",
//     "status":       "${buildStatus}",
//     "verdict":      "${verdict}",
//     "sentinel": {
//         "total_findings": ${total},
//         "critical":       ${critical},
//         "high":           ${high}
//     },
//     "findings": findings_list,
//     "sonarqube": {
//         "status":      "${sonarStatus}",
//         "project_key": sonar_proj,
//         "url":         f"{sonar_url_val}/dashboard?id={sonar_proj}",
//         "bugs":        int(sonar_data.get("bugs") or 0),
//         "vulnerabilities": int(sonar_data.get("vulnerabilities") or 0),
//         "code_smells": int(sonar_data.get("code_smells") or 0),
//         "coverage":    float(sonar_data.get("coverage") or 0),
//         "duplication": float(sonar_data.get("duplicated_lines_density") or 0),
//     }
// }).encode("utf-8")

// req = urllib.request.Request(
//     "${SENTINEL_URL}/ci/webhook",
//     data=payload,
//     headers={"Content-Type": "application/json"},
//     method="POST"
// )
// try:
//     with urllib.request.urlopen(req, timeout=10) as resp:
//         print("SENTINEL webhook:", resp.read().decode())
// except Exception as e:
//     print("SENTINEL webhook failed (non-critical):", e)
// """
//                 sh 'python3 _sentinel_webhook.py || true'
//                 echo "📊 Result posted to SENTINEL — verdict: ${verdict}"

//                 if (verdict == 'BLOCKED') {
//                     error("🚫 SENTINEL blocked: ${critical} CRITICAL vulnerabilities found")
//                 }
//             }
//         }
//         failure  { echo "❌ Pipeline FAILED" }
//         success  { echo "✅ Pipeline PASSED" }
//         unstable { echo "⚠️ Pipeline UNSTABLE" }
//     }
// }





pipeline {
    agent any

    environment {
        SONAR_HOST_URL   = 'http://localhost:9000'
        SENTINEL_URL     = 'http://localhost:8000'
        // Credentials are NOT expanded into env here — fetched safely at use time
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "📦 Checked out: ${GIT_COMMIT.take(8)} on ${GIT_BRANCH}"
            }
        }

        stage('Setup Python') {
            steps {
                sh 'python3 -m pip install --user --quiet pytest pytest-cov PyJWT requests'
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
                // FIX: Use withCredentials so the secret is never interpolated into
                //      a Groovy string — eliminates the shell injection warning and
                //      prevents the key from being embedded in any written file.
                withCredentials([string(credentialsId: 'sentinel-api-key', variable: 'SENTINEL_API_KEY')]) {
                    script {
                        echo "🛡️ Running SENTINEL RAG security scan..."

                        def changedFiles = sh(
                            script: '''
                                git diff --name-only HEAD~1 HEAD 2>/dev/null | grep "\\.py$" \
                                || git diff --name-only HEAD 2>/dev/null | grep "\\.py$" \
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

                        // FIX: Write scan script to a tmp path outside the workspace
                        //      so SonarQube never picks it up, and clean up afterwards.
                        def scanScript = '/tmp/_sentinel_scan_ci.py'
                        writeFile file: scanScript, text: '''
import json, urllib.request, sys, os

file_path    = sys.argv[1]
sentinel_url = sys.argv[2]
api_key      = sys.argv[3] if len(sys.argv) > 3 else ""
accum_file   = "sentinel_findings.json"

with open(file_path, "r", errors="replace") as f:
    code = f.read()

payload = json.dumps({
    "code":      code,
    "filename":  file_path,
    "provider":  "deepseek",
    "api_key":   api_key if api_key and api_key not in ("null", "") else None,
    "scan_mode": "full",
    "kb_layers": ["owasp", "mifid", "sebi", "cve", "pci", "dora"]
}).encode("utf-8")

req = urllib.request.Request(
    sentinel_url + "/scan",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST"
)
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw      = resp.read().decode("utf-8")
        data     = json.loads(raw)
        findings = data.get("findings", [])

        counts = {}
        for fnd in findings:
            s = fnd.get("severity", "LOW")
            counts[s] = counts.get(s, 0) + 1

        existing = []
        if os.path.exists(accum_file):
            try:
                with open(accum_file, "r") as af:
                    existing = json.load(af)
            except Exception:
                existing = []
        existing.extend(findings)
        with open(accum_file, "w") as af:
            json.dump(existing, af)

        crit  = counts.get("CRITICAL", 0)
        high  = counts.get("HIGH", 0)
        med   = counts.get("MEDIUM", 0)
        low   = counts.get("LOW", 0)
        total = len(findings)

        print(f"[SENTINEL] {file_path}: {total} findings — CRITICAL:{crit} HIGH:{high} MEDIUM:{med} LOW:{low}", flush=True)
        for fnd in findings:
            print(f"[SENTINEL]   [{fnd.get(\'severity\',\'?\')}] {fnd.get(\'title\',\'?\')}", flush=True)

        print(f"SENTINEL_COUNTS critical={crit} high={high} total={total}", flush=True)

except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8")
    print(f"[SENTINEL] HTTP ERROR {e.code}: {body[:400]}", flush=True)
    print("SENTINEL_COUNTS critical=0 high=0 total=0", flush=True)
except Exception as e:
    print(f"[SENTINEL] ERROR: {e}", flush=True)
    print("SENTINEL_COUNTS critical=0 high=0 total=0", flush=True)
'''

                        sh 'printf "[]" > sentinel_findings.json'

                        def overallVerdict = 'CLEAN'
                        def totalCritical  = 0
                        def totalHigh      = 0
                        def totalFindings  = 0

                        changedFiles.each { filePath ->
                            filePath = filePath.trim()
                            if (!filePath || !fileExists(filePath)) return

                            // FIX: Use single-quoted sh string + env var for the secret —
                            //      no Groovy string interpolation of SENTINEL_API_KEY.
                            def fullOutput = sh(
                                script: "python3 ${scanScript} \"${filePath}\" \"${SENTINEL_URL}\" \"\$SENTINEL_API_KEY\"",
                                returnStdout: true
                            ).trim()

                            echo fullOutput

                            def summaryLine = fullOutput.split('\n').find { it.startsWith('SENTINEL_COUNTS') } ?: 'SENTINEL_COUNTS critical=0 high=0 total=0'
                            def tokens      = summaryLine.tokenize(' ')
                            def criticalCount = tokens.find { it.startsWith('critical=') }?.tokenize('=')?.last()?.toInteger() ?: 0
                            def highCount     = tokens.find { it.startsWith('high=') }?.tokenize('=')?.last()?.toInteger() ?: 0
                            def fileFindings  = tokens.find { it.startsWith('total=') }?.tokenize('=')?.last()?.toInteger() ?: 0

                            totalCritical += criticalCount
                            totalHigh     += highCount
                            totalFindings += fileFindings

                            echo "  ${filePath}: ${fileFindings} findings — CRITICAL:${criticalCount} HIGH:${highCount}"
                        }

                        if      (totalCritical > 0)  overallVerdict = 'BLOCKED'
                        else if (totalHigh > 3)       overallVerdict = 'HIGH_RISK'

                        echo "🛡️ SENTINEL verdict: ${overallVerdict} — total:${totalFindings} critical:${totalCritical} high:${totalHigh}"

                        env.SENTINEL_VERDICT  = overallVerdict
                        env.SENTINEL_CRITICAL = totalCritical.toString()
                        env.SENTINEL_HIGH     = totalHigh.toString()
                        env.SENTINEL_TOTAL    = totalFindings.toString()

                        // FIX: Mark UNSTABLE for HIGH_RISK (previously silently ignored).
                        //      BLOCKED stays as hard FAILURE. HIGH_RISK is now visible.
                        if (overallVerdict == 'BLOCKED') {
                            currentBuild.result = 'FAILURE'
                        } else if (overallVerdict == 'HIGH_RISK') {
                            currentBuild.result = 'UNSTABLE'
                        }
                    }
                }
            }
            post {
                // FIX: Clean up the temp scan script so it doesn't linger between builds.
                always {
                    sh 'rm -f /tmp/_sentinel_scan_ci.py || true'
                }
            }
        }

        stage('SonarQube Analysis') {
            // FIX: Skip the Quality Gate wait if sonar-scanner was not found,
            //      avoiding a guaranteed 5-minute timeout every run.
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    script {
                        def sonarAvailable = sh(
                            script: "export PATH=\$PATH:/opt/homebrew/bin:/usr/local/bin && which sonar-scanner 2>/dev/null && echo yes || echo no",
                            returnStdout: true
                        ).trim().readLines().last()

                        env.SONAR_SCANNER_RAN = sonarAvailable

                        if (sonarAvailable == 'yes') {
                            withSonarQubeEnv('SonarQube-Local') {
                                sh '''
                                    export PATH=$PATH:/opt/homebrew/bin:/usr/local/bin
                                    sonar-scanner \
                                        -Dsonar.projectKey=sentinel-capital-markets \
                                        -Dsonar.projectName="SENTINEL Capital Markets" \
                                        -Dsonar.sources=. \
                                        -Dsonar.exclusions=**/tests/**,**/__pycache__/**,/tmp/_sentinel_* \
                                        -Dsonar.python.version=3 \
                                        -Dsonar.python.coverage.reportPaths=coverage.xml \
                                        -Dsonar.python.xunit.reportPath=test-results.xml
                                '''
                            }
                        } else {
                            echo "⚠️ sonar-scanner not found — skipping"
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            // FIX: Guard the entire stage — don't wait if SonarQube never ran.
            when {
                expression { return env.SONAR_SCANNER_RAN == 'yes' }
            }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
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

    }

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult ?: 'UNKNOWN'
                def verdict     = env.SENTINEL_VERDICT       ?: 'UNKNOWN'
                def critical    = env.SENTINEL_CRITICAL      ?: '0'
                def high        = env.SENTINEL_HIGH          ?: '0'
                def total       = env.SENTINEL_TOTAL         ?: '0'
                def sonarStatus = env.SONAR_GATE_STATUS      ?: ''

                // FIX: Write webhook script to /tmp (not workspace) so SonarQube
                //      never scans it and it's not committed to the repo.
                //      All dynamic values are passed as env vars, never interpolated
                //      into string literals inside the Python script — this prevents
                //      breakage on authors named O'Brien, URLs with & or ?, etc.
                def webhookScript = '/tmp/_sentinel_webhook_ci.py'

                withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_AUTH_TOKEN')]) {
                    writeFile file: webhookScript, text: '''
import json, urllib.request, os, base64, xml.etree.ElementTree as ET

# All dynamic pipeline values come from env vars — never hardcoded string literals.
# This means special characters in author names, URLs, etc. cannot break parsing.
sentinel_url   = os.environ.get("SENTINEL_URL",      "http://localhost:8000")
sonar_url_val  = os.environ.get("SONAR_HOST_URL",    "http://localhost:9000")
sonar_proj     = "sentinel-capital-markets"
sonar_token    = os.environ.get("SONAR_AUTH_TOKEN",  "")
build_number   = int(os.environ.get("BUILD_NUMBER",  "0"))
build_url      = os.environ.get("BUILD_URL",         "")
repo_url       = os.environ.get("GIT_URL",           "")
branch         = os.environ.get("GIT_BRANCH",        "")
commit_hash    = os.environ.get("GIT_COMMIT",        "")
author         = os.environ.get("GIT_COMMITTER_NAME","unknown")
build_status   = os.environ.get("BUILD_STATUS",      "UNKNOWN")
verdict        = os.environ.get("SENTINEL_VERDICT",  "UNKNOWN")
critical       = int(os.environ.get("SENTINEL_CRITICAL","0"))
high_count     = int(os.environ.get("SENTINEL_HIGH",   "0"))
total_findings = int(os.environ.get("SENTINEL_TOTAL",  "0"))
sonar_status   = os.environ.get("SONAR_GATE_STATUS", "")

# credentials('sonarqube-token') may return "sonarqube-token:<token>" if stored as
# UsernamePassword fallback. Strip the prefix so Basic auth works either way.
if ":" in sonar_token:
    sonar_token = sonar_token.split(":", 1)[1]

# ── Fetch SonarQube metrics ────────────────────────────────────────────────────
sonar_data = {}
try:
    headers_sq = {}
    if sonar_token:
        headers_sq["Authorization"] = "Basic " + base64.b64encode(
            f"{sonar_token}:".encode()
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
    print(f"SonarQube metrics fetched: {sonar_data}")
except Exception as e:
    print(f"SonarQube metrics fetch skipped: {e}")

# ── Coverage fallback from coverage.xml ───────────────────────────────────────
if "coverage" not in sonar_data and os.path.exists("coverage.xml"):
    try:
        tree = ET.parse("coverage.xml")
        root = tree.getroot()
        line_rate = float(root.attrib.get("line-rate", 0))
        sonar_data["coverage"] = round(line_rate * 100, 1)
        print(f"Coverage from coverage.xml: {sonar_data[\'coverage\']}%")
    except Exception as e:
        print(f"coverage.xml parse failed: {e}")

# ── Load accumulated findings ──────────────────────────────────────────────────
findings_list = []
try:
    with open("sentinel_findings.json", "r") as f:
        findings_list = json.load(f)
    print(f"Loaded {len(findings_list)} findings from sentinel_findings.json")
except Exception as e:
    print(f"Could not read sentinel_findings.json: {e}")

# ── Build and POST webhook payload ────────────────────────────────────────────
payload = json.dumps({
    "event":        "build_complete",
    "build_number": build_number,
    "build_url":    build_url,
    "repo_url":     repo_url,
    "branch":       branch,
    "commit_hash":  commit_hash,
    "author":       author,
    "status":       build_status,
    "verdict":      verdict,
    "sentinel": {
        "total_findings": total_findings,
        "critical":       critical,
        "high":           high_count,
    },
    "findings": findings_list,
    "sonarqube": {
        "status":            sonar_status,
        "project_key":       sonar_proj,
        "url":               f"{sonar_url_val}/dashboard?id={sonar_proj}",
        "bugs":              int(sonar_data.get("bugs") or 0),
        "vulnerabilities":   int(sonar_data.get("vulnerabilities") or 0),
        "code_smells":       int(sonar_data.get("code_smells") or 0),
        "coverage":          float(sonar_data.get("coverage") or 0),
        "duplication":       float(sonar_data.get("duplicated_lines_density") or 0),
    },
}).encode("utf-8")

req = urllib.request.Request(
    sentinel_url + "/ci/webhook",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST"
)
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        print("SENTINEL webhook:", resp.read().decode())
except Exception as e:
    print("SENTINEL webhook failed (non-critical):", e)
'''

                    // Pass every dynamic value as an env var so the Python script
                    // never needs string interpolation of potentially unsafe values.
                    withEnv([
                        "BUILD_STATUS=${buildStatus}",
                        "SENTINEL_VERDICT=${verdict}",
                        "SENTINEL_CRITICAL=${critical}",
                        "SENTINEL_HIGH=${high}",
                        "SENTINEL_TOTAL=${total}",
                        "SONAR_GATE_STATUS=${sonarStatus}",
                    ]) {
                        sh "python3 ${webhookScript} || true"
                    }
                }

                sh "rm -f ${webhookScript} sentinel_findings.json || true"
                echo "📊 Result posted to SENTINEL — verdict: ${verdict}"

                // FIX: error() call kept last so the webhook always fires before
                //      the build is marked as failed.
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
