pipeline {
    agent any

    environment {
        SONAR_HOST_URL   = 'http://localhost:9000'
        SONAR_TOKEN      = credentials('sonarqube-token')
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
import json, urllib.request, sys

file_path = sys.argv[1]
sentinel_url = sys.argv[2]

with open(file_path, 'r', errors='replace') as f:
    code = f.read()

payload = json.dumps({
    "code":      code,
    "filename":  file_path,
    "provider":  "deepseek",
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
        print(resp.read().decode('utf-8'))
except Exception as e:
    print(json.dumps({"findings": [], "error": str(e)}))
"""
                        def response = sh(
                            script: "python3 _sentinel_scan.py '${filePath}' '${SENTINEL_URL}'",
                            returnStdout: true
                        ).trim()

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
import json, urllib.request

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
