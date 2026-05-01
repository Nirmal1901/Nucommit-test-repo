pipeline {
    agent any

    environment {
        SONAR_HOST_URL    = 'http://localhost:9000'
        SONAR_TOKEN       = credentials('sonarqube-token')
        SENTINEL_API_KEY  = credentials('sentinel-api-key')
        SENTINEL_URL      = 'http://localhost:8000'
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
                        echo "⚠️ Some tests failed — continuing to scan stages"
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

                    // Collect all changed Python files since last commit
                    def changedFiles = sh(
                        script: "git diff --name-only HEAD~1 HEAD 2>/dev/null | grep '\\.py\$' || git ls-files '*.py'",
                        returnStdout: true
                    ).trim().split('\n').findAll { it }

                    echo "Files to scan: ${changedFiles}"

                    def overallVerdict = 'CLEAN'
                    def totalCritical  = 0
                    def totalHigh      = 0
                    def allFindings    = []

                    changedFiles.each { filePath ->
                        if (!fileExists(filePath)) return
                        def code = readFile(filePath)

                        // POST to SENTINEL /scan
                        def response = sh(script: """
                            curl -s -X POST ${SENTINEL_URL}/scan \\
                            -H "Content-Type: application/json" \\
                            -d '{
                                "code":      ${groovy.json.JsonOutput.toJson(code)},
                                "filename":  "${filePath}",
                                "provider":  "openai",
                                "scan_mode": "full",
                                "kb_layers": ["owasp","mifid","sebi","cve","pci","dora"]
                            }'
                        """, returnStdout: true).trim()

                        def result = readJSON text: response
                        def findings = result.findings ?: []

                        findings.each { f ->
                            if (f.severity == 'CRITICAL') totalCritical++
                            if (f.severity == 'HIGH')     totalHigh++
                            allFindings << "[${f.severity}] ${filePath}: ${f.title}"
                        }

                        echo "  ${filePath}: ${findings.size()} findings"
                    }

                    if (totalCritical > 0) overallVerdict = 'BLOCKED'
                    else if (totalHigh > 3) overallVerdict = 'HIGH_RISK'

                    echo "🛡️ SENTINEL verdict: ${overallVerdict} (${totalCritical} critical, ${totalHigh} high)"
                    allFindings.each { echo "  → ${it}" }

                    env.SENTINEL_VERDICT  = overallVerdict
                    env.SENTINEL_CRITICAL = totalCritical.toString()
                    env.SENTINEL_HIGH     = totalHigh.toString()
                    env.SENTINEL_TOTAL    = allFindings.size().toString()

                    if (overallVerdict == 'BLOCKED') {
                        currentBuild.result = 'FAILURE'
                        error("🚫 SENTINEL blocked: ${totalCritical} CRITICAL vulnerabilities found")
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube-Local') {
                    sh '''
                        sonar-scanner \
                            -Dsonar.projectKey=sentinel-capital-markets \
                            -Dsonar.projectName="SENTINEL Capital Markets" \
                            -Dsonar.sources=. \
                            -Dsonar.exclusions=**/tests/**,**/__pycache__/** \
                            -Dsonar.python.coverage.reportPaths=coverage.xml \
                            -Dsonar.python.xunit.reportPath=test-results.xml
                    '''
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
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

                // Post result back to SENTINEL dashboard
                sh """
                    curl -s -X POST ${SENTINEL_URL}/ci/webhook \\
                    -H "Content-Type: application/json" \\
                    -d '{
                        "event":          "build_complete",
                        "build_number":   ${BUILD_NUMBER},
                        "build_url":      "${BUILD_URL}",
                        "repo_url":       "${GIT_URL}",
                        "branch":         "${GIT_BRANCH}",
                        "commit_hash":    "${GIT_COMMIT}",
                        "commit_message": "${currentBuild.description ?: ""}",
                        "author":         "${GIT_AUTHOR_NAME ?: ""}",
                        "status":         "${buildStatus}",
                        "verdict":        "${verdict}",
                        "sentinel": {
                            "total_findings": ${total},
                            "critical":       ${critical},
                            "high":           ${high}
                        }
                    }' || true
                """

                echo "📊 Build result posted to SENTINEL dashboard"
            }
        }

        failure {
            echo "❌ Pipeline failed — check SENTINEL findings or SonarQube quality gate"
        }

        success {
            echo "✅ Pipeline passed — SENTINEL + SonarQube checks clean"
        }

        unstable {
            echo "⚠️ Pipeline unstable — review test failures and scan findings"
        }
    }
}
