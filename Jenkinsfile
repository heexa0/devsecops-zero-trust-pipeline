pipeline {
    agent any

    environment {
        ANTHROPIC_API_KEY = credentials('ANTHROPIC_API_KEY')
        GITHUB_TOKEN      = credentials('GITHUB_TOKEN')
        OLLAMA_URL        = "http://localhost:11434"
        APP_PORT          = "5000"
        IMAGE_NAME        = "zerotrust-app"
        IMAGE_TAG         = "${env.BUILD_NUMBER}"
    }

    options {
        ansiColor('xterm')
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {

        stage('1 · SAST — Semgrep') {
            steps {
                echo '[SAST] Analyse du code...'
                bat """
                semgrep --config=auto test-app/ ^
                --json --output=semgrep-results.json ^
                --severity=WARNING
                exit /b 0
                """
                archiveArtifacts artifacts: 'semgrep-results.json', fingerprint: true
            }
        }

        stage('2 · SCA — Trivy') {
            steps {
                echo '[SCA] Scan dépendances...'
                bat """
                trivy fs ./test-app ^
                --format json ^
                --output trivy-report.json ^
                --severity MEDIUM,HIGH,CRITICAL
                """
                archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
            }
        }

        stage('3 · AI Security Guard') {
            steps {
                echo '[IA] Agents IA...'
                bat "pip install anthropic requests rich --quiet"
                bat "python agent\\antitamper_agent.py"
                bat "python agent\\remediation_agent.py"

                archiveArtifacts artifacts: 'ai-remediation-report.json', allowEmptyArchive: true
            }
        }

        stage('4 · Build Docker') {
            steps {
                echo '[Docker] Build image...'
                bat "docker build -t %IMAGE_NAME%:%IMAGE_TAG% ."
                bat "docker tag %IMAGE_NAME%:%IMAGE_TAG% %IMAGE_NAME%:latest"
            }
        }

        stage('5 · Scan image Trivy') {
            steps {
                bat """
                trivy image %IMAGE_NAME%:%IMAGE_TAG% ^
                --severity CRITICAL ^
                --format table
                """
            }
        }

        stage('6 · DAST — OWASP ZAP') {
            steps {
                echo '[DAST] Scan ZAP...'
                bat """
                docker run -d --name zerotrust-app-dast ^
                -p 5000:5000 %IMAGE_NAME%:%IMAGE_TAG%

                timeout /t 5 /nobreak

                docker run --rm --network host ^
                -v %WORKSPACE%:/zap/wrk ^
                ghcr.io/zaproxy/zaproxy:stable ^
                zap-baseline.py -t http://localhost:5000 ^
                -J zap-report.json -r zap-report.html ^
                -l WARN

                docker stop zerotrust-app-dast
                docker rm zerotrust-app-dast
                """

                archiveArtifacts artifacts: 'zap-report.*', allowEmptyArchive: true
            }
        }

        stage('7 · Signature Cosign') {
            when {
                branch 'main'
            }
            steps {
                echo '[Cosign] Signature...'
                bat "cosign version"
                echo "Image prête : ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }
    }

    post {
        success {
            echo '✓ Pipeline réussi'
        }
        failure {
            echo '✗ Pipeline échoué'
        }
        always {
            bat "docker rm -f zerotrust-app-dast 2>nul || exit /b 0"
        }
    }
}