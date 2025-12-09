pipeline {
    agent any
    
    environment {
        NODE_VERSION = '18'
        DOCKER_REGISTRY = 'your-registry.com'
        IMAGE_NAME = 'api-automation'
        IMAGE_TAG = "${BUILD_NUMBER}"
        ALLURE_RESULTS = 'allure-results'
        ALLURE_REPORT = 'allure-report'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT_SHORT = sh(
                        script: "git rev-parse --short HEAD",
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Environment Setup') {
            parallel {
                stage('Node.js Setup') {
                    steps {
                        script {
                            def nodeHome = tool name: "NodeJS-${NODE_VERSION}", type: 'nodejs'
                            env.PATH = "${nodeHome}/bin:${env.PATH}"
                        }
                        sh 'node --version'
                        sh 'npm --version'
                    }
                }
                
                stage('Docker Setup') {
                    steps {
                        sh 'docker --version'
                        sh 'docker-compose --version'
                    }
                }
            }
        }
        
        stage('Dependencies') {
            steps {
                sh 'npm ci'
                sh 'npm run lint'
            }
        }
        
        stage('Build') {
            steps {
                sh 'npm run docs:generate'
            }
        }
        
        stage('Test') {
            parallel {
                stage('Beginner Tests') {
                    steps {
                        sh 'npm run test:beginner'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/beginner-*.xml'
                        }
                    }
                }
                
                stage('Design Patterns Tests') {
                    steps {
                        sh 'npm run test:design-patterns'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/design-patterns-*.xml'
                        }
                    }
                }
                
                stage('Intermediate Tests') {
                    steps {
                        sh 'npm run test:intermediate'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/intermediate-*.xml'
                        }
                    }
                }
                
                stage('Advanced Tests') {
                    steps {
                        sh 'npm run test:advanced'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/advanced-*.xml'
                        }
                    }
                }
                
                stage('Professional Tests') {
                    steps {
                        sh 'npm run test:professional'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/professional-*.xml'
                        }
                    }
                }
                
                stage('Expert Tests') {
                    steps {
                        sh 'npm run test:expert'
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'test-results/expert-*.xml'
                        }
                    }
                }
            }
        }
        
        stage('Performance Tests') {
            steps {
                sh 'npm run test:performance'
            }
            post {
                always {
                    publishTestResults testResultsPattern: 'performance-results/*.xml'
                }
            }
        }
        
        stage('Security Tests') {
            steps {
                sh 'npm audit --audit-level moderate'
                sh 'npm run security:scan'
            }
        }
        
        stage('Docker Build') {
            steps {
                script {
                    docker.build("${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}")
                    docker.build("${DOCKER_REGISTRY}/${IMAGE_NAME}:latest")
                }
            }
        }
        
        stage('Docker Test') {
            steps {
                sh 'docker-compose -f docker-compose.test.yml up --abort-on-container-exit'
            }
            post {
                always {
                    sh 'docker-compose -f docker-compose.test.yml down'
                }
            }
        }
        
        stage('Generate Reports') {
            steps {
                sh 'npm run allure:generate'
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                sh 'docker-compose -f docker-compose.staging.yml up -d'
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                input message: 'Deploy to production?', ok: 'Deploy'
                sh 'docker-compose -f docker-compose.prod.yml up -d'
            }
        }
    }
    
    post {
        always {
            // Clean workspace
            cleanWs()
            
            // Archive artifacts
            archiveArtifacts artifacts: 'allure-report/**/*', fingerprint: true
            archiveArtifacts artifacts: 'screenshots/**/*', fingerprint: true
            archiveArtifacts artifacts: 'logs/**/*', fingerprint: true
            
            // Publish Allure Report
            allure([
                includeProperties: false,
                jdk: '',
                properties: [],
                reportBuildPolicy: 'ALWAYS',
                results: [[path: "${ALLURE_RESULTS}"]]
            ])
            
            // Publish HTML Report
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: "${ALLURE_REPORT}",
                reportFiles: 'index.html',
                reportName: 'API Test Report'
            ])
            
            // Publish Test Results
            publishTestResults testResultsPattern: 'test-results/**/*.xml'
        }
        
        success {
            script {
                def message = """
                ✅ *API Automation Pipeline SUCCESS* ✅
                
                *Build:* #${BUILD_NUMBER}
                *Branch:* ${env.BRANCH_NAME}
                *Commit:* ${env.GIT_COMMIT_SHORT}
                *Duration:* ${currentBuild.durationString}
                
                *Reports:*
                • Allure Report: ${BUILD_URL}allure/
                • Test Results: ${BUILD_URL}testReport/
                
                *Docker Images:*
                • ${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                • ${DOCKER_REGISTRY}/${IMAGE_NAME}:latest
                """
                
                slackSend(
                    channel: '#api-automation',
                    color: 'good',
                    message: message
                )
            }
        }
        
        failure {
            script {
                def message = """
                ❌ *API Automation Pipeline FAILED* ❌
                
                *Build:* #${BUILD_NUMBER}
                *Branch:* ${env.BRANCH_NAME}
                *Commit:* ${env.GIT_COMMIT_SHORT}
                *Duration:* ${currentBuild.durationString}
                
                *Failed Stage:* ${env.STAGE_NAME}
                
                *Logs:* ${BUILD_URL}console
                """
                
                slackSend(
                    channel: '#api-automation',
                    color: 'danger',
                    message: message
                )
            }
        }
        
        unstable {
            script {
                def message = """
                ⚠️ *API Automation Pipeline UNSTABLE* ⚠️
                
                *Build:* #${BUILD_NUMBER}
                *Branch:* ${env.BRANCH_NAME}
                *Commit:* ${env.GIT_COMMIT_SHORT}
                *Duration:* ${currentBuild.durationString}
                
                *Reports:* ${BUILD_URL}allure/
                """
                
                slackSend(
                    channel: '#api-automation',
                    color: 'warning',
                    message: message
                )
            }
        }
    }
}
