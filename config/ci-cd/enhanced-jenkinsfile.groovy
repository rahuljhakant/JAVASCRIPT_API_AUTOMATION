// Enhanced Jenkinsfile for JavaScript API Automation Project
// Advanced CI/CD pipeline with comprehensive testing and deployment

pipeline {
    agent any
    
    options {
        skipDefaultCheckout()
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 60, unit: 'MINUTES')
        retry(3)
    }
    
    parameters {
        choice(
            name: 'ENVIRONMENT',
            choices: ['staging', 'production'],
            description: 'Target environment for deployment'
        )
        booleanParam(
            name: 'RUN_FULL_TEST_SUITE',
            defaultValue: true,
            description: 'Run complete test suite including performance and security tests'
        )
        booleanParam(
            name: 'SKIP_TESTS',
            defaultValue: false,
            description: 'Skip all tests (use with caution)'
        )
        string(
            name: 'CUSTOM_BRANCH',
            defaultValue: '',
            description: 'Custom branch to build (leave empty for current branch)'
        )
    }
    
    environment {
        NODE_VERSION = '18'
        DOCKER_REGISTRY = 'your-registry.com'
        IMAGE_NAME = "${env.JOB_NAME.toLowerCase()}"
        KUBECONFIG = credentials('kubeconfig')
        SONAR_TOKEN = credentials('sonar-token')
        SLACK_WEBHOOK = credentials('slack-webhook')
        GITHUB_TOKEN = credentials('github-token')
    }
    
    stages {
        stage('Checkout & Setup') {
            steps {
                script {
                    if (params.CUSTOM_BRANCH) {
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: "*/${params.CUSTOM_BRANCH}"]],
                            userRemoteConfigs: [[url: env.GIT_URL]]
                        ])
                    } else {
                        checkout scm
                    }
                }
                
                sh 'rm -rf node_modules package-lock.json'
                
                script {
                    env.BUILD_NUMBER = currentBuild.number
                    env.BUILD_URL = env.BUILD_URL
                    env.GIT_COMMIT = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                    env.GIT_BRANCH = sh(script: 'git rev-parse --abbrev-ref HEAD', returnStdout: true).trim()
                }
            }
        }
        
        stage('Code Quality & Security') {
            parallel {
                stage('Linting & Formatting') {
                    steps {
                        sh 'npm ci'
                        sh 'npm run lint'
                        sh 'npm run format -- --check'
                    }
                }
                
                stage('Security Audit') {
                    steps {
                        sh 'npm audit --audit-level=moderate'
                        sh 'npm run security:scan'
                    }
                }
                
                stage('SonarQube Analysis') {
                    steps {
                        script {
                            def scannerHome = tool 'SonarQubeScanner'
                            withSonarQubeEnv('SonarQube') {
                                sh "${scannerHome}/bin/sonar-scanner " +
                                   "-Dsonar.projectKey=${env.JOB_NAME} " +
                                   "-Dsonar.projectName=${env.JOB_NAME} " +
                                   "-Dsonar.projectVersion=${env.BUILD_NUMBER} " +
                                   "-Dsonar.sources=. " +
                                   "-Dsonar.exclusions=node_modules/**,coverage/**,dist/** " +
                                   "-Dsonar.javascript.lcov.reportPaths=coverage/lcov.info"
                            }
                        }
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Unit & Integration Tests') {
            when {
                not { params.SKIP_TESTS }
            }
            parallel {
                stage('Unit Tests') {
                    steps {
                        sh 'npm run test:unit'
                        publishTestResults testResultsPattern: 'test-results/unit-*.xml'
                    }
                }
                
                stage('Integration Tests') {
                    steps {
                        sh 'npm run test:integration'
                        publishTestResults testResultsPattern: 'test-results/integration-*.xml'
                    }
                }
                
                stage('Contract Tests') {
                    steps {
                        sh 'npm run test:contract'
                        publishTestResults testResultsPattern: 'test-results/contract-*.xml'
                    }
                }
            }
            post {
                always {
                    publishCoverage adapters: [
                        jacocoAdapter('coverage/lcov.info')
                    ], sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                }
            }
        }
        
        stage('Advanced Testing') {
            when {
                allOf {
                    not { params.SKIP_TESTS }
                    params.RUN_FULL_TEST_SUITE
                }
            }
            parallel {
                stage('Performance Tests') {
                    steps {
                        sh 'npm run test:performance'
                        archiveArtifacts artifacts: 'performance-results/**', fingerprint: true
                    }
                }
                
                stage('Security Tests') {
                    steps {
                        sh 'npm run test:security'
                        publishTestResults testResultsPattern: 'test-results/security-*.xml'
                    }
                }
                
                stage('Cross-Browser Tests') {
                    steps {
                        sh 'npm run test:cross-browser'
                        archiveArtifacts artifacts: 'cross-browser-results/**', fingerprint: true
                    }
                }
                
                stage('Mutation Tests') {
                    steps {
                        sh 'npm run test:mutation'
                        archiveArtifacts artifacts: 'mutation-results/**', fingerprint: true
                    }
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    def imageTag = "${env.DOCKER_REGISTRY}/${env.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    def latestTag = "${env.DOCKER_REGISTRY}/${env.IMAGE_NAME}:latest"
                    
                    sh "docker build -t ${imageTag} -t ${latestTag} ."
                    
                    withCredentials([usernamePassword(credentialsId: 'docker-registry', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
                        sh "echo \$DOCKER_PASSWORD | docker login ${env.DOCKER_REGISTRY} -u \$DOCKER_USERNAME --password-stdin"
                        sh "docker push ${imageTag}"
                        sh "docker push ${latestTag}"
                    }
                    
                    env.DOCKER_IMAGE = imageTag
                }
            }
        }
        
        stage('Docker Security Scan') {
            steps {
                script {
                    sh "trivy image --format json --output trivy-results.json ${env.DOCKER_IMAGE}"
                    sh "trivy image --format table ${env.DOCKER_IMAGE}"
                }
                archiveArtifacts artifacts: 'trivy-results.json', fingerprint: true
            }
        }
        
        stage('Deploy to Staging') {
            when {
                anyOf {
                    branch 'develop'
                    params.ENVIRONMENT == 'staging'
                }
            }
            steps {
                script {
                    sh "kubectl config use-context staging"
                    sh "kubectl apply -f k8s/staging/"
                    sh "kubectl set image deployment/api-automation api-automation=${env.DOCKER_IMAGE}"
                    sh "kubectl rollout status deployment/api-automation"
                }
            }
        }
        
        stage('Staging Tests') {
            when {
                anyOf {
                    branch 'develop'
                    params.ENVIRONMENT == 'staging'
                }
            }
            parallel {
                stage('Smoke Tests') {
                    steps {
                        sh 'npm run test:smoke -- --env=staging'
                    }
                }
                
                stage('Health Checks') {
                    steps {
                        sh 'npm run test:health -- --env=staging'
                    }
                }
                
                stage('API Tests') {
                    steps {
                        sh 'npm run test:api -- --env=staging'
                    }
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                allOf {
                    anyOf {
                        branch 'main'
                        params.ENVIRONMENT == 'production'
                    }
                    not { params.SKIP_TESTS }
                }
            }
            steps {
                script {
                    sh "kubectl config use-context production"
                    sh "kubectl apply -f k8s/production/"
                    sh "kubectl set image deployment/api-automation api-automation=${env.DOCKER_IMAGE}"
                    sh "kubectl rollout status deployment/api-automation"
                }
            }
        }
        
        stage('Production Tests') {
            when {
                anyOf {
                    branch 'main'
                    params.ENVIRONMENT == 'production'
                }
            }
            parallel {
                stage('Smoke Tests') {
                    steps {
                        sh 'npm run test:smoke -- --env=production'
                    }
                }
                
                stage('Health Checks') {
                    steps {
                        sh 'npm run test:health -- --env=production'
                    }
                }
                
                stage('Performance Monitoring') {
                    steps {
                        sh 'npm run test:monitoring -- --env=production'
                    }
                }
            }
        }
        
        stage('Generate Reports') {
            steps {
                script {
                    sh 'npm run generate:allure-report'
                    sh 'npm run generate:coverage-report'
                    sh 'npm run generate:performance-report'
                }
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'allure-report',
                    reportFiles: 'index.html',
                    reportName: 'Allure Test Report'
                ])
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'coverage-report',
                    reportFiles: 'index.html',
                    reportName: 'Coverage Report'
                ])
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'performance-report',
                    reportFiles: 'index.html',
                    reportName: 'Performance Report'
                ])
            }
        }
        
        stage('Create Release') {
            when {
                branch 'main'
            }
            steps {
                script {
                    def releaseNotes = """
                    ## Release ${env.BUILD_NUMBER}
                    
                    **Build Information:**
                    - Build Number: ${env.BUILD_NUMBER}
                    - Git Commit: ${env.GIT_COMMIT}
                    - Git Branch: ${env.GIT_BRANCH}
                    - Build URL: ${env.BUILD_URL}
                    
                    **Docker Image:** ${env.DOCKER_IMAGE}
                    
                    **Test Results:**
                    - Unit Tests: ${currentBuild.description}
                    - Integration Tests: ${currentBuild.description}
                    - Performance Tests: ${currentBuild.description}
                    - Security Tests: ${currentBuild.description}
                    """
                    
                    sh "echo '${releaseNotes}' > release-notes.md"
                    
                    withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                        sh """
                            curl -X POST \
                                -H "Authorization: token \$GITHUB_TOKEN" \
                                -H "Accept: application/vnd.github.v3+json" \
                                https://api.github.com/repos/${env.JOB_NAME}/releases \
                                -d '{
                                    "tag_name": "v${env.BUILD_NUMBER}",
                                    "target_commitish": "${env.GIT_COMMIT}",
                                    "name": "Release v${env.BUILD_NUMBER}",
                                    "body": "${releaseNotes}",
                                    "draft": false,
                                    "prerelease": false
                                }'
                        """
                    }
                }
            }
        }
    }
    
    post {
        always {
            script {
                // Clean up workspace
                sh 'docker system prune -f'
                sh 'rm -rf node_modules'
                
                // Archive artifacts
                archiveArtifacts artifacts: 'test-results/**', fingerprint: true
                archiveArtifacts artifacts: 'coverage/**', fingerprint: true
                archiveArtifacts artifacts: 'allure-results/**', fingerprint: true
            }
        }
        
        success {
            script {
                def message = """
                ✅ *Build Successful* - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                
                **Branch:** ${env.GIT_BRANCH}
                **Commit:** ${env.GIT_COMMIT}
                **Environment:** ${params.ENVIRONMENT ?: 'N/A'}
                
                **Reports:**
                - Test Report: ${env.BUILD_URL}allure/
                - Coverage Report: ${env.BUILD_URL}coverage/
                - Performance Report: ${env.BUILD_URL}performance/
                
                **Docker Image:** ${env.DOCKER_IMAGE ?: 'N/A'}
                """
                
                slackSend(
                    channel: '#deployments',
                    color: 'good',
                    message: message
                )
            }
        }
        
        failure {
            script {
                def message = """
                ❌ *Build Failed* - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                
                **Branch:** ${env.GIT_BRANCH}
                **Commit:** ${env.GIT_COMMIT}
                **Environment:** ${params.ENVIRONMENT ?: 'N/A'}
                
                **Build URL:** ${env.BUILD_URL}
                """
                
                slackSend(
                    channel: '#deployments',
                    color: 'danger',
                    message: message
                )
            }
        }
        
        unstable {
            script {
                def message = """
                ⚠️ *Build Unstable* - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                
                **Branch:** ${env.GIT_BRANCH}
                **Commit:** ${env.GIT_COMMIT}
                **Environment:** ${params.ENVIRONMENT ?: 'N/A'}
                
                **Build URL:** ${env.BUILD_URL}
                """
                
                slackSend(
                    channel: '#deployments',
                    color: 'warning',
                    message: message
                )
            }
        }
        
        cleanup {
            script {
                // Clean up Docker images
                sh 'docker rmi $(docker images -q) 2>/dev/null || true'
                
                // Clean up workspace
                cleanWs()
            }
        }
    }
}



