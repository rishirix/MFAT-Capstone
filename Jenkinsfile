pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Rebuild Docker Images') {
            steps{
                sh 'docker compose down backend || true'
                sh 'docker compose up -d --build backend'
            }
        }

    }
    post {
        success {
            echo '=== MFAT Pipeline PASSED. Dashboard at http://localhost:5000 ==='
        }
        failure {
            echo '=== MFAT Pipeline FAILED. Check the logs above. ==='
        }
        always {
            echo '--- Pipeline finished ---'
        }
    }
}