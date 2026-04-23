pipeline {
    agent any

    environment {
        MFAT_IMAGE = "mfat-backend"
        VOL2_IMAGE = "vol2"
        VOL3_IMAGE = "vol3"
    }

    stages {

        stage('Checkout') {
            steps {
                echo '--- Pulling latest code ---'
                checkout scm
            }
        }

        stage('Build Volatility3') {
            parallel {
                
                stage('Build vol3') {
                    steps {
                        sh 'docker build -t vol3 ./volatility3'
                    }
                }
            }
        }

        stage('Build Volatility2') {
            parallel {
                
                stage('Build vol2') {
                    steps {
                        sh 'docker build -t vol2 ./volatility2'
                    }
                }
            }
        }

        stage('Build Backend') {
            steps {
                echo '--- Building MFAT backend image ---'
                sh 'docker build -t mfat-backend -f backend/Dockerfile .'
            }
        }

        stage('Run Tests') {
            steps {
                echo '--- Running unit tests ---'
                sh '''
                    docker run --rm mfat-backend python -c "
import sys
sys.path.insert(0, '/app/preprocessing')
import parser
# Quick sanity check
result = parser.parse_pslist('System 4 0 82 0 ---- 0')
print('Parser test passed:', result)
"
                '''
            }
        }

        stage('Deploy') {
            steps {
                echo '--- Deploying MFAT ---'
                sh '''
                    docker stop mfat-backend-run 2>/dev/null || true
                    docker rm   mfat-backend-run 2>/dev/null || true
                    docker run -d \
                        --name mfat-backend-run \
                        -p 5000:5000 \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        -v mfat_dumps:/app/dump \
                        -v mfat_results:/app/results \
                        mfat-backend
                '''
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




