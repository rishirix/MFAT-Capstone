pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t backend:latest .'
            }
        }

        stage('Stop Old Container') {
            steps {
                sh 'docker rm -f backend || true'
            }
        }

        stage('Run New Container') {
            steps {
                sh '''
                docker run -d \
                  --name backend \
                  -p 5000:5000 \
                  -v dumps:/app/dump \
                  -v results:/app/results \
                  backend:latest
                '''
            }
        }
    }
}