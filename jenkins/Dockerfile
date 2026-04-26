FROM jenkins/jenkins:lts

USER root

# Install Docker CLI
RUN apt-get update && apt-get install -y docker.io \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Allow jenkins user to run docker
RUN usermod -aG docker jenkins

USER jenkins
