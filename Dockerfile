from python:3.12-slim

#run apt update && apt install python3-dev python3-pip -y

workdir /app

copy . .

run pip install --no-cache-dir -r backend/requirements.txt

run mkdir -p /app/dump /app/results

expose 5000

cmd ["python3","backend/app.py"]