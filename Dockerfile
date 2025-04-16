FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    openssl \
    ca-certificates \
    bash \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install LastPass CLI
RUN curl -sL https://github.com/lastpass/lastpass-cli/releases/download/v1.3.7/lastpass-cli-1.3.7.tar.gz | tar xz \
    && cd lastpass-cli-1.3.7 \
    && make install \
    && cd .. \
    && rm -rf lastpass-cli-1.3.7

# Install Bitwarden CLI
RUN npm install -g @bitwarden/cli

# Set up working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script
COPY sync_passwords.py .

# Create volume for logs
VOLUME ["/app/logs"]

# Set environment variables
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "sync_passwords.py"]
