FROM python:3.13.3-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    openssl \
    ca-certificates \
    bash \
    jq \
    bash-completion \
    build-essential \
    cmake \
    libcurl4  \
    libcurl4-openssl-dev  \
    libssl-dev  \
    libxml2 \
    libxml2-dev  \
    libssl3 \
    pkg-config \
    ca-certificates \
    xclip \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install LastPass CLI
RUN curl -sL https://github.com/lastpass/lastpass-cli/releases/download/v1.6.1/lastpass-cli-1.6.1.tar.gz | tar xz \
    && cd lastpass-cli-1.6.1 \
    && make install \
    && cd .. \
    && rm -rf lastpass-cli-1.6.1

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

# Set non-sensitive environment variables
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "sync_passwords.py"]
