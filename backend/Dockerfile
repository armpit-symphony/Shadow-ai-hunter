FROM python:3.11-slim

# Install system dependencies for network scanning
RUN apt-get update && apt-get install -y \
    nmap \
    tcpdump \
    net-tools \
    iproute2 \
    iptables \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security (but with sudo access for network ops)
RUN useradd -m -s /bin/bash shadowai && \
    usermod -aG sudo shadowai && \
    echo 'shadowai ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/sbin/iptables, /usr/bin/tcpdump' >> /etc/sudoers

# Set permissions
RUN chown -R shadowai:shadowai /app

# Switch to non-root user
USER shadowai

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/api/health')"

# Start command
CMD ["python", "server.py"]