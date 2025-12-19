FROM python:3.10-slim

WORKDIR /app

# System deps + Node.js (needed for npm install)
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    procps \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install python deps first (cache-friendly)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest
COPY . .

# Start
CMD ["python", "bot.py"]
