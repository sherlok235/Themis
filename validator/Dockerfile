FROM python:3.12-slim

# Install Firefox dependencies manually (avoids `playwright install-deps`
# which breaks on Debian trixie due to renamed/missing packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl \
    libgtk-3-0 \
    libx11-xcb1 \
    libdbus-glib-1-2 \
    libxt6 \
    libxrender1 \
    libxrandr2 \
    libxfixes3 \
    libxcomposite1 \
    libxdamage1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcairo-gobject2 \
    libgdk-pixbuf-xlib-2.0-0 \
    libnss3 \
    libnspr4 \
    libxss1 \
    libgbm1 \
    libpci3 \
    fonts-liberation \
    fonts-noto-color-emoji \
    fonts-unifont \
    && rm -rf /var/lib/apt/lists/*

# Install exact playwright version
RUN pip install --no-cache-dir playwright==1.44.0

# Install Firefox binary only (skip install-deps — done above manually)
RUN playwright install firefox

WORKDIR /app
COPY validator.py .

EXPOSE 9001
CMD ["python3", "validator.py"]
