# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12.6
FROM python:${PYTHON_VERSION}-slim as base

# Prevent Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create a non-privileged user that the app will run under.
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Download dependencies as a separate step to take advantage of Docker's caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Switch to the non-privileged user to run the application.
USER appuser

# Copy the source code into the container.
COPY app.py .
COPY config.py .
COPY functions.py .

# Expose the port that the application listens on.
EXPOSE 8000

# Run the application.
CMD ["gunicorn", "app:app", "--bind=0.0.0.0:8000"]
