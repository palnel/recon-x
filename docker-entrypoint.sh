#!/bin/sh
set -e

# Validate required environment variables
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL environment variable is required but not set."
    echo "Please set DATABASE_URL to a valid PostgreSQL connection string."
    echo "Example: postgres://user:password@host:5432/dbname"
    exit 1
fi

# Validate DATABASE_URL format (basic check)
if ! echo "$DATABASE_URL" | grep -qE '^postgres://'; then
    echo "WARNING: DATABASE_URL does not appear to be a valid PostgreSQL connection string."
    echo "Expected format: postgres://user:password@host:5432/dbname"
fi

# Set default PORT if not provided
export PORT=${PORT:-8080}

# Start the application
exec ./recon-x -server -port "$PORT"

