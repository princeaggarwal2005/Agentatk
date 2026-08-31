#!/bin/bash
# ==============================================================================
# AGENTATK — 1-Click Google Cloud Run Deployment Script
# ==============================================================================

set -e

echo "=========================================================================="
echo "          AGENTATK: Deploying to Google Cloud Run (Serverless)            "
echo "=========================================================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "[ERROR] Google Cloud SDK ('gcloud') is not installed or not in PATH."
    echo "Install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Retrieve or prompt for GCP Project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "(unset)" ]; then
    read -p "Enter your Google Cloud Project ID: " PROJECT_ID
    gcloud config set project "$PROJECT_ID"
fi

REGION="us-central1"
SERVICE_NAME="agentatk"

echo "[1/3] Enabling required Google Cloud APIs (Cloud Run, Cloud Build, Firestore)..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com firestore.googleapis.com --project="$PROJECT_ID"

echo "[2/3] Building and deploying AGENTATK directly to Google Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
    --source . \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --port 8080 \
    --set-env-vars "GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GEMINI_API_KEY=${GEMINI_API_KEY:-}"

echo "[3/3] Deployment complete! Retrieving live service URL..."
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --platform managed --region "$REGION" --format 'value(status.url)')

echo "=========================================================================="
echo "🚀 AGENTATK is LIVE on Google Cloud Run at:"
echo "   $SERVICE_URL"
echo "=========================================================================="
