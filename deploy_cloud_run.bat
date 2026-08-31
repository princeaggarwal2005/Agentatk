@echo off
REM ==============================================================================
REM AGENTATK — 1-Click Google Cloud Run Deployment Script (Windows)
REM ==============================================================================

echo ==========================================================================
echo           AGENTATK: Deploying to Google Cloud Run (Serverless)            
echo ==========================================================================

where gcloud >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Google Cloud SDK ('gcloud') is not installed or not in PATH.
    echo Install it from: https://cloud.google.com/sdk/docs/install
    exit /b 1
)

set /p PROJECT_ID="Enter your Google Cloud Project ID: "
if "%PROJECT_ID%"=="" (
    echo [ERROR] Project ID is required.
    exit /b 1
)

set REGION=us-central1
set SERVICE_NAME=agentatk

echo [1/3] Enabling required Google Cloud APIs (Cloud Run, Cloud Build, Firestore)...
call gcloud services enable run.googleapis.com cloudbuild.googleapis.com firestore.googleapis.com --project="%PROJECT_ID%"

echo [2/3] Building and deploying AGENTATK directly to Google Cloud Run...
call gcloud run deploy %SERVICE_NAME% --source . --platform managed --region %REGION% --allow-unauthenticated --port 8080 --set-env-vars GOOGLE_CLOUD_PROJECT=%PROJECT_ID%,GEMINI_API_KEY=%GEMINI_API_KEY%

echo [3/3] Deployment complete! Retrieving live service URL...
call gcloud run services describe %SERVICE_NAME% --platform managed --region %REGION% --format "value(status.url)"

echo ==========================================================================
echo Deployment finished. Visit the URL above to access AGENTATK on Cloud Run!
echo ==========================================================================
