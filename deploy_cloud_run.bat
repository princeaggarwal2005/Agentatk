@echo off
REM ==============================================================================
REM AGENTATK — 1-Click Google Cloud Run Deployment Script (Windows)
REM ==============================================================================

echo ==========================================================================
echo           AGENTATK: Deploying to Google Cloud Run (Serverless)            
echo ==========================================================================

where gcloud >nul 2>&1
if errorlevel 1 goto :no_gcloud

set /p PROJECT_ID="Enter your Google Cloud Project ID: "
if "%PROJECT_ID%"=="" (
    echo [ERROR] Project ID is required.
    exit /b 1
)

set REGION=us-central1
set SERVICE_NAME=agentatk

echo [1/3] Enabling required Google Cloud APIs...
call gcloud services enable run.googleapis.com cloudbuild.googleapis.com firestore.googleapis.com --project="%PROJECT_ID%"

echo [2/3] Building and deploying AGENTATK directly to Google Cloud Run...
call gcloud run deploy %SERVICE_NAME% --source . --platform managed --region %REGION% --allow-unauthenticated --port 8080 --set-env-vars GOOGLE_CLOUD_PROJECT=%PROJECT_ID%,GEMINI_API_KEY=%GEMINI_API_KEY%

echo [3/3] Deployment complete! Retrieving live service URL...
call gcloud run services describe %SERVICE_NAME% --platform managed --region %REGION% --format "value(status.url)"

echo ==========================================================================
echo Deployment finished. Visit the URL above to access AGENTATK on Cloud Run!
echo ==========================================================================
exit /b 0

:no_gcloud
echo.
echo [NOTE] Google Cloud SDK CLI is not installed or not found in PATH.
echo To deploy to Google Cloud Run:
echo 1. Install Google Cloud SDK: https://cloud.google.com/sdk/docs/install
echo 2. Run: gcloud init
echo 3. Re-run: deploy_cloud_run.bat (or deploy_cloud_run.ps1)
echo.
exit /b 1
