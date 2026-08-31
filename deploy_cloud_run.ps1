# ==============================================================================
# AGENTATK — 1-Click Google Cloud Run Deployment Script (PowerShell)
# ==============================================================================

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "          AGENTATK: Deploying to Google Cloud Run (Serverless)            " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Check if gcloud CLI is installed
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Host "`n[NOTE] Google Cloud SDK ('gcloud') CLI is not installed or not in PATH." -ForegroundColor Yellow
    Write-Host "To deploy to Google Cloud Run:" -ForegroundColor White
    Write-Host "1. Download Google Cloud SDK: https://cloud.google.com/sdk/docs/install" -ForegroundColor Cyan
    Write-Host "2. Run: gcloud init" -ForegroundColor Cyan
    Write-Host "3. Re-run this script: .\deploy_cloud_run.ps1`n" -ForegroundColor Cyan
    exit 1
}

# 2. Retrieve Project ID
$projectId = gcloud config get-value project 2>$null
if (-not $projectId -or $projectId -eq "(unset)") {
    $projectId = Read-Host "Enter your Google Cloud Project ID"
    if (-not $projectId) {
        Write-Host "[ERROR] Google Cloud Project ID is required." -ForegroundColor Red
        exit 1
    }
    gcloud config set project $projectId
}

$region = "us-central1"
$serviceName = "agentatk"

Write-Host "`n[1/3] Enabling required Google Cloud APIs (Cloud Run, Cloud Build, Firestore)..." -ForegroundColor Yellow
gcloud services enable run.googleapis.com cloudbuild.googleapis.com firestore.googleapis.com --project $projectId

Write-Host "[2/3] Building and deploying AGENTATK directly to Google Cloud Run..." -ForegroundColor Yellow
$geminiKey = $env:GEMINI_API_KEY
gcloud run deploy $serviceName `
    --source . `
    --platform managed `
    --region $region `
    --allow-unauthenticated `
    --port 8080 `
    --set-env-vars "GOOGLE_CLOUD_PROJECT=$projectId,GEMINI_API_KEY=$geminiKey"

Write-Host "[3/3] Deployment complete! Retrieving live service URL..." -ForegroundColor Yellow
$serviceUrl = gcloud run services describe $serviceName --platform managed --region $region --format "value(status.url)"

Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host "🚀 AGENTATK is LIVE on Google Cloud Run at:" -ForegroundColor Green
Write-Host "   $serviceUrl" -ForegroundColor Cyan
Write-Host "==========================================================================`n" -ForegroundColor Green
