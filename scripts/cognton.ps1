# Solar Farm OT Security Watchman - Windows PowerShell Helper
# Use this script on Windows if you don't have GNU Make (WSL2/Git Bash).
# Equivalent to the Makefile targets.
#
# Usage:
#   .\scripts\cognton.ps1 doctor
#   .\scripts\cognton.ps1 up
#   .\scripts\cognton.ps1 demo
#   .\scripts\cognton.ps1 scenario S1

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("doctor","build","up","down","status","logs","test","baseline","demo","scenario","evaluate","reset","help")]
    [string]$Target,

    [Parameter(Position=1)]
    [string]$Scenario = ""
)

$API_URL = "http://127.0.0.1:8000"
$DASHBOARD_URL = "http://127.0.0.1:8501"
$HMI_URL = "http://127.0.0.1:1881"

function Write-Header($msg) {
    Write-Host ""
    Write-Host "-- $msg" -ForegroundColor Cyan
}

switch ($Target) {
    "help" {
        Write-Host ""
        Write-Host "  Solar Farm OT Security Watchman - Windows Helper" -ForegroundColor Green
        Write-Host "  ================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  .\scripts\cognton.ps1 doctor       Check prerequisites"
        Write-Host "  .\scripts\cognton.ps1 build        Build Docker images"
        Write-Host "  .\scripts\cognton.ps1 up           Start the lab"
        Write-Host "  .\scripts\cognton.ps1 status       Service health"
        Write-Host "  .\scripts\cognton.ps1 logs         Follow service logs"
        Write-Host "  .\scripts\cognton.ps1 test         Run unit + integration tests"
        Write-Host "  .\scripts\cognton.ps1 baseline     Generate ML baseline"
        Write-Host "  .\scripts\cognton.ps1 demo         Run all attack scenarios"
        Write-Host "  .\scripts\cognton.ps1 scenario S1  Run a single scenario"
        Write-Host "  .\scripts\cognton.ps1 evaluate     Compute B.2 metrics"
        Write-Host "  .\scripts\cognton.ps1 reset        Reset lab data"
        Write-Host "  .\scripts\cognton.ps1 down         Stop the lab"
        Write-Host ""
        Write-Host "  URLs (after 'up'):"
        Write-Host "    Dashboard : $DASHBOARD_URL"
        Write-Host "    FUXA HMI  : $HMI_URL"
        Write-Host "    API docs  : $API_URL/docs"
        Write-Host ""
    }

    "doctor" {
        Write-Header "Running preflight checks"
        python scripts\doctor.py
    }

    "build" {
        Write-Header "Building Docker images"
        docker compose build
    }

    "up" {
        Write-Header "Starting the solar farm lab"
        docker compose up -d
        Write-Host "  Waiting for services to start..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        & $PSCommandPath status
        Write-Host ""
        Write-Host "  Dashboard : $DASHBOARD_URL" -ForegroundColor Green
        Write-Host "  FUXA HMI  : $HMI_URL" -ForegroundColor Green
        Write-Host "  API docs  : $API_URL/docs" -ForegroundColor Green
    }

    "down" {
        Write-Header "Stopping the lab"
        docker compose down
    }

    "status" {
        Write-Header "Service Health"
        docker compose ps
        Write-Host ""
        Write-Header "API Health"
        try {
            $r = Invoke-RestMethod -Uri "$API_URL/health" -TimeoutSec 5 -ErrorAction Stop
            $r | ConvertTo-Json
        } catch {
            Write-Host "  API not reachable" -ForegroundColor Red
        }
        Write-Host ""
        Write-Header "Sensor Health"
        try {
            $r = Invoke-RestMethod -Uri "$API_URL/sensor/health" -TimeoutSec 5 -ErrorAction Stop
            $r | ConvertTo-Json
        } catch {
            Write-Host "  Sensor health not available" -ForegroundColor Yellow
        }
    }

    "logs" {
        Write-Header "Following service logs (Ctrl+C to stop)"
        docker compose logs -f --tail=50
    }

    "test" {
        Write-Header "Running unit + integration tests"
        python -m pytest tests/ -v --tb=short
    }

    "baseline" {
        Write-Header "Generating normal-traffic baseline"
        Write-Host "  Posting synthetic baseline to API..." -ForegroundColor Yellow
        python scripts\generate_baseline.py --synthetic
        Write-Host ""
        Write-Host "  Baseline generated. ML model is now trained." -ForegroundColor Green
        Write-Host "  Run '.\scripts\cognton.ps1 demo' to start attack scenarios." -ForegroundColor Green
    }

    "demo" {
        Write-Header "Running full attack scenario demo"
        Write-Host "  All attacks target ONLY local lab containers." -ForegroundColor Yellow
        Write-Host "  No real OT systems, networks, or PLCs are affected." -ForegroundColor Yellow
        Write-Host ""
        python scripts\run_scenario.py all --trial 1
        Write-Host ""
        Write-Host "  Demo complete. View alerts at: $DASHBOARD_URL" -ForegroundColor Green
    }

    "scenario" {
        if ([string]::IsNullOrEmpty($Scenario)) {
            Write-Host "Usage: .\scripts\cognton.ps1 scenario S1" -ForegroundColor Red
            Write-Host "Available: S1 S2 S3 S4 S5" -ForegroundColor Yellow
            exit 1
        }
        Write-Header "Running scenario $Scenario"
        python scripts\run_scenario.py $Scenario
    }

    "evaluate" {
        Write-Header "Running B.2 evaluation trials and metrics scorecard"
        python scripts\evaluate.py --run-trials
    }

    "reset" {
        Write-Header "Resetting lab data"
        Write-Host "  Stopping services..." -ForegroundColor Yellow
        docker compose down
        Write-Host "  Removing SQLite database volume..." -ForegroundColor Yellow
        docker volume rm cognton_db_data 2>$null | Out-Null
        Write-Host "  Removing Zeek logs volume..." -ForegroundColor Yellow
        docker volume rm cognton_zeek_logs 2>$null | Out-Null
        Write-Host "  Removing PCAP data volume..." -ForegroundColor Yellow
        docker volume rm cognton_pcap_data 2>$null | Out-Null
        Write-Host "  Lab data reset. Run '.\scripts\cognton.ps1 up' to restart." -ForegroundColor Green
        Write-Host "  Source files are unchanged." -ForegroundColor Green
    }
}
