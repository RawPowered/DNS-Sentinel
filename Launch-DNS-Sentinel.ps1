$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

Write-Host "DNS-Sentinel launcher"
if (!(Test-Path "node_modules")) {
  npm install
}

Start-Process cmd -ArgumentList "/k", "npm run dev" -WorkingDirectory $projectRoot
Start-Sleep -Seconds 4
Start-Process "http://localhost:3000"
