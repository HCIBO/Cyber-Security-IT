Write-Host "Stopping GlobalProtect service..." -ForegroundColor Yellow
Stop-Service -Name PanGPS -Force -ErrorAction SilentlyContinue

$gpLocalPath = "$env:LOCALAPPDATA\Palo Alto Networks\GlobalProtect"
$gpRoamingPath = "$env:APPDATA\Palo Alto Networks\GlobalProtect"

Write-Host "Cleaning cached GlobalProtect configurations..." -ForegroundColor Yellow
if (Test-Path $gpLocalPath) {
    Remove-Item -Path $gpLocalPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Deleted: $gpLocalPath" -ForegroundColor Green
} else {
    Write-Host "Not found: $gpLocalPath" -ForegroundColor DarkGray
}

if (Test-Path $gpRoamingPath) {
    Remove-Item -Path $gpRoamingPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Deleted: $gpRoamingPath" -ForegroundColor Green
} else {
    Write-Host "Not found: $gpRoamingPath" -ForegroundColor DarkGray
}

Write-Host "Starting GlobalProtect service..." -ForegroundColor Yellow
Start-Service -Name PanGPS -ErrorAction SilentlyContinue

$gpApp = "$env:ProgramFiles\Palo Alto Networks\GlobalProtect\PanGPA.exe"
if (Test-Path $gpApp) {
    Start-Process -FilePath $gpApp
    Write-Host "GlobalProtect restarted successfully." -ForegroundColor Cyan
} else {
    Write-Host "GlobalProtect application not found at expected path: $gpApp" -ForegroundColor Red
}
