# setup_git.ps1 - one-shot git fix for the phishing-detector project
$ErrorActionPreference = "Continue"
$proj = "C:\Users\Abubaker\Desktop\files\phishing-detector"
Set-Location $proj
Write-Host "== project folder =="
(Get-Location).Path

if (-not (Test-Path ".git")) {
    git init
} else {
    Write-Host "repo already initialized"
}
git config user.name "Abubaker"
git config user.email "abubakerchemingui@gmail.com"

Set-Content -Path ".gitignore" -Value @(
    "*.pkl",
    "data/*.csv",
    "data/validation/",
    "__pycache__/",
    ".pytest_cache/",
    "out.txt"
) -Encoding utf8

git add -A
git commit -m "init: phishing detector + SMTP firewall (hardened core, tests, docs)"

$hasRemote = $false
if (git remote | Select-String -Quiet "^origin$") { $hasRemote = $true }
if (-not $hasRemote) {
    Write-Host ""
    Write-Host "== REMOTE NOT SET. Run this yourself in the same window: =="
    Write-Host "gh repo create phishing-detector --private --source . --push"
} else {
    git push -u origin main
}

Write-Host ""
Write-Host "== git log =="
git log --oneline -5
Write-Host ""
Write-Host "== git status =="
git status
Write-Host ""
Write-Host "DONE - paste everything above back to me."