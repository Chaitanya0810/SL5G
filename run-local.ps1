$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $basePython = Join-Path $env:LOCALAPPDATA "Programs\Thonny\python.exe"
    if (-not (Test-Path $basePython)) { $basePython = (Get-Command python -ErrorAction Stop).Source }
    & $basePython -m venv (Join-Path $PSScriptRoot ".venv")
}

& $python -c "import fastapi, uvicorn, sklearn, pydantic" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Installing CyberSentinel dependencies failed." }
}

$env:CYBERSENTINEL_LLM_PROVIDER = "ollama"
if ([string]::IsNullOrWhiteSpace($env:OLLAMA_MODEL)) { $env:OLLAMA_MODEL = "qwen2.5:1.5b" }
$env:OPENAI_BASE_URL = "http://localhost:11434/v1"
$env:OPENAI_API_KEY = "ollama-local"

Write-Host "CyberSentinel is using local Ollama model $env:OLLAMA_MODEL. Open http://127.0.0.1:8000"
& $python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
