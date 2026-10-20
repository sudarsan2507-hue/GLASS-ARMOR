# Keep Phase 3 going until every sample exists. Every 5 minutes:
#  - if qwen2.5-coder:7b is not installed and no pull is running: start `ollama pull` (it resumes)
#  - if no local migrate.py is running and its model is available: relaunch it (it resumes)
#  - every 30 minutes, if Groq samples are missing and no Groq run is active: relaunch it
#    (it stops by itself, writing nothing, while Groq's daily rate limit is in force)
# Start detached:  Start-Process powershell -WindowStyle Hidden -ArgumentList '-File','scripts\keep_migrating.ps1'
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\.venv\Scripts\python.exe"
$ollama = "C:\Users\sudar\AppData\Local\Programs\Ollama\ollama.exe"
$log = Join-Path $root "results\logs\phase3_migrate.log"
$groqLog = Join-Path $root "results\logs\phase3_groq.log"
$pullLog = Join-Path $root "results\logs\pull_qwen7b_clean.log"
$target = 400  # 3 local models + 1 Groq model, 100 samples each
$lastGroq = [datetime]::MinValue

function Count($dir) { (Get-ChildItem (Join-Path $root "results\raw\$dir") -Recurse -Filter "sample_*.json" -ErrorAction SilentlyContinue).Count }
function Running($pattern) { Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $pattern -and $_.Name -ne 'cmd.exe' -and $_.Name -ne 'powershell.exe' } }

while ($true) {
    $done = (Get-ChildItem (Join-Path $root "results\raw") -Recurse -Filter "sample_*.json" -ErrorAction SilentlyContinue).Count
    if ($done -ge $target) { Add-Content $log "watchdog: all $done samples present, stopping"; break }
    $installed = try { (Invoke-RestMethod -TimeoutSec 10 http://localhost:11434/api/tags).models.name } catch { @() }

    if ($installed -notcontains 'qwen2.5-coder:7b' -and -not (Running 'pull qwen2.5-coder:7b')) {
        Add-Content $log "watchdog: (re)starting qwen2.5-coder:7b download"
        Start-Process -FilePath "cmd.exe" -WindowStyle Hidden -ArgumentList '/c', "$ollama pull qwen2.5-coder:7b >> `"$pullLog`" 2>&1"  # no quotes at the start: cmd /c would mangle them
    }

    if (-not (Running 'migrate.py --models gemma3')) {
        $local = (Count "gemma3_4b") + (Count "qwen2.5-coder_3b") + (Count "qwen2.5-coder_7b")
        if ($local -lt 300 -and ($installed -contains 'qwen2.5-coder:7b' -or (Count "qwen2.5-coder_3b") -lt 100)) {
            Add-Content $log "watchdog: relaunching local migrate.py ($done/$target done)"
            Start-Process -FilePath "cmd.exe" -WindowStyle Hidden -ArgumentList '/c', "set PYTHONUNBUFFERED=1&& `"$py`" `"$root\harness\migrate.py`" --models gemma3:4b qwen2.5-coder:3b qwen2.5-coder:7b >> `"$log`" 2>&1"
        }
    }

    if ((Count "openai_gpt-oss-120b") -lt 100 -and -not (Running 'migrate.py --models openai/gpt-oss') -and ((Get-Date) - $lastGroq).TotalMinutes -ge 30) {
        $lastGroq = Get-Date
        Add-Content $groqLog "watchdog: relaunching Groq run at $lastGroq"
        Start-Process -FilePath "cmd.exe" -WindowStyle Hidden -ArgumentList '/c', "set PYTHONUNBUFFERED=1&& `"$py`" `"$root\harness\migrate.py`" --models openai/gpt-oss-120b >> `"$groqLog`" 2>&1"
    }
    Start-Sleep -Seconds 300
}
