# Keep Phase 4 (harness/repair.py) going until both parts print "Finished."
#  - local models: relaunched whenever not running (it resumes)
#  - Groq model: relaunched every 30 minutes when not running (it stops itself on rate limits)
# Start detached:  Start-Process powershell -WindowStyle Hidden -ArgumentList '-File','scripts\keep_repairing.ps1'
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\.venv\Scripts\python.exe"
$localLog = Join-Path $root "results\logs\phase4_local.log"
$groqLog = Join-Path $root "results\logs\phase4_groq.log"
$lastGroq = [datetime]::MinValue

function Running($pattern) { Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match $pattern } }
function Finished($file) { (Test-Path $file) -and ((Get-Content $file -Tail 1) -match '^Finished\.') }

while (-not ((Finished $localLog) -and (Finished $groqLog))) {
    if (-not (Finished $localLog) -and -not (Running 'repair.py --models gemma3')) {
        Add-Content $localLog "watchdog: launching local repair at $(Get-Date)"
        Start-Process -FilePath "cmd.exe" -WindowStyle Hidden -ArgumentList '/c', "set PYTHONUNBUFFERED=1&& `"$py`" `"$root\harness\repair.py`" --models gemma3:4b qwen2.5-coder:3b qwen2.5-coder:7b >> `"$localLog`" 2>&1"
    }
    if (-not (Finished $groqLog) -and -not (Running 'repair.py --models openai/gpt-oss') -and ((Get-Date) - $lastGroq).TotalMinutes -ge 30) {
        $lastGroq = Get-Date
        Add-Content $groqLog "watchdog: launching Groq repair at $lastGroq"
        Start-Process -FilePath "cmd.exe" -WindowStyle Hidden -ArgumentList '/c', "set PYTHONUNBUFFERED=1&& `"$py`" `"$root\harness\repair.py`" --models openai/gpt-oss-120b >> `"$groqLog`" 2>&1"
    }
    Start-Sleep -Seconds 300
}
