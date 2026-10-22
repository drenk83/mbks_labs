$ErrorActionPreference = 'Continue'
$log = 'C:\Users\winuser\Documents\mbks_labs\lab3\install-result.txt'
$root = 'C:\Users\winuser\Documents\mbks_labs\lab3'
$sysSrc = Join-Path $root 'FsFilterX\x64\Debug\FsFilterX.sys'
$sysDst = Join-Path $env:SystemRoot 'System32\drivers\FsFilterX.sys'
$filetool = Join-Path $root 'filetool\x64\Release\filetool.exe'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$note = 'C:\DriverConfig\data\note.txt'
$report = 'C:\DriverConfig\data\report.txt'
$free = 'C:\DriverConfig\data\free.txt'

function Log([string]$msg) {
    ($msg -replace "`r`n", "`n") | Tee-Object -FilePath $log -Append
}

Set-Content -Path $log -Value ("start " + (Get-Date -Format o)) -Encoding UTF8

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log ("admin: " + $admin)
if (-not $admin) { exit 4 }

try {
    Log ("SecureBoot: " + (Confirm-SecureBootUEFI))
} catch {
    Log ("SecureBoot check: " + $_.Exception.Message)
}

$enum = cmd /c "bcdedit /enum {current}" 2>&1 | Out-String
Log "ENUM:"
Log $enum
if ($enum -notmatch 'testsigning\s+Yes') {
    Log "STOP: testsigning is not Yes"
    exit 2
}

New-Item -ItemType Directory -Force -Path 'C:\DriverConfig\data' | Out-Null
Copy-Item (Join-Path $root 'config\Config.txt') 'C:\DriverConfig\Config.txt' -Force
Copy-Item (Join-Path $root 'config\data\note.txt') $note -Force
Set-Content -Path $report -Value "before" -Encoding ascii
Set-Content -Path $free -Value "free-before" -Encoding ascii
Log ("config bytes: " + (([IO.File]::ReadAllBytes('C:\DriverConfig\Config.txt') | ForEach-Object { $_.ToString('X2') }) -join ' '))

$existing = Get-Service FsFilterX -ErrorAction SilentlyContinue
if ($existing) {
    Log ("service already exists, status " + $existing.Status)
    $unload = cmd /c "fltmc unload FsFilterX" 2>&1 | Out-String
    Log "UNLOAD:"
    Log $unload
    Log ("unload exit: " + $LASTEXITCODE)
    Start-Sleep -Seconds 1
}

if (Test-Path $signtool) {
    $sign = & $signtool sign /fd SHA256 /sha1 906AA1ADCD98DCBC641051CCBEFA9BAADFAB2206 /s My $sysSrc 2>&1 | Out-String
    Log "SIGN:"
    Log $sign
    Log ("sign exit: " + $LASTEXITCODE)
}

Copy-Item $sysSrc $sysDst -Force
Log ("sys dst: " + (Get-Item $sysDst).Length + " " + (Get-Item $sysDst).LastWriteTime.ToString('o'))

if (Test-Path $signtool) {
    $verify = & $signtool verify /pa $sysDst 2>&1 | Out-String
    Log "VERIFY:"
    Log $verify
    Log ("verify exit: " + $LASTEXITCODE)
}

if (-not $existing) {
    $sc = cmd /c 'sc create FsFilterX type= filesys start= demand binPath= \SystemRoot\System32\drivers\FsFilterX.sys depend= FltMgr group= "FSFilter Activity Monitor"' 2>&1 | Out-String
    Log "SC CREATE:"
    Log $sc
    Log ("sc exit: " + $LASTEXITCODE)
}

$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\FsFilterX'
New-Item -Path "$base\Instances" -Force | Out-Null
New-ItemProperty -Path "$base\Instances" -Name DefaultInstance -Value 'FsFilterX Instance' -PropertyType String -Force | Out-Null
New-Item -Path "$base\Instances\FsFilterX Instance" -Force | Out-Null
New-ItemProperty -Path "$base\Instances\FsFilterX Instance" -Name Altitude -Value '370030' -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$base\Instances\FsFilterX Instance" -Name Flags -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name Group -Value 'FSFilter Activity Monitor' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $base -Name DebugFlags -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $base -Name SupportedFeatures -Value 3 -PropertyType DWord -Force | Out-Null

function Try-Load([string]$altitude) {
    New-ItemProperty -Path "$base\Instances\FsFilterX Instance" -Name Altitude -Value $altitude -PropertyType String -Force | Out-Null
    Log ("load altitude " + $altitude)
    $out = cmd /c "fltmc load FsFilterX" 2>&1 | Out-String
    Log $out
    Log ("fltmc load exit: " + $LASTEXITCODE)
    $filters = cmd /c "fltmc filters" 2>&1 | Out-String
    Log "FILTERS:"
    Log $filters
    return ($filters -match 'FsFilterX')
}

$loaded = Try-Load '370030'
if (-not $loaded) {
    cmd /c "fltmc unload FsFilterX" | Out-Null
    $loaded = Try-Load '370031'
}

$instances = cmd /c "fltmc instances" 2>&1 | Out-String
Log "INSTANCES:"
Log $instances

if (-not $loaded) {
    Log "STOP: filter is not loaded"
    exit 3
}

function Run-Tool([string]$title, [string]$exe, [string[]]$argList) {
    Log ("---- " + $title)
    Log ("CMD: " + $exe + " " + ($argList -join ' '))
    $out = & $exe @argList 2>&1 | Out-String
    Log ("tool exit: " + $LASTEXITCODE)
    Log ("stdout: [" + ($out -replace "`r", '<CR>' -replace "`n", '<LF>') + "]")
}

function Show-File([string]$path) {
    $t = [IO.File]::ReadAllText($path)
    Log ("content " + $path + " = [" + ($t -replace "`r", '<CR>' -replace "`n", '<LF>') + "]")
}

Copy-Item (Join-Path $root 'config\data\note.txt') $note -Force
Set-Content -Path $report -Value "before" -Encoding ascii
Set-Content -Path $free -Value "free-before" -Encoding ascii
Show-File $note

Run-Tool 'filetool read note' $filetool @('r', $note)
Show-File $note
Run-Tool 'filetool write note denied' $filetool @('w', $note, 'hacked')
Show-File $note
Run-Tool 'filetool write report' $filetool @('w', $report, 'written')
Show-File $report
Run-Tool 'filetool read report' $filetool @('r', $report)
Run-Tool 'filetool write free' $filetool @('w', $free, 'free-written')
Show-File $free

$notepadDir = Join-Path $env:TEMP 'lab3-notepad'
New-Item -ItemType Directory -Force -Path $notepadDir | Out-Null
$notepad = Join-Path $notepadDir 'notepad.exe'
Copy-Item $filetool $notepad -Force
Run-Tool 'notepad read note' $notepad @('r', $note)
Run-Tool 'notepad write note' $notepad @('w', $note, 'notepad-hacked')
Show-File $note

Log "done"
exit 0
