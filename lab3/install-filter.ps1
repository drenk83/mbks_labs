# Ставит FsFilterX и прогоняет проверки варианта 9.
# Запускать от администратора. Старый C:\DriverConfig\Config.txt не трогает.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\winuser\Documents\mbks_labs\lab3\install-result.txt'
$root = 'C:\Users\winuser\Documents\mbks_labs\lab3'
$sysSrc = Join-Path $root 'FsFilterX\FsFilterX\x64\Debug\FsFilterX.sys'
$sysDst = Join-Path $env:SystemRoot 'System32\drivers\FsFilterX.sys'
$filetool = Join-Path $root 'filetool\x64\Release\filetool.exe'
$fsctl = Join-Path $root 'fsctl\x64\Release\fsctl.exe'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$note = 'C:\DriverConfig\data\note.txt'
$report = 'C:\DriverConfig\data\report.txt'
$free = 'C:\DriverConfig\data\free.txt'
$policy = 'C:\DriverConfig\policy.xml'
$imageLog = 'C:\DriverConfig\image.log'
$thumb = '906AA1ADCD98DCBC641051CCBEFA9BAADFAB2206'
$failed = 0

function Log([string]$msg) {
    # Tee-Object писал бы строку ещё и в результат функции, а Add-Content в 5.1
    # дописывает BOM. Поэтому журнал пишется напрямую и не смешивается с stdout.
    $text = ($msg -replace "`r`n", "`n") + "`r`n"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::AppendAllText($log, $text, $utf8)
    Write-Host ($msg -replace "`r`n", "`n")
}

function Run-Step([string]$title, [scriptblock]$action) {
    Log ("---- " + $title)
    & $action
    Log ("step exit: " + $LASTEXITCODE)
}

Set-Content -Path $log -Value ("start " + (Get-Date -Format o)) -Encoding UTF8

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log ("admin: " + $admin)
if (-not $admin) { exit 4 }

$enum = cmd /c "bcdedit /enum {current}" 2>&1 | Out-String
Log "ENUM:"
Log $enum
if ($enum -notmatch 'testsigning\s+Yes') {
    Log "STOP: testsigning is not Yes"
    exit 2
}

if (Test-Path $signtool) {
    $sign = & $signtool sign /fd SHA256 /sha1 $thumb /s My $sysSrc 2>&1 | Out-String
    Log "SIGN:"
    Log $sign
    Log ("sign exit: " + $LASTEXITCODE)
}

# Пока фильтр загружен, powershell.exe не имеет права переписать note.txt и policy.xml.
$existing = Get-Service FsFilterX -ErrorAction SilentlyContinue
if ($existing) {
    $unload = cmd /c "fltmc unload FsFilterX" 2>&1 | Out-String
    Log "UNLOAD:"
    Log $unload
    Start-Sleep -Seconds 1
}

New-Item -ItemType Directory -Force -Path 'C:\DriverConfig\data' | Out-Null
Copy-Item (Join-Path $root 'config\policy.xml') $policy -Force
Copy-Item (Join-Path $root 'config\data\note.txt') $note -Force
Set-Content -Path $report -Value "before" -Encoding ascii
Set-Content -Path $free -Value "free-before" -Encoding ascii
if (Test-Path $imageLog) { Remove-Item $imageLog -Force }
$seeded = [IO.File]::ReadAllText($note)
Log ("note seeded: [" + $seeded.Trim() + "]")
if ($seeded -notmatch 'hello') {
    Log "STOP: note.txt was not reset to hello"
    exit 1
}
Log "policy prepared, Config.txt left as it was"

Copy-Item $sysSrc $sysDst -Force
Log ("sys dst: " + (Get-Item $sysDst).Length)

if (Test-Path $signtool) {
    $verify = & $signtool verify /pa $sysDst 2>&1 | Out-String
    Log "VERIFY:"
    Log $verify
    Log ("verify exit: " + $LASTEXITCODE)
    if ($LASTEXITCODE -ne 0) { $failed++ }
}

if (-not $existing) {
    $sc = cmd /c 'sc create FsFilterX type= filesys start= demand binPath= \SystemRoot\System32\drivers\FsFilterX.sys depend= FltMgr group= "FSFilter Activity Monitor"' 2>&1 | Out-String
    Log "SC CREATE:"
    Log $sc
}

$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\FsFilterX'
New-Item -Path "$base\Instances" -Force | Out-Null
New-ItemProperty -Path "$base\Instances" -Name DefaultInstance -Value 'FsFilterX Instance' -PropertyType String -Force | Out-Null
New-Item -Path "$base\Instances\FsFilterX Instance" -Force | Out-Null
New-ItemProperty -Path "$base\Instances\FsFilterX Instance" -Name Altitude -Value '370030' -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$base\Instances\FsFilterX Instance" -Name Flags -Value 0 -PropertyType DWord -Force | Out-Null

$load = cmd /c "fltmc load FsFilterX" 2>&1 | Out-String
Log "LOAD:"
Log $load
Log ("load exit: " + $LASTEXITCODE)
$filters = cmd /c "fltmc filters" 2>&1 | Out-String
Log "FILTERS:"
Log $filters
if ($filters -notmatch 'FsFilterX') {
    Log "STOP: filter is not loaded"
    exit 3
}

function Run-Tool([string]$title, [string]$exe, [string[]]$argList) {
    Log ("---- " + $title)
    Log ("CMD: " + $exe + " " + ($argList -join ' '))
    $out = & $exe @argList 2>&1 | Out-String
    Log ("tool exit: " + $LASTEXITCODE)
    Log ("stdout: [" + ($out -replace "`r", '<CR>' -replace "`n", '<LF>') + "]")
    return $out
}

function Read-Shared([string]$path) {
    # Драйвер держит image.log открытым на запись и разрешает только чтение.
    # Обычный ReadAllText не ставит FILE_SHARE_WRITE и получает sharing violation.
    if (-not (Test-Path $path)) {
        Log ("missing " + $path)
        return ""
    }
    try {
        $stream = New-Object IO.FileStream($path, 'Open', 'Read', 'ReadWrite')
        $buffer = New-Object byte[] $stream.Length
        [void]$stream.Read($buffer, 0, $buffer.Length)
        $stream.Close()
        return [Text.Encoding]::ASCII.GetString($buffer)
    } catch {
        Log ("read failed " + $path + " : " + $_.Exception.Message)
        return ""
    }
}

function Expect([string]$name, $ok) {
    $good = $false
    if ($ok -is [array]) {
        $good = ($ok.Count -gt 0)
    } elseif ($ok) {
        $good = $true
    }
    if ($good) {
        Log ("PASS " + $name)
    } else {
        Log ("FAIL " + $name)
        $script:failed++
    }
}

# After the filter loads, PowerShell is not a listed subject of note.txt.
# Read those files through filetool.
$out = Run-Tool 'filetool read note' $filetool @('r', $note)
Expect 'read note hello' ($out -match 'hello')

$out = Run-Tool 'filetool write note denied' $filetool @('w', $note, 'hacked')
Expect 'write note says failed' ($out -match 'file openning failed')
$out = Run-Tool 'filetool read note after denied write' $filetool @('r', $note)
Expect 'write note denied keeps hello' ($out -match 'hello' -and $out -notmatch 'hacked')

$out = Run-Tool 'filetool write report' $filetool @('w', $report, 'written')
Expect 'write report opened' ($out -notmatch 'file openning failed')
$out = Run-Tool 'filetool read report' $filetool @('r', $report)
Expect 'write report' ($out -match 'written')

$out = Run-Tool 'filetool write free' $filetool @('w', $free, 'free-ok')
Expect 'write free opened' ($out -notmatch 'file openning failed')
$out = Run-Tool 'filetool read free' $filetool @('r', $free)
Expect 'write free' ($out -match 'free-ok')

$notepadDir = Join-Path $env:TEMP 'lab3-notepad'
New-Item -ItemType Directory -Force -Path $notepadDir | Out-Null
$notepad = Join-Path $notepadDir 'notepad.exe'
Copy-Item $filetool $notepad -Force
$out = Run-Tool 'notepad read note' $notepad @('r', $note)
Expect 'notepad read denied' ($out -match 'file openning failed')
$out = Run-Tool 'notepad write note' $notepad @('w', $note, 'notepad-hacked')
Expect 'notepad write denied' ($out -match 'file openning failed')
$out = Run-Tool 'filetool read note after notepad' $filetool @('r', $note)
Expect 'note unchanged after notepad' ($out -match 'hello' -and $out -notmatch 'notepad-hacked')

$out = Run-Tool 'fsctl allow write' $fsctl @('set', $note, 'filetool.exe', '1', '1')
Expect 'fsctl set allow' ($LASTEXITCODE -eq 0)
$out = Run-Tool 'filetool write note allowed' $filetool @('w', $note, 'allowed-now')
Expect 'write allowed opened' ($out -notmatch 'file openning failed')
$out = Run-Tool 'filetool read note allowed' $filetool @('r', $note)
Expect 'write allowed after set' ($out -match 'allowed-now')

$out = Run-Tool 'fsctl deny write again' $fsctl @('set', $note, 'filetool.exe', '1', '0')
Expect 'fsctl set deny' ($LASTEXITCODE -eq 0)
$out = Run-Tool 'filetool write note denied again' $filetool @('w', $note, 'hacked-again')
Expect 'deny restored message' ($out -match 'file openning failed')
$out = Run-Tool 'filetool read note after restore' $filetool @('r', $note)
Expect 'deny restored' ($out -match 'allowed-now' -and $out -notmatch 'hacked-again')

$out = Run-Tool 'filetool read policy' $filetool @('r', $policy)
Expect 'policy hidden from filetool' ($out -match 'file openning failed')
$out = Run-Tool 'fsctl show' $fsctl @('show')
Expect 'fsctl reads policy' ($out -match 'filetool.exe' -and $out -match 'note.txt')

$out = Run-Tool 'fsctl notify on' $fsctl @('notify', 'on')
Expect 'notify on' ($LASTEXITCODE -eq 0)
Run-Tool 'filetool read note for image log' $filetool @('r', $note)
Start-Sleep -Milliseconds 500
$logText = Read-Shared $imageLog
Expect 'image log has filetool' ($logText -match 'process=filetool.exe')

# Длину снимаем после notify off: сам fsctl грузит DLL, пока нотификатор ещё включён.
$out = Run-Tool 'fsctl notify off' $fsctl @('notify', 'off')
Expect 'notify off' ($LASTEXITCODE -eq 0)
Start-Sleep -Milliseconds 500
$logLen = (Get-Item $imageLog).Length
Run-Tool 'filetool read note after notify off' $filetool @('r', $note)
Start-Sleep -Milliseconds 500
$logLen2 = (Get-Item $imageLog).Length
Expect 'log does not grow' ($logLen2 -eq $logLen)
Log ("log length " + $logLen + " then " + $logLen2)

$out = Run-Tool 'fsctl notify on before unload' $fsctl @('notify', 'on')
Expect 'notify on before unload' ($LASTEXITCODE -eq 0)
$unload = cmd /c "fltmc unload FsFilterX" 2>&1 | Out-String
Log "UNLOAD WITH NOTIFY:"
Log $unload
Expect 'unload with notify' ($LASTEXITCODE -eq 0)
$load = cmd /c "fltmc load FsFilterX" 2>&1 | Out-String
Log "RELOAD:"
Log $load
Expect 'load again' ($LASTEXITCODE -eq 0)
$out = Run-Tool 'filetool read note after reload' $filetool @('r', $note)
Expect 'read after reload' ($out -match 'allowed-now')

Log ("FAILED " + $failed)
if ($failed -gt 0) { exit 1 }
Log "done"
exit 0
