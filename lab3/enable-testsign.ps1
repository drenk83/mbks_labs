$ErrorActionPreference = 'Continue'
$log = 'C:\Users\winuser\Documents\mbks_labs\lab3\testsign-result.txt'
$cer = 'C:\Users\winuser\Documents\mbks_labs\lab3\FsFilterX\x64\Debug\FsFilterX.cer'
$sys = 'C:\Users\winuser\Documents\mbks_labs\lab3\FsFilterX\x64\Debug\FsFilterX.sys'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$thumb = '906AA1ADCD98DCBC641051CCBEFA9BAADFAB2206'

function Log([string]$msg) {
    $msg | Tee-Object -FilePath $log -Append
}

Set-Content -Path $log -Value ("start " + (Get-Date -Format o)) -Encoding UTF8

try {
    $sb = Confirm-SecureBootUEFI
    Log ("SecureBoot: " + $sb)
} catch {
    Log ("SecureBoot check: " + $_.Exception.Message)
}

$root = Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root
Log ("Root: " + $root.Thumbprint + " " + $root.Subject)
$pub = Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
Log ("TrustedPublisher: " + $pub.Thumbprint)

$sign = & $signtool sign /fd SHA256 /sha1 $thumb /s My $sys 2>&1 | Out-String
Log "SIGN:"
Log $sign

$verify = & $signtool verify /pa /v $sys 2>&1 | Out-String
Log "VERIFY:"
Log $verify

$bcd = & bcdedit /set testsigning on 2>&1 | Out-String
Log "BCDEDIT:"
Log $bcd

$enum = cmd /c "bcdedit /enum {current}" 2>&1 | Out-String
Log "ENUM:"
Log $enum
Log "done"
