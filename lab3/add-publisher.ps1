$log = 'C:\Users\winuser\Documents\mbks_labs\lab3\testsign-result.txt'
$cer = 'C:\Users\winuser\Documents\mbks_labs\lab3\FsFilterX\x64\Debug\FsFilterX.cer'
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher','LocalMachine')
$store.Open('ReadWrite')
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
$store.Add($cert)
$store.Close()
Set-Content -Path $log -Value ('added ' + $cert.Thumbprint) -Encoding UTF8
