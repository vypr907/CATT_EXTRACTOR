function Get-CACCertificate {
    [CmdletBinding()]
    param()

    $stores = @(
        'Cert:\CurrentUser\My\',
        'Cert:\LocalMachine\My\'
    )

    $certs = foreach ($store in $stores) {
        Get-ChildItem $store |
            Where-Object {
                # Grab all EKU friendly names (null-safe)
                $ekuNames = $_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName } | Where-Object { $_ }
                # Check if any EKU contains Client/Smart/PIV/Authentication (case-insensitive)
                ($ekuNames -match 'Client|Smart|PIV|Authentication') -or
                ($_.Subject -match 'PIV|Authentication')
            } |
            Select-Object @{Name='Store';Expression={$store}},
                          @{Name='CertObject';Expression={$_}},
                          Subject, Thumbprint, NotAfter
    }

    if (-not $certs) {
        Write-Host "No matching CAC/PIV certificates found — showing all personal certs." -ForegroundColor Yellow
        $certs = foreach ($store in $stores) {
            Get-ChildItem $store |
                Select-Object @{Name='Store';Expression={$store}},
                              @{Name='CertObject';Expression={$_}},
                              Subject, Thumbprint, NotAfter
        }
    }

    Write-Host "`nCertificates available for selection:`n"
    $i = 1
    foreach ($cert in $certs) {
        Write-Host ("[{0}] Store: {1} | Subject: {2} | Exp: {3}" -f $i, $cert.Store, $cert.Subject, $cert.NotAfter)
        $i++
    }

    $selection = Read-Host "`nEnter the number of the certificate to use"
    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $certs.Count) {
        $chosenCert = $certs[ [int]$selection - 1 ].CertObject
        Write-Host "`nYou selected:" -ForegroundColor Green
        $chosenCert | Format-List Subject, Thumbprint, NotAfter
        return $chosenCert
    } else {
        Write-Host "Invalid selection. Exiting." -ForegroundColor Red
        return $null
    }
}

# Example usage
$CACCert = Get-CACCertificate
if ($CACCert) {
    # Export for Python
    $exportPath = Join-Path $env:TEMP "cac_cert.xml"
    $CACCert | Export-CliXml -Path $exportPath
    Write-Host ""
    Write-Host "Certificate exported to $exportPath" -ForegroundColor Cyan
}
