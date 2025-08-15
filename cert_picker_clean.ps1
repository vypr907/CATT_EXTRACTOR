$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

# Display all certificates with a number
for ($i = 0; $i -lt $store.Certificates.Count; $i++) {
    $cert = $store.Certificates[$i]
    Write-Host "$i`: $($cert.Subject) - $($cert.Thumbprint)"
}

# Prompt user to pick a certificate
$selection = Read-Host "Enter the number of the certificate to use"

if ($selection -match '^\d+$' -and $selection -ge 0 -and $selection -lt $store.Certificates.Count) {
    $selectedCert = $store.Certificates[$selection]
    Write-Host "You selected: $($selectedCert.Subject)"
    # Export or use the certificate as needed
} else {
    Write-Host "Invalid selection."
}

$store.Close()
# g:\My Drive\CATT_EXTRACTOR\cert_picker_clean.ps1