param(
    [Parameter(Mandatory = $true)]
    [string]$appFile,

    [Parameter(Mandatory = $true)]
    [string]$user,

    [Parameter(Mandatory = $true)]
    [string]$password,

    [Parameter(Mandatory = $true)]
    [string]$totp,

    [Parameter(Mandatory = $false)]
    [ValidateSet("product", "sandbox")]
    [string]$mode = "product", # For Sandbox Certificate it must be "sandbox"

    [Parameter(Mandatory = $false)]
    [string]$timestampService = "http://ts.ssl.com",

    [Parameter(Mandatory = $false)]
    [string]$digestAlgorithm = "sha256"
)
# Start time
$startTime = [DateTime]::Now
# Immediately convert password and TOTP to SecureStrings
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$secureTotp = ConvertTo-SecureString -String $totp -AsPlainText -Force
# Now you can safely convert back to plain text internally when needed:
$passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)
$totpPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureTotp)
$plainTotp = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($totpPtr)
# Use $plainPassword and $plainTotp securely within your script only when needed.

# AL:Go and BCContainerHelper helper libraries import
# Write-Host "Importing AL:Go and BCContainerHelper helper libraries..."
# . (Join-Path -Path $PSScriptRoot -ChildPath "..\AL-Go-Helper.ps1" -Resolve)
# DownloadAndImportBcContainerHelper
$rawPath = Join-Path -Path $env:GITHUB_WORKSPACE -ChildPath "..\..\_actions\microsoft\AL-Go-Actions"
$basePath = (Resolve-Path $rawPath).Path
$versionFolder = Get-ChildItem -Path $basePath -Directory | Sort-Object Name -Descending | Select-Object -First 1
. (Join-Path -Path $versionFolder.FullName -ChildPath "AL-Go-Helper.ps1" -Resolve)
DownloadAndImportBcContainerHelper

Write-Host "=========== Signing $appFile process ===========" -ForegroundColor Yellow
Write-Host "===== 1. Register NavSip.dll =====" -ForegroundColor Yellow
function GetNavSipFromArtifacts
(
    [string] $NavSipDestination = "C:\Windows\System32"
) {
    $artifactTempFolder = Join-Path $([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

    try {
        Download-Artifacts -artifactUrl (Get-BCArtifactUrl -type Sandbox -country core) -basePath $artifactTempFolder | Out-Null
        Write-Host "Downloaded artifacts to $artifactTempFolder"
        $navsip = Get-ChildItem -Path $artifactTempFolder -Filter "NavSip.dll" -Recurse
        Write-Host "Found navsip at $($navsip.FullName)"
        Copy-Item -Path $navsip.FullName -Destination $NavSipDestination -Force | Out-Null
        Write-Host "Copied navsip to $NavSipDestination"
    }
    finally {
        Remove-Item -Path $artifactTempFolder -Recurse -Force
    }
}

function Register-NavSip() {
    $navSipDestination = "C:\Windows\System32"
    $navSipDllPath = Join-Path $navSipDestination "NavSip.dll"
    try {
        if (-not (Test-Path $navSipDllPath)) {
            GetNavSipFromArtifacts -NavSipDestination $navSipDllPath
        }

        Write-Host "Unregistering dll $navSipDllPath"
        RegSvr32 /u /s $navSipDllPath
        Write-Host "Registering dll $navSipDllPath"
        RegSvr32 /s $navSipDllPath
        $msvcr120Path = "C:\Windows\System32\msvcr120.dll"
        Write-Host "Unregistering dll $msvcr120Path"
        RegSvr32 /u /s $msvcr120Path
        Write-Host "Registering dll $msvcr120Path"
        RegSvr32 /s $msvcr120Path
    }
    catch {
        Write-Host "Failed to copy navsip to $navSipDestination"
    }

}
Register-NavSip
# Create download folder
$downloadFolder = (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))
if (-not (Test-Path $downloadFolder)) {
    New-Item -ItemType Directory -Path $downloadFolder | Out-Null
}

# Prepare prerequisites for signing
Write-Host "===== 2. Download/Install Visual C++ 2013/2015-2022 Redistribuitable Prerequisites =====" -ForegroundColor Yellow
if (!(Test-Path "C:\Windows\System32\msvcr120.dll")) {
    Write-Host "Downloading vcredist_x86"
        (New-Object System.Net.WebClient).DownloadFile('https://bcartifacts.blob.core.windows.net/prerequisites/vcredist_x86.exe', "$downloadFolder\vcredist_x86.exe")
    Write-Host "Installing vcredist_x86"
    start-process -Wait -FilePath $downloadFolder\vcredist_x86.exe -ArgumentList /q, /norestart
    Write-Host "Downloading vcredist_x64"
        (New-Object System.Net.WebClient).DownloadFile('https://bcartifacts.blob.core.windows.net/prerequisites/vcredist_x64.exe', "$downloadFolder\vcredist_x64.exe")
    Write-Host "Installing vcredist_x64"
    start-process -Wait -FilePath $downloadFolder\vcredist_x64.exe -ArgumentList /q, /norestart
}

if (!(Test-Path "C:\Windows\System32\vcruntime140_1.dll")) {
    Write-Host "Downloading vcredist_x64 (version 140)"
        (New-Object System.Net.WebClient).DownloadFile('https://aka.ms/vs/17/release/vc_redist.x64.exe', "$downloadFolder\vcredist_x64-140.exe")
    Write-Host "Installing vcredist_x64 (version 140)"
    start-process -Wait -FilePath $downloadFolder\vcredist_x64-140.exe -ArgumentList /q, /norestart
}
# Check/Download install eSignerCKATool
Write-Host "===== 3. Download/Install eSignerCKATool =====" -ForegroundColor Yellow
# Create a temporary directory for the installation
$TempInstallDir = Join-Path ([System.IO.Path]::GetTempPath()) "eSignerSetup"
New-Item -ItemType Directory -Force -Path $TempInstallDir | Out-Null
$eSignerCKATool = Join-Path -Path $TempInstallDir -ChildPath "eSignerCKATool.exe"

# Initialize $setupFolder to null to avoid referencing an undefined variable
$setupFolder = $null

if (!(Test-Path $eSignerCKATool)) {
    # Download and install eSignerCKA
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/SSLcom/eSignerCKA/releases/latest" -Headers @{ "User-Agent" = "PowerShell" }
    $targetAsset = $release.assets | Where-Object { $_.name -like "SSL.COM-eSigner-CKA_*.zip" } | Select-Object -First 1

    $filePath = Join-Path $downloadFolder "eSigner_CKA_Setup.zip"
    Write-Output "Found asset: $($targetAsset.name). Downloading..."
    Invoke-WebRequest -Uri $targetAsset.browser_download_url -OutFile $filePath
    Write-Output "Download complete: $filePath"

    # Expand the archive
    Write-Output "Expanding archive..."
    $parentFolder = Split-Path -Parent $filePath
    $setupFolder = Join-Path $parentFolder "eSigner_CKA_Setup"
    $tempExtractPath = Join-Path $parentFolder "temp_extract"

    # Create setup folder
    New-Item -Force -ItemType Directory -Path $setupFolder | Out-Null
    Expand-Archive -Force -Path $filePath -DestinationPath $tempExtractPath

    # Move installer
    Get-ChildItem -Path $tempExtractPath -Recurse -Filter "*.exe" | 
        Select-Object -First 1 | 
        Move-Item -Destination (Join-Path $setupFolder "eSigner_CKA_Installer.exe") -Force

    # Clean up extracted files
    Remove-Item -Path $filePath -Force
    Remove-Item -Path $tempExtractPath -Recurse -Force

    # Install eSigner
    Write-Output "Installing eSignerCKA..."
    $installerPath = Join-Path $setupFolder "eSigner_CKA_Installer.exe"
    $installArgs = "/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /DIR=`"$TempInstallDir`""
    Write-Output "Running installer: $installerPath $installArgs"
    Start-Process $installerPath -ArgumentList $installArgs -Wait
}
# Post-install steps
if (-not (Test-Path $TempInstallDir)) {
    Write-Error "Installation failed - directory not found"
    exit 1
}
# Run additional tools
$registerKsp = Join-Path $TempInstallDir "RegisterKSP.exe"
$configExe = Join-Path $TempInstallDir "eSignerCSP.Config.exe"

if (Test-Path $registerKsp) {
    Write-Output "Running RegisterKSP.exe..."
    Start-Process $registerKsp -Wait
}
if (Test-Path $configExe) {
    Write-Output "Running eSignerCSP.Config.exe..."
    Start-Process $configExe -Wait
}
# Only run installer again if $setupFolder was defined
if ($setupFolder -ne $null) {
    Start-Process (Join-Path $setupFolder "eSigner_CKA_Installer.exe") -ArgumentList "/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /DIR=`"$TempInstallDir`"" -Wait
}

# Configure eSigner
Write-Host "===== 4. Configuring eSignerCKA Auto Mode =====" -ForegroundColor Yellow
$masterKeyFile = Join-Path -Path $TempInstallDir -ChildPath "master.key"
$eSignerCKATool = Get-ChildItem -Path $TempInstallDir -Filter "eSignerCKATool.exe" -Recurse | Select-Object -First 1
Write-Output "Configuring eSignerCKA..."
& $eSignerCKATool.FullName config -mode $mode -user $user -pass $plainPassword -totp $plainTotp -key $masterKeyFile -r

Write-Host "===== 5. Loading the CodeSigning Certificate =====" -ForegroundColor Yellow
# Certificate validation
# Unload certificate
& $eSignerCKATool.FullName unload
Write-Output "Loading certificates..."
& $eSignerCKATool.FullName load

# Check certificates
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | 
Where-Object { $_.Subject -like "*Tipalti*" -and $_.NotAfter -gt (Get-Date) }
if (-not $cert) {
    Write-Error "No valid Tipalti certificates found"
    exit 1
}
else {
    Write-Output "Found valid Tipalti certificate $($cert.Thumbprint)"
}

Write-Host "===== 6. Download/Intall SignTool =====" -ForegroundColor Yellow
Write-Output "Get SignTool.exe..."
$signToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\SignTool.exe"
if (Test-Path $signToolPath) {
    $signtoolExe = Get-ChildItem $signToolPath | 
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1
}
else {
    Write-Host "Downloading SignTool.exe..."
    $winSdkSetupExe = "$downloadFolder\winsdksetup.exe"
    $winSdkSetupUrl = "https://bcartifacts.blob.core.windows.net/prerequisites/winsdksetup.exe"
    (New-Object System.Net.WebClient).DownloadFile($winSdkSetupUrl, $winSdkSetupExe)
    Write-Host "Installing Signing Tools"
    Start-Process $winSdkSetupExe -ArgumentList "/features OptionId.SigningTools /q" -Wait
    if (!(Test-Path "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\SignTool.exe")) {
        throw "Cannot locate signtool.exe after installation"
    }
    $signToolExe = (get-item "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\SignTool.exe").FullName
}

# Sign the application
Write-Host "===== 7. Signing the application =====" -ForegroundColor Yellow
Write-Output "Signing $appFile..."
& "$signToolExe" sign /a /debug /v /fd $digestAlgorithm /tr $timestampService /td $digestAlgorithm /sha1 "$($cert.Thumbprint)" "$appFile"

# Verify signature
Write-Output "Verifying signature..."
& "$signToolExe" verify /pa /v "$appFile"

# Clean up
Write-Host "===== 8. Cleaning up =====" -ForegroundColor Yellow
# Unload certificate
& $eSignerCKATool.FullName unload
# Clear sensitive data from memory after usage:
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($totpPtr)
# Clean up
if (Test-Path $downloadFolder) {
    Remove-Item $downloadFolder -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path $TempInstallDir) {
    Remove-Item $TempInstallDir -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path $tempExtractPath) {
    Remove-Item $tempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
}
        
if (Test-Path -Path $setupFolder) {
    $UninstallExe = "$setupFolder\unins000.exe"
    if (Test-Path -Path $UninstallExe) {
        & $UninstallExe /silent /norestart | Out-Null
    }
    Remove-Item -Path $setupFolder -Recurse -Force -ErrorAction SilentlyContinue
}

$endTime = [DateTime]::Now
$duration = $endTime.Subtract($startTime)
Write-Host "Duration: $([Math]::Round($duration.TotalSeconds,2)) seconds"