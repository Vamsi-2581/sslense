<#
.SYNOPSIS
    Publishes the SSLense apps and builds the MSI installer.

.DESCRIPTION
    Publishes the GUI, CLI, and service as self-contained win-x64 apps (no .NET install needed on the
    server) into artifacts\publish, then builds artifacts\installer\SSLense-<version>-x64.msi.

    WiX Toolset v7 requires accepting its Open Source Maintenance Fee (OSMF) EULA. Read it first:
    the text ships in the WixToolset.Sdk package as OSMFEULA.txt and is described at
    https://wixtoolset.org/osmf/. Then either pass -AcceptWixEula on each build, or accept it once for
    your Windows account with:
        dotnet build .\installer\SSLense.Installer -t:AcceptEula -p:EulaId=wix7

.EXAMPLE
    .\installer\build.ps1 -AcceptWixEula
#>
param(
    [switch] $AcceptWixEula,
    [string] $Configuration = "Release",

    # The .NET runtime bundled into the self-contained apps. Without this, publishing uses whatever patch
    # the installed SDK happens to know. Raise it to the latest 10.0.x servicing release (published on
    # Patch Tuesday) before every SSLense release so customers receive runtime security fixes.
    [string] $RuntimeVersion = "10.0.14"
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$publishRoot = Join-Path $root "artifacts\publish"
$installerOutput = Join-Path $root "artifacts\installer"

if (Test-Path $publishRoot) {
    Remove-Item $publishRoot -Recurse -Force
}

# Each app gets its own folder so differing dependency versions can never overwrite each other.
# WiX stores identical files once in the MSI, so the shared runtime adds little to its size.
$apps = @{ gui = "SSLense.Gui"; cli = "SSLense.Cli"; service = "SSLense.Service" }
foreach ($folder in $apps.Keys) {
    $project = Join-Path $root "src\$($apps[$folder])"
    dotnet publish $project -c $Configuration -r win-x64 --self-contained true -o (Join-Path $publishRoot $folder) `
        "-p:RuntimeFrameworkVersion=$RuntimeVersion" -nologo
    if ($LASTEXITCODE -ne 0) {
        throw "Publishing $($apps[$folder]) failed."
    }
}

# The installer's license dialog needs RTF. Generate it from LICENSE so the two can never drift apart.
$licenseRtf = Join-Path $root "artifacts\obj\License.rtf"
New-Item -ItemType Directory -Force (Split-Path $licenseRtf) | Out-Null
$escaped = (Get-Content (Join-Path $root "LICENSE") -Raw) -replace '\\', '\\' -replace '\{', '\{' -replace '\}', '\}'
$body = ($escaped -split "\r?\n") -join "\par`r`n"
Set-Content -Path $licenseRtf -Encoding ascii -Value "{\rtf1\ansi\deff0{\fonttbl{\f0\fmodern Consolas;}}\f0\fs16 $body}"

$buildArguments = @(
    (Join-Path $PSScriptRoot "SSLense.Installer\SSLense.Installer.wixproj"),
    "-c", $Configuration,
    "-p:PublishDir=$publishRoot\",
    "-p:LicenseRtf=$licenseRtf",
    "-o", $installerOutput,
    "-nologo"
)
if ($AcceptWixEula) {
    $buildArguments += "-p:AcceptEula=wix7"
}

dotnet build @buildArguments
if ($LASTEXITCODE -ne 0) {
    throw "Building the installer failed. If the error is WIX7015, read and accept the WiX OSMF EULA (see this script's help)."
}

Get-ChildItem $installerOutput -Filter *.msi | ForEach-Object { Write-Host "Built $($_.FullName)" }
