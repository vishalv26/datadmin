$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$extbin = Join-Path $repoRoot 'extbin'
$sharpLib = Join-Path $repoRoot 'SharpSSH\lib'
$cacheRoot = Join-Path $repoRoot '.nuget-cache'

New-Item -ItemType Directory -Force -Path $extbin, $sharpLib, $cacheRoot | Out-Null

function Install-NuGetPackage {
    param(
        [Parameter(Mandatory = $true)] [string] $PackageId,
        [Parameter(Mandatory = $true)] [string] $Destination,
        [Parameter(Mandatory = $true)] [string] $AssemblyName
    )

    $packagePath = Join-Path $cacheRoot $PackageId
    if (-not (Test-Path $packagePath)) {
        & nuget install $PackageId -OutputDirectory $cacheRoot -NonInteractive -Verbosity quiet | Out-Null
    }

    $dll = Get-ChildItem -Path $cacheRoot -Recurse -Filter $AssemblyName |
        Where-Object { $_.FullName -match '\\lib\\' -or $_.FullName -match '\\bin\\' -or $_.FullName -match '\\tools\\' } |
        Select-Object -First 1

    if (-not $dll) {
        throw "Could not find $AssemblyName in package $PackageId after restore."
    }

    Copy-Item -Path $dll.FullName -Destination (Join-Path $Destination $AssemblyName) -Force
    Write-Host "Installed $AssemblyName from $PackageId to $Destination"
}

Install-NuGetPackage -PackageId 'LinqBridge' -Destination $extbin -AssemblyName 'LinqBridge.dll'
Install-NuGetPackage -PackageId 'DiffieHellman' -Destination $sharpLib -AssemblyName 'DiffieHellman.dll'
Install-NuGetPackage -PackageId 'Org.Mentalis.Security' -Destination $sharpLib -AssemblyName 'Org.Mentalis.Security.dll'
