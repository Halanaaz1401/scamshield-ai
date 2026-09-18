param()

$sdkDir = "c:\Users\Hala\Downloads\Project Files\ScamShield AI\android\sdk"
$cmdLineLatest = Join-Path $sdkDir "cmdline-tools\latest"

if (-not (Test-Path $cmdLineLatest)) {
    New-Item -ItemType Directory -Path $sdkDir -Force | Out-Null
    
    $sourceCmdLine = "C:\Users\Hala\Android\Sdk\cmdline-tools"
    if (Test-Path $sourceCmdLine) {
        Write-Host "Copying from existing directory..."
        New-Item -ItemType Directory -Path (Join-Path $sdkDir "cmdline-tools") -Force | Out-Null
        Copy-Item -Path "$sourceCmdLine\*" -Destination (Join-Path $sdkDir "cmdline-tools") -Recurse -Force
    } else {
        $zipPath = Join-Path $sdkDir "tools.zip"
        Write-Host "Downloading Google command line tools..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip" -OutFile $zipPath
        Write-Host "Extracting tools..."
        $tempExtract = Join-Path $sdkDir "temp_extract"
        Expand-Archive -Path $zipPath -DestinationPath $tempExtract -Force
        New-Item -ItemType Directory -Path $cmdLineLatest -Force | Out-Null
        Copy-Item -Path "$tempExtract\cmdline-tools\*" -Destination $cmdLineLatest -Recurse -Force
        Remove-Item -Path $tempExtract -Recurse -Force
        Remove-Item -Path $zipPath -Force
    }
}

if (Test-Path (Join-Path $sdkDir "cmdline-tools\cmdline-tools")) {
    # Move structure to cmdline-tools/latest if needed
    New-Item -ItemType Directory -Path $cmdLineLatest -Force | Out-Null
    Move-Item -Path "$sdkDir\cmdline-tools\cmdline-tools\*" -Destination $cmdLineLatest -Force
    Remove-Item -Path "$sdkDir\cmdline-tools\cmdline-tools" -Recurse -Force
}

Write-Host "SDK cmdline-tools status:"
Get-ChildItem -Path (Join-Path $sdkDir "cmdline-tools")
