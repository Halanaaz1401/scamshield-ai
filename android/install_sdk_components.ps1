$sdkDir = "c:\Users\Hala\Downloads\Project Files\ScamShield AI\android\sdk"
$licensesDir = Join-Path $sdkDir "licenses"
New-Item -ItemType Directory -Path $licensesDir -Force | Out-Null

$sdkLicense = @"
24333f8a63b6825ea9c5514f83c2829b004d1fee
d56f5187479451eabf01fb7878896864468249dd
84831b9409646a33ee13ef6161f8ed83e24a79e4
89386a27e26330e16926e0be3078e22a561deff2
"@
Set-Content -Path (Join-Path $licensesDir "android-sdk-license") -Value $sdkLicense -NoNewline

$previewLicense = @"
84831b9409646a33ee13ef6161f8ed83e24a79e4
"@
Set-Content -Path (Join-Path $licensesDir "android-sdk-preview-license") -Value $previewLicense -NoNewline

$armLicense = @"
d975f751698a77b662f1254ddbeed3901e976f5a
"@
Set-Content -Path (Join-Path $licensesDir "android-googletv-license") -Value $armLicense -NoNewline

$sdkManager = "$sdkDir\cmdline-tools\latest\bin\sdkmanager.bat"
$env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot"
$env:ANDROID_HOME = $sdkDir

Write-Host "Installing packages with pre-accepted licenses..."
& $sdkManager --sdk_root="$sdkDir" "platforms;android-34" "build-tools;34.0.0" "platform-tools"

Write-Host "Done installing SDK packages."
