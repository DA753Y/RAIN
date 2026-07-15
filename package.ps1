param(
  [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$manifestPath = Join-Path $root "manifest.json"
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json

if (-not $OutputPath) {
  $OutputPath = Join-Path $root ("dist\RAIN-{0}.zip" -f $manifest.version)
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

$packageFiles = @(
  "manifest.json",
  "background.js",
  "content.js",
  "options.html",
  "options.js",
  "sidepanel.html",
  "sidepanel.js",
  "icons\icon16.png",
  "icons\icon32.png",
  "icons\icon48.png",
  "icons\icon128.png"
)

foreach ($relativePath in $packageFiles) {
  $sourcePath = Join-Path $root $relativePath
  if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Required package file is missing: $relativePath"
  }
}

$outputDirectory = Split-Path -Parent $OutputPath
[System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
if (Test-Path -LiteralPath $OutputPath) {
  Remove-Item -LiteralPath $OutputPath
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::Open($OutputPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  foreach ($relativePath in $packageFiles) {
    $sourcePath = Join-Path $root $relativePath
    $entryName = $relativePath.Replace("\", "/")
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $archive,
      $sourcePath,
      $entryName,
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
  }
} finally {
  $archive.Dispose()
}

Write-Output $OutputPath
