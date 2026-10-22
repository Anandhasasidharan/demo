# CVE-2022-40674 case study — Windows (guard-page allocator)
# Builds libexpat 2.4.8 (vulnerable), 2.4.8 + patch, and 2.4.9 (fixed),
# then runs the same trigger through each and compares.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$cc = if (Get-Command gcc -ErrorAction SilentlyContinue) { 'gcc' } else { throw 'gcc not found' }

# ---- source ----
if (-not (Test-Path src\.git)) {
  Write-Host 'cloning libexpat...'
  git -c http.sslBackend=openssl clone --quiet https://github.com/libexpat/libexpat.git src
}
git -C src -c http.sslBackend=openssl fetch --tags --quiet 2>$null

function Get-Source([string]$tag, [string]$dir) {
  if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
  New-Item -ItemType Directory $dir | Out-Null
  $tar = Join-Path $PWD 'src.tar'
  if (Test-Path $tar) { Remove-Item $tar -Force }
  git -C src archive --format=tar -o $tar $tag expat/lib
  tar -xf $tar -C $dir
  Remove-Item $tar -Force
}

function Build([string]$dir, [string]$exe) {
  & $cc -DXML_STATIC -I . -I "$dir\expat\lib" -O1 -g -o $exe `
      driver.c "$dir\expat\lib\xmlparse.c" "$dir\expat\lib\xmltok.c" "$dir\expat\lib\xmlrole.c"
  if ($LASTEXITCODE -ne 0) { throw "build failed: $dir" }
}

Write-Host 'extracting sources...'
Get-Source 'R_2_4_8' 'vuln'
Get-Source 'R_2_4_9' 'fixed'
Get-Source 'R_2_4_8' 'patched'

# apply the real fix to the vulnerable tree
Push-Location patched
git init --quiet . 2>$null
git apply ..\patch.diff
if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'patch did not apply' }
Pop-Location

Write-Host 'building...'
Build 'vuln'    'ap_vuln.exe'
Build 'patched' 'ap_patched.exe'
Build 'fixed'   'ap_fixed.exe'

# ---- run ----
$rows = @()
foreach ($t in @(
    @{ name = 'libexpat 2.4.8 (vulnerable)'; exe = 'ap_vuln.exe' },
    @{ name = '2.4.8 + patch.diff';         exe = 'ap_patched.exe' },
    @{ name = 'libexpat 2.4.9 (fixed)';     exe = 'ap_fixed.exe' })) {
  Write-Host "`n=== $($t.name) ==="
  & ".\$($t.exe)"
  $code = $LASTEXITCODE
  $u = [int64]$code -band 0xFFFFFFFFL
  $rows += [pscustomobject]@{
    Build  = $t.name
    Result = if ($code -eq 0) { 'no fault' } else { ('fault 0x{0:X8}' -f $u) }
    Exit   = $code
  }
}

Write-Host "`n=== summary ==="
$rows | Format-Table -AutoSize


