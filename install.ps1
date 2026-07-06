# nginxwatch installer for Windows (PowerShell).
# Installs nginxwatch.lua + a `nginxwatch.cmd` wrapper into $Dest (default
# %LOCALAPPDATA%\Programs\nginxwatch) and prints how to add it to PATH.
# Requires a Lua interpreter on PATH (lua, lua5.4, or luajit) —
# install via: scoop install lua   OR   choco install lua   OR use WSL.

param(
    [string]$Dest = "$env:LOCALAPPDATA\Programs\nginxwatch"
)

$ErrorActionPreference = "Stop"
$src = Split-Path -Parent $MyInvocation.MyCommand.Path

# locate a lua interpreter
$lua = $null
foreach ($cand in @("lua5.4", "lua", "luajit")) {
    $found = Get-Command $cand -ErrorAction SilentlyContinue
    if ($found) { $lua = $found.Source; break }
}
if (-not $lua) {
    Write-Error "No Lua interpreter found. Install with: scoop install lua  (or choco install lua)"
    exit 1
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item -Force (Join-Path $src "nginxwatch.lua") (Join-Path $Dest "nginxwatch.lua")

$luaScript = Join-Path $Dest "nginxwatch.lua"
$cmd = Join-Path $Dest "nginxwatch.cmd"
$cmdBody = "@echo off`r`n`"$lua`" `"$luaScript`" %*`r`n"
Set-Content -Path $cmd -Value $cmdBody -Encoding ascii -NoNewline

Write-Host "Installed: $cmd (using $lua)"
Write-Host "Add to PATH for this session:"
Write-Host "  `$env:Path += ';$Dest'"
Write-Host "Or permanently via System > Environment Variables. Then: nginxwatch --version"
