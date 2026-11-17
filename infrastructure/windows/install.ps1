#Requires -Version 5.1
<#
.SYNOPSIS
    Установка/обновление клиента VoidLink на Windows: служба tunnel-daemon + трей.
.DESCRIPTION
    Копирует tunnel-daemon.exe, tunnel-client.exe, tunnel-tray.exe и wintun.dll
    в %ProgramFiles%\Tunnel (каталог, куда пишет только администратор — DLL
    грузится службой только оттуда), регистрирует службу командой
    "tunnel-daemon install", запускает её и трей. Повторный запуск — обновление:
    служба останавливается, exe заменяются, служба стартует снова.
.PARAMETER Source
    Каталог с exe и wintun.dll (по умолчанию — каталог скрипта).
.PARAMETER NoTray
    Не запускать трей после установки.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$Source = $PSScriptRoot,
    [switch]$NoTray
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'TunnelDaemon'
$InstallDir = Join-Path $env:ProgramFiles 'Tunnel'
$Files = @('tunnel-daemon.exe', 'tunnel-client.exe', 'tunnel-tray.exe', 'wintun.dll')

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    # Перезапуск с повышением прав (UAC)
    Write-Host 'Нужны права администратора, перезапускаю с UAC...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-Source', "`"$Source`"")
    if ($NoTray) { $argList += '-NoTray' }
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -Wait -PassThru
    exit $p.ExitCode
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Поддерживается только 64-битная Windows.'
}

foreach ($f in $Files) {
    if (-not (Test-Path -LiteralPath (Join-Path $Source $f) -PathType Leaf)) {
        throw "Не найден $f в $Source"
    }
}

# Обновление: остановить службу и трей, иначе файлы заняты
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host "Останавливаю службу $ServiceName..."
    Stop-Service -Name $ServiceName -Force
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
Get-Process -Name 'tunnel-tray', 'tunnel-client' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
# Каталог установки: наследуемые права Program Files (запись — только админы/SYSTEM)
foreach ($f in $Files) {
    Copy-Item -LiteralPath (Join-Path $Source $f) -Destination (Join-Path $InstallDir $f) -Force
}
$uninst = Join-Path $PSScriptRoot 'uninstall.ps1'
if (Test-Path -LiteralPath $uninst) {
    Copy-Item -LiteralPath $uninst -Destination (Join-Path $InstallDir 'uninstall.ps1') -Force
}
Write-Host "Файлы скопированы в $InstallDir"

$daemon = Join-Path $InstallDir 'tunnel-daemon.exe'
if (-not $svc) {
    # Служба, %ProgramData%\tunnel с ACL, импорт client.json пользователя,
    # Run-ключ трея и ярлык — делает сам демон
    Write-Host 'Регистрирую службу (tunnel-daemon install)...'
    & $daemon install
    if ($LASTEXITCODE -ne 0) { throw "tunnel-daemon install завершился с кодом $LASTEXITCODE" }
} else {
    Write-Host 'Служба уже зарегистрирована — обновление файлов.'
}

Write-Host "Запускаю службу $ServiceName..."
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

if (-not $NoTray) {
    # Трей — в сессии пользователя без прав администратора. Если скрипт поднят
    # через UAC другим админом, трей появится при следующем входе (Run-ключ).
    try {
        $shell = New-Object -ComObject 'Shell.Application'
        $shell.ShellExecute((Join-Path $InstallDir 'tunnel-tray.exe'), '', $InstallDir, 'open', 1)
    } catch {
        Start-Process -FilePath (Join-Path $InstallDir 'tunnel-tray.exe') -WorkingDirectory $InstallDir
    }
}

Write-Host ''
Write-Host 'Готово. Служба TunnelDaemon запущена.'
Write-Host "Интерфейс: `"$InstallDir\tunnel-client.exe`" tui (права администратора не нужны)."
