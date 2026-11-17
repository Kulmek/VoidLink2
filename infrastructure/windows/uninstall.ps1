#Requires -Version 5.1
<#
.SYNOPSIS
    Удаление клиента VoidLink: служба, адаптер, трей, файлы.
.DESCRIPTION
    Останавливает трей и TUI, вызывает "tunnel-daemon uninstall" (стоп и
    удаление службы, адаптера Wintun, Run-ключа трея и ярлыка), удаляет
    %ProgramFiles%\Tunnel. Конфиг (%ProgramData%\tunnel: identity, друзья,
    серверы) сохраняется, если не указан -Purge.
.PARAMETER Purge
    Удалить также %ProgramData%\tunnel (identity будет потеряна — friend code
    сменится при следующей установке).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Purge
#>
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'TunnelDaemon'
$InstallDir = Join-Path $env:ProgramFiles 'Tunnel'
$DataDir = Join-Path $env:ProgramData 'tunnel'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Нужны права администратора, перезапускаю с UAC...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Purge) { $argList += '-Purge' }
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -Wait -PassThru
    exit $p.ExitCode
}

Get-Process -Name 'tunnel-tray', 'tunnel-client' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

$daemon = Join-Path $InstallDir 'tunnel-daemon.exe'
if (Test-Path -LiteralPath $daemon) {
    Write-Host 'tunnel-daemon uninstall...'
    if ($Purge) { & $daemon uninstall --purge } else { & $daemon uninstall }
    if ($LASTEXITCODE -ne 0) { Write-Warning "tunnel-daemon uninstall: код $LASTEXITCODE, удаляю вручную" }
}

# Страховка, если exe нет или uninstall не довёл дело до конца
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $ServiceName | Out-Null
}
Get-Process -Name 'tunnel-daemon' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $runKey -Name 'TunnelTray' -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds 500
if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "Удалён $InstallDir"
}

if ($Purge) {
    if (Test-Path -LiteralPath $DataDir) {
        Remove-Item -LiteralPath $DataDir -Recurse -Force
        Write-Host "Удалён $DataDir (конфиг и identity)"
    }
} else {
    Write-Host "Конфиг сохранён в $DataDir (удалить: -Purge)"
}

Write-Host 'VoidLink удалён.'
