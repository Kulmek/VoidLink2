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
        try {
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        } catch {
            Write-Warning "Служба $ServiceName не остановилась за 30 с, продолжаю"
        }
    }
    & sc.exe delete $ServiceName | Out-Null
}
Get-Process -Name 'tunnel-daemon' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $runKey -Name 'TunnelTray' -ErrorAction SilentlyContinue

# Дождаться выхода процессов, державших файлы каталога
Get-Process -Name 'tunnel-tray', 'tunnel-client', 'tunnel-daemon' -ErrorAction SilentlyContinue |
    Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $InstallDir) {
    # Файлы могут быть заняты ещё долю секунды — несколько попыток
    $removed = $false
    for ($i = 1; $i -le 5 -and -not $removed; $i++) {
        try {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction Stop
            $removed = $true
        } catch {
            if ($i -lt 5) { Start-Sleep -Seconds 1 }
        }
    }
    if ($removed) {
        Write-Host "Удалён $InstallDir"
    } else {
        Write-Warning "Не удалось удалить $InstallDir (файлы заняты) — удалите вручную после перезагрузки"
    }
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
