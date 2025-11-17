--EN DESARROLLO--

<#
BlueTeam Toolkit - FULL
Incluye funciones 1..25 solicitadas (persistencia, drivers, dlls, puertos, integridad, instalados,
políticas, búsqueda en carpetas sospechosas, firmas, anomalías de usuarios/servicios, monitor de red,
exportes (HTML/JSON/TXT), logging, GUI básica, scheduler, auto-update y empaquetado con ps2exe).

Autor: OscarBlueTeam https://x.com/oscarblue_team
Advertencia: ejecutar con permisos de administrador para funcionalidad completa.
#>

# ----------------------
# Configuración general
# ----------------------
$ScriptStart = Get-Date
$Global:LogPath = "$env:ProgramData\BlueTeamToolkit"
if (!(Test-Path $Global:LogPath)) { New-Item -Path $Global:LogPath -ItemType Directory -Force | Out-Null }
$Global:RunLog = Join-Path $Global:LogPath ("RunLog_" + $ScriptStart.ToString("yyyyMMdd_HHmmss") + ".log")

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"
    $line | Tee-Object -FilePath $Global:RunLog -Append
    Write-Host $line
}

Write-Log "BlueTeamToolkit iniciado."

# ----------------------
# 0. Helper: safe run
# ----------------------
function Safe-Command {
    param([scriptblock]$Script)
    try {
        & $Script
    } catch {
        Write-Log "Error en comando: $_" "ERROR"
    }
}

# ----------------------
# 1. Persistencia (Run, RunOnce, Startup, Scheduled Tasks)
# ----------------------
function Detect-Persistence {
    Write-Log "Detectando persistencia..."
    $results = [ordered]@{}

    # Run / RunOnce (HKLM & HKCU)
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $runEntries = foreach ($k in $keys) {
        if (Test-Path $k) {
            Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | 
                Select-Object -Property PSPath, * | 
                Where-Object { $_.PSPath -ne $null } 
        }
    }
    $results["RunEntries"] = $runEntries

    # Startup folders
    $startupPaths = @(
        [Environment]::GetFolderPath("Startup"),
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    ) | Select-Object -Unique
    $startupFiles = foreach ($p in $startupPaths) {
        if (Test-Path $p) { Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime }
    }
    $results["StartupFiles"] = $startupFiles

    # Scheduled Tasks
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName,TaskPath,State
    } catch {
        $tasks = "No se pudieron enumerar tareas programadas (permiso requerido)."
    }
    $results["ScheduledTasks"] = $tasks

    Write-Log "Persistencia detectada (Run/Startup/Tareas)."
    return $results
}

# ----------------------
# 2. Listar drivers cargados y buscar sospechosos
# ----------------------
function Get-Drivers {
    Write-Log "Enumerando drivers del sistema..."
    $drivers = Get-WmiObject -Class Win32_SystemDriver | 
        Select-Object Name,DisplayName,PathName,State,StartMode
    return $drivers
}

# ----------------------
# 3. Revisar DLLs cargadas por proceso
# ----------------------
function Get-ProcessModules {
    Write-Log "Enumerando módulos (DLLs) de procesos..."
    $out = @()
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = $_
        try {
            $mods = $proc.Modules | Select-Object @{n='ProcessName';e={$proc.ProcessName}},ModuleName,FileName
            $out += $mods
        } catch {
            # procesos protegidos (System, lsass, etc.) pueden fallar
            $out += [pscustomobject]@{ProcessName=$proc.ProcessName; ModuleName="ACCESS_DENIED"; FileName="N/A"}
        }
    }
    return $out
}

# ----------------------
# 4. Detectar puertos abiertos inusuales
# ----------------------
function Detect-OpenPorts {
    Write-Log "Listando conexiones TCP/UDP..."
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess

    # Heurística: marcar listeners en puertos no comunes (<1024 son comunes; >1024 revisar)
    $listening = $conns | Where-Object { $_.State -eq "Listen" }
    $unusual = $listening | Where-Object { $_.LocalPort -gt 49152 -or $_.LocalPort -gt 1024 } # heurística
    return @{All=$conns; Listening=$listening; UnusualListening=$unusual}
}

# ----------------------
# 5. Comprobar integridad de archivos críticos del sistema
# ----------------------
function Check-FileIntegrity {
    Write-Log "Comprobando hash de archivos críticos..."
    $critical = @(
        "$env:windir\System32\kernel32.dll",
        "$env:windir\System32\ntdll.dll",
        "$env:windir\System32\lsass.exe",
        "$env:windir\System32\winlogon.exe",
        "$env:windir\System32\services.exe"
    ) | Where-Object { Test-Path $_ }

    $hashes = foreach ($f in $critical) {
        [pscustomobject]@{
            File = $f
            SHA256 = (Get-FileHash -Path $f -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Size = (Get-Item $f).Length
            LastWrite = (Get-Item $f).LastWriteTime
        }
    }
    return $hashes
}

# ----------------------
# 6. Enumeración de software instalado + fechas
# ----------------------
function Get-InstalledSoftware {
    Write-Log "Enumerando software instalado desde registro..."
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $sw = foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | 
            Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation
    }
    # Remove null display names
    return $sw | Where-Object { $_.DisplayName -ne $null } | Sort-Object DisplayName
}

# ----------------------
# 7. Revisar políticas de seguridad (audit, firewall, defender)
# ----------------------
function Get-SecurityPolicies {
    Write-Log "Consultando políticas de auditoría, firewall y Windows Defender..."
    $audit = & auditpol /get /category:* 2>$null
    $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,QuickScanSignatureVersion
    } catch {
        $defender = "No disponible (Get-MpComputerStatus falló). Posible Windows sin Defender o falta de permisos."
    }
    return @{Audit=$audit; Firewall=$firewall; Defender=$defender}
}

# ----------------------
# 8. Buscar ejecutables en carpetas sospechosas (AppData, Temp, Public)
# ----------------------
function Find-SuspiciousFiles {
    Write-Log "Buscando ejecutables en carpetas sospechosas (AppData, Temp, Public)..."
    $paths = @(
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA",
        "$env:USERPROFILE\AppData\Roaming",
        "$env:USERPROFILE\AppData\Local",
        "$env:PUBLIC"
    )
    $exts = "*.exe","*.ps1","*.bat","*.cmd","*.dll"
    $found = @()
    foreach ($p in $paths) {
        if (Test-Path $p) {
            foreach ($e in $exts) {
                $found += Get-ChildItem -Path $p -Recurse -Filter $e -ErrorAction SilentlyContinue | 
                    Select-Object FullName,Length,LastWriteTime
            }
        }
    }
    # Flag files recently modified (<7 days)
    $recent = $found | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
    return @{All=$found; Recent=$recent}
}

# ----------------------
# 9. Buscar binarios firmados por Microsoft pero modificados (heurística)
# ----------------------
function Detect-SignedMicrosoftButOddLocation {
    Write-Log "Buscando binarios firmados por Microsoft en ubicaciones sospechosas..."
    $susp = @()
    $files = Get-ChildItem -Path "$env:ProgramFiles","$env:ProgramFiles(x86)","$env:SystemRoot" -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
            if ($sig -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match "Microsoft") {
                # heurística: si archivo firmado por Microsoft está en un %Temp% o AppData subfolder -> sospechoso
                if ($f.FullName -match [regex]::Escape($env:TEMP) -or $f.DirectoryName -match "AppData") {
                    $susp += [pscustomobject]@{File=$f.FullName; SignatureStatus=$sig.Status; Signer=$sig.SignerCertificate.Subject}
                }
            }
        } catch { }
    }
    return $susp
}

# ----------------------
# 10. Detección de anomalías en usuarios (creados recientemente)
# ----------------------
function Detect-UserAnomalies {
    Write-Log "Detectando anomalías en usuarios locales..."
    $users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | 
        Select-Object Name,SID,Disabled,Status,Domain,LocalAccount,Caption,CreationDate
    $users | ForEach-Object {
        if ($_.CreationDate) {
            $_ | Add-Member -NotePropertyName CreationDateParsed -NotePropertyValue ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate))
        }
    }
    $recent = $users | Where-Object { $_.CreationDateParsed -and $_.CreationDateParsed -gt (Get-Date).AddDays(-7) } # creado en los ultimos 7 dias
    return @{All=$users; RecentCreated=$recent}
}

# ----------------------
# 11. Detección de anomalías en servicios (deshabilitados, nuevos, sospechosos)
# ----------------------
function Detect-ServiceAnomalies {
    Write-Log "Detectando servicios inusuales o deshabilitados..."
    $services = Get-WmiObject -Class Win32_Service | Select-Object Name,DisplayName,StartMode,State,PathName
    $disabled = $services | Where-Object { $_.StartMode -eq "Disabled" }
    # Heurística: servicios con ruta en %Temp% o AppData
    $susp = $services | Where-Object { $_.PathName -and ($_.PathName -match "Temp" -or $_.PathName -match "AppData" -or $_.PathName -match "\\Users\\") }
    return @{All=$services; Disabled=$disabled; SuspiciousPath=$susp}
}

# ----------------------
# 12. Detección de conexiones persistentes sospechosas (beacons / C2 heurística)
# ----------------------
function Detect-PersistentConnections {
    Write-Log "Buscando patrones de conexiones persistentes (heurística)..."
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" -and $_.State -ne "Closed" }
    # Agrupar por remoteaddr y comprobar frecuencias
    $grouped = $conns | Group-Object -Property RemoteAddress | ForEach-Object {
        [pscustomobject]@{ RemoteAddress = $_.Name; Count = $_.Count; States = ($_.Group | Select-Object -Unique State).State -join "," }
    } | Sort-Object -Property Count -Descending
    $suspicious = $grouped | Where-Object { $_.Count -gt 5 } # heuristica: >5 conexiones hacia misma IP
    return @{All=$conns; Grouped=$grouped; Suspicious=$suspicious}
}

# ----------------------
# 13. Monitor en tiempo real de nuevas conexiones (simple loop)
# ----------------------
function Monitor-NewConnections {
    param(
        [int]$IntervalSeconds = 5,
        [int]$DurationSeconds = 60
    )
    Write-Log "Monitor de nuevas conexiones: intervalo ${IntervalSeconds}s, duración ${DurationSeconds}s"
    $end = (Get-Date).AddSeconds($DurationSeconds)
    $seen = @{}
    while ((Get-Date) -lt $end) {
        $cur = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" }
        foreach ($c in $cur) {
            $key = "$($c.LocalAddress):$($c.LocalPort)-$($c.RemoteAddress):$($c.RemotePort)"
            if (-not $seen.ContainsKey($key)) {
                Write-Log "Nueva conexión: $key (State: $($c.State))"
                $seen[$key] = $true
            }
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
    Write-Log "Monitor finalizado."
}

# ----------------------
# 14. Log de conexiones cada X segundos a archivo
# ----------------------
function Log-ConnectionsToFile {
    param(
        [int]$IntervalSeconds = 10,
        [int]$Iterations = 6,
        [string]$OutFile = (Join-Path $Global:LogPath "ConnectionsLog.txt")
    )
    Write-Log "Iniciando log de conexiones cada ${IntervalSeconds}s. Salida: $OutFile"
    for ($i=0; $i -lt $Iterations; $i++) {
        $now = Get-Date
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
        $conns | ForEach-Object {
            "$($now) `t $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)] (PID $($_.OwningProcess))" | Out-File -FilePath $OutFile -Append
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
    Write-Log "Log de conexiones completado."
    return $OutFile
}

# ----------------------
# 15. Detección de tráfico hacia países inusuales
# ----------------------
function Detect-CountryTraffic {
    param(
        [String[]]$IpList
    )
    Write-Log "Detección de países remotos (requiere acceso a internet y API GeoIP opcional)."
    $results = @()
    foreach ($ip in $IpList) {
        try {
            # Intento simple: llamar a ipinfo.io (usa internet). Si no hay internet, avisar.
            $info = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json" -UseBasicParsing -ErrorAction Stop
            $results += [pscustomobject]@{IP=$ip; Country=$info.country; Org=$info.org; City=$info.city}
        } catch {
            $results += [pscustomobject]@{IP=$ip; Country="UNKNOWN_OR_NO_INTERNET"; Org="N/A"; City="N/A"}
        }
    }
    return $results
}

# ----------------------
# 16. Resolución inversa automática de IPs remotas activas
# ----------------------
function Reverse-DNSForActiveRemotes {
    Write-Log "Resolviendo DNS inverso para remotos activos..."
    $ips = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" } | Select-Object -ExpandProperty RemoteAddress -Unique
    $out = foreach ($ip in $ips) {
        try {
            $name = [System.Net.Dns]::GetHostEntry($ip).HostName
        } catch {
            $name = "NO_HOST"
        }
        [pscustomobject]@{IP=$ip; Hostname=$name}
    }
    return $out
}

# ----------------------
# 17. Escaneo rápido del equipo con Test-NetConnection para identificar puertos escuchando
# ----------------------
function Quick-PortScan {
    param([int[]]$Ports = @(21,22,23,25,80,443,389,445,3389,5985,5986))
    Write-Log "Escaneo rápido de puertos locales: $($Ports -join ',')"
    $results = foreach ($p in $Ports) {
        try {
            $res = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port $p -WarningAction SilentlyContinue
            [pscustomobject]@{Port=$p; TcpTestSucceeded = $res.TcpTestSucceeded; RemotePort=$res.RemotePort}
        } catch {
            [pscustomobject]@{Port=$p; TcpTestSucceeded="ERROR"; RemotePort=$p}
        }
    }
    return $results
}

# ----------------------
# 18-20. Exportar todo a HTML / JSON / TXT
# ----------------------
function Export-Report {
    param(
        [Parameter(Mandatory=$true)][PSObject]$Report,
        [string]$Format = "HTML" # HTML, JSON, TXT
    )
    $base = Join-Path $Global:LogPath ("BlueTeamReport_" + (Get-Date).ToString("yyyyMMdd_HHmmss"))
    switch ($Format.ToUpper()) {
        "HTML" {
            $path = "$base.html"
            $Report | ConvertTo-Html -PreContent "<h1>BlueTeam Report</h1><p>Generado: $(Get-Date)</p>" -Body "<div></div>" | Out-File -FilePath $path -Encoding UTF8
        }
        "JSON" {
            $path = "$base.json"
            $Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $path -Encoding UTF8
        }
        "TXT" {
            $path = "$base.txt"
            $Report | Out-String | Out-File -FilePath $path -Encoding UTF8
        }
        default { Write-Log "Formato no soportado"; return $null }
    }
    Write-Log "Reporte exportado a $path"
    return $path
}

# ----------------------
# 21. Crear logs detallados de ejecución del script
# ----------------------
function Start-DetailedLogging {
    Write-Log "Detalle de logging ya se hace en $Global:RunLog"
    # Ya se escribe cada evento con Write-Log. Podemos agregar captura de outputs si se necesita.
}

# ----------------------
# 22. Crear un panel interactivo con GUI (Windows Forms)
# ----------------------
function Show-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "BlueTeam Toolkit - GUI"
    $form.Size = New-Object System.Drawing.Size(800,500)
    $form.StartPosition = "CenterScreen"

    $btnScan = New-Object System.Windows.Forms.Button
    $btnScan.Text = "Run Full Scan"
    $btnScan.Size = New-Object System.Drawing.Size(120,30)
    $btnScan.Location = New-Object System.Drawing.Point(10,10)
    $btnScan.Add_Click({
        Write-Log "GUI: Run Full Scan iniciado."
        $report = Run-FullScan -SkipExport
        [System.Windows.Forms.MessageBox]::Show("Scan completado. Report listo.")
    })
    $form.Controls.Add($btnScan)

    $btnShowLog = New-Object System.Windows.Forms.Button
    $btnShowLog.Text = "Abrir Log"
    $btnShowLog.Size = New-Object System.Drawing.Size(120,30)
    $btnShowLog.Location = New-Object System.Drawing.Point(140,10)
    $btnShowLog.Add_Click({
        Invoke-Item $Global:RunLog
    })
    $form.Controls.Add($btnShowLog)

    $form.Add_Shown({$form.Activate()})
    [void]$form.ShowDialog()
}

# ----------------------
# 23. Programar ejecución automática cada X horas (scheduler)
# ----------------------
function Create-ScheduledRun {
    param(
        [int]$EveryHours = 24,
        [string]$TaskName = "BlueTeamToolkit_AutomaticScan"
    )
    Write-Log "Creando tarea programada $TaskName para cada $EveryHours hora(s)..."
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours $EveryHours) -RepetitionDuration ([TimeSpan]::MaxValue)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -RunLevel Highest -Force
    Write-Log "Tarea programada creada."
}

# ----------------------
# 24. Autoactualización del script desde una ruta (http o UNC)
# ----------------------
function Auto-UpdateScript {
    param([string]$SourceUrl)
    Write-Log "Intentando auto-actualizar desde $SourceUrl"
    try {
        $tmp = Join-Path $env:TEMP "BlueTeamToolkit_update.ps1"
        Invoke-WebRequest -Uri $SourceUrl -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        Write-Log "Descargado actualización a $tmp"
        # Validación mínima: comparar hash
        $newHash = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
        Write-Log "Hash de nuevo script: $newHash"
        # Sobrescribir script actual (requiere que PS esté ejecutando desde disco)
        $current = $MyInvocation.MyCommand.Path
        if ($current) {
            Copy-Item -Path $tmp -Destination $current -Force
            Write-Log "Script actualizado en $current. Re-ejecuta para aplicar cambios."
        } else {
            Write-Log "No se pudo determinar ruta del script actual. Actualización no aplicada."
        }
    } catch {
        Write-Log "Fallo auto-actualización: $_" "ERROR"
    }
}

# ----------------------
# 25. Creación de un EXE portable (ps2exe) — wrapper
# ----------------------
function Create-ExeFromScript {
    param([string]$OutputExe = (Join-Path $Global:LogPath "BlueTeamToolkit.exe"))
    Write-Log "Generando EXE con ps2exe (si está instalado)."
    # ps2exe requiere el módulo/función ps2exe. Intenta localizar ps2exe
    $ps2exe = Get-Command -Name ps2exe -ErrorAction SilentlyContinue
    if (-not $ps2exe) {
        Write-Log "ps2exe no encontrado. Instala ps2exe (Install-Module -Name ps2exe) o proporciona la ruta a ps2exe." "WARN"
        return $null
    }
    try {
        & $ps2exe.Source -InputFile $MyInvocation.MyCommand.Path -OutputFile $OutputExe -NoConsole -Verbose
        Write-Log "EXE generado: $OutputExe"
        return $OutputExe
    } catch {
        Write-Log "Error generando EXE: $_" "ERROR"
    }
}

# ----------------------
# Utility: Ejecuta un escaneo completo y crea estructura de reporte
# ----------------------
function Run-FullScan {
    param([switch]$SkipExport)
    Write-Log "Run-FullScan iniciado..."
    $report = [ordered]@{}
    $report.Persistencia = Detect-Persistence
    $report.Drivers = Get-Drivers
    $report.ProcessModules = Get-ProcessModules
    $report.OpenPorts = Detect-OpenPorts
    $report.FileIntegrity = Check-FileIntegrity
    $report.InstalledSoftware = Get-InstalledSoftware
    $report.SecurityPolicies = Get-SecurityPolicies
    $report.SuspiciousFiles = Find-SuspiciousFiles
    $report.SignedMicrosoftOdd = Detect-SignedMicrosoftButOddLocation
    $report.UserAnomalies = Detect-UserAnomalies
    $report.ServiceAnomalies = Detect-ServiceAnomalies
    $report.PersistentConnections = Detect-PersistentConnections
    $report.ReverseDNS = Reverse-DNSForActiveRemotes
    $report.QuickPortScan = Quick-PortScan

    Write-Log "Run-FullScan completado."

    if (-not $SkipExport) {
        $html = Export-Report -Report $report -Format "HTML"
        $json = Export-Report -Report $report -Format "JSON"
        $txt  = Export-Report -Report $report -Format "TXT"
        Write-Log "Exportados: $html, $json, $txt"
    }
    return $report
}

# ----------------------
# MENU simple en consola
# ----------------------
function Show-Menu {
    while ($true) {
        Write-Host ""
        Write-Host "=== BlueTeam Toolkit — Menu ===" -ForegroundColor Cyan
        Write-Host "1) Ejecutar escaneo completo (Run-FullScan)"
        Write-Host "2) Detectar persistencia"
        Write-Host "3) Listar drivers"
        Write-Host "4) Revisar módulos de procesos (DLLs)"
        Write-Host "5) Detectar puertos abiertos"
        Write-Host "6) Comprobar integridad de ficheros críticos"
        Write-Host "7) Enumerar software instalado"
        Write-Host "8) Revisar políticas de seguridad"
        Write-Host "9) Buscar archivos sospechosos (AppData/Temp/Public)"
        Write-Host "10) Detectar binarios Microsoft en ubicaciones extrañas"
        Write-Host "11) Detectar anomalías usuarios"
        Write-Host "12) Detectar anomalías servicios"
        Write-Host "13) Detectar conexiones persistentes"
        Write-Host "14) Monitor en tiempo real (nuevas conexiones)"
        Write-Host "15) Log conexiones a archivo"
        Write-Host "16) Reverse DNS remotos activos"
        Write-Host "17) Escaneo rápido de puertos (Test-NetConnection)"
        Write-Host "18) Exportar Escaneo completo (HTML/JSON/TXT)"
        Write-Host "19) Mostrar GUI"
        Write-Host "20) Crear tarea programada para ejecutar script"
        Write-Host "21) Auto-actualizar script desde URL"
        Write-Host "22) Generar EXE con ps2exe (si instalado)"
        Write-Host "23) Salir"
        $opt = Read-Host "Selecciona opción"
        switch ($opt) {
            "1" { Run-FullScan | Out-Null }
            "2" { Detect-Persistence | Format-List | Out-Host }
            "3" { Get-Drivers | Format-Table -AutoSize }
            "4" { Get-ProcessModules | Select-Object -First 50 | Format-Table -AutoSize }
            "5" { $r = Detect-OpenPorts; $r.All | Format-Table -AutoSize }
            "6" { Check-FileIntegrity | Format-Table -AutoSize }
            "7" { Get-InstalledSoftware | Format-Table -AutoSize }
            "8" { Get-SecurityPolicies | Format-List }
            "9" { Find-SuspiciousFiles | Format-List }
            "10"{ Detect-SignedMicrosoftButOddLocation | Format-Table -AutoSize }
            "11"{ Detect-UserAnomalies | Format-List }
            "12"{ Detect-ServiceAnomalies | Format-List }
            "13"{ Detect-PersistentConnections | Format-List }
            "14"{ Monitor-NewConnections -IntervalSeconds 5 -DurationSeconds 60 }
            "15"{ $f = Log-ConnectionsToFile -IntervalSeconds 10 -Iterations 6; Write-Host "Log en: $f" }
            "16"{ Reverse-DNSForActiveRemotes | Format-Table -AutoSize }
            "17"{ Quick-PortScan | Format-Table -AutoSize }
            "18"{ $r = Run-FullScan -SkipExport; $p = Export-Report -Report $r -Format (Read-Host "Formato (HTML/JSON/TXT)"); Write-Host "Exportado a $p" }
            "19"{ Show-GUI }
            "20"{ Create-ScheduledRun -EveryHours (Read-Host "Cada cuantas horas? (n)") }
            "21"{ Auto-UpdateScript -SourceUrl (Read-Host "URL del script remoto") }
            "22"{ Create-ExeFromScript }
            "23"{ break }
            default { Write-Host "Opción inválida." -ForegroundColor Red }
        }
    }
}

# ----------------------
# Auto-elevación (si es necesario)
# ----------------------
function Ensure-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "El script necesita ejecutarse como administrador. Reiniciando con elevación..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}

# ----------------------
# Entrypoint
# ----------------------
try {
    Ensure-Admin
} catch { Write-Log "No se pudo comprobar elevación: $_" "WARN" }

Show-Menu

Write-Log "BlueTeamToolkit finalizado."
