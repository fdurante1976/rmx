$logFile = Join-Path $PSScriptRoot 'install_log.txt'
# Automatización de instalación de software desde la carpeta Install
Add-Type -AssemblyName System.Windows.Forms

# --- FUNCIÓN DE MENSAJES ---
function Show-Message($message) {
    [System.Windows.Forms.MessageBox]::Show($message, 'Instalador RMX') | Out-Null
}

# Comprobación de privilegios de administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Show-Message "Este script debe ejecutarse como Administrador. Por favor, cierre esta ventana y vuelva a ejecutar PowerShell como Administrador."
    exit 1
}

# Paso intermedio: Instalación de IIS y configuración web
Show-Message "Instalando y configurando IIS..."
# Instalación de características de IIS
$features = @(
    'IIS-WebServerRole', 'IIS-WebServer', 'IIS-CommonHttpFeatures', 'IIS-HttpErrors',
    'IIS-HttpRedirect', 'IIS-ApplicationDevelopment', 'IIS-HealthAndDiagnostics',
    'IIS-HttpLogging', 'IIS-LoggingLibraries', 'IIS-RequestMonitor', 'IIS-HttpTracing',
    'IIS-IIS6ManagementCompatibility', 'IIS-CustomLogging',
    'IIS-WMICompatibility', 'IIS-LegacyScripts', 'IIS-ManagementService',
    'NetFx4Extended-ASPNET45', 'IIS-NetFxExtensibility45', 'IIS-ISAPIExtensions',
    'IIS-ISAPIFilter', 'IIS-NetFxExtensibility', 'IIS-ASPNET', 'IIS-ASPNET45',
    'WAS-WindowsActivationService', 'WAS-ConfigurationAPI', 'WAS-NetFxEnvironment'
)
foreach ($f in $features) {
    $featureState = (Get-WindowsOptionalFeature -Online -FeatureName $f).State
    if ($featureState -eq 'Enabled') {
        Write-Host "La característica $f ya está habilitada."
    } else {
        Enable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart | Out-Null
    }
}
Show-Message "Instalando prerrequisitos..."
$projectRoot = Split-Path $PSScriptRoot -Parent
$installRoot = Join-Path $projectRoot 'Install'
$prerreqBase = Join-Path $installRoot '01._Prerrequisitos'
if (Test-Path $prerreqBase) {
    $subdirs = Get-ChildItem -Path $prerreqBase -Directory | Sort-Object Name
    foreach ($dir in $subdirs) {
        $prerreq = $dir.Name
        $dirPath = $dir.FullName
        if (-not (Test-Path $dirPath)) {
            Show-Message "No se encontró la carpeta $prerreq."
            Add-Content -Path $logFile -Value "No se encontró la carpeta $prerreq."
            continue
        }
        # Buscar EXE
        $exe = Get-ChildItem -Path $dirPath -Filter *.exe -File | Select-Object -First 1
        if ($exe) {
            $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exe.Name)
            $programFiles = @(
                Join-Path $env:ProgramFiles $exeName
                Join-Path ${env:ProgramFiles(x86)} $exeName
            )
            $alreadyInstalled = $false
            foreach ($pf in $programFiles) {
                if (Test-Path $pf) { $alreadyInstalled = $true; break }
            }
            if (-not $alreadyInstalled) {
                $msg = "Instalando prerrequisito EXE: $($exe.FullName)"
                Write-Host $msg
                Add-Content -Path $logFile -Value $msg
                Show-Message "Instalando $exeName..."
                try {
                    if ($exe.Name -eq 'SSCERuntime_x64-ESN.exe') {
                        Start-Process $exe.FullName -Wait -ErrorAction Stop
                    } else {
                        Start-Process $exe.FullName -ArgumentList '/S' -Wait -ErrorAction Stop
                    }
                    $msgOK = "Instalación EXE finalizada: $($exe.FullName)"
                    Add-Content -Path $logFile -Value $msgOK
                    Show-Message "$exeName instalado."
                } catch {
                    $msgErr = "ERROR instalando EXE: $($exe.FullName) - $_"
                    Write-Host $msgErr
                    Add-Content -Path $logFile -Value $msgErr
                    Show-Message "Error instalando $exeName."
                }
            } else {
                $msg = "El prerrequisito $exeName ya está instalado."
                Write-Host $msg
                Add-Content -Path $logFile -Value $msg
                Show-Message "$exeName ya está instalado."
            }
            continue
        }
        # Buscar MSI
        $msi = Get-ChildItem -Path $dirPath -Filter *.msi -File | Select-Object -First 1
        if ($msi) {
            $msiName = [System.IO.Path]::GetFileNameWithoutExtension($msi.Name)
            $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$msiName*" }
            if (-not $product) {
                $msg = "Instalando prerrequisito MSI: $($msi.FullName)"
                Write-Host $msg
                Add-Content -Path $logFile -Value $msg
                Show-Message "Instalando $msiName..."
                try {
                    $msiPath = $msi.FullName
                    $msiArgString = "/i `"$msiPath`" /qn /norestart"
                    $cmdLog = "Comando: msiexec.exe $msiArgString"
                    Add-Content -Path $logFile -Value $cmdLog
                    Start-Process msiexec.exe -ArgumentList $msiArgString -Wait -ErrorAction Stop
                    $msgOK = "Instalación MSI finalizada: $($msi.FullName)"
                    Add-Content -Path $logFile -Value $msgOK
                    Show-Message "$msiName instalado."
                } catch {
                    $msgErr = "ERROR instalando MSI: $($msi.FullName) - $_"
                    Write-Host $msgErr
                    Add-Content -Path $logFile -Value $msgErr
                    Show-Message "Error instalando $msiName."
                }
            } else {
                $msg = "El prerrequisito MSI $msiName ya está instalado."
                Write-Host $msg
                Add-Content -Path $logFile -Value $msg
                Show-Message "$msiName ya está instalado."
            }
            continue
        }
        Show-Message "No se encontró instalador EXE ni MSI en $prerreq."
        Add-Content -Path $logFile -Value "No se encontró instalador EXE ni MSI en $prerreq."
    }
    Show-Message "Prerrequisitos instalados."
} else {
    Show-Message "No se encontró la carpeta 01._Prerrequisitos."
}

# 1. Copiar 02._AgentB
Show-Message "Instalando AgentB..."
$agentBSource = Join-Path $installRoot '02._AgentB'
if (-not (Test-Path "C:\AgentB")) {
    Copy-Item -Path $agentBSource -Destination "C:\AgentB" -Recurse -Force
    Write-Host "Directorio AgentB copiado."
} else {
    Write-Host "El directorio AgentB ya existe."
}

# 2. Copiar 03._AgentB Client
Show-Message "Instalando AgentB Client..."
$agentBClientSource = Join-Path $installRoot '03._AgentB Client'
if (-not (Test-Path "C:\AgentB_Client")) {
    Copy-Item -Path $agentBClientSource -Destination "C:\AgentB_Client" -Recurse -Force
    Write-Host "Directorio AgentB_Client copiado."
} else {
    Write-Host "El directorio AgentB_Client ya existe."
}

# 3. Copiar 04._RCSAgent y lanzar instalación
Show-Message "Instalando RCSAgent..."
$rcsAgentSource = Join-Path $installRoot '04._RCSAgent'
# Comprobar si RCSAgent ya está instalado (por nombre en el registro)
$rcsAgentInstalled = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*RCSAgent*' }
if ($rcsAgentInstalled) {
    Show-Message "RCSAgent ya está instalado. Se omite la instalación."
} else {
    if (-not (Test-Path "C:\RCSAgent")) {
        Copy-Item -Path $rcsAgentSource -Destination "C:\RCSAgent" -Recurse -Force
        Write-Host "Directorio RCSAgent copiado."
    } else {
        Write-Host "El directorio RCSAgent ya existe."
    }
    if (Test-Path "C:\RCSAgent\RCSAgent.exe") {
        Start-Process "C:\RCSAgent\RCSAgent.exe" -Wait
    Show-Message "RCSAgent instalado."
    } else {
    Show-Message "No se encontró RCSAgent.exe en C:\RCSAgent"
    }
}

# 4. Copiar 05._RCSDesktop y lanzar instalación
Show-Message "Instalando RCSDesktop..."
$rcsDesktopSource = Join-Path $installRoot '05._RCSDesktop'
# Comprobar si RCSDesktop ya está instalado (por nombre en el registro)
$rcsDesktopInstalled = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*RCSDesktop*' -or $_.DisplayName -like '*RMXDesktop*' }
if ($rcsDesktopInstalled) {
    Show-Message "RCSDesktop ya está instalado. Se omite la instalación."
} else {
    if (-not (Test-Path "C:\RCSDesktop")) {
        Copy-Item -Path $rcsDesktopSource -Destination "C:\RCSDesktop" -Recurse -Force
        Write-Host "Directorio RCSDesktop copiado."
    } else {
        Write-Host "El directorio RCSDesktop ya existe."
    }
    if (Test-Path "C:\RCSDesktop\RMXDesktop.exe") {
        Start-Process "C:\RCSDesktop\RMXDesktop.exe" -Wait
    Show-Message "RMXDesktop instalado."
    } else {
    Show-Message "No se encontró RMXDesktop.exe en C:\RCSDesktop"
    }
}

# 5. Preguntar por Dispatching
$dispatching = [System.Windows.Forms.MessageBox]::Show("¿Qué software de Dispatching desea instalar?\nSí = LECA, No = PROIN", "Instalador RMX", "YesNo")
if ($dispatching -eq [System.Windows.Forms.DialogResult]::Yes) {
    Show-Message "Instalando LECA (Monit4C)..."
    $monitPath = Join-Path $installRoot "06._Dispatching/06.1_Leca/06.1.1_Monit4C"
    if (Test-Path $monitPath) {
        # Comprobar si Monit4C ya está instalado (por nombre en el registro)
        $lecaInstalled = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Monit4C*' -or $_.DisplayName -like '*LECA*' }
        if ($lecaInstalled) {
            Show-Message "LECA (Monit4C) ya está instalado. Se omite la instalación."
        } else {
            $monitExe = Join-Path $monitPath 'setup.exe'
            if (Test-Path $monitExe) {
                Start-Process $monitExe -Wait
                Show-Message "Monit4C instalado."
            } else {
                Show-Message "No se encontró setup.exe en 06.1.1_Monit4C."
            }
        }
    } else {
        Show-Message "No se encontró la carpeta 06.1.1_Monit4C."
    }
} else {
    Show-Message "Instalando PROIN..."
    $proinBase = Join-Path $installRoot '06._Dispatching/06.2_Proin'
    if (Test-Path $proinBase) {
        # 1. Instalar fuentes
    $fuentesPath = Join-Path $proinBase '06.2.1_Fuentes'
        if (Test-Path $fuentesPath) {
            Show-Message "Instalando fuentes..."
            $fontsShell = (New-Object -ComObject Shell.Application).Namespace(0x14)
            Get-ChildItem -Path $fuentesPath -Filter *.ttf | ForEach-Object {
                $fontFile = $_.FullName
                $fontName = $_.Name
                if (-not (Test-Path "C:\Windows\Fonts\$fontName")) {
                    $fontsShell.CopyHere($fontFile)
                }
            }
            Show-Message "Fuentes instaladas."
        } else {
            Show-Message "Instalando prerrequisitos..."
            $projectRoot = Split-Path $PSScriptRoot -Parent
            $installRoot = Join-Path $projectRoot 'Install'
            $prerreqBase = Join-Path $installRoot '01._Prerrequisitos'
            if (Test-Path $prerreqBase) {
                # Instalación secuencial y explícita de cada subcarpeta
                $prerreqs = @(
                    '01.1_ASPNetCore',
                    '01.2_CompactView',
                    '01.3_NetHosting',
                    '01.4_NetSDK',
                    '01.5_SSCERuntime'
                )
                foreach ($prerreq in $prerreqs) {
                    $dirPath = Join-Path $prerreqBase $prerreq
                    if (-not (Test-Path $dirPath)) {
                        Show-Message "No se encontró la carpeta $prerreq."
                        Add-Content -Path $logFile -Value "No se encontró la carpeta $prerreq."
                        continue
                    }
                    # Buscar EXE
                    $exe = Get-ChildItem -Path $dirPath -Filter *.exe -File | Select-Object -First 1
                    if ($exe) {
                        $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exe.Name)
                        $programFiles = @(Join-Path $env:ProgramFiles $exeName, Join-Path $env:ProgramFiles '(x86)' $exeName)
                        $alreadyInstalled = $false
                        foreach ($pf in $programFiles) {
                            if (Test-Path $pf) { $alreadyInstalled = $true; break }
                        }
                        if (-not $alreadyInstalled) {
                            $msg = "Instalando prerrequisito EXE: $($exe.FullName)"
                            Write-Host $msg
                            Add-Content -Path $logFile -Value $msg
                            Show-Message "Instalando $exeName..."
                            try {
                                Start-Process $exe.FullName -ArgumentList '/S' -Wait -ErrorAction Stop
                                $msgOK = "Instalación EXE finalizada: $($exe.FullName)"
                                Add-Content -Path $logFile -Value $msgOK
                                Show-Message "$exeName instalado."
                            } catch {
                                $msgErr = "ERROR instalando EXE: $($exe.FullName) - $_"
                                Write-Host $msgErr
                                Add-Content -Path $logFile -Value $msgErr
                                Show-Message "Error instalando $exeName."
                            }
                        } else {
                            $msg = "El prerrequisito $exeName ya está instalado."
                            Write-Host $msg
                            Add-Content -Path $logFile -Value $msg
                            Show-Message "$exeName ya está instalado."
                        }
                        continue
                    }
                    # Buscar MSI
                    $msi = Get-ChildItem -Path $dirPath -Filter *.msi -File | Select-Object -First 1
                    if ($msi) {
                        $msiName = [System.IO.Path]::GetFileNameWithoutExtension($msi.Name)
                        $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$msiName*" }
                        if (-not $product) {
                            $msg = "Instalando prerrequisito MSI: $($msi.FullName)"
                            Write-Host $msg
                            Add-Content -Path $logFile -Value $msg
                            Show-Message "Instalando $msiName..."
                            try {
                                $msiPath = $msi.FullName
                                $msiArgString = "/i `"$msiPath`" /qn /norestart"
                                $cmdLog = "Comando: msiexec.exe $msiArgString"
                                Add-Content -Path $logFile -Value $cmdLog
                                Start-Process msiexec.exe -ArgumentList $msiArgString -Wait -ErrorAction Stop
                                $msgOK = "Instalación MSI finalizada: $($msi.FullName)"
                                Add-Content -Path $logFile -Value $msgOK
                                Show-Message "$msiName instalado."
                            } catch {
                                $msgErr = "ERROR instalando MSI: $($msi.FullName) - $_"
                                Write-Host $msgErr
                                Add-Content -Path $logFile -Value $msgErr
                                Show-Message "Error instalando $msiName."
                            }
                        } else {
                            $msg = "El prerrequisito MSI $msiName ya está instalado."
                            Write-Host $msg
                            Add-Content -Path $logFile -Value $msg
                            Show-Message "$msiName ya está instalado."
                        }
                        continue
                    }
                    Show-Message "No se encontró instalador EXE ni MSI en $prerreq."
                    Add-Content -Path $logFile -Value "No se encontró instalador EXE ni MSI en $prerreq."
                }
                Show-Message "Prerrequisitos instalados."
            } else {
                Show-Message "No se encontró la carpeta 01._Prerrequisitos."
            }
        if ($lopeeditInstalled) {
            Show-Message 'LopeEdit ya está instalado. Se omite la instalación.'
        } elseif ($lopeeditExe) {
            Show-Message "Instalando LopeEdit..."
            Start-Process $lopeeditExe.FullName -Wait
            Show-Message "LopeEdit instalado."
        } else {
            Show-Message "No se encontró el instalador de LopeEdit."
        }

        Show-Message "PROIN instalado."
    } else {
        Show-Message "No se encontró la carpeta 06.2_Proin."
    }
}
}


# 6. Copias de seguridad
Show-Message "Realizando copia de seguridad de scripts..."
$backupSource = Join-Path $installRoot '07._Scripts Backup'
if (Test-Path $backupSource) {
    if (-not (Test-Path "C:\ScriptsBackup")) {
        Copy-Item -Path $backupSource -Destination "C:\ScriptsBackup" -Recurse -Force
        Write-Host "Directorio ScriptsBackup copiado."
    } else {
        Write-Host "El directorio ScriptsBackup ya existe."
    }
    Show-Message "Copia de seguridad completada."
} else {
    Show-Message "No se encontró la carpeta 07._Scripts Backup."
}

Show-Message "Instalación finalizada."
