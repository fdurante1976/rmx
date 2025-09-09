# Automatización de instalación de software desde la carpeta Install
Add-Type -AssemblyName System.Windows.Forms

# --- FUNCIÓN DE MENSAJES ---
function Show-Message($message) {
    [System.Windows.Forms.MessageBox]::Show($message, 'Instalador RMX') | Out-Null
}

# Paso intermedio: Instalación de IIS y configuración web
Show-Message 'Instalando y configurando IIS...'
# Instalación de características de IIS
$features = @(
    'IIS-WebServerRole', 'IIS-WebServer', 'IIS-CommonHttpFeatures', 'IIS-HttpErrors',
    'IIS-HttpRedirect', 'IIS-ApplicationDevelopment', 'IIS-HealthAndDiagnostics',
    'IIS-HttpLogging', 'IIS-LoggingLibraries', 'IIS-RequestMonitor', 'IIS-HttpTracing',
    'IIS-IIS6ManagementCompatibility', 'IIS-LegacySnapIn', 'IIS-CustomLogging',
    'IIS-WMICompatibility', 'IIS-LegacyScripts', 'IIS-ManagementService',
    'NetFx4Extended-ASPNET45', 'IIS-NetFxExtensibility45', 'IIS-ISAPIExtensions',
    'IIS-ISAPIFilter', 'IIS-NetFxExtensibility', 'IIS-ASPNET', 'IIS-ASPNET45',
    'WAS-WindowsActivationService', 'WAS-ConfigurationAPI', 'WAS-NetFxEnvironment'
)
foreach ($f in $features) {
    Enable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart | Out-Null
}
Show-Message 'Características de IIS instaladas.'

# Creación de AppPools
Import-Module WebAdministration
if (-not (Test-Path IIS:\AppPools\NetCore)) {
    New-Item -Path IIS:\AppPools\NetCore | Out-Null
    Set-ItemProperty -Path IIS:\AppPools\NetCore managedRuntimeVersion ""
}
if (-not (Test-Path IIS:\AppPools\AgentB_Client)) {
    New-Item -Path IIS:\AppPools\AgentB_Client | Out-Null
    Set-ItemProperty -Path IIS:\AppPools\AgentB_Client managedRuntimeVersion -Value 'v4.0'
}

# Creación de sitio web
if (-not (Test-Path IIS:\Sites\AgentB_Client)) {
    New-Item IIS:\Sites\AgentB_Client -physicalPath C:\AgentB_Client -bindings @{protocol="http";bindingInformation="*:4100:agentb.uat"} | Out-Null
    Set-ItemProperty IIS:\Sites\AgentB_Client -name applicationPool -value AgentB_Client
}

# Modificación del fichero hosts
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
$entry = "127.0.0.1`tagentb.uat"
if (-not (Select-String -Path $hostsPath -Pattern "agentb.uat" -Quiet)) {
    Add-Content -Path $hostsPath -Value $entry -Force
}
# Automatización de instalación de software desde la carpeta Install
Add-Type -AssemblyName System.Windows.Forms

# --- FUNCIÓN DE MENSAJES ---
function Show-Message($message) {
    [System.Windows.Forms.MessageBox]::Show($message, 'Instalador RMX') | Out-Null
}



# 0. Instalar prerrequisitos
Show-Message 'Instalando prerrequisitos...'
$prerreqBase = "./Install/01._Prerrequisitos"
if (Test-Path $prerreqBase) {
    $subdirs = Get-ChildItem -Path $prerreqBase -Directory | Sort-Object Name
    foreach ($dir in $subdirs) {
        $dirPath = $dir.FullName
        $exes = Get-ChildItem -Path $dirPath -Filter *.exe -File
        foreach ($exe in $exes) {
            Start-Process $exe.FullName -ArgumentList '/S' -Wait
        }
        $msis = Get-ChildItem -Path $dirPath -Filter *.msi -File
        foreach ($msi in $msis) {
            Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -Wait
        }
    }
    Show-Message 'Prerrequisitos instalados.'
} else {
    Show-Message 'No se encontró la carpeta 01._Prerrequisitos.'
}

# 1. Copiar 02._AgentB
Show-Message 'Instalando AgentB...'
Copy-Item -Path "./Install/02._AgentB" -Destination "C:\AgentB" -Recurse -Force

# 2. Copiar 03._AgentB Client
Show-Message 'Instalando AgentB Client...'
Copy-Item -Path "./Install/03._AgentB Client" -Destination "C:\AgentB_Client" -Recurse -Force

# 3. Copiar 04._RCSAgent y lanzar instalación
Show-Message 'Instalando RCSAgent...'
Copy-Item -Path "./Install/04._RCSAgent" -Destination "C:\RCSAgent" -Recurse -Force
if (Test-Path "C:\RCSAgent\RCSAgent.exe") {
    Start-Process "C:\RCSAgent\RCSAgent.exe" -Wait
    Show-Message 'RCSAgent instalado.'
} else {
    Show-Message 'No se encontró RCSAgent.exe en C:\RCSAgent'
}

# 4. Copiar 05._RCSDesktop y lanzar instalación
Show-Message 'Instalando RCSDesktop...'
Copy-Item -Path "./Install/05._RCSDesktop" -Destination "C:\RCSDesktop" -Recurse -Force
if (Test-Path "C:\RCSDesktop\RMXDesktop.exe") {
    Start-Process "C:\RCSDesktop\RMXDesktop.exe" -Wait
    Show-Message 'RMXDesktop instalado.'
} else {
    Show-Message 'No se encontró RMXDesktop.exe en C:\RCSDesktop'
}

# 5. Preguntar por Dispatching
$dispatching = [System.Windows.Forms.MessageBox]::Show('¿Qué software de Dispatching desea instalar?\nSí = LECA, No = PROIN', 'Instalador RMX', 'YesNo')
if ($dispatching -eq [System.Windows.Forms.DialogResult]::Yes) {
    Show-Message 'Instalando LECA...'
    $monitPath = "./Install/06._Dispatching/06.1_Leca/06.1.1_Monit4C"
    $actPath = "./Install/06._Dispatching/06.1_Leca/06.1.2_Act"
    if (Test-Path $monitPath) {
        Show-Message 'Instalando Monit4C...'
        $monitExe = Join-Path $monitPath 'setup.exe'
        if (Test-Path $monitExe) {
            Start-Process $monitExe -Wait
            Show-Message 'Monit4C instalado.'
        } else {
            Show-Message 'No se encontró setup.exe en 06.1.1_Monit4C.'
        }
    } else {
        Show-Message 'No se encontró la carpeta 06.1.1_Monit4C.'
    }
    if (Test-Path $actPath) {
        Show-Message 'Instalando Act...'
        $actExe = Get-ChildItem -Path $actPath -Filter *.exe | Select-Object -First 1
        if ($actExe -and $actExe.FullName) {
            Start-Process $actExe.FullName -Wait
            Show-Message 'Act instalado.'
        } else {
            Show-Message 'No se encontró ejecutable en 06.1.2_Act.'
        }
    } else {
        Show-Message 'No se encontró la carpeta 06.1.2_Act.'
    }
} else {
    Show-Message 'Instalando PROIN...'
    $proinBase = "./Install/06._Dispatching/06.2_Proin"
    if (Test-Path $proinBase) {
        # 1. Instalar fuentes
        $fuentesPath = Join-Path $proinBase '06.2.1_Fuentes'
        if (Test-Path $fuentesPath) {
            Show-Message 'Instalando fuentes...'
            $fontsShell = (New-Object -ComObject Shell.Application).Namespace(0x14)
            Get-ChildItem -Path $fuentesPath -Filter *.ttf | ForEach-Object {
                $fontFile = $_.FullName
                $fontName = $_.Name
                if (-not (Test-Path "C:\Windows\Fonts\$fontName")) {
                    $fontsShell.CopyHere($fontFile)
                }
            }
            Show-Message 'Fuentes instaladas.'
        } else {
            Show-Message 'No se encontró la carpeta de fuentes.'
        }

        # 2. Registrar OCX
        $mswinsckPath = Join-Path $proinBase '06.2.2_MSWINSCK'
        if (Test-Path $mswinsckPath) {
            Show-Message 'Registrando OCX...'
            $ocxFiles = Get-ChildItem -Path $mswinsckPath -Filter *.ocx
            foreach ($ocx in $ocxFiles) {
                $dest = "C:\Windows\SysWOW64\$($ocx.Name)"
                Copy-Item $ocx.FullName $dest -Force
                $reg = Start-Process regsvr32.exe -ArgumentList "/s $dest" -PassThru
                $reg.WaitForExit(5000)
                if ($reg.ExitCode -ne 0) {
                    Show-Message "Error al registrar $($ocx.Name)"
                }
            }
            Show-Message 'OCX registrados.'
        } else {
            Show-Message 'No se encontró la carpeta MSWINSCK.'
        }

        # 3. Instalar SQL Server 2019 Express
        $sqlPath = Join-Path $proinBase '06.2.3_SQL2K19'
        if (Test-Path $sqlPath) {
            Show-Message 'Instalando SQL Server 2019 Express...'
            $configFile = Join-Path $sqlPath 'ConfigurationFile.ini'
            $setupExe = Join-Path $sqlPath 'SETUP.EXE'
            if ((Test-Path $setupExe) -and (Test-Path $configFile)) {
                Start-Process $setupExe -ArgumentList "/ConfigurationFile=$configFile" -Wait
                Show-Message 'SQL Server 2019 Express instalado.'
            } else {
                Show-Message 'No se encontró SETUP.EXE o ConfigurationFile.ini.'
            }
        } else {
            Show-Message 'No se encontró la carpeta SQL2K19.'
        }

        # 4. Instalar SSMS
        $ssmsPath = Join-Path $proinBase '06.2.4_SSMS'
        $ssmsExe = Join-Path $ssmsPath 'SSMS-Setup-ENU.exe'
        if (Test-Path $ssmsExe) {
            Show-Message 'Instalando SQL Server Management Studio...'
            Start-Process $ssmsExe -ArgumentList "/install /quiet" -Wait
            Show-Message 'SSMS instalado.'
        } else {
            Show-Message 'No se encontró el instalador de SSMS.'
        }

        # 5. Instalar CodeMeter
        $codemeterPath = Join-Path $proinBase '06.2.5_CodeMeter'
        $codemeterExe = Get-ChildItem -Path $codemeterPath -Filter *.exe | Select-Object -First 1
        if ($codemeterExe) {
            Show-Message 'Instalando CodeMeter...'
            Start-Process $codemeterExe.FullName -Wait
            Show-Message 'CodeMeter instalado.'
        } else {
            Show-Message 'No se encontró el instalador de CodeMeter.'
        }

        # 6. Instalar LopeEdit
        $lopeeditPath = Join-Path $proinBase '06.2.5_LopeEdit'
        $lopeeditExe = Get-ChildItem -Path $lopeeditPath -Filter *.exe | Select-Object -First 1
        if ($lopeeditExe) {
            Show-Message 'Instalando LopeEdit...'
            Start-Process $lopeeditExe.FullName -Wait
            Show-Message 'LopeEdit instalado.'
        } else {
            Show-Message 'No se encontró el instalador de LopeEdit.'
        }

        Show-Message 'PROIN instalado.'
    } else {
        Show-Message 'No se encontró la carpeta 06.2_Proin.'
    }
}


# 6. Copias de seguridad
Show-Message 'Realizando copia de seguridad de scripts...'
$backupSource = "./Install/07._Scripts Backup"
if (Test-Path $backupSource) {
    Copy-Item -Path $backupSource -Destination "C:\ScriptsBackup" -Recurse -Force
    Show-Message 'Copia de seguridad completada.'
} else {
    Show-Message 'No se encontró la carpeta 07._Scripts Backup.'
}

Show-Message 'Instalación finalizada.'
