Set-ExecutionPolicy Bypass -Scope Process
<#
Instalación de prerrequisitos necesarios y en este orden
    - SSCERuntime_x64-ESN
    - aspnetcore-runtime-3.1.26-win-x64
    - dotnet-sdk-3.1.420-win-x64
    - dotnet-hosting-3.1.26-win
    - CompactView_1.4.16.0_Installer
#>
function installPrerrequisitos {

    [string[]]$listado1 = Split-Path -Path "C:\Instalación\01. Prerrequisitos\*.exe" -Leaf -Resolve
    $total1 = $listado1.Length

    [string[]]$listado2 = Split-Path -Path "C:\Instalación\01. Prerrequisitos\SSCERuntime\*.exe" -Leaf -Resolve
    $total2 = $listado2.Length

    $contador = 0
    Get-ChildItem "C:\Instalación\01. Prerrequisitos\*.exe" | ForEach-Object {
        $contador++
        Write-Progress -Activity "Instalando software" -CurrentOperation "Instalando - $_ .. $contador de $total1" -Status "Espere..." -PercentComplete (($contador) / ($total1) * 100)
        Start-Process $_.FullName -ArgumentList '/S' -Wait -PassThru
    }

    # Instalamos el SSCERuntime de manera independiente para que no de error
    $contador = 0
    Get-ChildItem "C:\Instalación\01. Prerrequisitos\SSCERuntime\*.exe" | ForEach-Object {
        $contador++
        Write-Progress -Activity "Instalando software" -CurrentOperation "Instalando - $_ .. $contador de $total2" -Status "Espere..." -PercentComplete (($contador) / ($total2) * 100)
        msiexec /i .\SSCERuntime_x64-ESN.exe /qn /norestart
    }

    # Instalamos el plugin JSON Viewer para Notepad++
    Copy-Item -Path "C:\Instalación\00. Notepad++ Plugin\NPPJSONViewer" -Destination "C:\Program Files\Notepad++\plugins" -Recurse

}

<#
Creación de directorios con sus ficheros necesarios
    - AgentB 2.0.1.7
    - AgentB_Client
    - RCSAgent 2.0.73
    - RCSDesktop 1.2.63
#>
function createDirectorios {

    Copy-Item -Path "C:\Instalación\02. AgentB" -Destination "C:\AgentB" -Recurse -ErrorAction SilentlyContinue
    if (-not $?) {
        Write-Warning "Fallo al copiar"
        $error[0].Exception.Message
    } else {
        Write-Host "Carpeta AgentB creada satisfactoriamente"
    }

    Copy-Item -Path "C:\Instalación\03. AgentB Client" -Destination "C:\AgentB_Client" -Recurse -ErrorAction SilentlyContinue
    if (-not $?) {
        Write-Warning "Fallo al copiar"
        $error[0].Exception.Message
    } else {
        Write-Host "Carpeta AgentB_Client creada satisfactoriamente"
    }

    Copy-Item -Path "C:\Instalación\04. RCSAgent" -Destination "C:\RCSAgent" -Recurse -ErrorAction SilentlyContinue
    if (-not $?) {
        Write-Warning "Fallo al copiar"
        $error[0].Exception.Message
    } else {
        Write-Host "Carpeta RCSAgent creada satisfactoriamente"
    }
    
    Copy-Item -Path "C:\Instalación\05. RCSDesktop" -Destination "C:\RCSDesktop" -Recurse -ErrorAction SilentlyContinue
    if (-not $?) {
        Write-Warning "Fallo al copiar"
        $error[0].Exception.Message
    } else {
        Write-Host "Carpeta RCSDesktop creada satisfactoriamente"
    }

}

function installRoots {

    $folderRCSAgent = 'C:\RCSAgent'
    $folderRCSDesktop = 'C:\RCSDesktop'
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

    # Instalamos RCSAgent comprobando que la carpeta existe
    if ( Test-Path -Path $folderRCSAgent ) {
        Start-Process 'C:\RCSAgent\RCSAgent.exe' "/S"
    } else {
        [System.Windows.Forms.MessageBox]::Show('No existe el directorio RCSAgent','ERROR')
    }

    # Instalamos RCSDesktop comprobando que la carpeta existe
    if ( Test-Path -Path $folderRCSDesktop ) {
        Start-Process 'C:\RCSDesktop\RCSDesktop.exe' "/S"
        Start-Sleep -Seconds 15
        # Instalamos el servicio
        Start-Process 'C:\RCSDesktop\autoUpdate\installService.bat'
        Start-Sleep -Seconds 15
        # Comprobamos si se ha instalado el servicio
        $servicio = Get-Service -Name RootsAutoupdate -ErrorAction SilentlyContinue
        if ($servicio -eq $null) {
            Write-Host "No se encuentra el servicio RootsAutoupdate"
        } else {
            Write-Host "Se ha encontrado el servicio RootsAutoupdate e iniciando"
            # Lo establecemos en automático e iniciamos
            Set-Service -Name RootsAutoupdate -StartupType Automatic -Status Running
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show('No existe el directorio RCSDesktop','ERROR')
    }

    [System.Windows.Forms.MessageBox]::Show('No olvides configurar las credenciales en el RCSAgent!!')

}

<#
Herramientas de administración web
    - Compatibilidad con la configuración de IIS 6 y metabase de IIS
    - Consola de administración de IIS 6
    - Consola de administración IIS
    - Compatibilidad con WMI de IIS 6
    - Herramientas de scripting de IIS 6
    - Servicio de administración de IIS
Características de rendimiento
    - Compresión de contenido estático
Características HTTP comunes
    - Contenido estático
    - Documento predeterminado
    - Errores HTTP
    - Examen de directorios
    - Redirección HTTP
Estado y diagnóstico
    - Herramientas de registro
    - Monitor de solicitudes
    - Registro HTTP
    - Seguimiento
    - Registro personalizado
Seguridad
    - Filtrado de solicitudes
.Net Framework 4.8 Advanced Services
        - ASP.NET 4.8
    Características de desarrollo de aplicaciones
        - .NET Extensibility 4.8
        - Extensiones ISAPI
        - Filtros ISAPI
        - Extensibilidad de .NET 3.5
        - ASP.NET 3.5
        - ASP.NET 4.8
Servicio WAS
    - API de configuración
    - Entorno de .NET
    - Modelo de proceso
#>
function installIIS {

    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-LegacySnapIn
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-CustomLogging
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WMICompatibility
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-LegacyScripts
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementService

    Enable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45

    Enable-WindowsOptionalFeature -Online -FeatureName WAS-WindowsActivationService
    Enable-WindowsOptionalFeature -Online -FeatureName WAS-ConfigurationAPI
    Enable-WindowsOptionalFeature -Online -FeatureName WAS-NetFxEnvironment

}

<#
Creamos el grupo de aplicaciones con nombre 'NetCore' y sin código administrado.
Se iniciará automáticamente.

Creamos el grupo de aplicaciones con nombre 'AgentB_Client'con código administrado v4.0
Se iniciará automáticamente.
#>
function createAppGroups {

    Import-Module WebAdministration
    New-Item -Path IIS:\AppPools\NetCore
    Get-ItemProperty IIS:\AppPools\NetCore | select *
    Set-ItemProperty -Path IIS:\AppPools\NetCore managedRuntimeVersion ""

    Import-Module WebAdministration
    New-Item -Path IIS:\AppPools\AgentB_Client
    Get-ItemProperty IIS:\AppPools\AgentB_Client | select *
    Set-ItemProperty -Path IIS:\AppPools\AgentB_Client managedRuntimeVersion -Value 'v4.0'

}

<#
Creamos el sitio web 'AgentB_Client'
    - Ruta de acceso física: 'C:\AgentB_Client'
    - Enlace tipo: 'http'
    - Dirección IP: 'todas las no asignadas' 
    - Puerto: '4100'
    - Nombre de host: 'agentb.uat'
    - Asignamos al AppPool 'AgentB_Client'
#>
function createWebSite {

    New-Item IIS:\Sites\AgentB_Client -physicalPath C:\AgentB_Client -bindings @{protocol="http";bindingInformation="*:4100:agentb.uat"}
    Set-ItemProperty IIS:\Sites\AgentB_Client -name applicationPool -value AgentB_Client

}
<#
Modificamos el fichero HOSTS
#>
function modifyHOST {

    Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n127.0.0.1`tagentb.uat" -Force

}

function selectDispatching {

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'AUTOMATISMO'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)
    
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Selecciona automatismo:'
    $form.Controls.Add($label)
    
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80
    
    [void] $listBox.Items.Add('LECA')
    [void] $listBox.Items.Add('PROIN')
    
    $form.Controls.Add($listBox)
    
    $form.Topmost = $true
    
    $result = $form.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $x = $listBox.SelectedItem

        if ($x -eq "LECA") {
            installLECA
        } elseif ($x -eq "PROIN") {
            installPROIN
        } else {
            Write-Output "ERROR"
        }
    }

}

function installLECA {

    Write-Host "==========================================="
    Write-Host "FASE 8.1 : SE HA SELECCIONADO LECA"
    Write-Host "==========================================="
    Write-Output "HAS ESCOGIDO LECA"
    Start-Process "C:\Instalación\06. Dispatching\06.1 Leca\Instalacion Monit 4C Leca 8.06\setup.exe"
    Start-Process "C:\Instalación\06. Dispatching\06.1 Leca\Act. Monit4C 8.09.exe"

}

function installPROIN {

    Write-Host "==========================================="
    Write-Host "FASE 8.2 : SE HA SELECCIONADO PROIN"
    Write-Host "==========================================="
    Write-Output "HAS ESCOGIDO PROIN"
    Start-Process "C:\Instalación\06. Dispatching\06.2 Proin\LopeEdit-setup.exe"
    Start-Process "C:\Instalación\06. Dispatching\06.2 Proin\CodeMeterRuntime.exe"

    # Copiamos las DLL
    Write-Host "Copiando las DLL..."
    Copy-Item -Path "C:\Instalación\06. Dispatching\06.2 Proin\MSWINSCK\ConexActiveX.ocx" -Destination "C:\Windows\SysWOW64" -Force
    Copy-Item -Path "C:\Instalación\06. Dispatching\06.2 Proin\MSWINSCK\MSWINSCK.OCX" -Destination "C:\Windows\SysWOW64" -Force

    # Registramos las DLL
    Write-Host "Registrando las DLL..."
    $regsvrp = Start-Process regsvr32.exe -ArgumentList "/s C:\Windows\SysWOW64\ConexActiveX.ocx" -PassThru
    $regsvrp.WaitForExit(5000) # Wait (up to) 5 seconds
    if($regsvrp.ExitCode -ne 0)
    {
        Write-Warning "Error al registrar ConexActiveX.ocx"
        Write-Warning "regsvr32 exited with error $($regsvrp.ExitCode)"
    }

    $regsvrp = Start-Process regsvr32.exe -ArgumentList "/s C:\Windows\SysWOW64\MSWINSCK.OCX" -PassThru
    $regsvrp.WaitForExit(5000) # Wait (up to) 5 seconds
    if($regsvrp.ExitCode -ne 0)
    {
        Write-Warning "Error al registrar MSWINSCK.OCX"
        Write-Warning "regsvr32 exited with error $($regsvrp.ExitCode)"
    }

    # Instalamos las fuentes necesarias para la última versión de Conex
    installFONTS

    # Instalamos SQL Server 2019 Express usando un fichero de configuración
    Write-Host "Instalando SQL Server 2019..."
    cd "C:\Instalación\06. Dispatching\06.2 Proin\SQL2K19"
    $configFile = "ConfigurationFile.ini"
    $command = ".\SETUP.EXE /ConfigurationFile=$($configFile)"
    Invoke-Expression -Command $command
    
    # Instalamos SQL Server Management Studio
    Write-Host "Instalando SQL Server Management Studio..."
    $path = "C:\Instalación\06. Dispatching\06.2 Proin\SSMS\SSMS-Setup-ENU.exe"
    $params = "/install /quiet"
    Start-Process -FilePath $path -ArgumentList $params -Wait

    # Habilitamos TCP en SQL Server
    enableTCP

    # Arrancamos el servicio SQL Browser
    # Comprobamos si se ha instalado el servicio
    $servicio = Get-Service -Name SQLBrowser -ErrorAction SilentlyContinue
    if ($servicio -eq $null) {
        Write-Host "No se encuentra el servicio SQLBrowser"
    } else {
        Write-Host "Se ha encontrado el servicio SQLBrowser e iniciando"
        # Lo establecemos en automático e iniciamos
        Set-Service -Name SQLBrowser -StartupType Automatic -Status Running
    }
  
}

function installFONTS {

    Write-Host "Instalando las fuentes..."
    cd "C:\Instalación\06. Dispatching\06.2 Proin\Fuentes"
    $fonts = (New-Object -ComObject Shell.Application).Namespace(0x14)
    foreach ($file in gci *.ttf)
    {
        $fileName = $file.Name
        if (-not(Test-Path -Path "C:\Windows\fonts\$fileName" )) {
            echo $fileName
            dir $file | %{ $fonts.CopyHere($_.fullname) }
        }
    }
    cp *.ttf c:\windows\fonts\

}

function enableTCP {

    Write-Host "Habilitando TCP en SQL..."
    # Get access to SqlWmiManagement DLL on the machine with SQL
    # we are on, which is where SQL Server was installed.
    # Note: this is installed in the GAC by SQL Server Setup.

    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement')

    # Instantiate a ManagedComputer object which exposes primitives to control the
    # installation of SQL Server on this machine.

    $wmi = New-Object 'Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer' localhost

    # Enable the TCP protocol on the default instance. If the instance is named, 
    # replace MSSQLSERVER with the instance name in the following line.

    $tcp = $wmi.ServerInstances['MSSQLSERVER'].ServerProtocols['Tcp']
    $tcp.IsEnabled = $true  
    $tcp.Alter()  

    # You need to restart SQL Server for the change to persist
    # -Force takes care of any dependent services, like SQL Agent.
    # Note: if the instance is named, replace MSSQLSERVER with MSSQL$ followed by
    # the name of the instance (e.g. MSSQL$MYINSTANCE)

    Write-Host "Reiniciando SQL..."
    Restart-Service -Name MSSQLSERVER -Force

}


#1
#Write-Host "==========================================="
#Write-Host "FASE 1 : INSTALACIÓN PRERREQUISITOS"
#Write-Host "==========================================="
#installPrerrequisitos
#Start-Sleep -Seconds 30

#2
Write-Host "==========================================="
Write-Host "FASE 2 : CREACIÓN DIRECTORIOS"
Write-Host "==========================================="
createDirectorios
Start-Sleep -Seconds 30

#3
Write-Host "==========================================="
Write-Host "FASE 3 : INSTALACIÓN ROOTS"
Write-Host "==========================================="
installRoots
Start-Sleep -Seconds 30

#4
Write-Host "==========================================="
Write-Host "FASE 4 : INSTALACIÓN IIS"
Write-Host "==========================================="
installIIS
Start-Sleep -Seconds 30

#5
Write-Host "==========================================="
Write-Host "FASE 5 : GRUPOS DE APLICACIONES"
Write-Host "==========================================="
createAppGroups
Start-Sleep -Seconds 30

#6
Write-Host "==========================================="
Write-Host "FASE 6 : SITIO WEB"
Write-Host "==========================================="
createWebSite
Start-Sleep -Seconds 30

#7
Write-Host "==========================================="
Write-Host "FASE 7 : MODIFICAR FICHERO HOST"
Write-Host "==========================================="
modifyHOST
Start-Sleep -Seconds 30

#8
Write-Host "==========================================="
Write-Host "FASE 8 : SELECCIONAR DISPATCHING"
Write-Host "==========================================="
selectDispatching