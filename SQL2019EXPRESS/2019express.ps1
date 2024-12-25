# Yönetici kontrolü

<#
.SYNOPSIS
    MS SQL Server sessiz kurulum betiği

.DESCRIPTION
    Bu betik, ISO görüntüsünden MS SQL Server'ı kullanıcı etkileşimi olmadan kurar.
    Tüm işlemin kaydı bir günlük dosyasına kaydedilir.

    Betik, yerel kurulum programına sağlanan parametreleri listeler ancak hassas verileri gizler. SQL Server sessiz kurulum ayrıntıları için sağlanan bağlantılara bakın.

.NOTES
    Sürüm: 1
#>

param(
    # Path to ISO file, if empty and current directory contains single ISO file, it will be used.
    [string] $IsoPath = $ENV:SQLSERVER_ISOPATH,

     # Sql Server features, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Feature
    [ValidateSet('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')]
    [string[]] $Features = @('SQL', 'SQLEngine', 'FullText','Tools','BC','Conn','LocalDB','SDK','SNAC_SDK'),

    # Specifies a nondefault installation directory
    [string] $InstallDir,

    # Data directory, by default "$Env:ProgramFiles\Microsoft SQL Server"
    [string] $DataDir,

    # Service name. Mandatory, by default MSSQLSERVER İstenene göre değiştirilebilir.
    [ValidateNotNullOrEmpty()]
    [string] $InstanceNam = 'MSSQLBILNEP',

    # sa user password. If empty, SQL security mode (mixed mode) is disabled
    [string] $SaPassword ='$SIFRE',

    # Username for the service account, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Accounts
    # Optional, by default 'NT Service\MSSQLSERVER'
    [string] $ServiceAccountName, # = "$Env:USERDOMAIN\$Env:USERNAME"

    # Password for the service account, should be used for domain accounts only
    # Mandatory with ServiceAccountName
    [string] $ServiceAccountPassword,

    # List of system administrative accounts in the form <domain>\<user>
    # Mandatory, by default current user will be added as system administrator
    [string[]] $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),

    # Product key, if omitted, evaluation is used unless VL edition which is already activated
    [string] $ProductKey,

    # Use bits transfer to get files from the Internet
    [switch] $UseBitsTransfer,

    # Enable SQL Server protocols: TCP/IP, Named Pipes
    [switch] $EnableProtocols
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Bu betik yönetici yetkileriyle çalıştırılmalıdır. Yeniden başlatılıyor..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}
##################################################### Rastgele Şifre Aşaması Uzunluk "length" kısmından arttırılabilir.  #####################################################
function Get-RandomCharacters($length, $characters) {
    # Rastgele karakterler seçmek için rastgele indeksler oluşturuyoruz
    $random = 1..$length | ForEach-Object { 
        # $characters dizisinin uzunluğu kadar rastgele bir sayı seçiyoruz
        Get-Random -Maximum $characters.Length
    }
    
    # Rastgele seçilen indekslere göre karakterleri alıyoruz ve bunları birleştiriyoruz
    $result = $random | ForEach-Object { $characters[$_] }
    return -join $result
}

function Scramble-String([string]$inputString){
    # Girdi string'ini bir karakter dizisine dönüştürüyoruz
    $characterArray = $inputString.ToCharArray()
    # Karakter dizisini karıştırıyoruz
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length
    # Karıştırılmış karakterleri birleştirip döndürüyoruz
    $outputString = -join $scrambledStringArray
    return $outputString
}

# Şifreyi rastgele oluşturuyoruz
$SIFRE = Get-RandomCharacters -length 11 -characters 'abcdefghiklmnoprstuvwxyz'
$SIFRE += Get-RandomCharacters -length 7 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
$SIFRE += Get-RandomCharacters -length 6 -characters '1234567890'
$SIFRE += Get-RandomCharacters -length 6 -characters '!"§$%/()=?}][{@#*+'

# Şifreyi karıştırıyoruz
$SIFRE = Scramble-String $SIFRE

# Sonuç şifresini bir dosyaya kaydediyoruz
"SqlID=SA SqlSifre=$SIFRE BağlantıID=$SystemAdminAccounts/$InstanceNam" | Out-File -FilePath "C:\SQLBILNEXIDSIFRE.txt" -Encoding UTF8

$ErrorActionPreference = 'Continue'
$scriptName = (Split-Path -Leaf $PSCommandPath).Replace('.ps1', '')

$start = Get-Date
Start-Transcript "$PSScriptRoot\$scriptName-$($start.ToString('s').Replace(':','-')).log"

##################################################### ISO INDIRME ATAMASI #####################################################
# Google Drive dosya kimliği
$FileId = "1ez0vA65Nfj5O-Ri_82wE83hwpXcqzeN5"  # Google Drive dosya kimliği 2019 express

# İndirme URL'si ve dosya kaydetme yolu
$downloadUrl = "https://drive.usercontent.google.com/download?id=$FileId&export=download&authuser=0&confirm=t&uuid=$([guid]::NewGuid())"
$saveDir = Join-Path $Env:TEMP "DownloadedFiles"
New-Item $saveDir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
$isoName = "DownloadedFile.iso"
$savePath = Join-Path $saveDir $isoName

# Dosya zaten mevcutsa kontrol et
if (Test-Path $savePath) {
    Write-Host "ISO file already exists at: $savePath"
} else {
    # TLS v1.2 protokolünü kullanmak için
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # HttpWebRequest kullanarak indirme işlemi
    Write-Host "Downloading ISO file from Google Drive..."
    $request = [System.Net.HttpWebRequest]::Create($downloadUrl)
    $response = $request.GetResponse()
    $contentLength = $response.ContentLength

    $stream = $response.GetResponseStream()
    $fileStream = [System.IO.File]::Create($savePath)
    $buffer = New-Object byte[] 8192
    $totalBytesRead = 0
    $lastReportedProgress = 0
    $lastUpdateTime = Get-Date

    try {
        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $bytesRead)
            $totalBytesRead += $bytesRead
            $progress = [math]::Round(($totalBytesRead / $contentLength) * 100, 2)

            # İlerlemeyi yalnızca belirli koşullarda yazdır
            $currentTime = Get-Date
            if (($progress -ge $lastReportedProgress + 1) -or (($currentTime - $lastUpdateTime).TotalSeconds -ge 10)) {
                Write-Progress -Activity "Downloading ISO file" -Status "$progress% completed" -PercentComplete $progress
                $lastReportedProgress = $progress
                $lastUpdateTime = $currentTime
            }
        }
    } finally {
        $fileStream.Close()
        $stream.Close()
        $response.Close()
    }

    Write-Host "`nISO file downloaded to: $savePath"

    # Dosyanın hash kontrolünü yap
    $hash = Get-FileHash -Algorithm MD5 $savePath | % Hash
    $hashFilePath = "$savePath.md5"

    # Hash değerini dosyaya yaz
    $hash | Out-File $hashFilePath
    Write-Host "MD5 hash written to: $hashFilePath"
}

# ISO dosyasını bağla
$IsoPath = $savePath  # ISO dosyasının yolu
Write-Host "Attempting to mount ISO from: $IsoPath"

try {
    # ISO'yu bağla ve sürücüyü al
    $volume = Mount-DiskImage -ImagePath $IsoPath -StorageType ISO -PassThru | Get-Volume
    if ($volume) {
        Write-Host "ISO mounted successfully. Volume details: $($volume.DriveLetter):"
        $iso_drive = $volume.DriveLetter + ':'
    } else {
        Write-Host "Failed to get volume after mounting ISO."
        throw "Unable to mount the ISO file correctly."
    }
} catch {
    Write-Host "Error mounting ISO: $_"
    throw "Unable to mount the ISO file."
}

Write-Host "`nISO drive: $iso_drive"

# ISO dosyasındaki dosyaları listele
Write-Host "Listing files in the ISO:"
Get-ChildItem $iso_drive | Format-Table -AutoSize | Out-String

# Yükleme işlemi için çalışan SQL Server kurulumunu sonlandırma
Get-CimInstance win32_process | Where-Object { $_.CommandLine -like '*setup.exe*/ACTION=install*' } | ForEach-Object {
    Write-Host "Sql Server installer is already running, killing it:" $_.Path "pid: " $_.ProcessId
    Stop-Process $_.ProcessId -Force
}
##################################################### Setup Kurulum Aşaması  #####################################################Sonrasında bilnexe entegre edilecek#######################

$cmd =@(
    "${iso_drive}setup.exe"
    '/Q'                                # Silent install
    '/INDICATEPROGRESS'                 # Specifies that the verbose Setup log file is piped to the console
    '/IACCEPTSQLSERVERLICENSETERMS'     # Must be included in unattended installations
    '/ACTION=install'                   # Required to indicate the installation workflow
    '/UPDATEENABLED=True'              # Should it discover and include product updates.

    "/INSTANCEDIR=""$InstallDir"""
    "/INSTALLSQLDATADIR=""$DataDir"""

    "/FEATURES=" + ($Features -join ',')

    #Security
    "/SQLSYSADMINACCOUNTS=""$SystemAdminAccounts"""
    '/SECURITYMODE=SQL'                 # Silinirse windows auth ile giriş yapılabilir. Bu şekilde ise sa ve diğer authlar çalışır.
    "/SAPWD=""$SIFRE"""            # Sa user password

    "/INSTANCENAME=$InstanceNam"       # Server ismi

    "/SQLSVCACCOUNT=""$ServiceAccountName"""
    "/SQLSVCPASSWORD=""$ServiceAccountPassword"""
    "/PID=$ProductKey"
)

# remove empty arguments
$cmd_out = $cmd = $cmd -notmatch '/.+?=("")?$'

# show all parameters but remove password details
Write-Host "Install parameters:`n"
'SAPWD', 'SQLSVCPASSWORD' | % { $cmd_out = $cmd_out -replace "(/$_=).+", '$1"****"' }
$cmd_out[1..100] | % { $a = $_ -split '='; Write-Host '   ' $a[0].PadRight(40).Substring(1), $a[1] }
Write-Host

"$cmd_out"
Invoke-Expression "$cmd"
if ($LastExitCode) {
    if ($LastExitCode -ne 3010) { throw "SqlServer installation failed, exit code: $LastExitCode" }
    Write-Warning "SYSTEM REBOOT IS REQUIRED"
}

"`nInstallation length: {0:f1} minutes" -f ((Get-Date) - $start).TotalMinutes

# Dismount ISO only if $IsoPath is valid
if ($IsoPath) {
    Dismount-DiskImage $IsoPath
} else {
    Write-Host "No ISO path found, skipping dismount."
}

##################################################### İP ATAMASI  #####################################################
try {
    # Aktif ağ bağdaştırıcılarını tespit et
    Write-Host "Aktif ağ bağdaştırıcıları tespit ediliyor..."
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }

    if ($adapters.Count -eq 0) {
        Write-Error "Aktif bir ağ bağdaştırıcısı bulunamadı."
        exit 1
    }

    foreach ($adapter in $adapters) {
        $interfaceAlias = $adapter.InterfaceAlias
        Write-Host "`nBağdaştırıcı: $interfaceAlias"

        # Mevcut IP bilgilerini al
        $currentIPConfig = Get-NetIPAddress -InterfaceAlias $interfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $currentGatewayConfig = Get-NetIPConfiguration -InterfaceAlias $interfaceAlias -ErrorAction SilentlyContinue

        if (-not $currentIPConfig) {
            Write-Host "Bu bağdaştırıcıda mevcut bir IP yapılandırması yok. Atlanıyor..."
            continue
        }

        # Mevcut yapılandırmayı oku
        $currentIP = $currentIPConfig.IPAddress
        $subnetMask = $currentIPConfig.PrefixLength
        $gateway = $currentGatewayConfig.IPv4DefaultGateway.NextHop
        $dns1 = $gateway  # DNS 1'i mevcut ağ geçidi olarak belirle
        $dns2 = "1.1.1.1"

        if (-not $gateway) {
            Write-Warning "Bu bağdaştırıcıda ağ geçidi bulunamadı. Varsayılan bir ağ geçidi atanacak: 192.168.1.1"
            $gateway = "192.168.1.1"
        }

        # DHCP'yi devre dışı bırak ve statik IP ayarla
        Write-Host "Statik IP ayarları uygulanıyor..."
        try {
            # Mevcut IP ve rotaları kaldır
            Remove-NetIPAddress -InterfaceAlias $interfaceAlias -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetRoute -InterfaceAlias $interfaceAlias -Confirm:$false -ErrorAction SilentlyContinue

            # Yeni IP adresi
            New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $currentIP -PrefixLength $subnetMask -ErrorAction Continue
            Write-Host "Statik IP başarıyla ayarlandı: $currentIP"

            # Ağ geçidini ekle
            New-NetRoute -InterfaceAlias $interfaceAlias -DestinationPrefix "0.0.0.0/0" -NextHop $gateway -ErrorAction Continue
            Write-Host "Ağ geçidi başarıyla yapılandırıldı: $gateway"
        } catch {
            Write-Error "Statik IP ayarlanırken bir hata oluştu: $_"
            exit 1
        }

        # DNS Ayarlarını Yapılandır
        Write-Host "DNS ayarları yapılandırılıyor..."
        try {
            Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses $dns1, $dns2 -ErrorAction Continue
            Write-Host "DNS ayarları başarıyla yapılandırıldı: $dns1, $dns2"
        } catch {
            Write-Error "DNS ayarları yapılandırılırken bir hata oluştu: $_"
            exit 1
        }
    }
    Write-Host "Tüm ayarlar başarıyla tamamlandı."
} catch {
    Write-Error "Bir hata oluştu: $_"
    exit 1
}
##################################################### 1. KISIM SONU İLK KISIM STATİK İP AYARLAMASINI YAPIYOR #####################################################
# SQL Server instance'larını tespit etme
Write-Host "Bilgisayardaki SQL Server instance'ları tespit ediliyor..."
$sqlInstances = @()

# 64-bit ve 32-bit Registry yollarını tarama
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",          # 64-bit
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL"  # 32-bit
)

# Her iki registry yolunu tarıyoruz
foreach ($rootPath in $registryPaths) {
    Write-Host "Kontrol edilen registry yolu: $rootPath"
    
    if (Test-Path $rootPath) {
        Write-Host "Registry yolu bulundu: $rootPath"
        
        # SQL Server instance isimlerini alalım
        $instanceNames = Get-ItemProperty -Path $rootPath
        foreach ($instanceName in $instanceNames.PSObject.Properties) {
            # Sadece geçerli instance'ları ekle
            if ($instanceName.Name -notmatch "PS*") {
                Write-Host "Bulunan SQL Server instance'ı: $($instanceName.Name)"
                $sqlInstances += $instanceName.Name
            }
        }
    } else {
        Write-Host "Registry yolu bulunamadı: $rootPath"
    }
}

# Sonuçları kontrol etme
if ($sqlInstances.Count -eq 0) {
    Write-Error "SQL Server instance'ı bulunamadı. Lütfen registry yollarını kontrol edin ve scripti tekrar çalıştırın."
    exit 1
}

# Instance seçme menüsü
Write-Host "Lütfen bir SQL Server instance'ı seçin:"

# Listeleme
$i = 1
foreach ($instance in $sqlInstances) {
    Write-Host "$i. $instance"
    $i++
}

# Seçim: Kullanıcı geçerli bir seçim yapana kadar tekrar sorulacak
$selectedIndex = 0
do {
    $selectedIndex = Read-Host "Seçiminizi yapın (1-$($sqlInstances.Count))"
    
    # Seçimin geçerli olup olmadığını kontrol etme
    if (-not ($selectedIndex -as [int])) {
        Write-Host "Geçersiz seçim. Lütfen bir sayı girin."
    } elseif ($selectedIndex -lt 1 -or $selectedIndex -gt $sqlInstances.Count) {
        Write-Host "Geçersiz seçim. Lütfen geçerli bir seçim yapın."
    }
} while (-not ($selectedIndex -as [int]) -or $selectedIndex -lt 1 -or $selectedIndex -gt $sqlInstances.Count)

$selectedIndex = [int]$selectedIndex
$selectedInstance = $sqlInstances[$selectedIndex - 1]
Write-Host "Seçilen SQL Server instance'ı: $selectedInstance"

# SQL Server'ın registry yolu
$instanceVersion = "MSSQL15"  # Örnek olarak MSSQL15, versiyonunuzu değiştirebilirsiniz.2017 VE ÖNCESİ 2019=15 2017=14 2016=12-10 Diye gidiyor.
$registryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceVersion.$selectedInstance\MSSQLServer\SuperSocketNetLib\Tcp"

# SQL Server Configuration Manager'da TCP/IP Ayarlarını Yapılandırma
try {
    Write-Host "Rastgele port oluşturuluyor..."
    
    do {
        $staticPort = Get-Random -Minimum 10000 -Maximum 63000
        $portInUse = (Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq $staticPort }).Count -gt 0
    } while ($portInUse)
    
    Write-Host "Rastgele port oluşturuldu: $staticPort"

    # IP Adres Yapılandırması
    if (Test-Path $registryPath) {
        Write-Host "SQL Server IP adres alanları yapılandırılıyor..."
        
        $ipKeys = Get-ChildItem -Path $registryPath | Where-Object { $_.PSChildName -match "IP\d+" }
        
        if ($ipKeys.Count -eq 0) {
            Write-Warning "Hiçbir IPx girdisi bulunamadı. Yapılandırma atlanıyor."
            exit 1
        }

        foreach ($ipKey in $ipKeys) {
            Write-Host "Ayarlanıyor: $($ipKey.PSChildName)"

            # Active ve Enabled ayarları
            Set-ItemProperty -Path $ipKey.PSPath -Name "Active" -Value 1 -ErrorAction Continue
            Write-Host "$($ipKey.PSChildName) 'Active' durumu etkinleştirildi."

            Set-ItemProperty -Path $ipKey.PSPath -Name "Enabled" -Value 1 -ErrorAction Continue
            Write-Host "$($ipKey.PSChildName) 'Enabled' durumu etkinleştirildi."

            # TcpDynamicPorts temizleme           
            New-ItemProperty -Path $ipKey.PSPath -Name "TcpDynamicPorts" -Value "" -PropertyType String -Force -ErrorAction Continue
            Write-Host "$($ipKey.PSChildName) 'TcpDynamicPorts' boş olarak ayarlandı."       

            # TcpPort ayarları
            Set-ItemProperty -Path $ipKey.PSPath -Name "TcpPort" -Value $staticPort -ErrorAction Continue
            Write-Host "$($ipKey.PSChildName) 'TcpPort' ayarlandı: $staticPort"

            # IP Address ayarları
            Set-ItemProperty -Path $ipKey.PSPath -Name "IPAddress" -Value $currentIP -ErrorAction Continue
            Write-Host "$($ipKey.PSChildName) 'TcpIPAddress' ayarlandı: $currentIP"
        }

        Write-Host "Tüm mevcut IPx girdileri başarıyla yapılandırıldı."
    } else {
        Write-Error "Seçilen instance için TCP ayarlarına ulaşılamadı. Registry yolu bulunamadı."
        exit 1
    }
} catch {
    Write-Error "SQL Server ayarlarında bir hata oluştu: $_"
    exit 1
}

# IPAll Yapılandırması
try {
    $ipAllPath = Join-Path -Path $registryPath -ChildPath "IPAll"
    Write-Host "IPAll ayarları yapılandırılıyor..."

    if (Test-Path $ipAllPath) {
        # TcpDynamicPorts boş olarak ayarlama
        try {
            Set-ItemProperty -Path $ipAllPath -Name "TcpDynamicPorts" -Value "" -Type String -ErrorAction Continue
            Write-Host "'TcpDynamicPorts' boş olarak ayarlandı."
        } catch {
            Write-Warning "'TcpDynamicPorts' boş olarak ayarlanamadı: $_"
        }

        # TcpPort ayarı
        try {
            Set-ItemProperty -Path $ipAllPath -Name "TcpPort" -Value $staticPort -Type String -ErrorAction Continue
            Write-Host "'TcpPort' ayarlandı: $staticPort"
        } catch {
            Write-Warning "'TcpPort' ayarlanamadı: $_"
        }
    } else {
        Write-Warning "IPAll girdisi bulunamadı. İşlem atlanıyor."
    }
} catch {
    Write-Error "IPAll yapılandırmasında bir hata oluştu: $_"
    exit 1
}

# SQL Server Servislerini Yeniden Başlatma
try {
    Write-Host "SQL Server ile ilişkili tüm servisler yeniden başlatılıyor..."
    # MSSQL ile başlayan tüm servisleri al
    $sqlServices = Get-Service | Where-Object { $_.Name -match "^MSSQL" }

    if (-not $sqlServices) {
        Write-Warning "MSSQL ile ilişkili herhangi bir servis bulunamadı. İşlem atlanıyor."
        return
    }

    # Servisleri durdur
    foreach ($service in $sqlServices) {
        try {
            Write-Host "Servis durduruluyor: $($service.Name)"
            Stop-Service -Name $service.Name -Force -ErrorAction Continue
        } catch {
            Write-Warning "Servis durdurulurken hata oluştu: $($service.Name) - $_"
        }
    }

    # Servisleri başlat
    foreach ($service in $sqlServices) {
        try {
            Write-Host "Servis başlatılıyor: $($service.Name)"
            Start-Service -Name $service.Name -ErrorAction Continue
        } catch {
            Write-Warning "Servis başlatılırken hata oluştu: $($service.Name) - $_"
        }
    }

    Write-Host "SQL Server servisleri başarıyla yeniden başlatıldı."
} catch {
    Write-Error "SQL Server servisleri yeniden başlatılırken bir hata oluştu: $_"
    exit 1
}


##################################################### 2. KISIM SONU İKİNCİ KISIM SQL SEÇİM KISMI #####################################################
# Güvenlik Duvarı Ayarları: Port Ekleme
do {
    $response = Read-Host "Güvenlik duvarına port eklemek ister misiniz? (evet/hayır)"
    switch ($response.ToLower()) {
        "evet" { $isValid = $true; $addPort = $true }
        "hayır" { $isValid = $true; $addPort = $false }
        default { 
            Write-Host "Lütfen sadece 'evet' veya 'hayır' yazın." -ForegroundColor Red
            $isValid = $false 
        }
    }
} while (-not $isValid)

if ($addPort) {
    try {
        Write-Host "Güvenlik duvarına port ekleniyor: $staticPort (TCP)..."
        
        # Mevcut aynı isimli veya aynı portlu kuralları kontrol etme
        $existingRules = Get-NetFirewallRule | Where-Object {
            $_.DisplayName -eq "SQL Server Port $staticPort" -or
            ($_.LocalPort -eq $staticPort -and $_.Protocol -eq "TCP")
        }

        if ($existingRules) {
            Write-Host "Mevcut aynı isimli veya aynı portlu kurallar bulundu. Aktif hale getiriliyor..."
            foreach ($rule in $existingRules) {
                Set-NetFirewallRule -Name $rule.Name -Enabled True -ErrorAction Continue
            }
        } else {
            # TCP için yeni kural ekleme
            New-NetFirewallRule -DisplayName "SQL Server Port $staticPort" `
                                -Direction Inbound `
                                -Action Allow `
                                -Protocol TCP `
                                -LocalPort $staticPort `
                                -ErrorAction Continue

            New-NetFirewallRule -DisplayName "SQL Server Port $staticPort" `
                                -Direction Outbound `
                                -Action Allow `
                                -Protocol TCP `
                                -LocalPort $staticPort `
                                -ErrorAction Continue

            Write-Host "Port güvenlik duvarına başarıyla eklendi."
        }
    } catch {
        Write-Error "Port güvenlik duvarına eklenirken bir hata oluştu: $_"
        exit 1
    }
} else {
    Write-Host "Güvenlik duvarına port ekleme atlandı."
}

##################################################### 3. KISIM SONU ÜÇÜNÇÜ KISIM PORT EKLEME KISMI #####################################################

# Ağ Paylaşım Ayarları
try {
    Write-Host "Ağ paylaşım ayarları yapılandırılıyor..."

    # Ağ Bulma ayarlarını etkinleştirme
    Write-Host "Ağ Bulma güvenlik duvarı ayarları kontrol ediliyor..."
    Set-NetFirewallRule -DisplayGroup "Ağ Bulma" -Enabled True -Profile Any -Action Allow
    Write-Host "Ağ Bulma ayarları başarıyla etkinleştirildi."

    # Paylaşım ayarlarını etkinleştirme
    Write-Host "Dosya ve Yazıcı Paylaşımı güvenlik duvarı ayarları kontrol ediliyor..."
    Set-NetFirewallRule -DisplayGroup "Dosya ve Yazıcı Paylaşımı" -Enabled True -Profile Any -Action Allow
    Write-Host "Dosya ve Yazıcı Paylaşımı ayarları başarıyla etkinleştirildi."

    # Parola korumalı paylaşımı kapatma
    Write-Host "Parola korumalı paylaşım ayarları kontrol ediliyor..."
    $sharingSettingsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $currentValue = (Get-ItemProperty -Path $sharingSettingsPath -Name "LimitBlankPasswordUse" -ErrorAction Continue).LimitBlankPasswordUse
    if ($currentValue -ne 0) {
        Set-ItemProperty -Path $sharingSettingsPath -Name "LimitBlankPasswordUse" -Value 0 -Force
        Write-Host "Parola korumalı paylaşım başarıyla devre dışı bırakıldı."
    } else {
        Write-Host "Parola korumalı paylaşım zaten devre dışı durumda."
    }

    Write-Host "Ağ paylaşım ayarları başarıyla yapılandırıldı."
} catch {
    Write-Error "Ağ paylaşım ayarları yapılandırılırken bir hata oluştu: $_"
    exit 1
}

Write-Host "Tüm ayarlar başarıyla tamamlandı."
##################################################### SON KISIM PAYLAŞIM AYARLARINI AÇIYOR NOT SON KISMI ÇOK ÇALIŞTIRMAYIN FAZLA ÇALIŞTIRMADA GÜVENLİK DUVARINI ÇORBA YAPIYOR  #####################################################

$baseregistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceVersion.$selectedInstance\MSSQLServer\SuperSocketNetLib"
######$baseRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$selectedInstance\MSSQLServer\SuperSocketNetLib"
$protocols = @(
    @{Name = "Shared Memory"; Path = "Sm"},
    @{Name = "Named Pipes"; Path = "Np"},
    @{Name = "TCP/IP"; Path = "Tcp"}
)

foreach ($protocol in $protocols) {
    $protocolPath = Join-Path -Path $baseRegistryPath -ChildPath $protocol.Path
    if (Test-Path $protocolPath) {
        Set-ItemProperty -Path $protocolPath -Name "Enabled" -Value 1 -ErrorAction SilentlyContinue
        Write-Host "$($protocol.Name) protokolü etkinleştirildi."
    } else {
        Write-Warning "$($protocol.Name) protokolü için yol bulunamadı. İşlem atlanıyor."
    }
}

trap {
    Write-Error "Hata oluştu: $_"
    if ($_.Exception) {
        Write-Error "Ayrıntılı hata: $($_.Exception.Message)"
    }
    exit 1
}

 Write-Host   SqlID:sa    SIFRE=$SIFRE

# Örnek işlemler
Write-Host "İşlemler tamamlandı."

# Kullanıcıdan yanıt alma
do {
    $response = Read-Host "İşlemler tamamlandı. Kapatılsın mı? (evet/hayır)"
    if ($response -ieq "evet") {
        Write-Host "Pencere kapatılıyor..."
        exit
    } elseif ($response -ieq "hayır") {
        Write-Host "Pencereyi kapatmak için manuel olarak çıkabilirsiniz."
        pause
        break
    } else {
        Write-Host "Lütfen sadece 'evet' veya 'hayır' yazın." -ForegroundColor Yellow
    }
} while ($true)