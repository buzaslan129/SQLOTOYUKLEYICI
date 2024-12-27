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
    [string] $IsoPath = $ENV:SQLSERVER_ISOPATH,
    [ValidateSet('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')]
    [string[]] $Features = @('SQL', 'SQLEngine', 'FullText','Tools','BC','Conn','LocalDB','SDK','SNAC_SDK'),
    [string] $InstallDir,
    [string] $DataDir,
    [ValidateNotNullOrEmpty()] [string] $InstanceName = 'MSSQLBILNEE',
    [string] $SaPassword ='$SIFRE',
    [string] $ServiceAccountName,
    [string] $ServiceAccountPassword,
    [string[]] $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),
    [string] $ProductKey,
    [switch] $UseBitsTransfer,
    [switch] $EnableProtocols
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Bu betik yönetici yetkileriyle çalıştırılmalıdır. Yeniden başlatılıyor..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { 
        Get-Random -Maximum $characters.Length
    }
    $result = $random | ForEach-Object { $characters[$_] }
    return -join $result
}

function Scramble-String([string]$inputString){
    $characterArray = $inputString.ToCharArray()
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length
    return -join $scrambledStringArray
}

# Şifreyi rastgele oluşturuyoruz
$SIFRE = Get-RandomCharacters -length 11 -characters 'abcdefghiklmnoprstuvwxyz'
$SIFRE += Get-RandomCharacters -length 7 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
$SIFRE += Get-RandomCharacters -length 6 -characters '1234567890'
$SIFRE += Get-RandomCharacters -length 6 -characters '!§$%/()=?}][{@#*+'

# Şifreyi karıştırıyoruz
$SIFRE = Scramble-String $SIFRE

$ErrorActionPreference = 'Stop'  # Hataları yönetirken tüm hataları yakalamak için 'Stop' kullanıldı.
$scriptName = (Split-Path -Leaf $PSCommandPath).Replace('.ps1', '')

$start = Get-Date
Start-Transcript "$PSScriptRoot\$scriptName-$($start.ToString('s').Replace(':','-')).log"

# ISO INDIRME ATAMASI
$FileId = "1ez0vA65Nfj5O-Ri_82wE83hwpXcqzeN5"
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

    Write-Host "Downloading ISO file from Google Drive..."
    try {
        $request = [System.Net.HttpWebRequest]::Create($downloadUrl)
        $response = $request.GetResponse()
        $contentLength = $response.ContentLength

        $stream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($savePath)
        $buffer = New-Object byte[] 8192
        $totalBytesRead = 0
        $lastReportedProgress = 0
        $lastUpdateTime = Get-Date

        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $bytesRead)
            $totalBytesRead += $bytesRead
            $progress = [math]::Round(($totalBytesRead / $contentLength) * 100, 2)
            $currentTime = Get-Date
            if (($progress -ge $lastReportedProgress + 1) -or (($currentTime - $lastUpdateTime).TotalSeconds -ge 10)) {
                Write-Progress -Activity "Downloading ISO file" -Status "$progress% completed" -PercentComplete $progress
                $lastReportedProgress = $progress
                $lastUpdateTime = $currentTime
            }
        }

        $fileStream.Close()
        $stream.Close()
        $response.Close()
        Write-Host "`nISO file downloaded to: $savePath"
    }
    catch {
        Write-Warning "ISO download failed: $_"
    }
}

# ISO dosyasını bağla
$IsoPath = $savePath  # ISO dosyasının yolu
Write-Host "Attempting to mount ISO from: $IsoPath"

try {
    $volume = Mount-DiskImage -ImagePath $IsoPath -StorageType ISO -PassThru | Get-Volume
    if ($volume) {
        Write-Host "ISO mounted successfully. Volume details: $($volume.DriveLetter):"
        $iso_drive = $volume.DriveLetter + ':'
    } else {
        Write-Warning "Failed to get volume after mounting ISO."
        throw "Unable to mount the ISO file correctly."
    }
} catch {
    Write-Warning "Error mounting ISO: $_"
}

Write-Host "`nISO drive: $iso_drive"

# ISO dosyasındaki dosyaları listele
Write-Host "Listing files in the ISO:"
try {
    Get-ChildItem $iso_drive | Format-Table -AutoSize | Out-String
} catch {
    Write-Warning "Error listing files in ISO: $_"
}

# Yükleme işlemi için çalışan SQL Server kurulumunu sonlandırma
Get-CimInstance win32_process | Where-Object { $_.CommandLine -like '*setup.exe*/ACTION=install*' } | ForEach-Object {
    Write-Host "Sql Server installer is already running, killing it:" $_.Path "pid: " $_.ProcessId
    Stop-Process $_.ProcessId -Force
}

$cmd = @(
    "${iso_drive}setup.exe"
    '/Q'                                # Silent install
    '/INDICATEPROGRESS'                 # Specifies that the verbose Setup log file is piped to the console
    '/IACCEPTSQLSERVERLICENSETERMS'     # Must be included in unattended installations
    '/ACTION=install'                   # Required to indicate the installation workflow
    '/UPDATEENABLED=True'              # Should it discover and include product updates.
    "/INSTANCEDIR=""$InstallDir"""
    "/INSTALLSQLDATADIR=""$DataDir"""
    "/FEATURES=" + ($Features -join ',')
    "/SQLSYSADMINACCOUNTS=""$SystemAdminAccounts"""
    '/SECURITYMODE=SQL'                 # Silinirse windows auth ile giriş yapılabilir. Bu şekilde ise sa ve diğer authlar çalışır.
    "/SAPWD=""$SIFRE"""            # Sa user password
    "/INSTANCENAME=$InstanceName"       # Server ismi
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

# Command to execute
"$cmd_out"
try {
    Invoke-Expression "$cmd"
    if ($LastExitCode) {
        if ($LastExitCode -ne 3010) {
            throw "SQL Server installation failed, exit code: $LastExitCode"
        }
        Write-Warning "SYSTEM REBOOT IS REQUIRED"
    }
} catch {
    Write-Error "An error occurred while running the SQL Server setup: $_"
	exit 1
}

"`nInstallation length: {0:f1} minutes" -f ((Get-Date) - $start).TotalMinutes

# Dismount ISO only if $IsoPath is valid
if ($IsoPath) {
    try {
        Dismount-DiskImage $IsoPath
        Write-Host "ISO file dismounted successfully."
    } catch {
        Write-Warning "Error dismounting ISO: $_"
    }
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
	pause
	break
    }

    foreach ($adapter in $adapters) {
        $interfaceAlias = $adapter.InterfaceAlias
        Write-Host "`nBağdaştırıcı: $interfaceAlias"

        # Mevcut IP bilgilerini al
        $currentIPConfig = Get-NetIPAddress -InterfaceAlias $interfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $currentGatewayConfig = Get-NetIPConfiguration -InterfaceAlias $interfaceAlias -ErrorAction SilentlyContinue

        if (-not $currentIPConfig) {
            Write-Host "Bu bağdaştırıcıda mevcut bir IP yapılandırması yok. Atlanıyor..." -ErrorAction SilentlyContinue
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
            New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $currentIP -PrefixLength $subnetMask -ErrorAction SilentlyContinue
            Write-Host "Statik IP başarıyla ayarlandı: $currentIP"

            # Ağ geçidini ekle
            New-NetRoute -InterfaceAlias $interfaceAlias -DestinationPrefix "0.0.0.0/0" -NextHop $gateway -ErrorAction SilentlyContinue
            Write-Host "Ağ geçidi başarıyla yapılandırıldı: $gateway"
        } catch {
            Write-Error "Statik IP ayarlanırken bir hata oluştu: $_" -ErrorAction SilentlyContinue
        }

        # DNS Ayarlarını Yapılandır
        Write-Host "DNS ayarları yapılandırılıyor..."
        try {
            Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses $dns1, $dns2 -ErrorAction SilentlyContinue
            Write-Host "DNS ayarları başarıyla yapılandırıldı: $dns1, $dns2"
        } catch {
            Write-Error "DNS ayarları yapılandırılırken bir hata oluştu: $_" -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Tüm ayarlar başarıyla tamamlandı."
} catch {
    Write-Error "Bir hata oluştu: $_" -ErrorAction SilentlyContinue
}

##################################################### İNSTANCE BÖLÜMÜ #####################################################
# Kullanıcıdan alınan SQL Server instance adı
# MSSQL versiyonlarını dinamik olarak kontrol etme

function Find-SqlServerInstance {
    param (
        [string] $InstanceName
    )
    $found = $false
    $registryPath = ""
    $baseregistryPath = ""

    # MSSQL5'ten MSSQL20'ye kadar versiyonları kontrol et
    for ($version = 5; $version -le 20; $version++) {
        $instanceVersion = "MSSQL$version"
        $testPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceVersion.$InstanceName\MSSQLServer\SuperSocketNetLib\Tcp"
        
        # Base registry path'i de versiyon numarasına göre ayarlama(dosya yolları için önceden kayıt bu kısım en son kısım için)
        $baseregistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceVersion.$InstanceName\MSSQLServer\SuperSocketNetLib"

        # Registry yolunu kontrol et
        if (Test-Path $testPath) {
            Write-Host "SQL Server instance bulundu: $testPath"
            $found = $true
            $registryPath = $testPath
            break
        }
    }

    if (-not $found) {
        Write-Warning "Hiçbir SQL Server instance bulunamadı."
    }

    # Hashtable döndürülüyor
    return @{RegistryPath=$registryPath; BaseRegistryPath=$baseregistryPath}
}

# Ana döngü: Instance bulunana kadar devam et
do {
    $result = Find-SqlServerInstance -InstanceName $InstanceName

    # Hashtabl’dan doğru değerleri al
    $registryPath = $result.RegistryPath
    $baseregistryPath = $result.BaseRegistryPath

    if (-not $registryPath) {
        Write-Host "SQL Server instance bulunamadı. Lütfen bir yol belirtin veya işlemi tekrar deneyin."
        Write-Host "Registry yolu önerisi: 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\...'"

        # Kullanıcıdan özel bir registry yolu alma
        $customPath = Read-Host "Registry yolunu manuel olarak girin veya Enter tuşuna basarak yeniden tarayın"

        if ($customPath -ne "") {
            if (Test-Path $customPath) {
                Write-Host "Kullanıcı tarafından sağlanan registry yolu bulundu: $customPath"
                $registryPath = $customPath
            } else {
                Write-Warning "Girilen registry yolu bulunamadı. Tekrar deneyin."
            }
        }
    }

    # Eğer hala bulunamadıysa tekrar döngüye girer
} while (-not $registryPath)

# Bulunan registry yoluna göre işlemlere devam et
Write-Host "Kullanılacak registry yolu: $registryPath"
Write-Host "Base registry yolu: $baseregistryPath"

##################################################### RANDOM PORT #####################################################

# SQL Server Configuration Manager'da TCP/IP Ayarlarını Yapılandırma
try {
    Write-Host "Rastgele port oluşturuluyor..."
    
    # Geçerli portu bulana kadar döngüye devam et
    do {
        $staticPort = Get-Random -Minimum 10000 -Maximum 63000
        $portInUse = (Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq $staticPort }).Count -gt 0
    } while ($portInUse)
    
    Write-Host "Rastgele port oluşturuldu: $staticPort"

    # IP Adres Yapılandırması
    if (Test-Path $registryPath) {
        Write-Host "SQL Server IP adres alanları yapılandırılıyor..."
        
        # IP adresi girdilerini al
        $ipKeys = Get-ChildItem -Path $registryPath | Where-Object { $_.PSChildName -match "IP\d+" }
        
        if ($ipKeys.Count -eq 0) {
            Write-Warning "Hiçbir IPx girdisi bulunamadı. Yapılandırma atlanıyor."
        }

        foreach ($ipKey in $ipKeys) {
            Write-Host "Ayarlanıyor: $($ipKey.PSChildName)"

            # Active ve Enabled ayarları
            try {
                Set-ItemProperty -Path $ipKey.PSPath -Name "Active" -Value 1 -ErrorAction Stop
                Write-Host "$($ipKey.PSChildName) 'Active' durumu etkinleştirildi."

                Set-ItemProperty -Path $ipKey.PSPath -Name "Enabled" -Value 1 -ErrorAction Stop
                Write-Host "$($ipKey.PSChildName) 'Enabled' durumu etkinleştirildi."

                # TcpDynamicPorts temizleme
                New-ItemProperty -Path $ipKey.PSPath -Name "TcpDynamicPorts" -Value "" -PropertyType String -Force -ErrorAction Stop
                Write-Host "$($ipKey.PSChildName) 'TcpDynamicPorts' boş olarak ayarlandı."       

                # TcpPort ayarları
                Set-ItemProperty -Path $ipKey.PSPath -Name "TcpPort" -Value $staticPort -ErrorAction Stop
                Write-Host "$($ipKey.PSChildName) 'TcpPort' ayarlandı: $staticPort"

                # IP Address ayarları
                Set-ItemProperty -Path $ipKey.PSPath -Name "IPAddress" -Value $currentIP -ErrorAction Stop
                Write-Host "$($ipKey.PSChildName) 'TcpIPAddress' ayarlandı: $currentIP"
            } catch {
                Write-Error "Ağ yapılandırma ayarı yapılırken bir hata oluştu: $_"
            }
        }

        Write-Host "Tüm mevcut IPx girdileri başarıyla yapılandırıldı."
    } else {
        Write-Error "Seçilen instance için TCP ayarlarına ulaşılamadı. Registry yolu bulunamadı."
    }
} catch {
    Write-Error "SQL Server ayarlarında bir hata oluştu: $_"
}
##################################################### IPAll Yapılandırması #####################################################
try {
    $ipAllPath = Join-Path -Path $registryPath -ChildPath "IPAll"
    Write-Host "IPAll ayarları yapılandırılıyor..."

    if (Test-Path $ipAllPath) {
        # TcpDynamicPorts boş olarak ayarlama
        try {
            Set-ItemProperty -Path $ipAllPath -Name "TcpDynamicPorts" -Value "" -Type String -ErrorAction Stop
            Write-Host "'TcpDynamicPorts' boş olarak ayarlandı."
        } catch {
            Write-Warning "'TcpDynamicPorts' boş olarak ayarlanamadı: $_"
        }

        # TcpPort ayarı
        try {
            Set-ItemProperty -Path $ipAllPath -Name "TcpPort" -Value $staticPort -Type String -ErrorAction Stop
            Write-Host "'TcpPort' ayarlandı: $staticPort"
        } catch {
            Write-Warning "'TcpPort' ayarlanamadı: $_"
        }
    } else {
        Write-Warning "IPAll girdisi bulunamadı. İşlem atlanıyor."
    }
} catch {
    Write-Error "IPAll yapılandırmasında bir hata oluştu: $_"
}

##################################################### SQL Server Servislerini Yeniden Başlatma #####################################################
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
            Stop-Service -Name $service.Name -Force -ErrorAction Stop
        } catch {
            Write-Warning "Servis durdurulurken hata oluştu: $($service.Name) - $_"
        }
    }

    # Servisleri başlat
    foreach ($service in $sqlServices) {
        try {
            Write-Host "Servis başlatılıyor: $($service.Name)"
            Start-Service -Name $service.Name -ErrorAction Stop
        } catch {
            Write-Warning "Servis başlatılırken hata oluştu: $($service.Name) - $_"
        }
    }

    Write-Host "SQL Server servisleri başarıyla yeniden başlatıldı."
} catch {
    Write-Error "SQL Server servisleri yeniden başlatılırken bir hata oluştu: $_"
}

##################################################### 2. KISIM SONU - SQL SEÇİMİ #####################################################
# Güvenlik Duvarı Ayarları: Port Ekleme
$addPort = $true
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
                # Mevcut kuralı etkinleştir
                Set-NetFirewallRule -Name $rule.Name -Enabled True -ErrorAction SilentlyContinue
                Write-Host "Port kuralı etkinleştirildi: $($rule.Name)"
            }
        } else {
            # TCP için yeni kural ekleme
            Write-Host "Yeni port kuralı oluşturuluyor..."

            # Inbound kuralı ekleme
            New-NetFirewallRule -DisplayName "SQL Server Port $staticPort" `
                                -Direction Inbound `
                                -Action Allow `
                                -Protocol TCP `
                                -LocalPort $staticPort `
                                -ErrorAction SilentlyContinue

            # Outbound kuralı ekleme
            New-NetFirewallRule -DisplayName "SQL Server Port $staticPort" `
                                -Direction Outbound `
                                -Action Allow `
                                -Protocol TCP `
                                -LocalPort $staticPort `
                                -ErrorAction SilentlyContinue

            Write-Host "Port güvenlik duvarına başarıyla eklendi."
        }
    } catch {
        Write-Error "Port güvenlik duvarına eklenirken bir hata oluştu: $_"
    }
} else {
    Write-Host "Güvenlik duvarına port ekleme atlandı."
}
##################################################### 3. KISIM SONU - PORT EKLEME #####################################################

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
    $currentValue = (Get-ItemProperty -Path $sharingSettingsPath -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue).LimitBlankPasswordUse
    if ($currentValue -ne 0) {
        Set-ItemProperty -Path $sharingSettingsPath -Name "LimitBlankPasswordUse" -Value 0 -Force -ErrorAction Stop
        Write-Host "Parola korumalı paylaşım başarıyla devre dışı bırakıldı."
    } else {
        Write-Host "Parola korumalı paylaşım zaten devre dışı durumda."
    }

    Write-Host "Ağ paylaşım ayarları başarıyla yapılandırıldı."
} catch {
    Write-Error "Ağ paylaşım ayarları yapılandırılırken bir hata oluştu: $_" -ErrorAction SilentlyContinue
}

Write-Host "Tüm ayarlar başarıyla tamamlandı."
##################################################### SON KISIM - PAYLAŞIM AYARLARI #####################################################

# Protokol ayarları
$protocols = @(
    @{Name = "Shared Memory"; Path = "Sm"},
    @{Name = "Named Pipes"; Path = "Np"},
    @{Name = "TCP/IP"; Path = "Tcp"}
)

# Protokol ayarlarını etkinleştir
foreach ($protocol in $protocols) {
    $protocolPath = Join-Path -Path $baseRegistryPath -ChildPath $protocol.Path
    if (Test-Path $protocolPath) {
        try {
            Set-ItemProperty -Path $protocolPath -Name "Enabled" -Value 1 -ErrorAction Stop
            Write-Host "$($protocol.Name) protokolü etkinleştirildi."
        } catch {
            Write-Warning "$($protocol.Name) protokolü etkinleştirilemedi: $_"
        }
    } else {
        Write-Warning "$($protocol.Name) protokolü için yol bulunamadı. İşlem atlanıyor."
    }
}

# Sonuç şifresini ve bağlantı bilgilerini kullanıcıya göster
Write-Host "SqlID: sa  SIFRE=$SIFRE  PORT=$staticPort"

# Bağlantı bilgilerini dosyaya kaydet
try {
    $outputText = "SqlID=SA SqlSifre=$SIFRE PORT=$staticPort BağlantıID=$SystemAdminAccounts/$InstanceNam"
    $filePath = "C:\SQLBILNEXIDSIFRE.txt"
    $outputText | Out-File -FilePath $filePath -Encoding UTF8 -Force
    Write-Host "Bağlantı bilgileri başarıyla kaydedildi: $filePath"
} catch {
    Write-Error "Bağlantı bilgileri kaydedilirken bir hata oluştu: $_"
}

# İşlem sonu mesajı
Write-Host "İşlemler tamamlandı."

# Hata yönetimi (trap kullanımı)
trap {
    Write-Error "Hata oluştu: $_"
    if ($_.Exception) {
        Write-Error "Ayrıntılı hata: $($_.Exception.Message)"
        pause
        break
    }
}

##################################################### KULLANICIDAN YANIT ALMA #####################################################

# Kullanıcıdan kapanış onayı alma
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
