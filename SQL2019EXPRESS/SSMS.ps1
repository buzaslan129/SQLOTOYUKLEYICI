if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Bu betik yönetici yetkileriyle çalıştırılmalıdır. Yeniden başlatılıyor..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# SSMS kurulum betiği
Write-Host "SQL Server Management Studio (SSMS) Kurulum Betiği" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# SSMS kurulum dosyası ve indirme fonksiyonları
function Download-File {
    param (
        [string]$url,
        [string]$destination
    )

    Write-Host "SSMS indiriliyor..."
    Write-Host "URL: $url" -ForegroundColor Yellow
    
    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.Timeout = 30000  # 30 saniye timeout
        $response = $request.GetResponse()
        $contentLength = $response.ContentLength

        $stream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($destination)
        $buffer = New-Object byte[] 8192
        $totalBytesRead = 0

        # Zamanlama ve ilerleme güncellemesi
        $lastUpdateTime = Get-Date
        $lastReportedProgress = 0

        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $bytesRead)
            $totalBytesRead += $bytesRead
            
            if ($contentLength -gt 0) {
                $progress = [math]::Round(($totalBytesRead / $contentLength) * 100, 2)
            } else {
                $progress = 0
            }
            
            $currentTime = Get-Date

            if (($progress -ge $lastReportedProgress + 5) -or (($currentTime - $lastUpdateTime).TotalSeconds -ge 10)) {
                if ($contentLength -gt 0) {
                    Write-Host "$progress% tamamlandı ($('{0:N2}' -f ($totalBytesRead / 1MB)) MB)"
                } else {
                    Write-Host "$('{0:N2}' -f ($totalBytesRead / 1MB)) MB indirildi..."
                }
                $lastReportedProgress = $progress
                $lastUpdateTime = $currentTime
            }
        }

        $fileStream.Close()
        $stream.Close()
        $response.Close()

        Write-Host "`nSSMS başarıyla indirildi: $destination" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "SSMS indirme işlemi başarısız oldu: $_"
        Write-Warning "İnternet bağlantınızı kontrol edin."
        
        # Hatalı dosyayı temizle
        if (Test-Path $destination) {
            try {
                Remove-Item $destination -Force -ErrorAction SilentlyContinue
                Write-Host "Hatalı dosya temizlendi."
            } catch {
                Write-Warning "Hatalı dosya temizlenemedi: $destination"
            }
        }
        return $false
    }
}

function Validate-FileSize {
    param (
        [string]$filePath,
        [int]$expectedSizeMB
    )

    try {
        if (-not (Test-Path $filePath)) {
            Write-Warning "Dosya bulunamadı: $filePath"
            return $false
        }
        
        $fileSizeMB = (Get-Item $filePath).Length / 1MB
        if ($fileSizeMB -lt ($expectedSizeMB * 0.9)) {  # %10 tolerans
            Write-Warning "Dosya boyutu beklentinin altında. ($([math]::Round($fileSizeMB,2)) MB < $expectedSizeMB MB)"
            return $false
        }
        Write-Host "Dosya boyutu doğrulandı: $([math]::Round($fileSizeMB,2)) MB" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Dosya boyutu kontrolü sırasında hata oluştu: $_"
        return $false
    }
}

# İndirilen dosyanın yolunu ve beklenen dosya boyutunu belirleyin
$tempDir = Join-Path -Path $env:TEMP -ChildPath "SSMS"
$savePath = Join-Path -Path $tempDir -ChildPath "SSMS-Setup-ENU.exe"
$ssmsDownloadUrl = "https://aka.ms/ssmsfullsetup"  # Microsoft'un resmi kısayolu
$expectedFileSizeMB = 473

Write-Host "Geçici klasör: $tempDir" -ForegroundColor Yellow

# Klasörü oluştur
if (-not (Test-Path $tempDir)) {
    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Write-Host "Kurulum klasörü oluşturuldu: $tempDir" -ForegroundColor Green
    } catch {
        Write-Error "Klasör oluşturulamadı: $tempDir - $_"
        pause
        exit 1
    }
}

# İndirme işlemi
$downloadSuccess = $false
if (Test-Path $savePath) {
    Write-Host "SSMS kurulum dosyası zaten mevcut: $savePath"
    if (-not (Validate-FileSize -filePath $savePath -expectedSizeMB $expectedFileSizeMB)) {
        Write-Host "Dosya geçersiz. Yeniden indiriliyor..." -ForegroundColor Yellow
        try {
            Remove-Item $savePath -Force -ErrorAction Stop
        } catch {
            Write-Warning "Mevcut dosya silinemedi: $_"
        }
        $downloadSuccess = Download-File -url $ssmsDownloadUrl -destination $savePath
    } else {
        $downloadSuccess = $true
    }
} else {
    $downloadSuccess = Download-File -url $ssmsDownloadUrl -destination $savePath
}

if (-not $downloadSuccess) {
    Write-Error "SSMS indirilemedi. İşlem durduruluyor."
    pause
    exit 1
}

Write-Host "SSMS indirme işlemi başarıyla tamamlandı." -ForegroundColor Green

# SSMS kurulumu
$arguments = "/install", "/quiet", "/norestart"
Write-Host "`nSSMS kurulumu başlatılıyor..." -ForegroundColor Yellow
Write-Host "Kurulum parametreleri: $($arguments -join ' ')"

try {
    $process = Start-Process -FilePath $savePath -ArgumentList $arguments -PassThru -Wait -Verb RunAs
    
    if ($process.ExitCode -eq 0) {
        Write-Host "SSMS kurulum işlemi başarıyla tamamlandı!" -ForegroundColor Green
    } elseif ($process.ExitCode -eq 3010) {
        Write-Warning "SSMS kurulumu tamamlandı ancak sistem yeniden başlatması gerekiyor."
    } else {
        Write-Warning "SSMS kurulumu tamamlandı ancak hata kodu döndü: $($process.ExitCode)"
    }
    
    # Kurulum dosyasını temizle
    try {
        Remove-Item $savePath -Force -ErrorAction SilentlyContinue
        Write-Host "Geçici kurulum dosyası temizlendi." -ForegroundColor Green
    } catch {
        Write-Warning "Geçici dosya temizlenemedi: $savePath"
    }
    
} catch {
    Write-Error "SSMS kurulumu sırasında hata oluştu: $($_.Exception.Message)"
    Write-Host "Kurulum dosyası korundu: $savePath"
    pause
    exit 1
}

Write-Host "`nSSMS kurulum işlemi tamamlandı!" -ForegroundColor Green
Write-Host "SQL Server Management Studio'yu başlatabilirsiniz." -ForegroundColor Cyan

# Kullanıcıdan onay al
do {
    $response = Read-Host "`nBu pencereyi kapatmak istiyor musunuz? (evet/hayır)"
    if ($response -ieq "evet") {
        exit 0
    } elseif ($response -ieq "hayır") {
        pause
        exit 0
    } else {
        Write-Host "Lütfen 'evet' veya 'hayır' yazın." -ForegroundColor Yellow
    }
} while ($true)