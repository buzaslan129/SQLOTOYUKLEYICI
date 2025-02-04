if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Bu betik yönetici yetkileriyle çalıştırılmalıdır. Yeniden başlatılıyor..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}
# SSMS kurulum dosyası ve indirme fonksiyonları
function Download-File {
    param (
        [string]$url,
        [string]$destination
    )

    Write-Host "SSMS indiriliyor..."
    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
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
            $progress = [math]::Round(($totalBytesRead / $contentLength) * 100, 2)
            $currentTime = Get-Date

            if (($progress -ge $lastReportedProgress + 5) -or (($currentTime - $lastUpdateTime).TotalSeconds -ge 10)) {
                Write-Host "$progress% tamamlandı"
                $lastReportedProgress = $progress
                $lastUpdateTime = $currentTime
            }
        }

        $fileStream.Close()
        $stream.Close()
        $response.Close()

        Write-Host "`nSSMS başarıyla indirildi: $destination"
    } catch {
        Write-Warning "SSMS indirme işlemi başarısız oldu: $_"
        pause
        break
    }
}

function Validate-FileSize {
    param (
        [string]$filePath,
        [int]$expectedSizeMB
    )

    try {
        $fileSizeMB = (Get-Item $filePath).Length / 1MB
        if ($fileSizeMB -lt $expectedSizeMB) {
            Write-Warning "Dosya boyutu beklentinin altında. ($fileSizeMB MB < $expectedSizeMB MB)"
            return $false
        }
        Write-Host "Dosya boyutu doğrulandı: $fileSizeMB MB"
        return $true
    } catch {
        Write-Warning "Dosya boyutu kontrolü sırasında hata oluştu: $_"
        return $false
    }
}

# İndirilen dosyanın yolunu ve beklenen dosya boyutunu belirleyin
$tempDir = Join-Path -Path $env:TEMP -ChildPath "SSMS"
$savePath = Join-Path -Path $tempDir -ChildPath "SSMS-Setup-ENU.exe"
$ssmsDownloadUrl = "https://aka.ms/ssmsfullsetup"
$expectedFileSizeMB = 473

# Klasörü oluştur
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    Write-Host "Kurulum klasörü oluşturuldu: $tempDir"
}

# İndirme işlemi
if (Test-Path $savePath) {
    Write-Host "SSMS kurulum dosyası zaten mevcut: $savePath"
    if (-not (Validate-FileSize -filePath $savePath -expectedSizeMB $expectedFileSizeMB)) {
        Write-Host "Dosya geçersiz. Yeniden indiriliyor..."
        Remove-Item $savePath -Force
        Download-File -url $ssmsDownloadUrl -destination $savePath
    }
} else {
    Download-File -url $ssmsDownloadUrl -destination $savePath
}

Write-Host "SSMS indirme işlemi tamamlandı."

$arguments = "/install","/quiet","/norestart"

Write-Verbose "SSMS kurulumu başlatılıyor " -Verbose

try {
    $result = Start-Process -FilePath $savePath -ArgumentList $arguments -PassThru -Wait
    Write-Host "SSMS kurulum işlemi tamamlandı."
} catch {
    Write-Warning "SSMS kurulumu sırasında hata oluştu: $($_.Exception.Message)"
}

Write-Host "Kurulum çıktıları C:\Temp\SSMS-Install-Output.log ve C:\Temp\SSMS-Install-Error.log dosyalarına kaydedildi."
pause