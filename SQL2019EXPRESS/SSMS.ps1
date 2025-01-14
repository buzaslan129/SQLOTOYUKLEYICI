if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Bu betik yönetici yetkileriyle çalıştırılmalıdır. Yeniden başlatılıyor..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}
Add-Type -AssemblyName System.Windows.Forms

function Check-RestartRequired {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            return $true
        }
    }

    return $false
}

if (Check-RestartRequired) {
    $dialogResult = [System.Windows.Forms.MessageBox]::Show(
        "Sistem yeniden başlatılması gerekiyor. Başlatılsın mı?",
        "Yeniden Başlatma Gerekliliği",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host "Kullanıcı yeniden başlatmayı kabul etti. Sistem yeniden başlatılıyor..."
        Restart-Computer -Force
    } else {
        Write-Host "Kullanıcı yeniden başlatmayı reddetti. Program Durduruluyor..."
        pause
        break
    }
} else {
    Write-Host "Yeniden başlatma gerekliliği bulunamadı. Program Devam ediyor..."
}
###########################################################################################################
function Test-FileInUse {
    param (
        [string]$filePath
    )
    try {
        $stream = [System.IO.File]::Open($filePath, 'Open', 'Read', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

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

        # Akışları kapatma işlemi bug oluyor diye
        $fileStream.Close()
        $stream.Close()
        $response.Close()

        Write-Host "`nSSMS başarıyla indirildi: $destination"
    } catch {
        Write-Warning "SSMS indirme işlemi başarısız oldu: $_"
        if (Test-Path $destination) {
            Write-Host "Dosya kullanımda değilse kaldırılıyor..."
            if (-not (Test-FileInUse -filePath $destination)) {
                Remove-Item $destination -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warning "Dosya başka bir işlem tarafından kullanılıyor ve silinemiyor."
            }
        }
        pause
        break
    }
}

# Dosya boyutunu kontrol et
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

# Hedef klasör ve dosya
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
        if (-not (Test-FileInUse -filePath $savePath)) {
            Remove-Item $savePath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Dosya başka bir işlem tarafından kullanılıyor ve yeniden indirilemiyor."
            pause 
            break
        }
        Download-File -url $ssmsDownloadUrl -destination $savePath
    }
} else {
    Download-File -url $ssmsDownloadUrl -destination $savePath
}

# SSMS'i kur
Write-Host "SSMS kurulumu başlatılıyor..."
try {
    Start-Process -FilePath $savePath -ArgumentList "/quiet /norestart" -Wait
    Write-Host "SSMS başarıyla kuruldu."
} catch {
    Write-Error "SSMS kurulumu sırasında bir hata oluştu: $_"
    pause
    break
}

Write-Host "SSMS kurulum işlemi tamamlandı."
pause
break
