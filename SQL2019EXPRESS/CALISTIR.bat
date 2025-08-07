@echo off
:: Yönetici yetkisi kontrolü
net session >nul 2>&1
if %errorlevel% neq 0 (
    cls
    echo KOMUTU YONETICI OLARAK BASLATINIZ.
    pause
    exit /b
)

:: Yonetici yetkisi mevcutsa devam et
cls
echo YONETICI OLARAK BASLATILIYOR...

:: SQL Server 2022 Express (Önerilen)
powershell.exe -executionpolicy bypass "%~dp0\2022EXPRESS.ps1" -EnableProtocols

:: Alternatif olarak diğer sürümler için aşağıdakilerden birini kullanın:
:: powershell.exe -executionpolicy bypass "%~dp0\2019KodrawEskihalisadecepowershell.ps1" -EnableProtocols
:: powershell.exe -executionpolicy bypass "%~dp0\2014EXPRESSMSLİ.ps1" -EnableProtocols
:: powershell.exe -executionpolicy bypass "%~dp0\2022FULLPAKETSSMSYOK.ps1" -EnableProtocols
pause