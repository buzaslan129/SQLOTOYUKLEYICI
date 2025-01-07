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

powershell.exe -executionpolicy bypass C:\SQL2019EXPRESS\2019Kodrawhali.ps1 -EnableProtocols
pause