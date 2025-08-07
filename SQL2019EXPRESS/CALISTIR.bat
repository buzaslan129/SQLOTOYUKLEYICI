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
:start
cls
echo ==========================================
echo    SQL SERVER OTOMATIK YUKLEYICI
echo ==========================================
echo.
echo Hangi SQL Server surumunu yuklemek istiyorsunuz?
echo.
echo 1. SQL Server 2022 Express (Onerilen)
echo 2. SQL Server 2019 
echo 3. SQL Server 2014 Express
echo 4. SQL Server 2022 Full Paket (SSMS Yok)
echo 5. Cikis
echo.
set /p choice="Seciminizi yapin (1-5): "

if "%choice%"=="1" goto install2022express
if "%choice%"=="2" goto install2019
if "%choice%"=="3" goto install2014express
if "%choice%"=="4" goto install2022full
if "%choice%"=="5" goto exit
echo Gecersiz secim! Lutfen 1-5 arasinda bir sayi girin.
pause
goto start

:install2022express
cls
echo SQL Server 2022 Express yukleniyor...
powershell.exe -executionpolicy bypass "%~dp0\2022EXPRESS.ps1" -EnableProtocols
goto end

:install2019
cls
echo SQL Server 2019 yukleniyor...
powershell.exe -executionpolicy bypass "%~dp0\2019KodrawEskihalisadecepowershell.ps1" -EnableProtocols
goto end

:install2014express
cls
echo SQL Server 2014 Express yukleniyor...
powershell.exe -executionpolicy bypass "%~dp0\2014EXPRESSMSLİ.ps1" -EnableProtocols
goto end

:install2022full
cls
echo SQL Server 2022 Full Paket yukleniyor...
powershell.exe -executionpolicy bypass "%~dp0\2022FULLPAKETSSMSYOK.ps1" -EnableProtocols
goto end

:exit
cls
echo Cikiliyor...
exit /b

:end
echo.
echo Yuklem tamamlandi!
pause