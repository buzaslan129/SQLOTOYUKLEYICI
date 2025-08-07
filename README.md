# SQL Otomatik Yükleyici (SQL Auto Installer)

Bu proje, Microsoft SQL Server'ı otomatik olarak kurmak için PowerShell betikleri içerir.

## Özellikler

- **Otomatik SQL Server Kurulumu**: 2014, 2019, 2022 versiyonları desteklenir
- **Express ve Full Sürümler**: Hem Express hem de Full sürümler için betikler mevcuttur
- **SSMS Kurulumu**: SQL Server Management Studio ayrı olarak kurulabilir
- **Ağ Yapılandırması**: TCP/IP, Named Pipes ve Shared Memory protokolleri otomatik yapılandırılır
- **Güvenlik Duvarı Ayarları**: Gerekli portlar otomatik olarak açılır
- **Rastgele Şifre Üretimi**: SA hesabı için güvenli rastgele şifre üretilir

## Kullanım

### Gereksinimler
- Windows işletim sistemi
- Yönetici yetkileri
- Internet bağlantısı (ISO dosyaları için)

### Kurulum Adımları

1. **Yönetici olarak çalıştırın**: `CALISTIR.bat` dosyasını sağ tıklayıp "Yönetici olarak çalıştır" seçin
2. **Sürüm seçin**: Açılan menüden istediğiniz SQL Server sürümünü seçin:
   - **1** - SQL Server 2022 Express (Önerilen)
   - **2** - SQL Server 2019
   - **3** - SQL Server 2014 Express  
   - **4** - SQL Server 2022 Full Paket (SSMS hariç)
   - **5** - Çıkış
3. **Kurulum başlar**: Seçiminizi yaptıktan sonra otomatik kurulum başlar

**Not**: Artık manuel olarak PowerShell scriptlerini çalıştırmanıza gerek yoktur. `CALISTIR.bat` interaktif menü ile hangi sürümü kuracağınızı seçmenizi sağlar.

### Betik Özellikleri

#### Otomatik Yapılandırma
- ISO dosyası otomatik indirilir
- Rastgele port atanır (10000-63000 arası)
- SA şifresi rastgele üretilir
- Ağ protokolleri etkinleştirilir
- Güvenlik duvarı kuralları eklenir

#### Çıktı Dosyaları
- Bağlantı bilgileri `C:\SQLBILNEXIDSIFRE.txt` dosyasına kaydedilir
- Log dosyaları kurulum sürecini kaydeder

## Güvenlik Notları

⚠️ **Önemli Güvenlik Uyarıları**:
- Şifre dosyaları düz metin olarak kaydedilir
- Güvenlik duvarı kuralları otomatik eklenir
- Ağ paylaşım ayarları değiştirilir
- Sadece güvenilir ortamlarda kullanın

## Sorun Giderme

### Yaygın Problemler
1. **Yönetici yetkileri eksik**: Betikleri mutlaka yönetici olarak çalıştırın
2. **Internet bağlantısı**: ISO indirme için stabil internet gereklidir
3. **Port çakışması**: Script rastgele port seçer, çakışma durumunda yeniden dener
4. **Antivirus müdahalesi**: Geçici olarak devre dışı bırakmanız gerekebilir

### Log Dosyaları
- Kurulum logları Windows Temp klasöründe saklanır
- Hata durumunda log dosyalarını kontrol edin

## Katkıda Bulunma

1. Bu repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/YeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/YeniOzellik`)
5. Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## Uyarılar

- Bu betikler sadece test ve geliştirme ortamları için tasarlanmıştır
- Üretim ortamlarında kullanmadan önce kapsamlı test yapın
- Mevcut SQL Server kurulumlarının üzerine yazar
- Sistem yeniden başlatma gerekebilir

## İletişim

Sorularınız için GitHub Issues kullanın.