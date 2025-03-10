# **ShadowScan**

**Gizli Bilgi ve Güvenlik Açığı Tarayıcı**

ShadowScan, dosyalarda, URL'lerde ve dizinlerde **hassas bilgileri** (API anahtarları, şifreler, e-posta adresleri vb.) tespit etmek ve **güvenlik açıklarını** belirlemek için geliştirilmiş bir araçtır.

## **Özellikler**


✅ Dosya, URL ve dizin bazlı tarama

✅ API anahtarları, şifreler, JWT, IP adresleri gibi hassas verileri bulma

✅ Güvenlik başlıklarını kontrol etme (CSP, HSTS, XSS korumaları vb.)

✅ Çoklu iş parçacığı (thread) desteği ile hızlı tarama

✅ Tespit edilen bulguları dosyaya kaydetme


## **Kurulum**

Projeyi yerel ortamınıza klonlamak ve gerekli bağımlılıkları kurmak için aşağıdaki adımları takip edin:

```bash
git clone https://github.com/kullanici/shadowscan.git  
cd shadowscan  
python3 -m venv venv  
source venv/bin/activate  # (Windows için: venv\Scripts\activate)  
pip install -e .  
```

## **Kullanım**

### **1. Dosya Taraması**

```bash
shadowscan -f dosya.txt
```

### **2. URL Taraması**

```bash
shadowscan -u "https://example.com"
```

### **3. Dizin Taraması**

```bash
shadowscan -d /path/to/directory
```

### **4. Sonuçları Dosyaya Kaydetme**

```bash
shadowscan -f dosya.txt -o sonuçlar.txt
```

## **Geliştirici**

**Nihat Bayram**
# shadowScanV2.0
