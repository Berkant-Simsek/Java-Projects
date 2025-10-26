# Java-Projects

## Project 1
Nowadays, we encounter various problems in stores like it is hard to keep track of everything if you are a boss and it is hard to figure out which product is more suitable for you, especially when you don’t buy it very often like with electronic devices. We think that making one app that can help the boss the worker and the customer with their daily requirements would make life easier. Project aims to give variant information about an electronics store. What makes this project superior to other projects is that it serves more than one group of people, for instance, the head of the store can use it to learn more information about the store’s stock situation, the worker would use it to check payment information and costumer would use it to know more about any device in the store that he is curious about. We think that we can serve different people in different positions simultaneously with this project.

Project Details:
1) From a programming perspective:
   - Project contain the following classes:
     - boss.java 
     - worker.java 
     - customers.java
     - computers.java
     - phones.java
     - devices.java
     - humans.java
     - technology_store1.java
     - technology_store2.java (main class)
     - technology_store.java
   - Encapsulation concept is in the following classes:
     - Phones.java
     - Computers.java
   - Overloading concept is applied in the following classes :
     - Phones.java
     - Computers.java
   - Overriding concept is applied in the following classes:
     - Boss.java
     - Worker.java
     - Customers.java
     - Phones.java
     - Computers.java

2) From a user perspective :
   - If you are a boss the first thing you will see using the project is the products you have in the stock with their detailed information then you easily- if you want to- alter any of the products existing in the stock. Following the instruction after each input the product would be altered successfully.
   - If you are a worker then you would a confirm a payment processes and after the operation completed the stock would change accordingly.
   - If you are a costumer then you can see all of the properties of any device available in the stock also you can check if it exist in the stock or not.



## Project 2

### 🔒 Kriptografi ve Kimlik Kartı Yönetim Uygulaması

Bu proje, güvenli veri işleme ve kimlik doğrulama işlemleri için tasarlanmış güçlü bir masaüstü uygulamasıdır. Uygulama, simetrik ve asimetrik şifreleme, dijital imzalama, hashleme ve Omnikey kart okuyucu ile kimlik kartı işlemlerini destekler. Kullanıcılar, verilerini şifreleyebilir/çözebilir, dosyaları dijital olarak imzalayabilir/doğrulayabilir, veri bütünlüğünü kontrol edebilir ve kimlik kartlarındaki sertifikaları okuyarak PDF formatında çıktı alabilir. Uygulama, kullanıcı dostu bir arayüz sunmak için **JavaFX** teknolojisiyle geliştirilmiştir.



#### 📋 Özellikler
- 🔐 Simetrik Şifreleme: Verilerinizi aynı anahtar ile hızlı ve güvenli bir şekilde şifreleme/çözme.
- 🔑 Asimetrik Şifreleme: Genel ve özel anahtar çiftleriyle güvenli veri şifreleme/çözme.
- ✍️ Dijital İmzalama: Dosyaların kaynağını ve bütünlüğünü garanti altına almak için imzalama ve doğrulama.
- 📜 Hashleme: Veri bütünlüğünü kontrol etmek için sabit uzunlukta hash kodları oluşturma ve doğrulama.
- 🛡️ Kimlik Kartı İşlemleri: Omnikey kart okuyucu ile sertifika okuma, PDF çıktısı alma, dosya imzalama ve doğrulama.



#### 🛠️ Kullanılan Teknolojiler
| Teknoloji          | Açıklama                                                                 |
|--------------------|-------------------------------------------------------------------------|
| **JavaFX** 🖥️     | Kullanıcı dostu arayüz geliştirme için kullanılan bir Java kütüphanesi. [Detaylar](https://openjfx.io/) |
| **Bouncy Castle** 🔐 | Şifreleme, imzalama ve hashleme işlemleri için güçlü bir kriptografi kütüphanesi. [Detaylar](https://www.bouncycastle.org/) |
| **Java Smart Card I/O API** 🪪 | Omnikey kart okuyucu ile güvenli iletişim kurmak için Java'nın yerleşik API'si. |
| **iText** 📄       | Kimlik sertifikası bilgilerini PDF formatında dışa aktarmak için kullanılan bir kütüphane. [Detaylar](https://itextpdf.com/) |


#### ⚙️ Kurulum
Uygulamayı yerel makinenizde çalıştırmak için aşağıdaki adımları izleyin:

##### 📌 Gereksinimler
- ☕ Java Development Kit (JDK): Sürüm 17 veya üstü
- 🪶 Maven: Proje bağımlılıklarını yönetmek için
- 🪪 Omnikey Kart Okuyucu: Kimlik kartı işlemleri için (sürücüler yüklü olmalı)
- 📦 Bağımlılıklar: Bouncy Castle ve iText kütüphaneleri (Maven ile otomatik yüklenir)

##### 🛠️ Kurulum Adımları
Repoyu Klonlayın 🌀
```bash
git clone https://github.com/berkantsimsek-1/project.git && cd project
```
Omnikey Kart Okuyucu Sürücülerini Kurun: Omnikey kart okuyucu sürücülerini resmi web sitesinden indirin ve kurun. Cihazın USB üzerinden doğru bağlandığını kontrol edin.

Uygulamayı Çalıştırın: Proje kök dizininde uygulamayı başlatmak için
```bash
mvn clean package && cd target && java -jar java-baslangic-1.0-SNAPSHOT.jar -pin=123456
```
> 📝 Not: Yukarıdaki kodda yer alan PIN değerini lütfen kendi kimlik kartınızın PIN kodu ile değiştirin.



#### 🚀 Kullanım
Uygulama, kullanıcı dostu bir arayüz üzerinden aşağıdaki işlemleri destekler. Ayrıntılı talimatlar için ilgili kullanım kılavuzlarına göz atabilirsiniz.
Uygulamayı Başlatın: Ana menüden istediğiniz işlemi seçin (şifreleme, imzalama, hashleme veya kart okuyucu).



#### ⚠️ Önemli Notlar
- 🛡️ Güvenlik: Kimlik kartlarındaki özel anahtarlar dışarı çıkarılamaz.
- 🔓 Kilit Mekanizması: İşlem sırasında giriş alanları kilitlenebilir. Kilidi açmak için “Yeniden Aktif Et” butonuna tıklayın.
- ❌ Hata Mesajları: Hatalar için ekranda açıklayıcı mesajlar görüntülenir.
- 📁 Dosya Desteği: Uygulama hem metin girişli hem de dosya tabanlı işlemleri destekler.



#### 📚 Kullanım Kılavuzları
Ayrıntılı talimatlar için aşağıdaki kılavuzlara göz atabilirsiniz:
- Simetrik Şifreleme Kılavuzu
- Asimetrik Şifreleme Kılavuzu
- Dijital İmzalama Kılavuzu
- Hashleme Kılavuzu
- Kart Okuyucu Kılavuzu
> 📝 Not: Kılavuz dosyaları proje dosyaları arasında veya uygulama arayüzünde bulunabilir.



#### 🤝 Katkıda Bulunma
Projeye katkıda bulunmak isterseniz, aşağıdaki adımları izleyin:
- [ ] Depoyu forklayın: https://github.com/berkantsimsek-1/project.git
- [ ] Yeni bir branch oluşturun: git checkout -b feature/yeni-ozellik
- [ ] Değişikliklerinizi yapın ve commit edin: git commit -m "Yeni özellik eklendi"
- [ ] Branch’i push edin: git push origin feature/yeni-ozellik
- [ ] Bir Pull Request oluşturun.



#### 📜 Üçüncü Taraf Lisansları
Bu proje, aşağıdaki üçüncü taraf kütüphaneleri kullanır:
- Bouncy Castle: MIT benzeri lisans (detaylar).
  - İçerdiği OpenPGP kütüphanesi: Apache 2.0 Lisansı.
  - İçerdiği MLS kütüphanesi: io.grpc (Apache 2.0) ve com.google.protobuf (3-Clause BSD Lisansı).
- iText: GNU AGPL v3 veya ticari lisans (detaylar). Bu proje, iText’in açık kaynak (AGPL) sürümünü kullanır. Eğer projenizi ağ üzerinden sunuyorsanız, AGPL gereği kaynak kodunu paylaşmanız gerekebilir.
- JavaFX ve Java Smart Card I/O API: Oracle’ın lisansları altında sağlanır. Ticari kullanım için ek koşullar gerekebilir.
> ⚠️ Uyarı: iText’in AGPL lisansı, ağ üzerinden erişilen uygulamalarda kaynak kodunun paylaşılmasını zorunlu kılabilir. Bu proje bir masaüstü uygulaması olduğundan, bu zorunluluk genellikle geçerli değildir, ancak lisans koşullarını dikkatlice inceleyin.



#### 📜 Lisans
Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır. Daha fazla bilgi için lisans dosyasını inceleyin.
