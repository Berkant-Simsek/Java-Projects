package org.example.gui;

//import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.io.File;

public class MenuComponents {

    public VBox mainMenu;
    public RadioButton encryptOption;
    public RadioButton signOption;
    public RadioButton hashOption;
    public RadioButton smartCardOption;

    public VBox encryptSubMenu;
    public RadioButton symmetricOption;
    public RadioButton asymmetricOption;

    public VBox symmetricSubMenu;
    public RadioButton desOption;
    public RadioButton threeDesOption;
    public RadioButton aesOption;

    public VBox asymmetricSubMenu;
    public RadioButton rsaOptionEncrypt;
    public RadioButton eciesOption;

    public VBox signSubMenu;
    public RadioButton rsaOptionSign;
    public RadioButton ecdsaOption;
    public RadioButton dsaOption;

    public VBox hashSubMenu;
    public RadioButton md5Option;
    public RadioButton sha1Option;
    public RadioButton sha256Option;
    public RadioButton sha3Option;
    public RadioButton sha512Option;
    public RadioButton blake2Option;
    public RadioButton argon2Option;


    public HBox symmetricBox;
    public HBox desBox;
    public HBox threeDesBox;
    public HBox aesBox;
    public HBox asymmetricBox;
    public HBox rsaBoxEncrypt;
    public HBox eciesBox;
    public HBox rsaBoxSign;
    public HBox ecdsaBox;
    public HBox dsaBox;
    public HBox md5Box;
    public HBox sha1Box;
    public HBox sha256Box;
    public HBox sha3Box;
    public HBox sha512Box;
    public HBox blake2Box;
    public HBox argon2Box;
    //public Insets valueForPadding20;
    //public Insets valueForPadding40;


    public Button confirmButton;
    public File selectedFile;
    public String selectedFileName;
    public File selectedFileAlternative;
    public String selectedFileAlternativeName;

    public VBox processMenuForSymmetric;
    public Button processMenuForSymmetricButtonBack;
    public Button processMenuForSymmetricButtonFileEncryptEnter;
    public Button processMenuForSymmetricButtonFileEncryptEnterActivate;
    public Button processMenuForSymmetricButtonEncrypt;
    public Button processMenuForSymmetricButtonEncryptActivate;
    public Button processMenuForSymmetricButtonFileEncrypt;
    public Button processMenuForSymmetricButtonFileEncryptActivate;
    public Button processMenuForSymmetricButtonFileDecryptEnter;
    public Button processMenuForSymmetricButtonFileDecryptEnterActivate;
    public Button processMenuForSymmetricButtonDecrypt;
    public Button processMenuForSymmetricButtonDecryptActivate;
    public Button processMenuForSymmetricButtonFileDecrypt;
    public Button processMenuForSymmetricButtonFileDecryptActivate;
    public TextArea encryptionMessageForSymmetric;
    public TextArea decryptionMessageForSymmetric;
    public TextArea decryptionKeyForSymmetric;
    public Button copyKeyButtonForSymmetric;
    public Button copyKeyFileButtonForSymmetric;
    public Button copyEncryptMessageButtonForSymmetric;
    public Button saveEncryptFileButtonForSymmetric;
    public Button copyDecryptMessageButtonForSymmetric;
    public Button saveDecryptFileButtonForSymmetric;
    public GridPane firstGridSymmetric;
    public GridPane secondGridSymmetric;
    public GridPane thirdGridSymmetric;

    public VBox processMenuForAsymmetric;
    public Button processMenuForAsymmetricButtonBack;
    public Button processMenuForAsymmetricButtonGenerateKeys;
    public Button processMenuForAsymmetricButtonGenerateKeysActivate;
    public Button processMenuForAsymmetricButtonGenerateKeysFile;
    public Button processMenuForAsymmetricButtonGenerateKeysFileActivate;
    public Button processMenuForAsymmetricButtonFileEncryptEnter;
    public Button processMenuForAsymmetricButtonFileEncryptEnterActivate;
    public Button processMenuForAsymmetricButtonEncrypt;
    public Button processMenuForAsymmetricButtonEncryptActivate;
    public Button processMenuForAsymmetricButtonFileEncrypt;
    public Button processMenuForAsymmetricButtonFileEncryptActivate;
    public Button processMenuForAsymmetricButtonFileDecryptEnter;
    public Button processMenuForAsymmetricButtonFileDecryptEnterActivate;
    public Button processMenuForAsymmetricButtonDecrypt;
    public Button processMenuForAsymmetricButtonDecryptActivate;
    public Button processMenuForAsymmetricButtonFileDecrypt;
    public Button processMenuForAsymmetricButtonFileDecryptActivate;
    public TextArea encryptMessageForAsymmetric;
    public TextArea encryptKeyForAsymmetric;
    public TextArea decryptMessageForAsymmetric;
    public TextArea decryptKeyForAsymmetric;
    public Button copyEncryptKeyButtonForAsymmetric;
    public Button copyEncryptKeyFileButtonForAsymmetric;
    public Button copyDecryptKeyButtonForAsymmetric;
    public Button copyDecryptKeyFileButtonForAsymmetric;
    public Button copyEncryptedMessageButtonForAsymmetric;
    public Button saveEncryptFileButtonForAsymmetric;
    public Button copyDecryptedMessageButtonForAsymmetric;
    public Button saveDecryptFileButtonForAsymmetric;
    public GridPane firstGridAsymmetric;
    public GridPane secondGridAsymmetric;
    public GridPane thirdGridAsymmetric;
    public GridPane fourthGridAsymmetric;

    public VBox processMenuForSign;
    public Button processMenuForSignButtonBack;
    public Button processMenuForSignButtonGenerateKeys;
    public Button processMenuForSignButtonGenerateKeysActivate;
    public Button processMenuForSignButtonGenerateKeysFile;
    public Button processMenuForSignButtonGenerateKeysFileActivate;
    public Button processMenuForSignButtonFileSignEnter;
    public Button processMenuForSignButtonFileSignEnterActivate;
    public Button processMenuForSignButtonSign;
    public Button processMenuForSignButtonSignActivate;
    public Button processMenuForSignButtonFileSign;
    public Button processMenuForSignButtonFileSignActivate;
    public Button processMenuForSignButtonFileValidateEnter;
    public Button processMenuForSignButtonFileValidateEnterActivate;
    public Button processMenuForSignButtonFileSignedEnter;
    public Button processMenuForSignButtonFileSignedEnterActivate;
    public Button processMenuForSignButtonValidate;
    public Button processMenuForSignButtonValidateActivate;
    public Button processMenuForSignButtonFileValidate;
    public Button processMenuForSignButtonFileValidateActivate;
    public TextArea signMessageForSign;
    public TextArea signKeyForSign;
    public TextArea validateMessageForSign;
    public TextArea validateSignatureForSign;
    public TextArea validateKeyForSign;
    public Button copySignKeyButtonForSign;
    public Button copySignKeyFileButtonForSign;
    public Button copyValidateKeyButtonForSign;
    public Button copyValidateKeyFileButtonForSign;
    public Button copySignedMessageButtonForSign;
    public Button saveSignedFileButtonForSign;
    public GridPane firstGridSign;
    public GridPane secondGridSign;
    public GridPane thirdGridSign;
    public GridPane fourthGridSign;

    public VBox processMenuForHash;
    public Button processMenuForHashButtonBack;
    public Button processMenuForHashButtonFileHashEnter;
    public Button processMenuForHashButtonFileHashEnterActivate;
    public Button processMenuForHashButtonHash;
    public Button processMenuForHashButtonHashActivate;
    public Button processMenuForHashButtonFileHash;
    public Button processMenuForHashButtonFileHashActivate;
    public Button processMenuForHashButtonFileMatchEnter;
    public Button processMenuForHashButtonFileMatchEnterActivate;
    public Button processMenuForHashButtonMatch;
    public Button processMenuForHashButtonMatchActivate;
    public Button processMenuForHashButtonFileMatch;
    public Button processMenuForHashButtonFileMatchActivate;
    public TextArea hashMessageForHash;
    public TextArea matchMessageForHash;
    public TextArea hashForHash;
    public Button copyHashButtonForHash;
    public Button copyHashFileButtonForHash;
    public GridPane firstGridHash;
    public GridPane secondGridHash;

    public MenuComponents() {

        mainMenu = new VBox(10);
        mainMenu.getStylesheets().add("root");
        mainMenu.setAlignment(Pos.CENTER);
        Label explanation = new Label("Hoş geldiniz! Bu uygulama ile metinlerinizi güvenli bir şekilde şifreleyebilir (AES, DES gibi), dijital imza atabilir (RSA, ECDSA) veya hash hesaplayabilirsiniz.\n" +
                "Aşağıdan işlem türünü seçin ve devam edin. (Daha fazla bilgi için her seçeneğin üzerine gelin.)");
        explanation.setWrapText(true);
        explanation.getStyleClass().add("explanation-text");
        encryptOption = new RadioButton("Şifreleme Algoritmaları");
        encryptOption.setTooltip(new Tooltip("Şifreleme algoritmaları, verileri yetkisiz erişime karşı korur. İki türü vardır:\n" +
                "Simetrik (DES, 3DES, AES: aynı anahtar ile şifreleme/çözme)\n" +
                "Asimetrik (RSA, ECIES: genel/özel anahtar çifti ile şifreleme/çözme)"));
        signOption = new RadioButton("İmzalama Algoritmaları");
        signOption.setTooltip(new Tooltip("Dijital imzalar, verinin gerçekliğini, bütünlüğünü ve reddedilemezliğini sağlamak için kullanılır.\n" +
                "Mesajın değiştirilmediğini ve güvenilir bir kaynak tarafından gönderildiğini doğrulamaya olanak tanırlar.\n" +
                "Kullanım Örnekleri:\n" +
                "\tDijital sertifikalar (SSL/TLS)\n" +
                "\tGüvenli e-posta iletişimi (PGP)\n" +
                "\tGüvenli mesajlaşma uygulamalarında kimlik doğrulama"));
        hashOption = new RadioButton("Hash Algoritmaları");
        hashOption.setTooltip(new Tooltip("Karma işlemi, verileri sabit uzunlukta bir çıktıya dönüştürerek bütünlük ve güvenlik sağlar.\n" +
                "Kullanım Örnekleri:\n" +
                "\tParolaların güvenli bir şekilde depolanması\n" +
                "\tDijital imzalarda veri bütünlüğünün sağlanması\n" +
                "\tBlok zinciri işlem doğrulaması"));
        smartCardOption = new RadioButton("Akıllı Kart Sertifika İşlemleri");
        smartCardOption.setTooltip(new Tooltip("Akıllı kartların içerisinde gömülü olan kimlik doğrulama sertifika işlemlerini kapsar."));

        encryptSubMenu = new VBox();
        // encryptSubMenu.setPadding(new Insets(5,0,0,20));
        encryptSubMenu.setVisible(false);
        symmetricOption = new RadioButton("Simetrik Algoritmalar");
        symmetricOption.setTooltip(new Tooltip("Hem şifreleme hem de şifre çözme için tek bir gizli anahtar kullanılır.\n" +
                "Kullanım Örnekleri:\n" +
                "\tVeritabanı kayıtlarının şifrelenmesi\n" +
                "\tVPN'lerde iletişimin güvenliğinin sağlanması\n" +
                "\tAPI belirteçlerinin korunması"));
        asymmetricOption = new RadioButton("Asimetrik Algoritmalar");
        asymmetricOption.setTooltip(new Tooltip("Bir anahtar çifti (genel ve özel anahtarlar) kullanır. Genel anahtar verileri şifreler, özel anahtar ise şifresini çözer.\n" +
                "Kullanım Örnekleri:\n" +
                "\tDijital sertifikalar (SSL/TLS)\n" +
                "\tGüvenli e-posta iletişimi (PGP)\n" +
                "\tGüvenli mesajlaşma uygulamalarında kimlik doğrulama"));

        symmetricSubMenu = new VBox();
        // symmetricSubMenu.setPadding(new Insets(5,0,0,40));
        symmetricSubMenu.setVisible(false);
        desOption = new RadioButton("DES Algoritması");
        desOption.setTooltip(new Tooltip("DES = Data Encryption Standard"));
        threeDesOption = new RadioButton("3DES Algoritması");
        threeDesOption.setTooltip(new Tooltip("3DES = Triple Data Encryption Standard"));
        aesOption = new RadioButton("AES Algoritması");
        aesOption.setTooltip(new Tooltip("AES = Advanced Encryption Standard"));

        asymmetricSubMenu = new VBox();
        // asymmetricSubMenu.setPadding(new Insets(5,0,0,40));
        asymmetricSubMenu.setVisible(false);
        rsaOptionEncrypt = new RadioButton("RSA Algoritması");
        rsaOptionEncrypt.setTooltip(new Tooltip("RSA = Rivest-Shamir-Adleman"));
        eciesOption = new RadioButton("ECIES Algoritması");
        eciesOption.setTooltip(new Tooltip("ECIES = Elliptic Curve Integrated Encryption Scheme"));

        signSubMenu = new VBox();
        // signSubMenu.setPadding(new Insets(5,0,0,20));
        signSubMenu.setVisible(false);
        rsaOptionSign = new RadioButton("RSA Algoritması");
        rsaOptionSign.setTooltip(new Tooltip("RSA = Rivest-Shamir-Adleman"));
        ecdsaOption = new RadioButton("ECDSA Algoritması");
        ecdsaOption.setTooltip(new Tooltip("ECDSA = Elliptic Curve Digital Signature Algorithm"));
        dsaOption = new RadioButton("DSA Algoritması");
        dsaOption.setTooltip(new Tooltip("DSA = Digital Signature Algorithm"));

        hashSubMenu = new VBox();
        // hashSubMenu.setPadding(new Insets(5,0,0,20));
        hashSubMenu.setVisible(false);
        md5Option = new RadioButton("MD5 Algoritması");
        md5Option.setTooltip(new Tooltip("MD5 = Message-Digest"));
        sha1Option = new RadioButton("SHA-1 Algoritması");
        sha1Option.setTooltip(new Tooltip("SHA-1 = Secure Hash Algorithm"));
        sha256Option = new RadioButton("SHA-256 Algoritması");
        sha256Option.setTooltip(new Tooltip("SHA-256 = Secure Hash Algorithm"));
        sha3Option = new RadioButton("SHA-3 Algoritması");
        sha3Option.setTooltip(new Tooltip("SHA-3 = Secure Hash Algorithm"));
        sha512Option = new RadioButton("SHA-512 Algoritması");
        sha512Option.setTooltip(new Tooltip("SHA-512 = Secure Hash Algorithm"));
        blake2Option = new RadioButton("BLAKE2 Algoritması");
        blake2Option.setTooltip(new Tooltip("BLAKE2"));
        argon2Option = new RadioButton("Argon2 Algoritması");
        argon2Option.setTooltip(new Tooltip("Argon2"));


        symmetricBox = new HBox(0, symmetricOption);

        desBox = new HBox(0, desOption);
        threeDesBox = new HBox(0, threeDesOption);
        aesBox = new HBox(0, aesOption);
        GridPane symmetricGrid = new GridPane();
        symmetricGrid.add(desBox, 5, 0);
        symmetricGrid.add(threeDesBox, 5, 1);
        symmetricGrid.add(aesBox, 5, 2);
        symmetricGrid.setHgap(5);
        symmetricGrid.setVgap(5);

        asymmetricBox = new HBox(0, asymmetricOption);

        rsaBoxEncrypt = new HBox(0, rsaOptionEncrypt);
        eciesBox = new HBox(0, eciesOption);
        GridPane asymmetricGrid = new GridPane();
        asymmetricGrid.add(rsaBoxEncrypt, 5, 0);
        asymmetricGrid.add(eciesBox, 5, 1);
        asymmetricGrid.setHgap(5);
        asymmetricGrid.setVgap(5);

        rsaBoxSign = new HBox(0, rsaOptionSign);
        ecdsaBox = new HBox(0, ecdsaOption);
        dsaBox = new HBox(0, dsaOption);
        GridPane signGrid = new GridPane();
        signGrid.add(rsaBoxSign, 5, 0);
        signGrid.add(ecdsaBox, 5, 1);
        signGrid.add(dsaBox, 5, 2);
        signGrid.setHgap(5);
        signGrid.setVgap(5);

        md5Box = new HBox(0, md5Option);
        sha1Box = new HBox(0, sha1Option);
        sha256Box = new HBox(0, sha256Option);
        sha3Box = new HBox(0, sha3Option);
        sha512Box = new HBox(0, sha512Option);
        blake2Box = new HBox(0, blake2Option);
        argon2Box = new HBox(0, argon2Option);
        GridPane hashGrid = new GridPane();
        hashGrid.add(md5Box, 5, 0);
        hashGrid.add(sha1Box, 5, 1);
        hashGrid.add(sha256Box, 5, 2);
        hashGrid.add(sha3Box, 5, 3);
        hashGrid.add(sha512Box, 5, 4);
        hashGrid.add(blake2Box, 5, 5);
        hashGrid.add(argon2Box, 5, 6);
        hashGrid.setHgap(5);
        hashGrid.setVgap(5);

        /*valueForPadding20 = new Insets(5, 0, 0, 20);
        valueForPadding40 = new Insets(5, 0, 0, 40);
        symmetricBox.setPadding(valueForPadding20);
        desBox.setPadding(valueForPadding40);
        threeDesBox.setPadding(valueForPadding40);
        aesBox.setPadding(valueForPadding40);
        asymmetricBox.setPadding(valueForPadding20);
        rsaBoxEncrypt.setPadding(valueForPadding40);
        eciesBox.setPadding(valueForPadding40);
        rsaBoxSign.setPadding(valueForPadding20);
        ecdsaBox.setPadding(valueForPadding20);
        dsaBox.setPadding(valueForPadding20);
        md5Box.setPadding(valueForPadding40);
        sha1Box.setPadding(valueForPadding40);
        sha256Box.setPadding(valueForPadding40);
        sha3Box.setPadding(valueForPadding40);
        sha512Box.setPadding(valueForPadding40);
        blake2Box.setPadding(valueForPadding40);
        argon2Box.setPadding(valueForPadding40);*/

        symmetricSubMenu.getChildren().addAll(symmetricGrid);
        asymmetricSubMenu.getChildren().addAll(asymmetricGrid);
        GridPane encryptGrid = new GridPane();
        encryptGrid.add(symmetricBox, 5, 0);
        encryptGrid.add(symmetricSubMenu, 5, 1);
        encryptGrid.add(asymmetricBox, 5, 2);
        encryptGrid.add(asymmetricSubMenu, 5, 3);
        encryptGrid.setHgap(5);
        encryptGrid.setVgap(5);
        encryptSubMenu.getChildren().addAll(encryptGrid);
        // encryptSubMenu.getChildren().addAll(symmetricBox, symmetricSubMenu, asymmetricBox, asymmetricSubMenu);
        signSubMenu.getChildren().addAll(signGrid);
        hashSubMenu.getChildren().addAll(hashGrid);


        confirmButton = new Button("Seçimi Onayla");
        confirmButton.setId("confirmButton");
        confirmButton.setDisable(true);
        // mainMenu.getChildren().addAll(confirmButton);
        GridPane generalGrid = new GridPane();
        generalGrid.add(explanation, 0, 0, 2, 1);
        generalGrid.add(encryptOption, 0, 1);
        generalGrid.add(encryptSubMenu, 0, 2);
        generalGrid.add(signOption, 0, 3);
        generalGrid.add(signSubMenu, 0, 4);
        generalGrid.add(hashOption, 0, 5);
        generalGrid.add(hashSubMenu, 0, 6);
        generalGrid.add(smartCardOption, 1, 1);
        generalGrid.add(confirmButton, 2, 7);
        generalGrid.setHgap(5);
        generalGrid.setVgap(5);
        mainMenu.getChildren().addAll(generalGrid);
        // mainMenu.getChildren().addAll(explanation, encryptOption, encryptSubMenu, signOption, signSubMenu, hashOption, hashSubMenu);




        processMenuForSymmetric = new VBox(10);
        processMenuForSymmetric.getStyleClass().add("root");
        processMenuForSymmetricButtonBack = new Button("Geri");
        processMenuForSymmetricButtonFileEncryptEnter = new Button("Dosya Seç");
        processMenuForSymmetricButtonFileEncryptEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForSymmetricButtonEncrypt = new Button("Girilen Metni Şifrele");
        processMenuForSymmetricButtonEncryptActivate = new Button("Tekrardan Metin Şifrelemeyi Aç");
        processMenuForSymmetricButtonFileEncrypt = new Button("Seçilen Dosyayı Şifrele");
        processMenuForSymmetricButtonFileEncryptActivate = new Button("Tekrardan Dosya Şifrelemeyi Aç");
        processMenuForSymmetricButtonFileDecryptEnter = new Button("Dosya Seç");
        processMenuForSymmetricButtonFileDecryptEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForSymmetricButtonDecrypt = new Button("Girilen Metni Çöz");
        processMenuForSymmetricButtonDecryptActivate = new Button("Tekrardan Metin Çözmeyi Aç");
        processMenuForSymmetricButtonFileDecrypt = new Button("Seçilen Dosyayı Çöz");
        processMenuForSymmetricButtonFileDecryptActivate = new Button("Tekrardan Dosya Çözmeyi Aç");
        encryptionMessageForSymmetric = new TextArea();
        encryptionMessageForSymmetric.setWrapText(true);
        decryptionMessageForSymmetric = new TextArea();
        decryptionMessageForSymmetric.setWrapText(true);
        decryptionKeyForSymmetric = new TextArea();
        decryptionKeyForSymmetric.setWrapText(true);
        copyKeyButtonForSymmetric = new Button("Oluşturulan Anahtarı Kopyala");
        copyKeyFileButtonForSymmetric = new Button("Oluşturulan Anahtarı Kopyala");
        copyEncryptMessageButtonForSymmetric = new Button("Oluşturulan Şifreli Metni Kopyala");
        saveEncryptFileButtonForSymmetric = new Button("Oluşturulan Şifreli Dosyayı Kaydet");
        copyDecryptMessageButtonForSymmetric = new Button("Çözülmüş Metni Kopyala");
        saveDecryptFileButtonForSymmetric = new Button("Çözülmüş Dosyayı Kaydet");
        processMenuForSymmetricButtonBack.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonEncrypt.setDisable(false);
        processMenuForSymmetricButtonEncryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileEncrypt.setDisable(false);
        processMenuForSymmetricButtonFileEncryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForSymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForSymmetricButtonDecrypt.setDisable(false);
        processMenuForSymmetricButtonDecryptActivate.setDisable(true);
        processMenuForSymmetricButtonFileDecrypt.setDisable(false);
        processMenuForSymmetricButtonFileDecryptActivate.setDisable(true);
        encryptionMessageForSymmetric.setEditable(true);
        decryptionMessageForSymmetric.setEditable(true);
        decryptionKeyForSymmetric.setEditable(true);
        copyKeyButtonForSymmetric.setVisible(false);
        copyKeyFileButtonForSymmetric.setVisible(false);
        copyEncryptMessageButtonForSymmetric.setVisible(false);
        saveEncryptFileButtonForSymmetric.setVisible(false);
        copyDecryptMessageButtonForSymmetric.setVisible(false);
        saveDecryptFileButtonForSymmetric.setVisible(false);



        processMenuForAsymmetric = new VBox(10);
        processMenuForAsymmetric.getStyleClass().add("root");
        processMenuForAsymmetricButtonBack = new Button("Geri");
        processMenuForAsymmetricButtonGenerateKeys = new Button("Metin için Genel ve Özel Anahtar Oluştur");
        processMenuForAsymmetricButtonGenerateKeysActivate = new Button("Tekrardan Metin için Anahtar Oluşturmayı Aç");
        processMenuForAsymmetricButtonGenerateKeysFile = new Button("Dosya için Genel ve Özel Anahtar Oluştur");
        processMenuForAsymmetricButtonGenerateKeysFileActivate = new Button("Tekrardan Dosya için Anahtar Oluşturmayı Aç");
        processMenuForAsymmetricButtonFileEncryptEnter = new Button("Dosya Seç");
        processMenuForAsymmetricButtonFileEncryptEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForAsymmetricButtonEncrypt = new Button("Girilen Metni Şifrele");
        processMenuForAsymmetricButtonEncryptActivate = new Button("Tekrardan Metin Şifrelemeyi Aç");
        processMenuForAsymmetricButtonFileEncrypt = new Button("Seçilen Dosyayı Şifrele");
        processMenuForAsymmetricButtonFileEncryptActivate = new Button("Tekrardan Dosya Şifrelemeyi Aç");
        processMenuForAsymmetricButtonFileDecryptEnter = new Button("Dosya Seç");
        processMenuForAsymmetricButtonFileDecryptEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForAsymmetricButtonDecrypt = new Button("Girilen Metni Çöz");
        processMenuForAsymmetricButtonDecryptActivate = new Button("Tekrardan Metin Çözmeyi Aç");
        processMenuForAsymmetricButtonFileDecrypt = new Button("Seçilen Dosyayı Çöz");
        processMenuForAsymmetricButtonFileDecryptActivate = new Button("Tekrardan Dosya Çözmeyi Aç");
        encryptMessageForAsymmetric = new TextArea();
        encryptMessageForAsymmetric.setWrapText(true);
        encryptKeyForAsymmetric = new TextArea();
        encryptKeyForAsymmetric.setWrapText(true);
        decryptMessageForAsymmetric = new TextArea();
        decryptMessageForAsymmetric.setWrapText(true);
        decryptKeyForAsymmetric = new TextArea();
        decryptKeyForAsymmetric.setWrapText(true);
        copyEncryptKeyButtonForAsymmetric = new Button("Oluşturulan Genel Anahtarı Kopyala");
        copyEncryptKeyFileButtonForAsymmetric = new Button("Oluşturulan Genel Anahtarı Kopyala");
        copyDecryptKeyButtonForAsymmetric = new Button("Oluşturulan Özel Anahtarı Kopyala");
        copyDecryptKeyFileButtonForAsymmetric = new Button("Oluşturulan Özel Anahtarı Kopyala");
        copyEncryptedMessageButtonForAsymmetric = new Button("Oluşturulan Şifreli Metni Kopyala");
        saveEncryptFileButtonForAsymmetric = new Button("Oluşturulan Şifreli Dosyayı Kaydet");
        copyDecryptedMessageButtonForAsymmetric = new Button("Çözülmüş Metni Kopyala");
        saveDecryptFileButtonForAsymmetric = new Button("Çözülmüş Dosyayı Kaydet");
        processMenuForAsymmetricButtonBack.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
        processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonEncrypt.setDisable(false);
        processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonDecrypt.setDisable(false);
        processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
        encryptMessageForAsymmetric.setEditable(true);
        encryptKeyForAsymmetric.setEditable(true);
        decryptMessageForAsymmetric.setEditable(true);
        decryptKeyForAsymmetric.setEditable(true);
        copyEncryptKeyButtonForAsymmetric.setVisible(false);
        copyEncryptKeyFileButtonForAsymmetric.setVisible(false);
        copyDecryptKeyButtonForAsymmetric.setVisible(false);
        copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
        copyEncryptedMessageButtonForAsymmetric.setVisible(false);
        saveEncryptFileButtonForAsymmetric.setVisible(false);
        copyDecryptedMessageButtonForAsymmetric.setVisible(false);
        saveDecryptFileButtonForAsymmetric.setVisible(false);



        processMenuForSign = new VBox(10);
        processMenuForSign.getStyleClass().add("root");
        processMenuForSignButtonBack = new Button("Geri");
        processMenuForSignButtonGenerateKeys = new Button("Genel ve Özel Anahtar Oluştur");
        processMenuForSignButtonGenerateKeysActivate = new Button("Tekrardan Anahtar Oluşturmayı Aç");
        processMenuForSignButtonGenerateKeysFile = new Button("Dosya için Genel ve Özel Anahtar Oluştur");
        processMenuForSignButtonGenerateKeysFileActivate = new Button("Tekrardan Dosya için Anahtar Oluşturmayı Aç");
        processMenuForSignButtonFileSignEnter = new Button("Dosya Seç");
        processMenuForSignButtonFileSignEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForSignButtonSign = new Button("Girilen Metni İmzala");
        processMenuForSignButtonSignActivate = new Button("Tekrardan Metin İmzalamayı Aç");
        processMenuForSignButtonFileSign = new Button("Seçilen Dosyayı İmzala");
        processMenuForSignButtonFileSignActivate = new Button("Tekrardan Dosya İmzalamayı Aç");
        processMenuForSignButtonFileValidateEnter = new Button("Dosya Seç");
        processMenuForSignButtonFileValidateEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForSignButtonFileSignedEnter = new Button("Dosya Seç");
        processMenuForSignButtonFileSignedEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForSignButtonValidate = new Button("Girilen Metni Doğrula");
        processMenuForSignButtonValidateActivate = new Button("Tekrardan Metin Doğrulamayı Aç");
        processMenuForSignButtonFileValidate = new Button("Seçilen Dosyayı Doğrula");
        processMenuForSignButtonFileValidateActivate = new Button("Tekrardan Dosya Doğrulamayı Aç");
        signMessageForSign = new TextArea();
        signMessageForSign.setWrapText(true);
        signKeyForSign = new TextArea();
        signKeyForSign.setWrapText(true);
        validateMessageForSign = new TextArea();
        validateMessageForSign.setWrapText(true);
        validateSignatureForSign = new TextArea();
        validateSignatureForSign.setWrapText(true);
        validateKeyForSign = new TextArea();
        validateKeyForSign.setWrapText(true);
        copySignKeyButtonForSign = new Button("Oluşturulan Özel Anahtarı Kopyala");
        copySignKeyFileButtonForSign = new Button("Oluşturulan Özel Anahtarı Kopyala");
        copyValidateKeyButtonForSign = new Button("Oluşturulan Genel Anahtarı Kopyala");
        copyValidateKeyFileButtonForSign = new Button("Oluşturulan Genel Anahtarı Kopyala");
        copySignedMessageButtonForSign = new Button("Oluşturulan İmzalanmış Metni Kopyala");
        saveSignedFileButtonForSign = new Button("Oluşturulan İmzalanmış Dosyayı Kaydet");
        processMenuForSignButtonBack.setDisable(false);
        processMenuForSignButtonGenerateKeys.setDisable(false);
        processMenuForSignButtonGenerateKeysActivate.setDisable(true);
        processMenuForSignButtonGenerateKeysFile.setDisable(false);
        processMenuForSignButtonGenerateKeysFileActivate.setDisable(true);
        processMenuForSignButtonFileSignEnter.setDisable(false);
        processMenuForSignButtonFileSignEnterActivate.setDisable(true);
        processMenuForSignButtonSign.setDisable(false);
        processMenuForSignButtonSignActivate.setDisable(true);
        processMenuForSignButtonFileSign.setDisable(false);
        processMenuForSignButtonFileSignActivate.setDisable(true);
        processMenuForSignButtonFileValidateEnter.setDisable(false);
        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSignButtonFileSignedEnter.setDisable(false);
        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSignButtonValidate.setDisable(false);
        processMenuForSignButtonValidateActivate.setDisable(true);
        processMenuForSignButtonFileValidate.setDisable(false);
        processMenuForSignButtonFileValidateActivate.setDisable(true);
        signMessageForSign.setEditable(true);
        signKeyForSign.setEditable(true);
        validateMessageForSign.setEditable(true);
        validateSignatureForSign.setEditable(true);
        validateKeyForSign.setEditable(true);
        copySignKeyButtonForSign.setVisible(false);
        copySignKeyFileButtonForSign.setVisible(false);
        copyValidateKeyButtonForSign.setVisible(false);
        copyValidateKeyFileButtonForSign.setVisible(false);
        copySignedMessageButtonForSign.setVisible(false);
        saveSignedFileButtonForSign.setVisible(false);



        processMenuForHash = new VBox(10);
        processMenuForHash.getStyleClass().add("root");
        processMenuForHashButtonBack = new Button("Geri");
        processMenuForHashButtonFileHashEnter = new Button("Dosya Seç");
        processMenuForHashButtonFileHashEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForHashButtonHash = new Button("Girilen Metni Hashle");
        processMenuForHashButtonHashActivate = new Button("Tekrardan Metin Hashlemeyi Aç");
        processMenuForHashButtonFileHash = new Button("Seçilen Dosyayı Hashle");
        processMenuForHashButtonFileHashActivate = new Button("Tekrardan Dosya Hashlemeyi Aç");
        processMenuForHashButtonFileMatchEnter = new Button("Dosya Seç");
        processMenuForHashButtonFileMatchEnterActivate = new Button("Tekrardan Dosya Seçmeyi Aç");
        processMenuForHashButtonMatch = new Button("Girilen Metni Doğrula");
        processMenuForHashButtonMatchActivate = new Button("Tekrardan Metin Doğrulamayı Aç");
        processMenuForHashButtonFileMatch = new Button("Seçilen Dosyayı Doğrula");
        processMenuForHashButtonFileMatchActivate = new Button("Tekrardan Dosya Doğrulamayı Aç");
        hashMessageForHash = new TextArea();
        hashMessageForHash.setWrapText(true);
        matchMessageForHash = new TextArea();
        matchMessageForHash.setWrapText(true);
        hashForHash = new TextArea();
        hashForHash.setWrapText(true);
        copyHashButtonForHash = new Button("Oluşturulan Hashi Kopyala");
        copyHashFileButtonForHash = new Button("Oluşturulan Hashi Kopyala");
        processMenuForHashButtonBack.setDisable(false);
        processMenuForHashButtonFileHashEnter.setDisable(false);
        processMenuForHashButtonFileHashEnterActivate.setDisable(true);
        processMenuForHashButtonHash.setDisable(false);
        processMenuForHashButtonHashActivate.setDisable(true);
        processMenuForHashButtonFileHash.setDisable(false);
        processMenuForHashButtonFileHashActivate.setDisable(true);
        processMenuForHashButtonFileMatchEnter.setDisable(false);
        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
        processMenuForHashButtonMatch.setDisable(false);
        processMenuForHashButtonMatchActivate.setDisable(true);
        processMenuForHashButtonFileMatch.setDisable(false);
        processMenuForHashButtonFileMatchActivate.setDisable(true);
        hashMessageForHash.setEditable(true);
        matchMessageForHash.setEditable(true);
        hashForHash.setEditable(true);
        copyHashButtonForHash.setVisible(false);
        copyHashFileButtonForHash.setVisible(false);
    }
}
