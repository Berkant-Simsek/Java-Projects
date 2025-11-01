package org.example.gui;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class MainApp extends Application {

    @Override
    public void start(Stage primaryStage) {

        primaryStage.setTitle("Şifreleme ve İmzalama Uygulaması");

        MenuFunctions menuFunctions = new MenuFunctions(primaryStage);

        // Ana menü
        VBox mainMenu = menuFunctions.mainMenu;
        mainMenu.setPadding(new Insets(20,20,20,20));
        // Şifreleme alt menüsü (Simetrik, Asimetrik ve Hash)
        // Şifreleme alt menüsü simetrik alt menüsü (DES, AES, Blowfish, Twofish, IDEA, CAST-128, Hill Cipher)
        // Şifreleme alt menüsü asimetrik alt menüsü (Merkle-Hellman, RSA)
        // Şifreleme alt menüsü hash alt menüsü (MD5, SHA-1, SHA-256, SHA-3, BLAKE2)
        // İmzalama alt menüsü (RSA, ECC, Diffie-Hellman, ElGamal, DSA, ECDSA, EdDSA, PSS, Schnorr)


        // Şifreleme alt menüsü (Simetrik ve Asimetrik)
        // Şifreleme simetrik alt menüsü (DES, 3DES, AES)
        //    A single secret key is used for both encryption and decryption.
        //    DES = Data Encryption Standard
        //    3DES = Triple DES
        //    AES = Advanced Encryption Standard
        //       Use Cases:
        //          Encrypting database records
        //          Securing communication in VPNs
        //          Protecting API tokens
        // Şifreleme asimetrik alt menüsü (RSA, ECIES, DH)
        //    Uses a key pair (public and private keys). The public key encrypts data, and the private key decrypts it.
        //    RSA = Rivest-Shamir-Adleman
        //    ECIES = Elliptic Curve Integrated Encryption Scheme
        //       Use Cases:
        //          Digital certificates (SSL/TLS)
        //          Secure email communication (PGP)
        //          Authentication in secure messaging applications
        // İmzalama alt menüsü (RSA, ECDSA, DSA)
        //    Digital signatures are used to ensure data authenticity, integrity, and non-repudiation. They allow verifying that the message was not altered and was sent by a trusted source.
        //    RSA = Rivest-Shamir-Adleman
        //    ECDSA = Elliptic Curve Digital Signature Algorithm
        //    DSA = Digital Signature Algorithm
        //       Use Cases:
        //          Digital certificates (SSL/TLS)
        //          Secure email communication (PGP)
        //          Authentication in secure messaging applications
        // Hash alt menüsü (MD5, SHA-1, SHA-256, SHA-3, SHA-512, BLAKE2, Argon2)
        //    Hashing converts data into a fixed-length output, ensuring integrity and security.
        //    MD5 = Message-Digest
        //    SHA-1, SHA-256, SHA-3, SHA-512 = Secure Hash Algorithm
        //    BLAKE2 and Argon2
        //       Use Cases:
        //          Storing hashed passwords securely
        //          Ensuring data integrity in digital signatures
        //          Blockchain transaction validation
        
        
        
        menuFunctions.encryptOption.setVisible(true);
        menuFunctions.signOption.setVisible(true);
        menuFunctions.encryptOption.setSelected(false);
        menuFunctions.signOption.setSelected(false);


        Scene mainMenuScene = new Scene(mainMenu);
        mainMenuScene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        primaryStage.setScene(mainMenuScene);
        //primaryStage.setMinWidth(600);
        //primaryStage.setMinHeight(350);
        primaryStage.setWidth(1200);
        primaryStage.setHeight(900);
        primaryStage.setResizable(false);
        primaryStage.show();
    }

    public void launchIt(String[] args) {
        launch(args);
    }
}
