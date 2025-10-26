package org.example.gui;

public class Main {

    public static String pin = null;

    public static void main(String[] args) {
        MainApp mainApp = new MainApp();

        for (String arg : args) {
            if (arg.startsWith("-pin=")) {
                pin = arg.substring(5);
            }
        }

        mainApp.launchIt(args);

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
    }
}





