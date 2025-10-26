package org.example.algoritmalar;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.algoritmalar.hash.*;
import org.example.algoritmalar.imzalama.ImzalamaDsa;
import org.example.algoritmalar.imzalama.ImzalamaEcdsa;
import org.example.algoritmalar.imzalama.ImzalamaRsa;
import org.example.algoritmalar.sifreleme.asimetrik.SifrelemeAsimetrikEcies;
import org.example.algoritmalar.sifreleme.asimetrik.SifrelemeAsimetrikRsa;
import org.example.algoritmalar.sifreleme.simetrik.SifrelemeSimetrik3des;
import org.example.algoritmalar.sifreleme.simetrik.SifrelemeSimetrikAes;
import org.example.algoritmalar.sifreleme.simetrik.SifrelemeSimetrikDes;

import java.security.Security;

public abstract class Algoritmalar {

    public abstract String giveInfo();

    public static String startMessage(String algoritma, String userInputMessage, String userInputSignKey, String userOutputMessage, String userInputSignature, String userInputKeyAndValidateKeyAndHash) {
        Security.addProvider(new BouncyCastleProvider());

        if (algoritma.equals("Simetrik Şifreleme: DES Algoritması")) {
            return SifrelemeSimetrikDes.startDesMessage(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Simetrik Şifreleme: 3DES Algoritması")) {
            return SifrelemeSimetrik3des.start3desMessage(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Simetrik Şifreleme: AES Algoritması")) {
            return SifrelemeSimetrikAes.startAesMessage(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }



        if (algoritma.equals("Asimetrik Şifreleme: RSA Algoritması")) {
            return SifrelemeAsimetrikRsa.startRsaMessage(userInputMessage, userInputSignKey, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Asimetrik Şifreleme: ECIES Algoritması")) {
            return SifrelemeAsimetrikEcies.startEciesMessage(userInputMessage, userInputSignKey, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }



        if (algoritma.equals("İmzalama: RSA Algoritması")) {
            return ImzalamaRsa.startRsaMessage(userInputMessage, userInputSignKey, userOutputMessage, userInputSignature, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("İmzalama: ECDSA Algoritması")) {
            return ImzalamaEcdsa.startEcdsaMessage(userInputMessage, userInputSignKey, userOutputMessage, userInputSignature, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("İmzalama: DSA Algoritması")) {
            return ImzalamaDsa.startDsaMessage(userInputMessage, userInputSignKey, userOutputMessage, userInputSignature, userInputKeyAndValidateKeyAndHash);
        }



        if (algoritma.equals("Hash: MD5 Algoritması")) {
            return HashMd5.startMd5Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-1 Algoritması")) {
            return HashSha1.startSha1Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-256 Algoritması")) {
            return HashSha256.startSha256Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-3 Algoritması")) {
            return HashSha3.startSha3Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-512 Algoritması")) {
            return HashSha512.startSha512Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: BLAKE2 Algoritması")) {
            return HashBlake2.startBlake2Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: Argon2 Algoritması")) {
            return HashArgon2.startArgon2Message(userInputMessage, userOutputMessage, userInputKeyAndValidateKeyAndHash);
        }

        else return "Sorun var sanki?";
    }



    public static byte[] startFile(String algoritma, byte[] userInputFile, String userInputSignKey, byte[] userOutputFile, byte[] userInputSignature, String userInputKeyAndValidateKeyAndHash) {
        Security.addProvider(new BouncyCastleProvider());

        if (algoritma.equals("Simetrik Şifreleme: DES Algoritması")) {
            return SifrelemeSimetrikDes.startDesFile(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Simetrik Şifreleme: 3DES Algoritması")) {
            return SifrelemeSimetrik3des.start3desFile(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Simetrik Şifreleme: AES Algoritması")) {
            return SifrelemeSimetrikAes.startAesFile(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }



        if (algoritma.equals("Asimetrik Şifreleme: RSA Algoritması")) {
            return SifrelemeAsimetrikRsa.startRsaFile(userInputFile, userInputSignKey, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Asimetrik Şifreleme: ECIES Algoritması")) {
            return SifrelemeAsimetrikEcies.startEciesFile(userInputFile, userInputSignKey, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }



        if (algoritma.equals("İmzalama: RSA Algoritması")) {
            return ImzalamaRsa.startRsaFile(userInputFile, userInputSignKey, userOutputFile, userInputSignature, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("İmzalama: ECDSA Algoritması")) {
            return ImzalamaEcdsa.startEcdsaFile(userInputFile, userInputSignKey, userOutputFile, userInputSignature, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("İmzalama: DSA Algoritması")) {
            return ImzalamaDsa.startDsaFile(userInputFile, userInputSignKey, userOutputFile, userInputSignature, userInputKeyAndValidateKeyAndHash);
        }



        if (algoritma.equals("Hash: MD5 Algoritması")) {
            return HashMd5.startMd5File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-1 Algoritması")) {
            return HashSha1.startSha1File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-256 Algoritması")) {
            return HashSha256.startSha256File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-3 Algoritması")) {
            return HashSha3.startSha3File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: SHA-512 Algoritması")) {
            return HashSha512.startSha512File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: BLAKE2 Algoritması")) {
            return HashBlake2.startBlake2File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }
        if (algoritma.equals("Hash: Argon2 Algoritması")) {
            return HashArgon2.startArgon2File(userInputFile, userOutputFile, userInputKeyAndValidateKeyAndHash);
        }

        else  return null;
    }



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
