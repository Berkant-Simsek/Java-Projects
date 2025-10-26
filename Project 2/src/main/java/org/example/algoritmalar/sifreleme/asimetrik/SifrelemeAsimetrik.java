package org.example.algoritmalar.sifreleme.asimetrik;

import org.example.algoritmalar.sifreleme.Sifreleme;

public abstract class SifrelemeAsimetrik extends Sifreleme {

    @Override
    public String giveInfo() {

        return "Uses a key pair (public and private keys). The public key encrypts data, and the private key decrypts it.\n" +
                "\tRSA = Rivest-Shamir-Adleman\n" +
                "\tECIES = Elliptic Curve Integrated Encryption Scheme\n" +
                "\n" +
                "\tUse Cases:\n" +
                "\t\tDigital certificates (SSL/TLS)\n" +
                "\t\tSecure email communication (PGP)\n" +
                "\t\tAuthentication in secure messaging applications";
    }

    public abstract String getMessage(String userInputSignMessage, String userInputSignKey);
    public abstract String solveMessage(String userInputDecrypt, String userInputKey);
    public abstract byte[] getFile(byte[] userInputFile, String userInputEncryptKey);
    public abstract byte[] solveFile(byte[] userOutputFile, String userInputDecryptKey);
}