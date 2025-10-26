package org.example.algoritmalar.imzalama;

import org.example.algoritmalar.Algoritmalar;
import org.example.algoritmalar.sifreleme.Sifreleme;

import javax.crypto.SecretKey;

public abstract class Imzalama extends Algoritmalar {

    @Override
    public String giveInfo() {

        return "Digital signatures are used to ensure data authenticity, integrity, and non-repudiation. They allow verifying that the message was not altered and was sent by a trusted source.\n" +
                "\tRSA = Rivest-Shamir-Adleman\n" +
                "\tECDSA = Elliptic Curve Digital Signature Algorithm\n" +
                "\tDSA = Digital Signature Algorithm\n" +
                "\n" +
                "\tUse Cases:\n" +
                "\t\tDigital certificates (SSL/TLS)\n" +
                "\t\tSecure email communication (PGP)\n" +
                "\t\tAuthentication in secure messaging applications";
    }

    public abstract String getMessage(String userInputSignMessage, String userInputSignKey);
    public abstract String generateKeysMessage();
    public abstract String validateMessage(String userInputValidateMessage, String userInputSignature, String userInputValidateKey);
    public abstract byte[] getFile(byte[] userInputFile, String userInputSignKey);
    public abstract byte[] generateKeysFile();
    public abstract byte[] validateFile(byte[] userOutputFile, byte[] userInputSignature, String userInputValidateKey);

}
