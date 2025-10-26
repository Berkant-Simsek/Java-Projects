package org.example.algoritmalar.sifreleme.simetrik;

import org.example.algoritmalar.sifreleme.Sifreleme;

import javax.crypto.SecretKey;

public abstract class SifrelemeSimetrik extends Sifreleme {

    public SecretKey secretKey;

    @Override
    public String giveInfo() {

        return "A single secret key is used for both encryption and decryption.\n" +
                "\tDES = Data Encryption Standard\n" +
                "\t3DES = Triple DES\n" +
                "\tAES = Advanced Encryption Standard\n" +
                "\n" +
                "\tUse Cases:\n" +
                "\t\tEncrypting database records\n" +
                "\t\tSecuring communication in VPNs\n" +
                "\t\tProtecting API tokens";
    }

    public abstract String getMessage(String userInputEncrypt);
    public abstract String solveMessage(String userInputDecrypt, String userInputKey);
    public abstract byte[] getFile(byte[] userInputFile);
    public abstract byte[] solveFile(byte[] userOutputFile, String userInputKey);
}
