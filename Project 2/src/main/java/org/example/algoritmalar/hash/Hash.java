package org.example.algoritmalar.hash;

import org.example.algoritmalar.Algoritmalar;

public abstract class Hash extends Algoritmalar {

    @Override
    public String giveInfo() {

        return "Hashing converts data into a fixed-length output, ensuring integrity and security.\n" +
                "\tMD5 = Message-Digest\n" +
                "\tSHA-1, SHA-256, SHA-3, SHA-512 = Secure Hash Algorithm\n" +
                "\tBLAKE2 and Argon2\n" +
                "\n" +
                "\tUse Cases:\n" +
                "\t\tStoring hashed passwords securely\n" +
                "\t\tEnsuring data integrity in digital signatures\n" +
                "\t\tBlockchain transaction validation";
    }

    public abstract String getMessage(String userInputHashMessage);
    public abstract String matchMessage(String userInputMatch, String userInputHash);
    public abstract byte[] getFile(byte[] userInputFile);
    public abstract byte[] matchFile(byte[] userOutputFile, String userInputHash);
}
