package org.example.algoritmalar.hash;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.MD5Digest;

import java.io.UnsupportedEncodingException;

public class HashBlake2 extends Hash {

    public static String startBlake2Message(String userInputHashMessage, String userInputMatch, String userInputHash) {
        HashBlake2 worker = new HashBlake2();
        if (userInputHashMessage.equals("İlk") && userInputMatch.equals("İlk") && userInputHash.equals("İlk")) {
            return worker.giveInfo();
        }

        if (userInputHashMessage.equals("") && !userInputMatch.equals("") && !userInputHash.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (!userInputHashMessage.equals("") && userInputMatch.equals("") || userInputHash.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (userInputMatch.equals("Hashle") && userInputHash.equals("Hashle")) {
            return worker.getMessage(userInputHashMessage);
        } else {
            return worker.matchMessage(userInputMatch, userInputHash);
        }
    }

    @Override
    public String getMessage(String userInputHashMessage) {
        byte[] inputBytesEncrypt;
        try {
            inputBytesEncrypt = userInputHashMessage.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        Blake2bDigest blake2b = new Blake2bDigest();
        blake2b.update(inputBytesEncrypt, 0, inputBytesEncrypt.length);
        byte[] blake2bBytes = new byte[64];
        blake2b.doFinal(blake2bBytes, 0);

        String hexHash = bytesToHex(blake2bBytes);
        return "BLAKE2 ile metin hashlendi! " + hexHash;
    }

    @Override
    public String matchMessage(String userInputMatch, String userInputHash) {
        byte[] inputBytesMatchEncrypt;
        try {
            inputBytesMatchEncrypt = userInputMatch.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        Blake2bDigest blake2bMatch = new Blake2bDigest();
        blake2bMatch.update(inputBytesMatchEncrypt, 0, inputBytesMatchEncrypt.length);
        byte[] blake2bMatchBytes = new byte[64];
        blake2bMatch.doFinal(blake2bMatchBytes, 0);

        String hexMatch = bytesToHex(blake2bMatchBytes);

        if (hexMatch.equals(userInputHash)) {
            return "Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)";
        } else {
            return "Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)";
        }
    }


    public static byte[] startBlake2File(byte[] userInputFile, byte[] userOutputFile, String userInputHash) {
        HashBlake2 worker = new HashBlake2();

        if (userInputFile == null && userOutputFile == null && !userInputHash.equals("")) {
            return null;
        }

        if (userInputFile == null && userOutputFile == null || userInputHash.equals("")) {
            return null;
        }

        if (userOutputFile == null && userInputHash.equals("Hashle")) {
            return worker.getFile(userInputFile);
        }

        else {
            return worker.matchFile(userOutputFile, userInputHash);
        }
    }

    @Override
    public byte[] getFile(byte[] userInputFile) {
        Blake2bDigest blake2b = new Blake2bDigest();
        blake2b.update(userInputFile, 0, userInputFile.length);
        byte[] blake2bBytes = new byte[64];
        blake2b.doFinal(blake2bBytes, 0);

        return blake2bBytes;
    }

    @Override
    public byte[] matchFile(byte[] userOutputFile, String userInputHash) {
        String[] fileAndFormat = bytesToHex(userOutputFile).split("012345677654321031");
        byte[] userOutputFileByte = hexToBytes(fileAndFormat[0]);

        String[] hashAndFormat = userInputHash.split(":");

        Blake2bDigest blake2bMatch = new Blake2bDigest();
        blake2bMatch.update(userOutputFileByte, 0, userOutputFileByte.length);
        byte[] blake2bMatchBytes = new byte[64];
        blake2bMatch.doFinal(blake2bMatchBytes, 0);

        String hexMatch = bytesToHex(blake2bMatchBytes);

        if (hexMatch.equals(hashAndFormat[0]) && fileAndFormat[1].equals(hashAndFormat[1])) {
            byte[] trueMatchBytes = new byte[] {0x31};
            return trueMatchBytes;
        } else {

            byte[] falseMatchBytes = new byte[] {0x31, 0x31};
            return falseMatchBytes;
        }
    }


    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Geçersiz hex formatı");
        }
        String hexLower = hex.toLowerCase();
        if (!hexLower.matches("[0-9a-f]+")) {
            throw new IllegalArgumentException("Geçersiz hex formatı: Sadece 0-9 ve a-f karakterleri kullanılabilir");
        }
        int len = hexLower.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexLower.charAt(i), 16) << 4)
                    + Character.digit(hexLower.charAt(i + 1), 16));
        }
        return data;
    }
}