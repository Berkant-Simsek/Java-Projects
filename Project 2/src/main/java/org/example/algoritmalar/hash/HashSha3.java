package org.example.algoritmalar.hash;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.io.UnsupportedEncodingException;

public class HashSha3 extends Hash {

    public static String startSha3Message(String userInputHashMessage, String userInputMatch, String userInputHash) {
        HashSha3 worker = new HashSha3();
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

        SHA3Digest sha3 = new SHA3Digest();
        sha3.update(inputBytesEncrypt, 0, inputBytesEncrypt.length);
        byte[] sha3Bytes = new byte[48];
        sha3.doFinal(sha3Bytes, 0);

        String hexHash = bytesToHex(sha3Bytes);
        return "SHA-3 ile metin hashlendi! " + hexHash;
    }

    @Override
    public String matchMessage(String userInputMatch, String userInputHash) {
        byte[] inputBytesMatchEncrypt;
        try {
            inputBytesMatchEncrypt = userInputMatch.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        SHA3Digest sha3Match = new SHA3Digest();
        sha3Match.update(inputBytesMatchEncrypt, 0, inputBytesMatchEncrypt.length);
        byte[] sha3MatchBytes = new byte[48];
        sha3Match.doFinal(sha3MatchBytes, 0);

        String hexMatch = bytesToHex(sha3MatchBytes);

        if (hexMatch.equals(userInputHash)) {
            return "Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)";
        } else {
            return "Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)";
        }
    }

    public static byte[] startSha3File(byte[] userInputFile, byte[] userOutputFile, String userInputHash) {
        HashSha3 worker = new HashSha3();

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
        SHA3Digest sha3 = new SHA3Digest();
        sha3.update(userInputFile, 0, userInputFile.length);
        byte[] sha3Bytes = new byte[48];
        sha3.doFinal(sha3Bytes, 0);

        return sha3Bytes;
    }

    @Override
    public byte[] matchFile(byte[] userOutputFile, String userInputHash) {
        String[] fileAndFormat = bytesToHex(userOutputFile).split("012345677654321031");
        byte[] userOutputFileByte = hexToBytes(fileAndFormat[0]);

        String[] hashAndFormat = userInputHash.split(":");

        SHA3Digest sha3Match = new SHA3Digest();
        sha3Match.update(userOutputFileByte, 0, userOutputFileByte.length);
        byte[] sha3MatchBytes = new byte[48];
        sha3Match.doFinal(sha3MatchBytes, 0);

        String hexMatch = bytesToHex(sha3MatchBytes);

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