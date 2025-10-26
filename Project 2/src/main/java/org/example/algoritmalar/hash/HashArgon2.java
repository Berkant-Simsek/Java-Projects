package org.example.algoritmalar.hash;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

public class HashArgon2 extends Hash {

    public static String startArgon2Message(String userInputHashMessage, String userInputMatch, String userInputHash) {
        HashArgon2 worker = new HashArgon2();
        if (userInputHashMessage.equals("İlk") && userInputMatch.equals("İlk") && userInputHash.equals("İlk")) {
            return worker.giveInfo();
        }

        if (userInputHashMessage.isEmpty() && !userInputMatch.isEmpty() && !userInputHash.isEmpty()) {
            return "Giriş Yapılmadı.";
        }

        if (!userInputHashMessage.isEmpty() && userInputMatch.equals("") || userInputHash.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (userInputMatch.equals("Hashle") && userInputHash.equals("Hashle")) {
            return worker.getMessage(userInputHashMessage);
        }

        return worker.matchMessage(userInputMatch, userInputHash);

    }

    @Override
    public String getMessage(String userInputHashMessage) {
        byte[] inputBytesEncrypt;
        try {
            inputBytesEncrypt = userInputHashMessage.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        Argon2BytesGenerator argon2id = new Argon2BytesGenerator();
        Argon2Parameters argon2idParam = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withSalt(salt).withMemoryAsKB(65536).withIterations(3).withParallelism(4).build();
        argon2id.init(argon2idParam);

        byte[] argon2idBytes = new byte[32];
        argon2id.generateBytes(inputBytesEncrypt, argon2idBytes);

        String hexHash = bytesToHex(argon2idBytes);
        String hexSalt = bytesToHex(salt);
        return "Argon2 ile metin hashlendi! " + hexHash + ":" + hexSalt;
    }

    @Override
    public String matchMessage(String userInputMatch, String userInputHash) {
        byte[] inputBytesMatchEncrypt;
        try {
            inputBytesMatchEncrypt = userInputMatch.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        String[] parts = userInputHash.split(":");
        byte[] salt = hexToBytes(parts[1]);

        Argon2BytesGenerator argon2idMatch = new Argon2BytesGenerator();
        Argon2Parameters argon2idParamMatch = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withSalt(salt).withMemoryAsKB(65536).withIterations(3).withParallelism(4).build();
        argon2idMatch.init(argon2idParamMatch);

        byte[] argon2idMatchBytes = new byte[32];
        argon2idMatch.generateBytes(inputBytesMatchEncrypt, argon2idMatchBytes);

        String hexMatch = bytesToHex(argon2idMatchBytes);

        if (hexMatch.equals(parts[0])) {
            return "Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)";
        }

        return "Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)";

    }


    public static byte[] startArgon2File(byte[] userInputFile, byte[] userOutputFile, String userInputHash) {
        HashArgon2 worker = new HashArgon2();

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
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        Argon2BytesGenerator argon2id = new Argon2BytesGenerator();
        Argon2Parameters argon2idParam = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withSalt(salt).withMemoryAsKB(65536).withIterations(3).withParallelism(4).build();
        argon2id.init(argon2idParam);

        byte[] argon2idBytes = new byte[32];
        argon2id.generateBytes(userInputFile, argon2idBytes);

        byte[] numbers = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x31, 0x31, 0x31, 0x31};
        byte[] argon2Bytes = new byte[argon2idBytes.length+18+salt.length];
        System.arraycopy(argon2idBytes, 0, argon2Bytes, 0, argon2idBytes.length);
        System.arraycopy(numbers, 0, argon2Bytes, argon2idBytes.length, 18);
        System.arraycopy(salt, 0, argon2Bytes, argon2idBytes.length+18, salt.length);

        return argon2Bytes;
    }

    @Override
    public byte[] matchFile(byte[] userOutputFile, String userInputHash) {
        String[] fileAndFormat = bytesToHex(userOutputFile).split("012345677654321031");
        byte[] userOutputFileByte = hexToBytes(fileAndFormat[0]);

        String[] hashAndFormat = userInputHash.split(":");
        String[] argon2idAndSalt = hashAndFormat[0].split("112233445566777766554433221131313131");
        byte[] salt = hexToBytes(argon2idAndSalt[1]);

        Argon2BytesGenerator argon2idMatch = new Argon2BytesGenerator();
        Argon2Parameters argon2idParamMatch = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withSalt(salt).withMemoryAsKB(65536).withIterations(3).withParallelism(4).build();
        argon2idMatch.init(argon2idParamMatch);

        byte[] argon2idMatchBytes = new byte[32];
        argon2idMatch.generateBytes(userOutputFileByte, argon2idMatchBytes);

        String hexMatch = bytesToHex(argon2idMatchBytes);

        if (hexMatch.equals(argon2idAndSalt[0]) && fileAndFormat[1].equals(hashAndFormat[1])) {
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