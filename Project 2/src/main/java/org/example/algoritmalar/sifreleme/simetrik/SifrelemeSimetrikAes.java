package org.example.algoritmalar.sifreleme.simetrik;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.KeyGenerator;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class SifrelemeSimetrikAes extends SifrelemeSimetrik{

    public static String startAesMessage(String userInputEncrypt, String userInputDecrypt, String userInputKey) {
        SifrelemeSimetrikAes worker = new SifrelemeSimetrikAes();
        if (userInputEncrypt.equals("İlk") && userInputDecrypt.equals("İlk") && userInputKey.equals("İlk")) {
            return worker.giveInfo();
        }

        if (userInputEncrypt.equals("") && !userInputDecrypt.equals("") && !userInputKey.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (!userInputEncrypt.equals("") && userInputDecrypt.equals("") || userInputKey.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (userInputDecrypt.equals("Şifrele") && userInputKey.equals("Şifrele")) {
            return worker.generateKeysMessage() + "\n" + worker.getMessage(userInputEncrypt);
        }

        else {
            return worker.solveMessage(userInputDecrypt, userInputKey);
        }
    }

    @Override
    public String getMessage(String userInputEncrypt) {
        byte[] inputBytesEncrypt;
        try {
            inputBytesEncrypt = userInputEncrypt.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        KeyParameter keyParam = new KeyParameter(secretKey.getEncoded());
        BlockCipher engine = new AESEngine();
        CBCBlockCipher cbcCipher = new CBCBlockCipher(engine);
        PKCS7Padding padding = new PKCS7Padding();
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcCipher, padding);
        CipherParameters params = new ParametersWithIV(keyParam, iv);

        cipher.init(true, params);
        int outputSize = cipher.getOutputSize(inputBytesEncrypt.length);
        byte[] encryptedBytes = new byte[outputSize];
        int len = cipher.processBytes(inputBytesEncrypt, 0, inputBytesEncrypt.length, encryptedBytes, 0);
        try {
            len += cipher.doFinal(encryptedBytes, len);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        byte[] finalEncrypted = new byte[len];
        System.arraycopy(encryptedBytes, 0, finalEncrypted, 0, len);

        byte[] resultWithIv = new byte[iv.length + finalEncrypted.length];
        System.arraycopy(iv, 0, resultWithIv, 0, iv.length);
        System.arraycopy(finalEncrypted, 0, resultWithIv, iv.length, finalEncrypted.length);

        String hexEncrypted = bytesToHex(resultWithIv);
        return "AES ile metin şifrelendi! " + hexEncrypted;
    }

    @Override
    public String generateKeysMessage() {

        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        generator.init(128);
        secretKey = generator.generateKey();

        String hexKey = bytesToHex(secretKey.getEncoded());
        return "AES ile anahtar oluşturuldu! " + hexKey;
    }

    @Override
    public String solveMessage(String userInputDecrypt, String userInputKey) {
        try {
            inputBytesDecrypt = hexToBytes(userInputDecrypt);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Geçersiz hex şifrelenmiş metin", e);
        }

        try {
            inputBytesKey = hexToBytes(userInputKey);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Geçersiz hex anahtar", e);
        }

        if (inputBytesKey.length != 16) {
            throw new IllegalArgumentException("AES anahtarı 16 bayt olmalı, ama " + inputBytesKey.length + " bayt alındı");
        }

        byte[] iv = new byte[16];
        System.arraycopy(inputBytesDecrypt, 0, iv, 0, 16);

        byte[] encryptedData = new byte[inputBytesDecrypt.length - 16];
        System.arraycopy(inputBytesDecrypt, 16, encryptedData, 0, encryptedData.length);

        KeyParameter keyParam = new KeyParameter(inputBytesKey);
        CipherParameters params = new ParametersWithIV(keyParam, iv);

        BlockCipher engine = new AESEngine();
        CBCBlockCipher cbcCipher = new CBCBlockCipher(engine);
        PKCS7Padding padding = new PKCS7Padding();
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcCipher, padding);
        cipher.init(false, params);

        int outputSize = cipher.getOutputSize(encryptedData.length);
        byte[] decryptedBytes = new byte[outputSize];

        int len = cipher.processBytes(encryptedData, 0, encryptedData.length, decryptedBytes, 0);
        try {
            len += cipher.doFinal(decryptedBytes, len);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("Şifre çözme hatası", e);
        }

        byte[] finalDecrypted = new byte[len];
        System.arraycopy(decryptedBytes, 0, finalDecrypted, 0, len);

        String originalText;
        try {
            originalText = new String(finalDecrypted, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return "Şifresi çözülmüş metin oluşturuldu! " + originalText;
    }




    public static byte[] startAesFile(byte[] userInputFile, byte[] userOutputFile, String userInputKey) {
        SifrelemeSimetrikAes worker = new SifrelemeSimetrikAes();

        if (userInputFile == null && userOutputFile == null && !userInputKey.equals("")) {
            return null;
        }

        if (userInputFile == null && userOutputFile == null || userInputKey.equals("")) {
            return null;
        }

        if (userOutputFile == null && userInputKey.equals("Şifrele")) {
            byte[] key = worker.generateKeysFile();
            byte[] encrypt = worker.getFile(userInputFile);
            byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
            byte[] finalBytes = new byte[key.length + 9 + encrypt.length];
            System.arraycopy(key, 0, finalBytes, 0, key.length);
            System.arraycopy(numbers, 0, finalBytes, key.length, 9);
            System.arraycopy(encrypt, 0, finalBytes, key.length+9, encrypt.length);
            return finalBytes;
        }

        else {
            return worker.solveFile(userOutputFile, userInputKey);
        }
    }

    @Override
    public byte[] getFile(byte[] userInputFile) {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        KeyParameter keyParam = new KeyParameter(secretKey.getEncoded());
        BlockCipher engine = new AESEngine();
        CBCBlockCipher cbcCipher = new CBCBlockCipher(engine);
        PKCS7Padding padding = new PKCS7Padding();
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcCipher, padding);
        CipherParameters params = new ParametersWithIV(keyParam, iv);

        cipher.init(true, params);
        int outputSize = cipher.getOutputSize(userInputFile.length);
        byte[] encryptedBytes = new byte[outputSize];
        int len = cipher.processBytes(userInputFile, 0, userInputFile.length, encryptedBytes, 0);
        try {
            len += cipher.doFinal(encryptedBytes, len);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        byte[] finalEncrypted = new byte[len];
        System.arraycopy(encryptedBytes, 0, finalEncrypted, 0, len);

        byte[] resultWithIv = new byte[iv.length + finalEncrypted.length];
        System.arraycopy(iv, 0, resultWithIv, 0, iv.length);
        System.arraycopy(finalEncrypted, 0, resultWithIv, iv.length, finalEncrypted.length);

        return resultWithIv;
    }

    @Override
    public byte[] generateKeysFile() {
        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        generator.init(128);
        secretKey = generator.generateKey();

        return secretKey.getEncoded();
    }

    @Override
    public byte[] solveFile(byte[] userOutputFile, String userInputKey) {
        String[] parts = userInputKey.split(":");

        byte[] keyInfoBytes = hexToBytes(parts[0]);
        byte[] fileFormatBytes = hexToBytes(parts[1]);

        inputBytesDecrypt = userOutputFile;
        inputBytesKey = keyInfoBytes;

        if (inputBytesKey.length != 16) {
            throw new IllegalArgumentException("AES anahtarı 16 bayt olmalı, ama " + inputBytesKey.length + " bayt alındı");
        }

        byte[] iv = new byte[16];
        System.arraycopy(inputBytesDecrypt, 0, iv, 0, 16);

        byte[] encryptedData = new byte[inputBytesDecrypt.length - 16];
        System.arraycopy(inputBytesDecrypt, 16, encryptedData, 0, encryptedData.length);

        KeyParameter keyParam = new KeyParameter(inputBytesKey);
        CipherParameters params = new ParametersWithIV(keyParam, iv);

        BlockCipher engine = new AESEngine();
        CBCBlockCipher cbcCipher = new CBCBlockCipher(engine);
        PKCS7Padding padding = new PKCS7Padding();
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcCipher, padding);
        cipher.init(false, params);

        int outputSize = cipher.getOutputSize(encryptedData.length);
        byte[] decryptedBytes = new byte[outputSize];

        int len = cipher.processBytes(encryptedData, 0, encryptedData.length, decryptedBytes, 0);
        try {
            len += cipher.doFinal(decryptedBytes, len);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException("Şifre çözme hatası", e);
        }

        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] finalDecrypted = new byte[len+9+fileFormatBytes.length];
        System.arraycopy(decryptedBytes, 0, finalDecrypted, 0, len);
        System.arraycopy(numbers, 0, finalDecrypted, len, 9);
        System.arraycopy(fileFormatBytes, 0, finalDecrypted, len+9, fileFormatBytes.length);

        return finalDecrypted;
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
