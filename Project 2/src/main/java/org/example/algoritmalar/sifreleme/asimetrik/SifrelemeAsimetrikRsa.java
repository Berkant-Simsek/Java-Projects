package org.example.algoritmalar.sifreleme.asimetrik;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SifrelemeAsimetrikRsa extends SifrelemeAsimetrik {

    public static String startRsaMessage(String userInputEncryptMessage, String userInputEncryptKey, String userInputDecryptMessage, String userInputDecryptKey) {
        SifrelemeAsimetrikRsa worker = new SifrelemeAsimetrikRsa();
        if (userInputEncryptMessage.equals("İlk") && userInputEncryptKey.equals("İlk") && userInputDecryptMessage.equals("İlk") && userInputDecryptKey.equals("İlk")) {
            return worker.giveInfo();
        }

        if ((userInputEncryptMessage.equals("") || userInputEncryptKey.equals("")) && !userInputDecryptMessage.equals("") && !userInputDecryptKey.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (!userInputEncryptMessage.equals("") && !userInputEncryptKey.equals("") && (userInputDecryptMessage.equals("") || userInputDecryptKey.equals(""))) {
            return "Giriş Yapılmadı.";
        }

        if (userInputEncryptMessage.equals("Anahtar") && userInputEncryptKey.equals("Anahtar") && userInputDecryptMessage.equals("Anahtar") && userInputDecryptKey.equals("Anahtar")) {
            return worker.generateKeysMessage();
        }

        if (userInputDecryptMessage.equals("Şifrele") && userInputDecryptKey.equals("Şifrele")) {
            return worker.getMessage(userInputEncryptMessage, userInputEncryptKey);
        } else {
            return worker.solveMessage(userInputDecryptMessage, userInputDecryptKey);
        }
    }

    @Override
    public String getMessage(String userInputEncryptMessage, String userInputEncryptKey) {
        byte[] inputBytesEncryptMessage;
        try {
            inputBytesEncryptMessage = userInputEncryptMessage.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        String[] parts = userInputEncryptKey.split(":");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        RSAKeyParameters publicKey = new RSAKeyParameters(false, modulus, exponent);

        RSAEngine rsaEngine = new RSAEngine();
        OAEPEncoding rsaOaep = new OAEPEncoding(rsaEngine);
        rsaOaep.init(true, publicKey);
        byte[] encryptedMessageBytes;
        try {
            encryptedMessageBytes = rsaOaep.processBlock(inputBytesEncryptMessage, 0, inputBytesEncryptMessage.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        String hexEncryptMessage = bytesToHex(encryptedMessageBytes);
        return "RSA ile metin şifrelendi! " + hexEncryptMessage;
    }

    @Override
    public String generateKeysMessage() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 2048, 80));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
        byte[] privateModulus = privateKey.getModulus().toByteArray();
        byte[] privateExponent = privateKey.getExponent().toByteArray();
        byte[] pBytesPrivate = privateKey.getP().toByteArray();
        byte[] qBytesPrivate = privateKey.getQ().toByteArray();
        byte[] dpBytesPrivate = privateKey.getDP().toByteArray();
        byte[] dqBytesPrivate = privateKey.getDQ().toByteArray();
        byte[] qInvBytesPrivate = privateKey.getQInv().toByteArray();
        String privateKeyHex = bytesToHex(privateModulus) + ":" + bytesToHex(privateExponent) + ":";
        privateKeyHex =  privateKeyHex + bytesToHex(pBytesPrivate) + ":" + bytesToHex(qBytesPrivate) + ":";
        privateKeyHex =  privateKeyHex + bytesToHex(dpBytesPrivate) + ":" + bytesToHex(dqBytesPrivate) + ":";
        privateKeyHex =  privateKeyHex + bytesToHex(qInvBytesPrivate);

        RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
        byte[] publicModulus = publicKey.getModulus().toByteArray();
        byte[] publicExponent = publicKey.getExponent().toByteArray();
        String publicKeyHex = bytesToHex(publicModulus) + ":" + bytesToHex(publicExponent);

        return "RSA ile genel anahtar oluşturuldu! " + publicKeyHex + "\n" + "RSA ile özel anahtar oluşturuldu! " + privateKeyHex;
    }

    @Override
    public String solveMessage(String userInputDecryptMessage, String userInputDecryptKey) {
        byte[] inputBytesDecryptMessage= hexToBytes(userInputDecryptMessage);

        String[] parts = userInputDecryptKey.split(":");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        BigInteger p = new BigInteger(1, hexToBytes(parts[2]));
        BigInteger q = new BigInteger(1, hexToBytes(parts[3]));
        BigInteger dp = new BigInteger(1, hexToBytes(parts[4]));
        BigInteger dq = new BigInteger(1, hexToBytes(parts[5]));
        BigInteger qInv = new BigInteger(1, hexToBytes(parts[6]));
        RSAPrivateCrtKeyParameters privateKey = new RSAPrivateCrtKeyParameters(modulus, BigInteger.valueOf(65537), exponent, p, q, dp, dq, qInv);

        RSAEngine rsaEngine = new RSAEngine();
        OAEPEncoding rsaOaep = new OAEPEncoding(rsaEngine);
        rsaOaep.init(false, privateKey);
        byte[] decryptedMessageBytes;
        try {
            decryptedMessageBytes = rsaOaep.processBlock(inputBytesDecryptMessage, 0, inputBytesDecryptMessage.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        String decryptedMessage;
        try {
            decryptedMessage = new String(decryptedMessageBytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return "Şifresi çözülmüş metin oluşturuldu! " + decryptedMessage;
    }



    public static byte[] startRsaFile(byte[] userInputFile, String userInputEncryptKey, byte[] userOutputFile, String userInputDecryptKey) {
        SifrelemeAsimetrikRsa worker = new SifrelemeAsimetrikRsa();

        if (userInputFile == null && userInputEncryptKey.equals("") && !(userOutputFile == null) && !userInputDecryptKey.equals("")) {
            return null;
        }

        if (!(userInputFile == null) && !userInputEncryptKey.equals("") && userOutputFile == null && userInputDecryptKey.equals("")) {
            return null;
        }

        if (userInputFile == null && userInputEncryptKey.equals("Anahtar") && userOutputFile == null && userInputDecryptKey.equals("Anahtar")) {
            return worker.generateKeysFile();
        }

        if (userOutputFile == null && userInputDecryptKey.equals("Şifrele")) {
            return worker.getFile(userInputFile, userInputEncryptKey);
        }

        else {
            return worker.solveFile(userOutputFile, userInputDecryptKey);
        }
    }

    @Override
    public byte[] getFile(byte[] userInputFile, String userInputEncryptKey) {
        String separate = bytesToHex(userInputFile);
        String[] partss = separate.split("012345677654321031");
        byte[] userInputFileBytes = hexToBytes(partss[0]);
        byte[] userInputFileFormatBytes = hexToBytes(partss[1]);

        String[] parts = userInputEncryptKey.split("012345677654321031");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        RSAKeyParameters publicKey = new RSAKeyParameters(false, modulus, exponent);

        RSAEngine rsaEngine = new RSAEngine();
        OAEPEncoding rsaOaep = new OAEPEncoding(rsaEngine);
        rsaOaep.init(true, publicKey);
        byte[] encryptedMessageBytes;
        try {
            encryptedMessageBytes = rsaOaep.processBlock(userInputFileBytes, 0, userInputFileBytes.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        } catch (DataLengthException ee) {
            byte[] tooLong = new byte[] {0x31};
            return tooLong;
        }

        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] encryptedMessageFinalBytes = new byte[encryptedMessageBytes.length+9+userInputFileFormatBytes.length];
        System.arraycopy(encryptedMessageBytes, 0, encryptedMessageFinalBytes, 0, encryptedMessageBytes.length);
        System.arraycopy(numbers, 0, encryptedMessageFinalBytes, encryptedMessageBytes.length, 9);
        System.arraycopy(userInputFileFormatBytes, 0, encryptedMessageFinalBytes, encryptedMessageBytes.length+9, userInputFileFormatBytes.length);

        return encryptedMessageFinalBytes;
    }

    @Override
    public byte[] generateKeysFile() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 2048, 80));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
        byte[] privateModulus = privateKey.getModulus().toByteArray();
        byte[] privateExponent = privateKey.getExponent().toByteArray();
        byte[] pBytesPrivate = privateKey.getP().toByteArray();
        byte[] qBytesPrivate = privateKey.getQ().toByteArray();
        byte[] dpBytesPrivate = privateKey.getDP().toByteArray();
        byte[] dqBytesPrivate = privateKey.getDQ().toByteArray();
        byte[] qInvBytesPrivate = privateKey.getQInv().toByteArray();
        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] privateKeyBytes = new byte[privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length+9+dpBytesPrivate.length+9+dqBytesPrivate.length+9+qInvBytesPrivate.length];
        System.arraycopy(privateModulus, 0, privateKeyBytes, 0, privateModulus.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateModulus.length, 9);
        System.arraycopy(privateExponent, 0, privateKeyBytes, privateModulus.length+9, privateExponent.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length, 9);
        System.arraycopy(pBytesPrivate, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9, pBytesPrivate.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length, 9);
        System.arraycopy(qBytesPrivate, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9, qBytesPrivate.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length, 9);
        System.arraycopy(dpBytesPrivate, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length+9, dpBytesPrivate.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length+9+dpBytesPrivate.length, 9);
        System.arraycopy(dqBytesPrivate, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length+9+dpBytesPrivate.length+9, dqBytesPrivate.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length+9+dpBytesPrivate.length+9+dqBytesPrivate.length, 9);
        System.arraycopy(qInvBytesPrivate, 0, privateKeyBytes, privateModulus.length+9+privateExponent.length+9+pBytesPrivate.length+9+qBytesPrivate.length+9+dpBytesPrivate.length+9+dqBytesPrivate.length+9, qInvBytesPrivate.length);

        RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
        byte[] publicModulus = publicKey.getModulus().toByteArray();
        byte[] publicExponent = publicKey.getExponent().toByteArray();
        byte[] numberss = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] publicKeyBytes = new byte[publicModulus.length+9+publicExponent.length];
        System.arraycopy(publicModulus, 0, publicKeyBytes, 0, publicModulus.length);
        System.arraycopy(numberss, 0, publicKeyBytes, publicModulus.length, 9);
        System.arraycopy(publicExponent, 0, publicKeyBytes, publicModulus.length+9, publicExponent.length);

        byte[] numbersss = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31, 0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] publicKeyAndPrivateKeyBytes = new byte[publicKeyBytes.length+18+privateKeyBytes.length];
        System.arraycopy(publicKeyBytes, 0, publicKeyAndPrivateKeyBytes, 0, publicKeyBytes.length);
        System.arraycopy(numbersss, 0, publicKeyAndPrivateKeyBytes, publicKeyBytes.length, 18);
        System.arraycopy(privateKeyBytes, 0, publicKeyAndPrivateKeyBytes, publicKeyBytes.length+18, privateKeyBytes.length);

        return publicKeyAndPrivateKeyBytes;
    }

    @Override
    public byte[] solveFile(byte[] userOutputFile, String userInputDecryptKey) {
        String userOutputFileSplit = bytesToHex(userOutputFile);
        String[] parts = userOutputFileSplit.split("012345677654321031012345677654321031");
        byte[] inputBytesDecryptMessage = hexToBytes(parts[0]);

        String[] partss = userInputDecryptKey.split("012345677654321031");
        BigInteger modulus = new BigInteger(1, hexToBytes(partss[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(partss[1]));
        BigInteger p = new BigInteger(1, hexToBytes(partss[2]));
        BigInteger q = new BigInteger(1, hexToBytes(partss[3]));
        BigInteger dp = new BigInteger(1, hexToBytes(partss[4]));
        BigInteger dq = new BigInteger(1, hexToBytes(partss[5]));
        BigInteger qInv = new BigInteger(1, hexToBytes(partss[6]));
        RSAPrivateCrtKeyParameters privateKey = new RSAPrivateCrtKeyParameters(modulus, BigInteger.valueOf(65537), exponent, p, q, dp, dq, qInv);

        RSAEngine rsaEngine = new RSAEngine();
        OAEPEncoding rsaOaep = new OAEPEncoding(rsaEngine);
        rsaOaep.init(false, privateKey);
        byte[] decryptedMessageBytes;
        try {
            decryptedMessageBytes = rsaOaep.processBlock(inputBytesDecryptMessage, 0, inputBytesDecryptMessage.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        byte[] fileFormatBytes = hexToBytes(parts[1]);
        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] finalDecrypted = new byte[decryptedMessageBytes.length+9+fileFormatBytes.length];
        System.arraycopy(decryptedMessageBytes, 0, finalDecrypted, 0, decryptedMessageBytes.length);
        System.arraycopy(numbers, 0, finalDecrypted, decryptedMessageBytes.length, 9);
        System.arraycopy(fileFormatBytes, 0, finalDecrypted, decryptedMessageBytes.length+9, fileFormatBytes.length);

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
