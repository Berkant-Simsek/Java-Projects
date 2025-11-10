package org.example.algoritmalar.imzalama;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.RSADigestSigner;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ImzalamaRsa extends Imzalama {

    public static String startRsaMessage(String userInputSignMessage, String userInputSignKey, String userInputValidateMessage, String userInputSignature, String userInputValidateKey) {
        ImzalamaRsa worker = new ImzalamaRsa();
        if (userInputSignMessage.equals("İlk") && userInputSignKey.equals("İlk") && userInputValidateMessage.equals("İlk") && userInputValidateKey.equals("İlk")) {
            return worker.giveInfo();
        }

        if ((userInputSignMessage.equals("") || userInputSignKey.equals("")) && !userInputValidateMessage.equals("") && !userInputSignature.equals("") && !userInputValidateKey.equals("")) {
            return "Giriş Yapılmadı.";
        }

        if (!userInputSignMessage.equals("") && !userInputSignKey.equals("") && (userInputValidateMessage.equals("") || userInputSignature.equals("") || userInputValidateKey.equals(""))) {
            return "Giriş Yapılmadı.";
        }

        if (userInputSignMessage.equals("Anahtar") && userInputSignKey.equals("Anahtar") && userInputValidateMessage.equals("Anahtar") && userInputSignature.equals("Anahtar") && userInputValidateKey.equals("Anahtar")) {
            return worker.generateKeysMessage();
        }

        if (userInputValidateMessage.equals("İmzala") && userInputSignature.equals("İmzala") && userInputValidateKey.equals("İmzala")) {
            return worker.getMessage(userInputSignMessage, userInputSignKey);
        } else {
            return worker.validateMessage(userInputValidateMessage, userInputSignature, userInputValidateKey);
        }
    }

    @Override
    public String getMessage(String userInputSignMessage, String userInputSignKey) {
        byte[] inputBytesSignMessage;
        try {
            inputBytesSignMessage = userInputSignMessage.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(inputBytesSignMessage, 0, inputBytesSignMessage.length);
        byte[] sha256Bytes = new byte[32];
        sha256.doFinal(sha256Bytes, 0);

        String[] parts = userInputSignKey.split(":");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        BigInteger p = new BigInteger(1, hexToBytes(parts[2]));
        BigInteger q = new BigInteger(1, hexToBytes(parts[3]));
        BigInteger dp = new BigInteger(1, hexToBytes(parts[4]));
        BigInteger dq = new BigInteger(1, hexToBytes(parts[5]));
        BigInteger qInv = new BigInteger(1, hexToBytes(parts[6]));
        RSAPrivateCrtKeyParameters privateKey = new RSAPrivateCrtKeyParameters(modulus, BigInteger.valueOf(65537), exponent, p, q, dp, dq, qInv);

        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, privateKey);
        signer.update(sha256Bytes, 0, sha256Bytes.length);
        byte[] signatureBytes;
        try {
            signatureBytes = signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String hexSignature = bytesToHex(signatureBytes);
        return "RSA ile metin imzalandı! " + hexSignature;
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

        RSAPrivateCrtKeyParameters publicKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
        byte[] publicModulus = publicKey.getModulus().toByteArray();
        byte[] publicExponent = publicKey.getPublicExponent().toByteArray();
        String publicKeyHex = bytesToHex(publicModulus) + ":" + bytesToHex(publicExponent);

        return "RSA ile özel anahtar oluşturuldu! " + privateKeyHex + "\n" + "RSA ile genel anahtar oluşturuldu! " + publicKeyHex;
    }

    @Override
    public String validateMessage(String userInputValidateMessage, String userInputSignature, String userInputValidateKey) {
        byte[] inputBytesValidateMessage;
        try {
            inputBytesValidateMessage = userInputValidateMessage.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        SHA256Digest sha256Match = new SHA256Digest();
        sha256Match.update(inputBytesValidateMessage, 0, inputBytesValidateMessage.length);
        byte[] sha256MatchBytes = new byte[32];
        sha256Match.doFinal(sha256MatchBytes, 0);

        String[] parts = userInputValidateKey.split(":");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        RSAKeyParameters publicKey = new RSAKeyParameters(false, modulus, exponent);

        byte[] inputBytesSignature = hexToBytes(userInputSignature);
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(false, publicKey);
        signer.update(sha256MatchBytes, 0, sha256MatchBytes.length);

        boolean verified = signer.verifySignature(inputBytesSignature);

        if (verified) {
            return "Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)";
        } else {
            return "Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)";
        }
    }






    public static byte[] startRsaFile(byte[] userInputFile, String userInputSignKey, byte[] userOutputFile, byte[] userInputSignature, String userInputValidateKey) {
        ImzalamaRsa worker = new ImzalamaRsa();

        if (userInputFile == null && userInputSignKey.equals("") && !(userOutputFile == null) && !(userInputSignature == null) && !userInputValidateKey.equals("")) {
            return null;
        }

        if (!(userInputFile == null) && !userInputSignKey.equals("") && userOutputFile == null && userInputSignature == null && userInputValidateKey.equals("")) {
            return null;
        }

        if (userInputFile == null && userInputSignKey.equals("Anahtar") && userOutputFile == null && userInputSignature == null && userInputValidateKey.equals("Anahtar")) {
            return worker.generateKeysFile();
        }

        if (userOutputFile == null && userInputSignature == null && userInputValidateKey.equals("İmzala")) {
            return worker.getFile(userInputFile, userInputSignKey);
        } else {
            return worker.validateFile(userOutputFile, userInputSignature, userInputValidateKey);
        }
    }

    @Override
    public byte[] getFile(byte[] userInputFile, String userInputSignKey) {
        String separate = bytesToHex(userInputFile);
        String[] partss = separate.split("012345677654321031");
        byte[] userInputFileBytes = hexToBytes(partss[0]);
        byte[] userInputFileFormatBytes = hexToBytes(partss[1]);

        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(userInputFileBytes, 0, userInputFileBytes.length);
        byte[] sha256Bytes = new byte[32];
        sha256.doFinal(sha256Bytes, 0);

        String[] parts = userInputSignKey.split("012345677654321031");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        BigInteger p = new BigInteger(1, hexToBytes(parts[2]));
        BigInteger q = new BigInteger(1, hexToBytes(parts[3]));
        BigInteger dp = new BigInteger(1, hexToBytes(parts[4]));
        BigInteger dq = new BigInteger(1, hexToBytes(parts[5]));
        BigInteger qInv = new BigInteger(1, hexToBytes(parts[6]));
        RSAPrivateCrtKeyParameters privateKey = new RSAPrivateCrtKeyParameters(modulus, BigInteger.valueOf(65537), exponent, p, q, dp, dq, qInv);

        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, privateKey);
        signer.update(sha256Bytes, 0, sha256Bytes.length);
        byte[] signatureBytes;
        try {
            signatureBytes = signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] signedMessageFinalBytes = new byte[signatureBytes.length+9+userInputFileFormatBytes.length];
        System.arraycopy(signatureBytes, 0, signedMessageFinalBytes, 0, signatureBytes.length);
        System.arraycopy(numbers, 0, signedMessageFinalBytes, signatureBytes.length, 9);
        System.arraycopy(userInputFileFormatBytes, 0, signedMessageFinalBytes, signatureBytes.length+9, userInputFileFormatBytes.length);

        return signedMessageFinalBytes;
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
        byte[] privateKeyAndPublicKeyBytes = new byte[privateKeyBytes.length+18+publicKeyBytes.length];
        System.arraycopy(privateKeyBytes, 0, privateKeyAndPublicKeyBytes, 0, privateKeyBytes.length);
        System.arraycopy(numbersss, 0, privateKeyAndPublicKeyBytes, privateKeyBytes.length, 18);
        System.arraycopy(publicKeyBytes, 0, privateKeyAndPublicKeyBytes, privateKeyBytes.length+18, publicKeyBytes.length);

        return privateKeyAndPublicKeyBytes;
    }

    @Override
    public byte[] validateFile(byte[] userOutputFile, byte[] userInputSignature, String userInputValidateKey) {
        String separate = bytesToHex(userOutputFile);
        String[] fileAndFormat = separate.split("012345677654321031");
        byte[] userInputFileBytes = hexToBytes(fileAndFormat[0]);

        SHA256Digest sha256Match = new SHA256Digest();
        sha256Match.update(userInputFileBytes, 0, userInputFileBytes.length);
        byte[] sha256MatchBytes = new byte[32];
        sha256Match.doFinal(sha256MatchBytes, 0);

        String[] parts = userInputValidateKey.split("012345677654321031");
        BigInteger modulus = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger exponent = new BigInteger(1, hexToBytes(parts[1]));
        RSAKeyParameters publicKey = new RSAKeyParameters(false, modulus, exponent);

        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(false, publicKey);
        signer.update(sha256MatchBytes, 0, sha256MatchBytes.length);

        String separateSignature = bytesToHex(userInputSignature);
        String[] separeteSignatureAndFileFormat = separateSignature.split("012345677654321031012345677654321031");
        byte[] separeteSignatureBytes = hexToBytes(separeteSignatureAndFileFormat[0]);
        boolean verified = signer.verifySignature(separeteSignatureBytes);

        if (verified && fileAndFormat[1].equals(separeteSignatureAndFileFormat[1])) {
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
