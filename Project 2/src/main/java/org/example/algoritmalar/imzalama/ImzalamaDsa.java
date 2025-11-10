package org.example.algoritmalar.imzalama;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ImzalamaDsa extends Imzalama {

    public static String startDsaMessage(String userInputSignMessage, String userInputSignKey, String userInputValidateMessage, String userInputSignature, String userInputValidateKey) {
        ImzalamaDsa worker = new ImzalamaDsa();
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
        BigInteger privateKeyP = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger privateKeyQ = new BigInteger(1, hexToBytes(parts[1]));
        BigInteger privateKeyG = new BigInteger(1, hexToBytes(parts[2]));
        BigInteger privateXBytes = new BigInteger(1, hexToBytes(parts[3]));
        DSAParameters dsaParams = new DSAParameters(privateKeyP, privateKeyQ, privateKeyG);
        DSAPrivateKeyParameters privateKey = new DSAPrivateKeyParameters(privateXBytes, dsaParams);

        DSASigner signer = new DSASigner();
        signer.init(true, privateKey);
        BigInteger[] signature = signer.generateSignature(sha256Bytes);

        BigInteger r = signature[0];
        BigInteger s = signature[1];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        String hexSignature = bytesToHex(rBytes) + ":" + bytesToHex(sBytes);

        return "DSA ile metin imzalandı! " + hexSignature;
    }

    @Override
    public String generateKeysMessage() {
        DSAParametersGenerator paramGen = new DSAParametersGenerator();
        paramGen.init(2048, 256, new SecureRandom());
        DSAParameters dsaParams = paramGen.generateParameters();

        DSAKeyGenerationParameters keyParam = new DSAKeyGenerationParameters(new SecureRandom(), dsaParams);

        DSAKeyPairGenerator keyGen = new DSAKeyPairGenerator();
        keyGen.init(keyParam);
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

        DSAPrivateKeyParameters privateKey = (DSAPrivateKeyParameters) keyPair.getPrivate();
        BigInteger privateX = privateKey.getX();
        byte[] privateKeyP = dsaParams.getP().toByteArray();
        byte[] privateKeyQ = dsaParams.getQ().toByteArray();
        byte[] privateKeyG = dsaParams.getG().toByteArray();
        byte[] privateXBytes = privateX.toByteArray();
        String privateKeyHex = bytesToHex(privateKeyP) + ":" + bytesToHex(privateKeyQ) + ":";
        privateKeyHex = privateKeyHex + bytesToHex(privateKeyG) + ":"+ bytesToHex(privateXBytes);

        DSAPublicKeyParameters publicKey = (DSAPublicKeyParameters) keyPair.getPublic();
        BigInteger publicY = publicKey.getY();
        byte[] publicKeyP = dsaParams.getP().toByteArray();
        byte[] publicKeyQ = dsaParams.getQ().toByteArray();
        byte[] publicKeyG = dsaParams.getG().toByteArray();
        byte[] publicYBytes = publicY.toByteArray();
        String publicKeyHex = bytesToHex(publicKeyP) + ":" + bytesToHex(publicKeyQ) + ":";
        publicKeyHex = publicKeyHex + bytesToHex(publicKeyG) + ":"+ bytesToHex(publicYBytes);

        return "DSA ile özel anahtar oluşturuldu! " + privateKeyHex + "\n" + "DSA ile genel anahtar oluşturuldu! " + publicKeyHex;
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

        String[] partsSignature = userInputSignature.split(":");
        BigInteger r = new BigInteger(1, hexToBytes(partsSignature[0]));
        BigInteger s = new BigInteger(1, hexToBytes(partsSignature[1]));

        String[] partsKey = userInputValidateKey.split(":");
        BigInteger publicKeyP = new BigInteger(1, hexToBytes(partsKey[0]));
        BigInteger publicKeyQ = new BigInteger(1, hexToBytes(partsKey[1]));
        BigInteger publicKeyG = new BigInteger(1, hexToBytes(partsKey[2]));
        BigInteger publicYBytes = new BigInteger(1, hexToBytes(partsKey[3]));
        DSAParameters dsaParams = new DSAParameters(publicKeyP, publicKeyQ, publicKeyG);
        DSAPublicKeyParameters publicKey = new DSAPublicKeyParameters(publicYBytes, dsaParams);

        DSASigner signer = new DSASigner();
        signer.init(false, publicKey);
        boolean verified = signer.verifySignature(sha256MatchBytes, r, s);


        if (verified) {
            return "Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)";
        } else {
            return "Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)";
        }
    }



    public static byte[] startDsaFile(byte[] userInputFile, String userInputSignKey, byte[] userOutputFile, byte[] userInputSignature, String userInputValidateKey) {
        ImzalamaDsa worker = new ImzalamaDsa();

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
        BigInteger privateKeyP = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger privateKeyQ = new BigInteger(1, hexToBytes(parts[1]));
        BigInteger privateKeyG = new BigInteger(1, hexToBytes(parts[2]));
        BigInteger privateXBytes = new BigInteger(1, hexToBytes(parts[3]));
        DSAParameters dsaParams = new DSAParameters(privateKeyP, privateKeyQ, privateKeyG);
        DSAPrivateKeyParameters privateKey = new DSAPrivateKeyParameters(privateXBytes, dsaParams);

        DSASigner signer = new DSASigner();
        signer.init(true, privateKey);
        BigInteger[] signature = signer.generateSignature(sha256Bytes);

        BigInteger r = signature[0];
        BigInteger s = signature[1];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        byte[] numberss = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x31, 0x31, 0x31, 0x31};
        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] signedMessageFinalBytes = new byte[rBytes.length+18+sBytes.length+9+userInputFileFormatBytes.length];
        System.arraycopy(rBytes, 0, signedMessageFinalBytes, 0, rBytes.length);
        System.arraycopy(numberss, 0, signedMessageFinalBytes, rBytes.length, 18);
        System.arraycopy(sBytes, 0, signedMessageFinalBytes, rBytes.length+18, sBytes.length);
        System.arraycopy(numbers, 0, signedMessageFinalBytes, rBytes.length+18+sBytes.length, 9);
        System.arraycopy(userInputFileFormatBytes, 0, signedMessageFinalBytes, rBytes.length+18+sBytes.length+9, userInputFileFormatBytes.length);

        return signedMessageFinalBytes;
    }

    @Override
    public byte[] generateKeysFile() {
        DSAParametersGenerator paramGen = new DSAParametersGenerator();
        paramGen.init(2048, 256, new SecureRandom());
        DSAParameters dsaParams = paramGen.generateParameters();

        DSAKeyGenerationParameters keyParam = new DSAKeyGenerationParameters(new SecureRandom(), dsaParams);

        DSAKeyPairGenerator keyGen = new DSAKeyPairGenerator();
        keyGen.init(keyParam);
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

        DSAPrivateKeyParameters privateKey = (DSAPrivateKeyParameters) keyPair.getPrivate();
        BigInteger privateX = privateKey.getX();
        byte[] privateKeyP = dsaParams.getP().toByteArray();
        byte[] privateKeyQ = dsaParams.getQ().toByteArray();
        byte[] privateKeyG = dsaParams.getG().toByteArray();
        byte[] privateXBytes = privateX.toByteArray();
        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] privateKeyBytes = new byte[privateKeyP.length+9+privateKeyQ.length+9+privateKeyG.length+9+privateXBytes.length];
        System.arraycopy(privateKeyP, 0, privateKeyBytes, 0, privateKeyP.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateKeyP.length, 9);
        System.arraycopy(privateKeyQ, 0, privateKeyBytes, privateKeyP.length+9, privateKeyQ.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateKeyP.length+9+privateKeyQ.length, 9);
        System.arraycopy(privateKeyG, 0, privateKeyBytes, privateKeyP.length+9+privateKeyQ.length+9, privateKeyG.length);
        System.arraycopy(numbers, 0, privateKeyBytes, privateKeyP.length+9+privateKeyQ.length+9+privateKeyG.length, 9);
        System.arraycopy(privateXBytes, 0, privateKeyBytes, privateKeyP.length+9+privateKeyQ.length+9+privateKeyG.length+9, privateXBytes.length);

        DSAPublicKeyParameters publicKey = (DSAPublicKeyParameters) keyPair.getPublic();
        BigInteger publicY = publicKey.getY();
        byte[] publicKeyP = dsaParams.getP().toByteArray();
        byte[] publicKeyQ = dsaParams.getQ().toByteArray();
        byte[] publicKeyG = dsaParams.getG().toByteArray();
        byte[] publicYBytes = publicY.toByteArray();
        byte[] numberss = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] publicKeyBytes = new byte[publicKeyP.length+9+publicKeyQ.length+9+publicKeyG.length+9+publicYBytes.length];
        System.arraycopy(publicKeyP, 0, publicKeyBytes, 0, publicKeyP.length);
        System.arraycopy(numberss, 0, publicKeyBytes, publicKeyP.length, 9);
        System.arraycopy(publicKeyQ, 0, publicKeyBytes, publicKeyP.length+9, publicKeyQ.length);
        System.arraycopy(numberss, 0, publicKeyBytes, publicKeyP.length+9+publicKeyQ.length, 9);
        System.arraycopy(publicKeyG, 0, publicKeyBytes, publicKeyP.length+9+publicKeyQ.length+9, publicKeyG.length);
        System.arraycopy(numberss, 0, publicKeyBytes, publicKeyP.length+9+publicKeyQ.length+9+publicKeyG.length, 9);
        System.arraycopy(publicYBytes, 0, publicKeyBytes, publicKeyP.length+9+publicKeyQ.length+9+publicKeyG.length+9, publicYBytes.length);

        byte[] numbersss = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31, 0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] privateKeyAndPublicKeyBytes = new byte[privateKeyBytes.length+18+publicKeyBytes.length];
        System.arraycopy(privateKeyBytes, 0, privateKeyAndPublicKeyBytes, 0, privateKeyBytes.length);
        System.arraycopy(numbersss, 0, privateKeyAndPublicKeyBytes, privateKeyBytes.length, 18);
        System.arraycopy(publicKeyBytes, 0, privateKeyAndPublicKeyBytes, privateKeyBytes.length+18, publicKeyBytes.length);

        return privateKeyAndPublicKeyBytes;
    }

    @Override
    public byte[] validateFile(byte[] userOutputFile, byte[] userInputSignature, String userInputValidateKey) {
        String separateFile = bytesToHex(userOutputFile);
        String[] fileAndFormat = separateFile.split("012345677654321031");
        byte[] userInputFileBytes = hexToBytes(fileAndFormat[0]);

        SHA256Digest sha256Match = new SHA256Digest();
        sha256Match.update(userInputFileBytes, 0, userInputFileBytes.length);
        byte[] sha256MatchBytes = new byte[32];
        sha256Match.doFinal(sha256MatchBytes, 0);

        String[] parts = userInputValidateKey.split("012345677654321031");
        BigInteger publicKeyP = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger publicKeyQ = new BigInteger(1, hexToBytes(parts[1]));
        BigInteger publicKeyG = new BigInteger(1, hexToBytes(parts[2]));
        BigInteger publicYBytes = new BigInteger(1, hexToBytes(parts[3]));
        DSAParameters dsaParams = new DSAParameters(publicKeyP, publicKeyQ, publicKeyG);
        DSAPublicKeyParameters publicKey = new DSAPublicKeyParameters(publicYBytes, dsaParams);

        String separateSignature = bytesToHex(userInputSignature);
        String[] separeteSignatureAndFileFormat = separateSignature.split("012345677654321031012345677654321031");
        String[] rAndS = separeteSignatureAndFileFormat[0].split("112233445566777766554433221131313131");
        BigInteger r = new BigInteger(1, hexToBytes(rAndS[0]));
        BigInteger s = new BigInteger(1, hexToBytes(rAndS[1]));

        DSASigner signer = new DSASigner();
        signer.init(false, publicKey);
        boolean verified = signer.verifySignature(sha256MatchBytes, r, s);

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
