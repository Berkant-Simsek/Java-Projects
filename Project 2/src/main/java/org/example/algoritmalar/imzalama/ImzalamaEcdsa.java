package org.example.algoritmalar.imzalama;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ImzalamaEcdsa extends Imzalama {

    public static String startEcdsaMessage(String userInputSignMessage, String userInputSignKey, String userInputValidateMessage, String userInputSignature, String userInputValidateKey) {
        ImzalamaEcdsa worker = new ImzalamaEcdsa();
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

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters domainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        byte[] inputBytesSignKey = hexToBytes(userInputSignKey);
        BigInteger d = new BigInteger(1, inputBytesSignKey);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParameters);

        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privateKey);
        BigInteger[] signature = signer.generateSignature(sha256Bytes);

        BigInteger r = signature[0];
        BigInteger s = signature[1];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        String hexSignature = bytesToHex(rBytes) + ":" + bytesToHex(sBytes);

        return "ECDSA ile metin imzalandı! " + hexSignature;
    }

    @Override
    public String generateKeysMessage() {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH()), new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        BigInteger privateKeyD = privateKey.getD();
        byte[] privateKeyBytes = privateKeyD.toByteArray();
        String privateKeyHex = bytesToHex(privateKeyBytes);

        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        ECPoint publicKeyQ = publicKey.getQ();
        byte[] publicKeyBytes = publicKeyQ.getEncoded(true);
        String publicKeyHex = bytesToHex(publicKeyBytes);

        return "ECDSA ile özel anahtar oluşturuldu! " + privateKeyHex + "\n" + "ECDSA ile genel anahtar oluşturuldu! " + publicKeyHex;
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

        String[] parts = userInputSignature.split(":");
        BigInteger r = new BigInteger(1, hexToBytes(parts[0]));
        BigInteger s = new BigInteger(1, hexToBytes(parts[1]));

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters domainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        byte[] publicKeyBytes = hexToBytes(userInputValidateKey);
        ECPoint Q = spec.getCurve().decodePoint(publicKeyBytes);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(Q, domainParameters);

        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKey);
        boolean verified = signer.verifySignature(sha256MatchBytes, r, s);


        if (verified) {
            return "Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)";
        } else {
            return "Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)";
        }
    }



    public static byte[] startEcdsaFile(byte[] userInputFile, String userInputSignKey, byte[] userOutputFile, byte[] userInputSignature, String userInputValidateKey) {
        ImzalamaEcdsa worker = new ImzalamaEcdsa();

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

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters domainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        byte[] inputBytesSignKey = hexToBytes(userInputSignKey);
        BigInteger d = new BigInteger(1, inputBytesSignKey);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParameters);

        ECDSASigner signer = new ECDSASigner();
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
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH()), new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        BigInteger privateKeyD = privateKey.getD();
        byte[] privateKeyBytes = privateKeyD.toByteArray();

        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        ECPoint publicKeyQ = publicKey.getQ();
        byte[] publicKeyBytes = publicKeyQ.getEncoded(true);

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

        String[] publicKeyAndFormat = userInputValidateKey.split(":");

        String separateSignature = bytesToHex(userInputSignature);
        String[] rAndS = separateSignature.split("112233445566777766554433221131313131");
        BigInteger r = new BigInteger(1, hexToBytes(rAndS[0]));
        BigInteger s = new BigInteger(1, hexToBytes(rAndS[1]));

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECDomainParameters domainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        byte[] publicKeyBytes = hexToBytes(publicKeyAndFormat[0]);
        ECPoint Q = spec.getCurve().decodePoint(publicKeyBytes);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(Q, domainParameters);

        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKey);
        boolean verified = signer.verifySignature(sha256MatchBytes, r, s);

        if (verified && fileAndFormat[1].equals(publicKeyAndFormat[1])) {
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
