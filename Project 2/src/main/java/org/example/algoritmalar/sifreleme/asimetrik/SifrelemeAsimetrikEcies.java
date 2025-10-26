package org.example.algoritmalar.sifreleme.asimetrik;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.example.algoritmalar.sifreleme.simetrik.SifrelemeSimetrikDes;

import javax.crypto.KeyGenerator;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class SifrelemeAsimetrikEcies extends SifrelemeAsimetrik {

    public static String startEciesMessage(String userInputEncryptMessage, String userInputEncryptKey, String userInputDecryptMessage, String userInputDecryptKey) {
        SifrelemeAsimetrikEcies worker = new SifrelemeAsimetrikEcies();
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

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
        ECDomainParameters domainParameters = new ECDomainParameters(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH(), ecSpec.getSeed());
        byte[] publicKeyBytes = hexToBytes(userInputEncryptKey);

        ECPoint Q = ecSpec.getCurve().decodePoint(publicKeyBytes);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(Q, domainParameters);
        IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new HMac(new SHA256Digest()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
        IESWithCipherParameters iesParams = new IESWithCipherParameters(null, null, 128, 128);

        ECNamedCurveParameterSpec specEphemeral = ECNamedCurveTable.getParameterSpec("secp521r1");
        ECKeyPairGenerator genEphemeral = new ECKeyPairGenerator();
        genEphemeral.init(new ECKeyGenerationParameters(new ECDomainParameters(specEphemeral.getCurve(), specEphemeral.getG(), specEphemeral.getN(), specEphemeral.getH()), new SecureRandom()));
        AsymmetricCipherKeyPair ephemeralKeyPair = genEphemeral.generateKeyPair();
        ECPrivateKeyParameters ephemeralPrivateKey = (ECPrivateKeyParameters) ephemeralKeyPair.getPrivate();
        ECPublicKeyParameters ephemeralPublicKey = (ECPublicKeyParameters) ephemeralKeyPair.getPublic();

        engine.init(true, ephemeralPrivateKey, publicKey, iesParams);
        byte[] encryptedBytes;
        try {
            encryptedBytes = engine.processBlock(inputBytesEncryptMessage, 0, inputBytesEncryptMessage.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        byte[] ephemeralPublicKeyBytes = ephemeralPublicKey.getQ().getEncoded(true);

        String hexEncryptedMessage = bytesToHex(ephemeralPublicKeyBytes) + ":" + bytesToHex(encryptedBytes);
        return "ECIES ile metin şifrelendi! " + hexEncryptedMessage;
    }

    @Override
    public String generateKeysMessage() {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp521r1");
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

        return "ECIES ile genel anahtar oluşturuldu! " + publicKeyHex + "\n" + "ECIES ile özel anahtar oluşturuldu! " + privateKeyHex;
    }

    @Override
    public String solveMessage(String userInputDecryptMessage, String userInputDecryptKey) {
        String[] parts = userInputDecryptMessage.split(":");
        byte[] inputBytesDecryptMessage = hexToBytes(parts[1]);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp521r1");
        ECDomainParameters domainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        byte[] privateKeyBytes = hexToBytes(userInputDecryptKey);
        BigInteger d = new BigInteger(1, privateKeyBytes);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParameters);
        IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new HMac(new SHA256Digest()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
        IESWithCipherParameters iesParams = new IESWithCipherParameters(null, null, 128, 128);

        byte[] ephemeralPublicKeyBytes = hexToBytes(parts[0]);
        ECPoint R = spec.getCurve().decodePoint(ephemeralPublicKeyBytes);
        ECPublicKeyParameters ephemeralPublicKey = new ECPublicKeyParameters(R, domainParameters);

        engine.init(false, privateKey, ephemeralPublicKey, iesParams);
        byte[] decryptedBytes;
        try {
            decryptedBytes = engine.processBlock(inputBytesDecryptMessage, 0, inputBytesDecryptMessage.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        String decryptedMessage;
        try {
            decryptedMessage = new String(decryptedBytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        return "Şifresi çözülmüş metin oluşturuldu! " + decryptedMessage;
    }



    public static byte[] startEciesFile(byte[] userInputFile, String userInputEncryptKey, byte[] userOutputFile, String userInputDecryptKey) {
        SifrelemeAsimetrikEcies worker = new SifrelemeAsimetrikEcies();

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

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
        ECDomainParameters domainParameters = new ECDomainParameters(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH(), ecSpec.getSeed());
        byte[] publicKeyBytes = hexToBytes(userInputEncryptKey);

        ECPoint Q = ecSpec.getCurve().decodePoint(publicKeyBytes);
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(Q, domainParameters);
        IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new HMac(new SHA256Digest()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
        IESWithCipherParameters iesParams = new IESWithCipherParameters(null, null, 128, 128);

        ECNamedCurveParameterSpec specEphemeral = ECNamedCurveTable.getParameterSpec("secp521r1");
        ECKeyPairGenerator genEphemeral = new ECKeyPairGenerator();
        genEphemeral.init(new ECKeyGenerationParameters(new ECDomainParameters(specEphemeral.getCurve(), specEphemeral.getG(), specEphemeral.getN(), specEphemeral.getH()), new SecureRandom()));
        AsymmetricCipherKeyPair ephemeralKeyPair = genEphemeral.generateKeyPair();
        ECPrivateKeyParameters ephemeralPrivateKey = (ECPrivateKeyParameters) ephemeralKeyPair.getPrivate();
        ECPublicKeyParameters ephemeralPublicKey = (ECPublicKeyParameters) ephemeralKeyPair.getPublic();

        engine.init(true, ephemeralPrivateKey, publicKey, iesParams);
        byte[] encryptedBytes;
        try {
            encryptedBytes = engine.processBlock(userInputFileBytes, 0, userInputFileBytes.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        byte[] ephemeralPublicKeyBytes = ephemeralPublicKey.getQ().getEncoded(true);

        byte[] numberss = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x31, 0x31, 0x31, 0x31};
        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] encryptedMessageFinalBytes = new byte[ephemeralPublicKeyBytes.length+18+encryptedBytes.length+9+userInputFileFormatBytes.length];
        System.arraycopy(ephemeralPublicKeyBytes, 0, encryptedMessageFinalBytes, 0, ephemeralPublicKeyBytes.length);
        System.arraycopy(numberss, 0, encryptedMessageFinalBytes, ephemeralPublicKeyBytes.length, 18);
        System.arraycopy(encryptedBytes, 0, encryptedMessageFinalBytes, ephemeralPublicKeyBytes.length+18, encryptedBytes.length);
        System.arraycopy(numbers, 0, encryptedMessageFinalBytes, ephemeralPublicKeyBytes.length+18+encryptedBytes.length, 9);
        System.arraycopy(userInputFileFormatBytes, 0, encryptedMessageFinalBytes, ephemeralPublicKeyBytes.length+18+encryptedBytes.length+9, userInputFileFormatBytes.length);

        return encryptedMessageFinalBytes;
    }


    @Override
    public byte[] generateKeysFile() {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp521r1");
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
        byte[] publicKeyAndPrivateKeyBytes = new byte[publicKeyBytes.length+18+privateKeyBytes.length];
        System.arraycopy(publicKeyBytes, 0, publicKeyAndPrivateKeyBytes, 0, publicKeyBytes.length);
        System.arraycopy(numbersss, 0, publicKeyAndPrivateKeyBytes, publicKeyBytes.length, 18);
        System.arraycopy(privateKeyBytes, 0, publicKeyAndPrivateKeyBytes, publicKeyBytes.length+18, privateKeyBytes.length);

        return publicKeyAndPrivateKeyBytes;
    }


    @Override
    public byte[] solveFile(byte[] userOutputFile, String userInputDecryptKey) {
        String[] parts = userInputDecryptKey.split(":");

        String userOutputFileSplit = bytesToHex(userOutputFile);
        String[] partss = userOutputFileSplit.split("112233445566777766554433221131313131");
        byte[] userOutputFileSplitBytes = hexToBytes(partss[1]);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp521r1");
        ECDomainParameters domainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        byte[] privateKeyBytes = hexToBytes(parts[0]);
        BigInteger d = new BigInteger(1, privateKeyBytes);
        ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, domainParameters);
        IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), new HMac(new SHA256Digest()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
        IESWithCipherParameters iesParams = new IESWithCipherParameters(null, null, 128, 128);

        byte[] ephemeralPublicKeyBytes = hexToBytes(partss[0]);
        ECPoint R = spec.getCurve().decodePoint(ephemeralPublicKeyBytes);
        ECPublicKeyParameters ephemeralPublicKey = new ECPublicKeyParameters(R, domainParameters);

        engine.init(false, privateKey, ephemeralPublicKey, iesParams);
        byte[] decryptedBytes;
        try {
            decryptedBytes = engine.processBlock(userOutputFileSplitBytes, 0, userOutputFileSplitBytes.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }

        byte[] fileFormatBytes = hexToBytes(parts[1]);
        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] finalDecrypted = new byte[decryptedBytes.length+9+fileFormatBytes.length];
        System.arraycopy(decryptedBytes, 0, finalDecrypted, 0, decryptedBytes.length);
        System.arraycopy(numbers, 0, finalDecrypted, decryptedBytes.length, 9);
        System.arraycopy(fileFormatBytes, 0, finalDecrypted, decryptedBytes.length+9, fileFormatBytes.length);

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