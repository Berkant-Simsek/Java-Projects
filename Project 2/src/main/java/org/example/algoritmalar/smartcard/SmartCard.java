package org.example.algoritmalar.smartcard;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.smartcardio.*;
import java.security.PublicKey;
import java.security.Security;
import java.util.*;

import static org.example.gui.Main.pin;

public class SmartCard{

    public static byte[] signFile(byte[] userInputFile, Card card) throws Exception {
        String separate = bytesToHex(userInputFile);
        String[] partss = separate.split("012345677654321031");
        byte[] userInputFileBytes = hexToBytes(partss[0]);
        byte[] userInputFileFormatBytes = hexToBytes(partss[1]);

        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(userInputFileBytes, 0, userInputFileBytes.length);
        byte[] sha256Bytes = new byte[32];
        sha256.doFinal(sha256Bytes, 0);

        CardChannel channel = card.getBasicChannel();

        byte[] selectApduPin = new byte[] {0x00, (byte) 0xA4, 0x00, 0x00, 0x02, 0x3D, 0x00, 0x00};
        channel.transmit(new CommandAPDU(selectApduPin));

        byte[] pinBytes = new byte[pin.length()];
        for (int i = 0; i < pin.length(); i++) {
            pinBytes[i] = (byte) pin.charAt(i);
        }
        byte[] verifyCommand = new byte[11];
        byte[] staticHeader = {0x00, 0x20, 0x00, 0x01, 0x06};
        System.arraycopy(staticHeader, 0, verifyCommand, 0, staticHeader.length);
        System.arraycopy(pinBytes, 0, verifyCommand, staticHeader.length, pinBytes.length);
        channel.transmit(new CommandAPDU(verifyCommand));

        byte[] selectApduSign = new byte[] {(byte) 0x00, (byte) 0x22, (byte) 0x41, (byte) 0xB6, (byte) 0x06, (byte) 0x80, (byte) 0x01, (byte) 0x91, (byte) 0x84, (byte) 0x01, (byte) 0x81};
        channel.transmit(new CommandAPDU(selectApduSign));

        byte[] psoCommand = new byte[] {(byte) 0x00, (byte) 0x2A, (byte) 0x9E, (byte) 0x9A, (byte) 0x20};
        byte[] psoCommandNext =new byte[] {(byte) 0x00};
        byte[] finalCommand = new byte[psoCommand.length+ sha256Bytes.length+psoCommandNext.length];
        System.arraycopy(psoCommand, 0, finalCommand, 0, psoCommand.length);
        System.arraycopy(sha256Bytes, 0, finalCommand, psoCommand.length, sha256Bytes.length);
        System.arraycopy(psoCommandNext, 0, finalCommand, psoCommand.length+ sha256Bytes.length, psoCommandNext.length);
        ResponseAPDU response = channel.transmit(new CommandAPDU(finalCommand));
        byte[] signedHashBytes = response.getData();

        byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] signedMessageFinalBytes = new byte[signedHashBytes.length+9+userInputFileFormatBytes.length];
        System.arraycopy(signedHashBytes, 0, signedMessageFinalBytes, 0, signedHashBytes.length);
        System.arraycopy(numbers, 0, signedMessageFinalBytes, signedHashBytes.length, 9);
        System.arraycopy(userInputFileFormatBytes, 0, signedMessageFinalBytes, signedHashBytes.length+9, userInputFileFormatBytes.length);

        //System.out.println("SHA256 Input Data  : "+HexFormat.of().formatHex(sha256Bytes));
        //System.out.println("Hex Signature Data : "+HexFormat.of().formatHex(signedHashBytes));

        return signedMessageFinalBytes;
    }

    public static byte[] validateFile(byte[] userOutputFile, byte[] userInputSignature, PublicKey publicKeyValue) {
        Security.addProvider(new BouncyCastleProvider());

        String separate1 = bytesToHex(userOutputFile);
        String[] fileAndFormat = separate1.split("012345677654321031");
        byte[] userInputFileBytes = hexToBytes(fileAndFormat[0]);


//        SHA256Digest sha256Match = new SHA256Digest();
//        sha256Match.update(userInputFileBytes, 0, userInputFileBytes.length);
//        byte[] sha256MatchBytes = new byte[32];
//        sha256Match.doFinal(sha256MatchBytes, 0);


        String separate2 = bytesToHex(userInputSignature);
        String[] signatureAndFormat = separate2.split("012345677654321031");
        byte[] userInputSignatureBytes = hexToBytes(signatureAndFormat[0]);


//        RSAKeyParameters publicKey = new RSAKeyParameters(false, modulus, exponent);
//        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
//        signer.init(false, publicKey);
//        signer.update(sha256MatchBytes, 0, sha256MatchBytes.length);
//        boolean verified = signer.verifySignature(userInputSignatureBytes);
//
//        System.out.println("SHA uzunluk: " + sha256MatchBytes.length);
//        System.out.println("İmza uzunluk: " + userInputSignatureBytes.length);


//        PSSSigner pssVerifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
//        pssVerifier.init(false, publicKey);
//        pssVerifier.update(sha256MatchBytes, 0, sha256MatchBytes.length);
//        boolean verified = pssVerifier.verifySignature(userInputSignatureBytes);


//        for (Provider provider : Security.getProviders()) {
//            System.out.println("Provider: " + provider.getName());
//            for (Provider.Service service : provider.getServices()) {
//                if ("Signature".equals(service.getType())) {
//                    System.out.println("  " + service.getAlgorithm());
//                }
//            }
//        }


//        ASN1InputStream asn1Input = new ASN1InputStream(userInputSignatureBytes);
//        try {
//            ASN1Primitive obj = asn1Input.readObject();
//            System.out.println("İmza ASN.1 yapısı: " + obj);
//        } catch (Exception e) {
//            System.out.println("İmza ham PSS, ASN.1 değil: " + e.getMessage());
//        } finally {
//            asn1Input.close();
//        }


//        Signature sign = Signature.getInstance("SHA256withRSAandMGF1", "BC");
//        PSSParameterSpec param = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
//        sign.setParameter(param);
//        sign.initVerify(publicKeyValue);
//        sign.update(sha256MatchBytes, 0, sha256MatchBytes.length);
//        boolean verified = sign.verify(userInputSignatureBytes);


//        String[] algorithms = Security.getAlgorithms("Signature").toArray(new String[0]);
//        System.out.println("Desteklenen Signature Algoritmaları:");
//        for (String algorithm : algorithms) {
//            System.out.println(algorithm);
//        }
//
//        X509Certificate cert = getCertificateFromCard(card);
//        PublicKey publicKey = cert.getPublicKey();
//        byte[] originalData = sha256MatchBytes;
//        byte[] signedData = userInputSignatureBytes;
//        PSSParameterSpec pssSpec = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
//        Signature signature = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
//        signature.setParameter(pssSpec);
//        signature.initVerify(publicKey);
//        signature.update(originalData);
//        boolean verified = signature.verify(signedData);


        BCRSAPublicKey publicKey = (BCRSAPublicKey) publicKeyValue;
        RSAKeyParameters publicKeyParams = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent());
        SHA256Digest sha256 = new SHA256Digest();
        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), sha256, sha256.getDigestSize(), PSSSigner.TRAILER_IMPLICIT);
        signer.init(false, publicKeyParams);
        signer.update(userInputFileBytes, 0, userInputFileBytes.length);
        boolean verified = signer.verifySignature(userInputSignatureBytes);


        //System.out.println(separate2);
        //System.out.println(signatureAndFormat[0]);
        //System.out.println("Hex Signature Data : "+HexFormat.of().formatHex(userInputSignatureBytes));
        //System.out.println("SHA256 Output Data : "+HexFormat.of().formatHex(sha256MatchBytes));

        //System.out.println(verified);
        //System.out.println(fileAndFormat[1].equals(signatureAndFormat[1]));


        if (verified && fileAndFormat[1].equals(signatureAndFormat[1])) {
            return new byte[] {0x31};
        } else {
            return new byte[] {0x31, 0x31};
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
