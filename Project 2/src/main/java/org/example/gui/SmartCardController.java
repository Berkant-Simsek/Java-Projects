package org.example.gui;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.algoritmalar.smartcard.SmartCard;

import javax.smartcardio.*;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

public class SmartCardController implements Initializable {

    private String algoritma;
    public VBox mainMenu;
    public Stage stage;

    public Card card;
    public LinkedHashMap<String, String> certificationInfo;

    public CheckBox[] checkboxes;

    public static byte[] atrBytes;

    public X509Certificate cert;
    public static String serialNumber;
    public static String version;
    public static String subject;
    public static String validFrom;
    public static String validTo;
    public static String issuer;
    public static String signatureAlgorithm;
    public static String publicKeyAlgorithm;
    public static PublicKey publicKeyValue;
    public static List<String> keyUsage;
    public static List<String> extendedKeyUsage;
    public static String sdoHash;
    public static String documentNo;
    public static String basicConstraints;
    public static String authorityKeyIdentifier;
    public static String subjectKeyIdentifier;
    public static List<String> crlDistributionPoint;
    public static List<String> authorityInformationAccess;
    public static List<String> certificatePolicy;

    public byte[] signContentBytes;
    public byte[] signFileInfoBytes;
    public byte[] validateContentBytes;

    public File selectedFileSmartCardSign;
    public String selectedFileSmartCardSignName;
    public File selectedFileSmartCardValidate;
    public String selectedFileSmartCardValidateName;
    public File selectedFileSmartCardSigned;
    public String selectedFileSmartCardSignedName;

    // Bilgilendirme Tab
    @FXML
    private TextArea smartCardExplanation;
    @FXML
    private Button processMenuForSmartCardButtonBack;

    // Kart Bağlama Tab
    @FXML
    private Label connectMessageExplanation;
    @FXML
    private Button processMenuForSmartCardButtonConnectCard;

    // Sertifika Okuma Tab
    @FXML
    private CheckBox serialNumberCheck;
    @FXML
    private CheckBox versionCheck;
    @FXML
    private CheckBox subjectCheck;
    @FXML
    private CheckBox validFromCheck;
    @FXML
    private CheckBox validToCheck;
    @FXML
    private CheckBox issuerCheck;
    @FXML
    private CheckBox signatureAlgorithmCheck;
    @FXML
    private CheckBox publicKeyAlgorithmCheck;
    @FXML
    private CheckBox publicKeyValueCheck;
    @FXML
    private CheckBox keyUsageCheck;
    @FXML
    private CheckBox extendedKeyUsageCheck;
    @FXML
    private CheckBox sdoHashCheck;
    @FXML
    private CheckBox documentNoCheck;
    @FXML
    private CheckBox basicConstraintsCheck;
    @FXML
    private CheckBox authorityKeyIdentifierCheck;
    @FXML
    private CheckBox subjectKeyIdentifierCheck;
    @FXML
    private CheckBox crlDistributionPointCheck;
    @FXML
    private CheckBox authorityInformationAccessCheck;
    @FXML
    private CheckBox certificatePolicyCheck;
    @FXML
    private Label pdfMessageExplanation;
    @FXML
    private Button savePdfFileButtonForSmartCard;
    @FXML
    private Button savePdfFileButtonForSmartCardActivate;
    @FXML
    private Button processMenuForSmartCardButtonReadCertificate;
    @FXML
    private Label readMessageExplanation;

    // Kart ile Dosya İmzalama Tab
    @FXML
    private Label signMessageExplanation;
    @FXML
    private TextArea signFileMessageForSmartCard;
    @FXML
    private Button processMenuForSmartCardButtonFileSignEnterActivate;
    @FXML
    private Button processMenuForSmartCardButtonFileSignEnter;
    @FXML
    private Button processMenuForSmartCardButtonFileSign;
    @FXML
    private Label signInfoLabel;
    @FXML
    private Button processMenuForSmartCardButtonFileSignActivate;
    @FXML
    private Button saveSignedFileButtonForSmartCard;

    // Kart ile Dosya Doğrulama Tab
    @FXML
    private Label validateMessageExplanation;
    @FXML
    private TextArea validateFileMessageForSmartCard;
    @FXML
    private Button processMenuForSmartCardButtonFileValidateEnter;
    @FXML
    private Button processMenuForSmartCardButtonFileValidateEnterActivate;
    @FXML
    private Button processMenuForSmartCardButtonFileValidate;
    @FXML
    private Button processMenuForSmartCardButtonFileValidateActivate;
    @FXML
    private TextArea validateFileSignatureForSmartCard;
    @FXML
    private Label validateSignatureExplanation;
    @FXML
    private Button processMenuForSmartCardButtonFileSignedEnter;
    @FXML
    private Button processMenuForSmartCardButtonFileSignedEnterActivate;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        checkboxes = new CheckBox[] {
                serialNumberCheck, versionCheck, subjectCheck, validFromCheck, validToCheck,
                issuerCheck, signatureAlgorithmCheck, publicKeyAlgorithmCheck, publicKeyValueCheck,
                keyUsageCheck, extendedKeyUsageCheck, sdoHashCheck, documentNoCheck, basicConstraintsCheck,
                authorityKeyIdentifierCheck, subjectKeyIdentifierCheck, crlDistributionPointCheck,
                authorityInformationAccessCheck, certificatePolicyCheck
        };

        processMenuForSmartCardButtonBack.setDisable(false);
        processMenuForSmartCardButtonConnectCard.setDisable(false);
        if (checkboxes != null) {
            for (CheckBox checkbox : checkboxes) {
                if (checkbox != null) {
                    checkbox.setSelected(false);
                    checkbox.setDisable(false);
                } else {
                    System.out.print("");
                }
            }
        } else {
            System.out.print("");
        }
        processMenuForSmartCardButtonReadCertificate.setDisable(false);
        processMenuForSmartCardButtonFileSignEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSign.setDisable(false);
        processMenuForSmartCardButtonFileSignActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidateEnter.setDisable(false);
        processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSignedEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidate.setDisable(false);
        processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
        savePdfFileButtonForSmartCard.setDisable(false);
        savePdfFileButtonForSmartCardActivate.setDisable(true);
        signFileMessageForSmartCard.setEditable(false);
        validateFileMessageForSmartCard.setEditable(false);
        validateFileSignatureForSmartCard.setEditable(false);
        saveSignedFileButtonForSmartCard.setVisible(false);
    }

    public void setAlgoritma(String algoritma) {
        this.algoritma = algoritma;
    }

    public void setMainMenu(VBox mainMenu) {
        this.mainMenu = mainMenu;
    }

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    @FXML
    private void processMenuForSmartCardButtonBack() {
        processMenuForSmartCardButtonConnectCard.setDisable(false);
        for (CheckBox checkbox : checkboxes) {
            checkbox.setSelected(false);
            checkbox.setDisable(false);
        }
        processMenuForSmartCardButtonReadCertificate.setDisable(false);
        processMenuForSmartCardButtonFileSignEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSign.setDisable(false);
        processMenuForSmartCardButtonFileSignActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidateEnter.setDisable(false);
        processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSignedEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidate.setDisable(false);
        processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
        savePdfFileButtonForSmartCard.setDisable(false);
        savePdfFileButtonForSmartCardActivate.setDisable(true);
        signFileMessageForSmartCard.clear();
        signFileMessageForSmartCard.setEditable(false);
        validateFileMessageForSmartCard.clear();
        validateFileMessageForSmartCard.setEditable(false);
        validateFileSignatureForSmartCard.clear();
        validateFileSignatureForSmartCard.setEditable(false);
        saveSignedFileButtonForSmartCard.setVisible(false);
        selectedFileSmartCardSign = null;
        selectedFileSmartCardValidate = null;
        selectedFileSmartCardSigned = null;

        StackPane newContainer = new StackPane();
        newContainer.getChildren().add(mainMenu);
        Scene mainMenuScene = new Scene(newContainer);
        mainMenuScene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());
        stage.setScene(mainMenuScene);
        stage.setWidth(1200);
        stage.setHeight(900);
        stage.setResizable(false);
        stage.show();
    }

    @FXML
    private void processMenuForSmartCardButtonConnectCard() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminals terminals = factory.terminals();
        List<CardTerminal> terminalList = terminals.list();

        if (terminalList.isEmpty()) {
            throw new Exception("Hiç kart okuyucusu bulunamadı.");
        }

        CardTerminal terminal = terminalList.get(0);
        //System.out.println("Kullanılan kart okuyucu: " + terminal.getName());

        if (!terminal.isCardPresent()) {
            throw new Exception("Kart okuyucuda kart yok.");
        }

        //System.out.println("Kart algılandı, bağlantı deneniyor...");
        card = terminal.connect("T=1");
        ATR atr = card.getATR();
        atrBytes = atr.getBytes();
        //System.out.println("Kart ATR: " + bytesToHex(atr.getBytes()));

        Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
        alertEntering.setHeaderText("Kart Bağlantısı Gerçekleşti");
        alertEntering.setContentText("Kullanılan Kart Okuyucu: " + terminal.getName() + "\n" +
                "Kart ATR: " + bytesToHex(atr.getBytes()));
        alertEntering.showAndWait();
    }

    @FXML
    private void processMenuForSmartCardButtonReadCertificate() throws Exception {
        CardChannel channel = card.getBasicChannel();

        byte[][] commands = {

                new byte[] {0x00, (byte)0xA4, 0x00, 0x00, 0x00},

                new byte[] {0x00, (byte)0xA4, 0x00, 0x00, 0x02, 0x3D, 0x00, 0x00},

                new byte[] {0x00, (byte)0xA4, 0x02, 0x00, 0x02, 0x2F, 0x10, 0x00},

                new byte[] {0x00, (byte)0xB0, 0x00, 0x00, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x00, (byte)0xD0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x01, (byte)0xA0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x02, 0x70, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x03, 0x40, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x04, 0x10, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x04, (byte)0xE0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x05, (byte)0xB0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x06, (byte)0x80, 0x41},

                new byte[] {0x00, (byte)0xB0, 0x00, 0x00, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x00, (byte)0xD0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x01, (byte)0xA0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x02, 0x70, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x03, 0x40, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x04, 0x10, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x04, (byte)0xE0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x05, (byte)0xB0, (byte)0xD0},
                new byte[] {0x00, (byte)0xB0, 0x06, (byte)0x80, 0x41},
        };

        ArrayList<byte[]> dataChunks = new ArrayList<>();
        int offset = 0;
        for (byte[] command : commands) {
            ResponseAPDU response = channel.transmit(new CommandAPDU(command));
            int sw = response.getSW();
            if (sw != 0x9000) {
                throw new Exception("APDU Hatası: SW=" + Integer.toHexString(sw));
            }
            if (command[1] == (byte)0xB0) {
                byte[] data = response.getData();
                if (data.length > 0) {
                    dataChunks.add(data);
                    offset += data.length;
                } else if (sw == 0x9000) {
                    break;
                }
            }
        }

        byte[] fullCertificate = new byte[offset];
        int pos = 0;
        for (byte[] chunk : dataChunks) {
            System.arraycopy(chunk, 0, fullCertificate, pos, chunk.length);
            pos += chunk.length;
        }

        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(fullCertificate));
        certificationInfo = new LinkedHashMap<>();
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd MMMM yyyy EEEE HH:mm:ss", Locale.forLanguageTag("tr-TR"));
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

        serialNumber = cert.getSerialNumber().toString(16);
        certificationInfo.put("Seri Numarası", serialNumber);

        int versionInt = cert.getVersion();
        version = "";
        if (versionInt == 1) {
            version = "V1";
        }
        if (versionInt == 2) {
            version = "V2";
        }
        if (versionInt == 3) {
            version = "V3";
        }
        certificationInfo.put("Sürüm", version);

        subject = cert.getSubjectX500Principal().getName();
        certificationInfo.put("Sertifika Sahibi", subject);

        if (cert.getNotBefore() != null) {
            validFrom = dateFormat.format(cert.getNotBefore());
            certificationInfo.put("Geçerlilik Başlangıcı", validFrom);
        } else {
            certificationInfo.put("Geçerlilik Başlangıcı", "Yok");
        }

        if (cert.getNotAfter() != null) {
            validTo = dateFormat.format(cert.getNotAfter());
            certificationInfo.put("Geçerlilik Sonu", validTo);
        } else {
            certificationInfo.put("Geçerlilik Sonu", "Yok");
        }

        issuer = cert.getIssuerX500Principal().getName();
        certificationInfo.put("Yayıncı", issuer);

        signatureAlgorithm = cert.getSigAlgName();
        certificationInfo.put("İmza Algoritması", signatureAlgorithm);

        publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();
        certificationInfo.put("Genel Anahtar Algoritma", publicKeyAlgorithm);
        publicKeyValue = cert.getPublicKey();
        certificationInfo.put("Genel Anahtar Değer", String.valueOf(publicKeyValue));

        boolean[] keyUsageTrueOrFalse = cert.getKeyUsage();
        if (keyUsageTrueOrFalse != null) {
            keyUsage = new ArrayList<>();
            String[] usageNames = {
                    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
            };
            for (int i = 0; i < keyUsageTrueOrFalse.length; i++) {
                if (keyUsageTrueOrFalse[i]) {
                    keyUsage.add(usageNames[i]);
                }
            }
            certificationInfo.put("Anahtar Kullanımı", keyUsage.isEmpty() ? "None" : String.join(", ", keyUsage));
        } else {
            certificationInfo.put("Anahtar Kullanımı", "Yok");
        }

        try {
            List<String> extKeyUsages = cert.getExtendedKeyUsage();
            if (extKeyUsages != null) {
                Map<String, String> oidToName = new HashMap<>();
                oidToName.put("1.3.6.1.5.5.7.3.1", "serverAuth");
                oidToName.put("1.3.6.1.5.5.7.3.2", "clientAuth");
                oidToName.put("1.3.6.1.5.5.7.3.4", "emailProtection");
                extendedKeyUsage = new ArrayList<>();
                for (String oid : extKeyUsages) {
                    extendedKeyUsage.add(oidToName.getOrDefault(oid, oid));
                }
                certificationInfo.put("Gelişmiş Anahtar Kullanımı", extendedKeyUsage.isEmpty() ? "None" : String.join(", ", extendedKeyUsage));
            } else {
                certificationInfo.put("Gelişmiş Anahtar Kullanımı", "Yok");
            }
        } catch (Exception e) {
            certificationInfo.put("Gelişmiş Anahtar Kullanımı", "Hata: " + e.getMessage());
        }

        byte[] sdoHashBytes = cert.getExtensionValue("2.16.792.1.2.1.1.5.2.200.1");
        if (sdoHashBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(sdoHashBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                byte[] value = octet.getOctets();
                sdoHash = bytesToHex(value);
                certificationInfo.put("SDOHash", sdoHash);
                asn1Input.close();
            } catch (Exception e) {
                certificationInfo.put("SDOHash", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("SDOHash", "Yok");
        }

        byte[] kartSeriNoBytes = cert.getExtensionValue("2.16.792.1.2.1.1.5.2.200.2");
        if (kartSeriNoBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(kartSeriNoBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                byte[] value = octet.getOctets();
                ASN1InputStream valueInput = new ASN1InputStream(value);
                ASN1Primitive valueObj = valueInput.readObject();
                String kartSeriNo = valueObj instanceof ASN1String ? ((ASN1String) valueObj).getString() : bytesToHex(value);
                documentNo = hexToString(kartSeriNo);
                certificationInfo.put("Kart Seri Numarası", documentNo);
                asn1Input.close();
                valueInput.close();
            } catch (Exception e) {
                certificationInfo.put("Kart Seri Numarası", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("Kart Seri Numarası", "Yok");
        }

        int basicConstraintsInt = cert.getBasicConstraints();
        basicConstraints = "";
        if (basicConstraintsInt == -1) {
            basicConstraints = "Not CA";
        }
        if (basicConstraintsInt >= 0) {
            basicConstraints = "CA, PathLen: " + basicConstraintsInt;
        }
        certificationInfo.put("Temel Kısıtlar", basicConstraints);

        byte[] akiBytes = cert.getExtensionValue("2.5.29.35");
        if (akiBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(akiBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                ASN1InputStream octetInput = new ASN1InputStream(octet.getOctets());
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(octetInput.readObject());
                byte[] keyId = aki.getKeyIdentifier();
                authorityKeyIdentifier = bytesToHex(keyId);
                certificationInfo.put("Yayıncı Anahtar Tanımlayıcısı", keyId != null ? "KeyID: " + authorityKeyIdentifier : "Yok");
                asn1Input.close();
                octetInput.close();
            } catch (Exception e) {
                certificationInfo.put("Yayıncı Anahtar Tanımlayıcısı", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("Yayıncı Anahtar Tanımlayıcısı", "Yok");
        }

        byte[] skiBytes = cert.getExtensionValue("2.5.29.14");
        if (skiBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(skiBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(octet.getOctets());
                subjectKeyIdentifier = bytesToHex(ski.getKeyIdentifier());
                certificationInfo.put("Özne Anahtar Tanımlayıcı", "KeyID: " + subjectKeyIdentifier);
                asn1Input.close();
            } catch (Exception e) {
                certificationInfo.put("Özne Anahtar Tanımlayıcı", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("Özne Anahtar Tanımlayıcı", "Yok");
        }

        byte[] crlBytes = cert.getExtensionValue("2.5.29.31");
        if (crlBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(crlBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                ASN1InputStream octetInput = new ASN1InputStream(octet.getOctets());
                CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(octetInput.readObject());
                crlDistributionPoint = new ArrayList<>();
                for (DistributionPoint dp : crlDistPoint.getDistributionPoints()) {
                    DistributionPointName dpn = dp.getDistributionPoint();
                    if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralNames names = (GeneralNames) dpn.getName();
                        for (GeneralName name : names.getNames()) {
                            if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                crlDistributionPoint.add(name.getName().toString());
                            }
                        }
                    }
                }
                certificationInfo.put("Sil Dağıtım Noktaları", crlDistributionPoint.isEmpty() ? "None" : String.join(", ", crlDistributionPoint));
                asn1Input.close();
                octetInput.close();
            } catch (Exception e) {
                certificationInfo.put("Sil Dağıtım Noktaları", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("Sil Dağıtım Noktaları", "Yok");
        }

        byte[] aiaBytes = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (aiaBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(aiaBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                ASN1InputStream octetInput = new ASN1InputStream(octet.getOctets());
                AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(octetInput.readObject());
                authorityInformationAccess = new ArrayList<>();
                for (AccessDescription ad : aia.getAccessDescriptions()) {
                    String type = ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp) ? "OCSP" : "Issuer";
                    authorityInformationAccess.add(type + ": " + ad.getAccessLocation().getName());
                }
                certificationInfo.put("Üretici Erişim Noktaları", authorityInformationAccess.isEmpty() ? "None" : String.join(", ", authorityInformationAccess));
                asn1Input.close();
                octetInput.close();
            } catch (Exception e) {
                certificationInfo.put("Üretici Erişim Noktaları", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("Üretici Erişim Noktaları", "Yok");
        }

        byte[] policyBytes = cert.getExtensionValue("2.5.29.32");
        if (policyBytes != null) {
            try {
                ASN1InputStream asn1Input = new ASN1InputStream(policyBytes);
                ASN1OctetString octet = (ASN1OctetString) asn1Input.readObject();
                ASN1InputStream octetInput = new ASN1InputStream(octet.getOctets());
                CertificatePolicies policies = CertificatePolicies.getInstance(octetInput.readObject());
                certificatePolicy = new ArrayList<>();
                for (PolicyInformation pi : policies.getPolicyInformation()) {
                    StringBuilder policyStr = new StringBuilder("Policy: " + pi.getPolicyIdentifier().getId());
                    ASN1Sequence qualifiers = pi.getPolicyQualifiers();
                    if (qualifiers != null) {
                        for (ASN1Encodable qualifier : qualifiers) {
                            PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifier);
                            if (pqi.getPolicyQualifierId().equals(PolicyQualifierId.id_qt_cps)) {
                                policyStr.append(", CPS: ").append(pqi.getQualifier().toString());
                            }
                        }
                    }
                    certificatePolicy.add(policyStr.toString());
                }
                certificationInfo.put("Sertifika İlkesi", certificatePolicy.isEmpty() ? "None" : String.join("; ", certificatePolicy));
                asn1Input.close();
                octetInput.close();
            } catch (Exception e) {
                certificationInfo.put("Sertifika İlkesi", "Hata: " + e.getMessage());
            }
        } else {
            certificationInfo.put("Sertifika İlkesi", "Yok");
        }

        for (Map.Entry<String, String> entry : certificationInfo.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }

        Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
        alertEntering.setHeaderText("Kart Sertifikası Okundu");
        alertEntering.setContentText("İçerikleri PDF Olarak Alabilirsiniz");
        alertEntering.showAndWait();
    }

    @FXML
    private void savePdfFileButtonForSmartCard() {
        byte[] bytes = generatePdfBytes();
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("PDF Dosyasını Kaydet");
        fileChooser.setInitialFileName("certification_data.pdf");
        FileChooser.ExtensionFilter pdfFilter = new FileChooser.ExtensionFilter("PDF Dosyaları", "*.pdf");
        fileChooser.getExtensionFilters().add(pdfFilter);
        fileChooser.getSelectedExtensionFilter();
        File file = fileChooser.showSaveDialog(stage);
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("İmzalı Dosya Kaydedildi");
        messageEncrypt.showAndWait();
    }

    @FXML
    private void savePdfFileButtonForSmartCardActivate() {
        // hello
    }

    @FXML
    private void processMenuForSmartCardButtonFileSignEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSmartCardSign = fileChooser.showOpenDialog(stage);
        if (selectedFileSmartCardSign != null) {
            processMenuForSmartCardButtonFileSignEnter.setDisable(true);
            processMenuForSmartCardButtonFileSignEnterActivate.setDisable(false);
            processMenuForSmartCardButtonFileSign.setDisable(false);
            processMenuForSmartCardButtonFileSignActivate.setDisable(true);
            signFileMessageForSmartCard.setEditable(false);
            signFileMessageForSmartCard.clear();
            selectedFileSmartCardSignName = selectedFileSmartCardSign.getName();
            signFileMessageForSmartCard.appendText("Seçtiğiniz Dosya:\n" + selectedFileSmartCardSignName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSmartCardButtonFileSignEnter.setDisable(false);
            processMenuForSmartCardButtonFileSignEnterActivate.setDisable(true);
            processMenuForSmartCardButtonFileSign.setDisable(false);
            processMenuForSmartCardButtonFileSignActivate.setDisable(true);
            signFileMessageForSmartCard.setEditable(false);
            signFileMessageForSmartCard.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSmartCardButtonFileSignEnterActivate() {
        processMenuForSmartCardButtonFileSignEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSign.setDisable(false);
        processMenuForSmartCardButtonFileSignActivate.setDisable(true);
        signFileMessageForSmartCard.setEditable(false);
        signFileMessageForSmartCard.clear();
    }

    @FXML
    private void processMenuForSmartCardButtonFileSign() {
        if (selectedFileSmartCardSign != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileSmartCardSign.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] fileFormat = selectedFileSmartCardSignName.split("\\.");
            byte[] fileFormatBytes;
            try {
                fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ee) {
                throw new RuntimeException(ee);
            }

            byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
            byte[] fileBytesAll = new byte[fileBytes.length+9+fileFormatBytes.length];
            System.arraycopy(fileBytes, 0, fileBytesAll, 0, fileBytes.length);
            System.arraycopy(numbers, 0, fileBytesAll, fileBytes.length, 9);
            System.arraycopy(fileFormatBytes, 0, fileBytesAll, fileBytes.length+9, fileFormatBytes.length);

            try {
                signContentBytes = SmartCard.signFile(fileBytesAll, card);
            } catch (Exception error) {
                showErrorMessage("Girilen Dosya Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (bytesToHex(signContentBytes).equals("31")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Dosya Şifrelenemiyor");
                alertEntering.setContentText("Girilen Dosya Çok Büyük");
                alertEntering.showAndWait();
                throw new RuntimeException("Girilen Dosya Çok Büyük");
            }

            if (signContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
                processMenuForSmartCardButtonFileSignEnter.setDisable(true);
                processMenuForSmartCardButtonFileSignEnterActivate.setDisable(false);
                processMenuForSmartCardButtonFileSign.setDisable(false);
                processMenuForSmartCardButtonFileSignActivate.setDisable(true);
                signFileMessageForSmartCard.setEditable(false);
                saveSignedFileButtonForSmartCard.setVisible(false);
            }

            else {
                signFileInfoBytes = (signContentBytes);

                processMenuForSmartCardButtonFileSignEnter.setDisable(true);
                processMenuForSmartCardButtonFileSignEnterActivate.setDisable(true);
                processMenuForSmartCardButtonFileSign.setDisable(true);
                processMenuForSmartCardButtonFileSignActivate.setDisable(false);
                signFileMessageForSmartCard.setEditable(false);
                saveSignedFileButtonForSmartCard.setVisible(true);
            }
        }
        else {
            processMenuForSmartCardButtonFileSignEnter.setDisable(true);
            processMenuForSmartCardButtonFileSignEnterActivate.setDisable(false);
            processMenuForSmartCardButtonFileSign.setDisable(false);
            processMenuForSmartCardButtonFileSignActivate.setDisable(true);
            signFileMessageForSmartCard.setEditable(false);
            saveSignedFileButtonForSmartCard.setVisible(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSmartCardButtonFileSignActivate() {
        processMenuForSmartCardButtonFileSignEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSign.setDisable(false);
        processMenuForSmartCardButtonFileSignActivate.setDisable(true);
        signFileMessageForSmartCard.setEditable(false);
        saveSignedFileButtonForSmartCard.setVisible(false);
    }

    @FXML
    private void saveSignedFileButtonForSmartCard() {
        byte[] bytes = signFileInfoBytes;
        String[] fileName = selectedFileSmartCardSignName.split("\\.");
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Oluşturulan İmzalı Dosyayı Kaydet");
        fileChooser.setInitialFileName(fileName[0]);
        FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("İmzalanmış Dosyalar", "*.sig");
        fileChooser.getExtensionFilters().add(fileFormat);
        fileChooser.getSelectedExtensionFilter();
        File file = fileChooser.showSaveDialog(stage);
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("İmzalı Dosya Kaydedildi");
        messageEncrypt.showAndWait();
    }

    @FXML
    private void processMenuForSmartCardButtonFileValidateEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSmartCardValidate = fileChooser.showOpenDialog(stage);
        if (selectedFileSmartCardValidate != null) {
            processMenuForSmartCardButtonFileValidateEnter.setDisable(true);
            processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(false);
            processMenuForSmartCardButtonFileValidate.setDisable(false);
            processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSmartCard.setEditable(false);
            validateFileSignatureForSmartCard.setEditable(false);
            validateFileMessageForSmartCard.clear();
            selectedFileSmartCardValidateName = selectedFileSmartCardValidate.getName();
            validateFileMessageForSmartCard.appendText("Seçtiğiniz Dosya:\n" + selectedFileSmartCardValidateName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSmartCardButtonFileValidateEnter.setDisable(false);
            processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
            processMenuForSmartCardButtonFileValidate.setDisable(false);
            processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSmartCard.setEditable(false);
            validateFileSignatureForSmartCard.setEditable(false);
            validateFileMessageForSmartCard.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSmartCardButtonFileValidateEnterActivate() {
        processMenuForSmartCardButtonFileValidateEnter.setDisable(false);
        processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidate.setDisable(false);
        processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
        validateFileMessageForSmartCard.setEditable(false);
        validateFileSignatureForSmartCard.setEditable(false);
        validateFileMessageForSmartCard.clear();
    }

    @FXML
    private void processMenuForSmartCardButtonFileSignedEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSmartCardSigned = fileChooser.showOpenDialog(stage);
        if (selectedFileSmartCardSigned != null) {
            processMenuForSmartCardButtonFileSignedEnter.setDisable(true);
            processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(false);
            processMenuForSmartCardButtonFileValidate.setDisable(false);
            processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSmartCard.setEditable(false);
            validateFileSignatureForSmartCard.setEditable(false);
            validateFileSignatureForSmartCard.clear();
            selectedFileSmartCardSignedName = selectedFileSmartCardSigned.getName();
            validateFileSignatureForSmartCard.appendText("Seçtiğiniz Dosya:\n" + selectedFileSmartCardSignedName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileAlternativeName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSmartCardButtonFileSignedEnter.setDisable(false);
            processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
            processMenuForSmartCardButtonFileValidate.setDisable(false);
            processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSmartCard.setEditable(false);
            validateFileSignatureForSmartCard.setEditable(false);
            validateFileSignatureForSmartCard.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSmartCardButtonFileSignedEnterActivate() {
        processMenuForSmartCardButtonFileSignedEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidate.setDisable(false);
        processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
        validateFileMessageForSmartCard.setEditable(false);
        validateFileSignatureForSmartCard.setEditable(false);
        validateFileSignatureForSmartCard.clear();
    }

    @FXML
    private void processMenuForSmartCardButtonFileValidate() {
        if (selectedFileSmartCardValidate != null) {
            byte[] fileBytesValidate;
            try {
                fileBytesValidate = Files.readAllBytes(selectedFileSmartCardValidate.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] fileFormat = selectedFileSmartCardValidateName.split("\\.");
            byte[] fileFormatBytes;
            try {
                fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ee) {
                throw new RuntimeException(ee);
            }

            byte[] numbers = new byte[]{0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
            byte[] fileBytesValidateFinal = new byte[fileBytesValidate.length + 9 + fileFormatBytes.length];
            System.arraycopy(fileBytesValidate, 0, fileBytesValidateFinal, 0, fileBytesValidate.length);
            System.arraycopy(numbers, 0, fileBytesValidateFinal, fileBytesValidate.length, 9);
            System.arraycopy(fileFormatBytes, 0, fileBytesValidateFinal, fileBytesValidate.length + 9, fileFormatBytes.length);

            byte[] fileBytesSignature;
            try {
                fileBytesSignature = Files.readAllBytes(selectedFileSmartCardSigned.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            try {
                validateContentBytes = SmartCard.validateFile(fileBytesValidateFinal, fileBytesSignature, publicKeyValue);
            } catch (Exception error) {
                showErrorMessage("Girilen Genel Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }


            if (validateContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
                alertEntering.showAndWait();
                processMenuForSmartCardButtonFileValidateEnter.setDisable(false);
                processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
                processMenuForSmartCardButtonFileSignedEnter.setDisable(false);
                processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
                processMenuForSmartCardButtonFileValidate.setDisable(false);
                processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
                validateFileMessageForSmartCard.setEditable(false);
                validateFileSignatureForSmartCard.setEditable(false);
            } else {
                if (bytesToHex(validateContentBytes).equals("3131")) {
                    Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                    alertEntering.setHeaderText("Dikkat");
                    alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                    alertEntering.showAndWait();
                    processMenuForSmartCardButtonFileValidateEnter.setDisable(true);
                    processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
                    processMenuForSmartCardButtonFileSignedEnter.setDisable(true);
                    processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
                    processMenuForSmartCardButtonFileValidate.setDisable(true);
                    processMenuForSmartCardButtonFileValidateActivate.setDisable(false);
                    validateFileMessageForSmartCard.setEditable(false);
                    validateFileSignatureForSmartCard.setEditable(false);
                }
                if (bytesToHex(validateContentBytes).equals("31")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Sorun Yok");
                    alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                    alertEntering.showAndWait();
                    processMenuForSmartCardButtonFileValidateEnter.setDisable(true);
                    processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
                    processMenuForSmartCardButtonFileSignedEnter.setDisable(true);
                    processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
                    processMenuForSmartCardButtonFileValidate.setDisable(true);
                    processMenuForSmartCardButtonFileValidateActivate.setDisable(false);
                    validateFileMessageForSmartCard.setEditable(false);
                    validateFileSignatureForSmartCard.setEditable(false);
                }
            }
        }
    }

    @FXML
    private void processMenuForSmartCardButtonFileValidateActivate() {
        processMenuForSmartCardButtonFileValidateEnter.setDisable(false);
        processMenuForSmartCardButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileSignedEnter.setDisable(false);
        processMenuForSmartCardButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSmartCardButtonFileValidate.setDisable(false);
        processMenuForSmartCardButtonFileValidateActivate.setDisable(true);
        validateFileMessageForSmartCard.setEditable(false);
        validateFileSignatureForSmartCard.setEditable(false);
    }

    public byte[] generatePdfBytes() {
        String pdfText = createPdfTextContent();

        File tempPdfFile = new File("certification_data.pdf");

        try {
            Document document = new Document();
            PdfWriter.getInstance(document, new FileOutputStream(tempPdfFile));

            document.open();
            document.add(new Paragraph(pdfText));
            document.close();

            return Files.readAllBytes(tempPdfFile.toPath());
        } catch (DocumentException | IOException e) {
            throw new RuntimeException("PDF dosyası oluşturulurken bir hata oluştu.", e);
        }
    }

    public String createPdfTextContent() {
        String pdfText = "";

        Map<String, String> checkboxTitleMap = new HashMap<>();
        checkboxTitleMap.put("serialNumberCheck", "Seri Numarası");
        checkboxTitleMap.put("versionCheck", "Sürüm");
        checkboxTitleMap.put("subjectCheck", "Sertifika Sahibi");
        checkboxTitleMap.put("validFromCheck", "Geçerlilik Başlangıcı");
        checkboxTitleMap.put("validToCheck", "Geçerlilik Sonu");
        checkboxTitleMap.put("issuerCheck", "Yayıncı");
        checkboxTitleMap.put("signatureAlgorithmCheck", "İmza Algoritması");
        checkboxTitleMap.put("publicKeyAlgorithmCheck", "Genel Anahtar Algoritma");
        checkboxTitleMap.put("publicKeyValueCheck", "Genel Anahtar Değer");
        checkboxTitleMap.put("keyUsageCheck", "Anahtar Kullanımı");
        checkboxTitleMap.put("extendedKeyUsageCheck", "Gelişmiş Anahtar Kullanımı");
        checkboxTitleMap.put("sdoHashCheck", "SDOHash");
        checkboxTitleMap.put("documentNoCheck", "Kart Seri Numarası");
        checkboxTitleMap.put("basicConstraintsCheck", "Temel Kısıtlar");
        checkboxTitleMap.put("authorityKeyIdentifierCheck", "Yayıncı Anahtar Tanımlayıcısı");
        checkboxTitleMap.put("subjectKeyIdentifierCheck", "Özne Anahtar Tanımlayıcı");
        checkboxTitleMap.put("crlDistributionPointCheck", "Sil Dağıtım Noktaları");
        checkboxTitleMap.put("authorityInformationAccessCheck", "Üretici Erişim Noktaları");
        checkboxTitleMap.put("certificatePolicyCheck", "Sertifika İlkesi");

        for (CheckBox checkbox : checkboxes) {
            if (checkbox.isSelected()) {
                String checkBoxId = checkbox.getId();
                String title = checkboxTitleMap.get(checkBoxId);
                if (certificationInfo.containsKey(title)) {
                    pdfText += title + ": " + certificationInfo.get(title) + "\n";
                }
            }
        }
        return pdfText;
    }

    public static void showErrorMessage(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Hata İle Karşılaşıldı.");
        alert.setHeaderText(message);
        alert.showAndWait();
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

    public static String hexToString(String hex) {
        hex = hex.replaceAll("\\s", "");

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            int decimal = Integer.parseInt(str, 16);

            if (decimal >= 0x20 && decimal <= 0x7E) {
                sb.append((char) decimal);
            } else {
                sb.append(".");
            }
        }
        return sb.toString();
    }
}
