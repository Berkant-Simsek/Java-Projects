package org.example.gui;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.example.algoritmalar.Algoritmalar;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ResourceBundle;

public class SignController implements Initializable {

    private String algoritma;
    public VBox mainMenu;
    public Stage stage;

    public String signKeyInfo;
    public String validateKeyInfo;
    public String signedMessageInfo;
    public byte[] privateKeyFileInfoBytes;
    public byte[] privateKeyFileFormatBytes;
    public byte[] signKeyInfoBytes;
    public byte[] validateKeyInfoBytes;
    public String keysContent;
    public byte[] keysContentBytes;
    public String signContent;
    public byte[] signContentBytes;
    public String validateContent;
    public byte[] validateContentBytes;

    public File selectedFileSignSign;
    public String selectedFileSignSignName;
    public File selectedFileSignValidate;
    public String selectedFileSignValidateName;
    public File selectedFileSignSigned;
    public String selectedFileSignSignedName;

    // Bilgilendirme Tab
    @FXML
    private TextArea signExplanation;
    @FXML
    private Button processMenuForSignButtonBack;

    // Metin Anahtarları Oluşturma Tab
    @FXML
    private Label keysExplanation;
    @FXML
    private Label signKeyInfoLabel;
    @FXML
    private Label validateKeyInfoLabel;
    @FXML
    private Button processMenuForSignButtonGenerateKeys;
    @FXML
    private Button processMenuForSignButtonGenerateKeysActivate;
    @FXML
    private Button copySignKeyButtonForSign;
    @FXML
    private Button copyValidateKeyButtonForSign;

    // Metin Şifreleme Tab (Signing)
    @FXML
    private Label signMessageExplanation;
    @FXML
    private Label signKeyExplanation;
    @FXML
    private TextArea signMessageForSign;
    @FXML
    private TextArea signKeyForSign;
    @FXML
    private Button processMenuForSignButtonSign;
    @FXML
    private Button processMenuForSignButtonSignActivate;
    @FXML
    private Button copySignedMessageButtonForSign;
    @FXML
    private Label signedMessageInfoLabel;

    // Metin Çözme Tab (Verification)
    @FXML
    private Label validateMessageExplanation;
    @FXML
    private Label validateKeyExplanation;
    @FXML
    private Label validateSignatureExplanation;
    @FXML
    private TextArea validateMessageForSign;
    @FXML
    private TextArea validateKeyForSign;
    @FXML
    private TextArea validateSignatureForSign;
    @FXML
    private Button processMenuForSignButtonValidate;
    @FXML
    private Button processMenuForSignButtonValidateActivate;

    // Dosya Anahtarları Oluşturma Tab
    @FXML
    private Button processMenuForSignButtonGenerateKeysFile;
    @FXML
    private Button processMenuForSignButtonGenerateKeysFileActivate;
    @FXML
    private Button copySignKeyFileButtonForSign;
    @FXML
    private Button copyValidateKeyFileButtonForSign;

    // Dosya Şifreleme Tab (File Signing)
    @FXML
    private TextArea signFileMessageForSign;
    @FXML
    private TextArea signFileKeyForSign;
    @FXML
    private Button processMenuForSignButtonFileSign;
    @FXML
    private Button processMenuForSignButtonFileSignActivate;
    @FXML
    private Button saveSignedFileButtonForSign;
    @FXML
    private Button processMenuForSignButtonFileSignEnter;
    @FXML
    private Button processMenuForSignButtonFileSignEnterActivate;

    // Dosya Çözme Tab (File Verification)
    @FXML
    private TextArea validateFileMessageForSign;
    @FXML
    private TextArea validateFileKeyForSign;
    @FXML
    private TextArea validateFileSignatureForSign;
    @FXML
    private Button processMenuForSignButtonFileValidate;
    @FXML
    private Button processMenuForSignButtonFileValidateActivate;
    @FXML
    private Button processMenuForSignButtonFileValidateEnter;
    @FXML
    private Button processMenuForSignButtonFileValidateEnterActivate;
    @FXML
    private Button processMenuForSignButtonFileSignedEnter;
    @FXML
    private Button processMenuForSignButtonFileSignedEnterActivate;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        processMenuForSignButtonBack.setDisable(false);
        processMenuForSignButtonGenerateKeys.setDisable(false);
        processMenuForSignButtonGenerateKeysActivate.setDisable(true);
        processMenuForSignButtonGenerateKeysFile.setDisable(false);
        processMenuForSignButtonGenerateKeysFileActivate.setDisable(true);
        processMenuForSignButtonFileSignEnter.setDisable(false);
        processMenuForSignButtonFileSignEnterActivate.setDisable(true);
        processMenuForSignButtonSign.setDisable(false);
        processMenuForSignButtonSignActivate.setDisable(true);
        processMenuForSignButtonFileSign.setDisable(false);
        processMenuForSignButtonFileSignActivate.setDisable(true);
        processMenuForSignButtonFileValidateEnter.setDisable(false);
        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSignButtonFileSignedEnter.setDisable(false);
        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSignButtonValidate.setDisable(false);
        processMenuForSignButtonValidateActivate.setDisable(true);
        processMenuForSignButtonFileValidate.setDisable(false);
        processMenuForSignButtonFileValidateActivate.setDisable(true);
        signMessageForSign.setEditable(true);
        signKeyForSign.setEditable(true);
        validateMessageForSign.setEditable(true);
        validateSignatureForSign.setEditable(true);
        validateKeyForSign.setEditable(true);
        signFileMessageForSign.setEditable(false);
        signFileKeyForSign.setEditable(true);
        validateFileMessageForSign.setEditable(false);
        validateFileSignatureForSign.setEditable(false);
        validateFileKeyForSign.setEditable(true);
        copySignKeyButtonForSign.setVisible(false);
        copySignKeyFileButtonForSign.setVisible(false);
        copyValidateKeyButtonForSign.setVisible(false);
        copyValidateKeyFileButtonForSign.setVisible(false);
        copySignedMessageButtonForSign.setVisible(false);
        saveSignedFileButtonForSign.setVisible(false);
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
    private void processMenuForSignButtonBack() {
        processMenuForSignButtonGenerateKeys.setDisable(false);
        processMenuForSignButtonGenerateKeysActivate.setDisable(true);
        processMenuForSignButtonGenerateKeysFile.setDisable(false);
        processMenuForSignButtonGenerateKeysFileActivate.setDisable(true);
        processMenuForSignButtonFileSignEnter.setDisable(false);
        processMenuForSignButtonFileSignEnterActivate.setDisable(true);
        processMenuForSignButtonSign.setDisable(false);
        processMenuForSignButtonSignActivate.setDisable(true);
        processMenuForSignButtonFileSign.setDisable(false);
        processMenuForSignButtonFileSignActivate.setDisable(true);
        processMenuForSignButtonFileValidateEnter.setDisable(false);
        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSignButtonFileSignedEnter.setDisable(false);
        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSignButtonValidate.setDisable(false);
        processMenuForSignButtonValidateActivate.setDisable(true);
        processMenuForSignButtonFileValidate.setDisable(false);
        processMenuForSignButtonFileValidateActivate.setDisable(true);
        signMessageForSign.clear();
        signMessageForSign.setEditable(true);
        signKeyForSign.clear();
        signKeyForSign.setEditable(true);
        validateMessageForSign.clear();
        validateMessageForSign.setEditable(true);
        validateSignatureForSign.clear();
        validateSignatureForSign.setEditable(true);
        validateKeyForSign.clear();
        validateKeyForSign.setEditable(true);
        signFileMessageForSign.clear();
        signFileMessageForSign.setEditable(false);
        signFileKeyForSign.clear();
        signFileKeyForSign.setEditable(true);
        validateFileMessageForSign.clear();
        validateFileMessageForSign.setEditable(false);
        validateFileSignatureForSign.clear();
        validateFileSignatureForSign.setEditable(false);
        validateFileKeyForSign.clear();
        validateFileKeyForSign.setEditable(true);
        copySignKeyButtonForSign.setVisible(false);
        copySignKeyFileButtonForSign.setVisible(false);
        copyValidateKeyButtonForSign.setVisible(false);
        copyValidateKeyFileButtonForSign.setVisible(false);
        copySignedMessageButtonForSign.setVisible(false);
        saveSignedFileButtonForSign.setVisible(false);
        selectedFileSignSign = null;
        selectedFileSignValidate = null;
        selectedFileSignSigned = null;

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
    private void processMenuForSignButtonGenerateKeys() {
        try {
            keysContent = Algoritmalar.startMessage(algoritma, "Anahtar", "Anahtar", "Anahtar", "Anahtar", "Anahtar");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
        String[] keysInfoContent = keysContent.split("\n");

        signKeyInfo = keysInfoContent[0];
        validateKeyInfo = keysInfoContent[1];
        processMenuForSignButtonGenerateKeys.setDisable(true);
        processMenuForSignButtonGenerateKeysActivate.setDisable(false);
        copySignKeyButtonForSign.setVisible(true);
        copyValidateKeyButtonForSign.setVisible(true);
    }

    @FXML
    private void processMenuForSignButtonGenerateKeysActivate() {
        processMenuForSignButtonGenerateKeys.setDisable(false);
        processMenuForSignButtonGenerateKeysActivate.setDisable(true);
        copySignKeyButtonForSign.setVisible(false);
        copyValidateKeyButtonForSign.setVisible(false);
    }

    @FXML
    private void copySignKeyButtonForSign() {
        String[] signKey = signKeyInfo.split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(signKey[1]);
        clipboard.setContent(content);

        Alert signKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        signKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
        signKeyCopy.showAndWait();
    }

    @FXML
    private void copyValidateKeyButtonForSign() {
        String[] validateKey = validateKeyInfo.split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(validateKey[1]);
        clipboard.setContent(content);

        Alert validateKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        validateKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
        validateKeyCopy.showAndWait();
    }

    @FXML
    private void processMenuForSignButtonSign() {
        String userInputSignMessage = signMessageForSign.getText();
        String userInputSignKey = signKeyForSign.getText();
        try {
            signContent = Algoritmalar.startMessage(algoritma, userInputSignMessage, userInputSignKey, "İmzala", "İmzala", "İmzala");
        } catch (Exception error) {
            showErrorMessage("Girilen Özel Anahtar Hatalıdır.");
            throw new RuntimeException(error);
        }
        String[] signInfoContent = signContent.split("\n");

        if (signContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen İmzalanmasını İstediğiniz Metni ve Özel Anahtarı Girin");
            alertEntering.showAndWait();
            processMenuForSignButtonSign.setDisable(false);
            processMenuForSignButtonSignActivate.setDisable(true);
            signMessageForSign.setEditable(true);
            signKeyForSign.setEditable(true);
            copySignedMessageButtonForSign.setVisible(false);
        }

        else {
            signedMessageInfo = signInfoContent[0];
            processMenuForSignButtonSign.setDisable(true);
            processMenuForSignButtonSignActivate.setDisable(false);
            signMessageForSign.setEditable(false);
            signKeyForSign.setEditable(false);
            copySignedMessageButtonForSign.setVisible(true);
        }
    }

    @FXML
    private void processMenuForSignButtonSignActivate() {
        processMenuForSignButtonSign.setDisable(false);
        processMenuForSignButtonSignActivate.setDisable(true);
        signMessageForSign.setEditable(true);
        signKeyForSign.setEditable(true);
        copySignedMessageButtonForSign.setVisible(false);
    }

    @FXML
    private void copySignedMessageButtonForSign() {
        String[] signed = signedMessageInfo.split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(signed[1]);
        clipboard.setContent(content);

        Alert signedCopy = new Alert(Alert.AlertType.INFORMATION);
        signedCopy.setHeaderText("İmzalanmış Metin Kopyalandı");
        signedCopy.showAndWait();
    }

    @FXML
    private void processMenuForSignButtonValidate() {
        String userInputValidateMessage = validateMessageForSign.getText();
        String userInputSignature = validateSignatureForSign.getText();
        String userInputValidateKey = validateKeyForSign.getText();
        try {
            validateContent = Algoritmalar.startMessage(algoritma, "Doğrula", "Doğrula", userInputValidateMessage, userInputSignature, userInputValidateKey);
        } catch (Exception error) {
            showErrorMessage("Girilen Genel Anahtar Hatalıdır.");
            throw new RuntimeException(error);
        }

        if (validateContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Doğrulamak İstediğiniz Metni ve Genel Anahtarı Girin");
            alertEntering.showAndWait();
            processMenuForSignButtonValidate.setDisable(false);
            processMenuForSignButtonValidateActivate.setDisable(true);
            validateMessageForSign.setEditable(true);
            validateSignatureForSign.setEditable(true);
            validateKeyForSign.setEditable(true);
        }

        else {
            if (validateContent.equals("Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)")) {
                Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                alertEntering.setHeaderText("Dikkat");
                alertEntering.setContentText("Doğrulama Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                alertEntering.showAndWait();
                processMenuForSignButtonValidate.setDisable(true);
                processMenuForSignButtonValidateActivate.setDisable(false);
                validateMessageForSign.setEditable(false);
                validateSignatureForSign.setEditable(false);
                validateKeyForSign.setEditable(false);
            }
            if (validateContent.equals("Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Sorun Yok");
                alertEntering.setContentText("Doğrulama Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                alertEntering.showAndWait();
                processMenuForSignButtonValidate.setDisable(true);
                processMenuForSignButtonValidateActivate.setDisable(false);
                validateMessageForSign.setEditable(false);
                validateSignatureForSign.setEditable(false);
                validateKeyForSign.setEditable(false);
            }
        }
    }

    @FXML
    private void processMenuForSignButtonValidateActivate() {
        processMenuForSignButtonValidate.setDisable(false);
        processMenuForSignButtonValidateActivate.setDisable(true);
        validateMessageForSign.setEditable(true);
        validateSignatureForSign.setEditable(true);
        validateKeyForSign.setEditable(true);
    }

    @FXML
    private void processMenuForSignButtonGenerateKeysFile() {
        try {
            keysContentBytes = Algoritmalar.startFile(algoritma, null, "Anahtar", null, null, "Anahtar");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
        String keysInfoContent = bytesToHex(keysContentBytes);
        String[] partsPublicAndPrivate = keysInfoContent.split("012345677654321031012345677654321031");


        signKeyInfoBytes = hexToBytes(partsPublicAndPrivate[0]);
        validateKeyInfoBytes = hexToBytes(partsPublicAndPrivate[1]);
        processMenuForSignButtonGenerateKeysFile.setDisable(true);
        processMenuForSignButtonGenerateKeysFileActivate.setDisable(false);
        copySignKeyFileButtonForSign.setVisible(true);
        copyValidateKeyFileButtonForSign.setVisible(true);
    }

    @FXML
    private void processMenuForSignButtonGenerateKeysFileActivate() {
        processMenuForSignButtonGenerateKeysFile.setDisable(false);
        processMenuForSignButtonGenerateKeysFileActivate.setDisable(true);
        copySignKeyFileButtonForSign.setVisible(false);
        copyValidateKeyFileButtonForSign.setVisible(false);
    }

    @FXML
    private void copySignKeyFileButtonForSign() {
        String signKey = bytesToHex(signKeyInfoBytes);
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(signKey);
        clipboard.setContent(content);

        Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        encryptKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
        encryptKeyCopy.showAndWait();
    }

    @FXML
    private void copyValidateKeyFileButtonForSign() {
        String validateKey = bytesToHex(validateKeyInfoBytes);
        String decryptKeyAndFormat = validateKey;

        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(decryptKeyAndFormat);
        clipboard.setContent(content);

        Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        encryptKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
        encryptKeyCopy.showAndWait();
    }

    @FXML
    private void processMenuForSignButtonFileSignEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSignSign = fileChooser.showOpenDialog(stage);
        if (selectedFileSignSign != null) {
            processMenuForSignButtonFileSignEnter.setDisable(true);
            processMenuForSignButtonFileSignEnterActivate.setDisable(false);
            processMenuForSignButtonFileSign.setDisable(false);
            processMenuForSignButtonFileSignActivate.setDisable(true);
            signFileMessageForSign.setEditable(false);
            signFileKeyForSign.setEditable(true);
            signFileMessageForSign.clear();
            selectedFileSignSignName = selectedFileSignSign.getName();
            signFileMessageForSign.appendText("Seçtiğiniz Dosya:\n" + selectedFileSignSignName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSignButtonFileSignEnter.setDisable(false);
            processMenuForSignButtonFileSignEnterActivate.setDisable(true);
            processMenuForSignButtonFileSign.setDisable(false);
            processMenuForSignButtonFileSignActivate.setDisable(true);
            signFileMessageForSign.setEditable(false);
            signFileKeyForSign.setEditable(true);
            signFileMessageForSign.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSignButtonFileSignEnterActivate() {
        processMenuForSignButtonFileSignEnter.setDisable(false);
        processMenuForSignButtonFileSignEnterActivate.setDisable(true);
        processMenuForSignButtonFileSign.setDisable(false);
        processMenuForSignButtonFileSignActivate.setDisable(true);
        signFileMessageForSign.setEditable(false);
        signFileKeyForSign.setEditable(true);
        signFileMessageForSign.clear();
    }

    @FXML
    private void processMenuForSignButtonFileSign() {
        if (selectedFileSignSign != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileSignSign.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] fileFormat = selectedFileSignSignName.split("\\.");
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


            String userInputSignKey = signFileKeyForSign.getText();

            try {
                signContentBytes = Algoritmalar.startFile(algoritma, fileBytesAll, userInputSignKey, null, null, "İmzala");
            } catch (Exception error) {
                showErrorMessage("Girilen Dosya ya da Anahtar Hatalıdır.");
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
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForSignButtonFileSignEnter.setDisable(true);
                processMenuForSignButtonFileSignEnterActivate.setDisable(false);
                processMenuForSignButtonFileSign.setDisable(false);
                processMenuForSignButtonFileSignActivate.setDisable(true);
                signFileMessageForSign.setEditable(false);
                signFileKeyForSign.setEditable(true);
                saveSignedFileButtonForSign.setVisible(false);
            }

            else {
                String keyAndFormat = bytesToHex(signContentBytes);
                String[] parts = keyAndFormat.split("012345677654321031");
                privateKeyFileInfoBytes = hexToBytes(parts[0]);
                privateKeyFileFormatBytes = hexToBytes(parts[1]);

                processMenuForSignButtonFileSignEnter.setDisable(true);
                processMenuForSignButtonFileSignEnterActivate.setDisable(true);
                processMenuForSignButtonFileSign.setDisable(true);
                processMenuForSignButtonFileSignActivate.setDisable(false);
                signFileMessageForSign.setEditable(false);
                signFileKeyForSign.setEditable(true);
                saveSignedFileButtonForSign.setVisible(true);
            }
        }
        else {
            processMenuForSignButtonFileSignEnter.setDisable(true);
            processMenuForSignButtonFileSignEnterActivate.setDisable(false);
            processMenuForSignButtonFileSign.setDisable(false);
            processMenuForSignButtonFileSignActivate.setDisable(true);
            signFileMessageForSign.setEditable(false);
            signFileKeyForSign.setEditable(true);
            saveSignedFileButtonForSign.setVisible(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSignButtonFileSignActivate() {
        processMenuForSignButtonFileSignEnter.setDisable(false);
        processMenuForSignButtonFileSignEnterActivate.setDisable(true);
        processMenuForSignButtonFileSign.setDisable(false);
        processMenuForSignButtonFileSignActivate.setDisable(true);
        signFileMessageForSign.setEditable(false);
        signFileKeyForSign.setEditable(true);
        saveSignedFileButtonForSign.setVisible(false);
    }

    @FXML
    private void saveSignedFileButtonForSign() {
        byte[] numbersss = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31, 0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
        byte[] bytes = new byte[privateKeyFileInfoBytes.length+18+privateKeyFileFormatBytes.length];
        System.arraycopy(privateKeyFileInfoBytes, 0, bytes, 0, privateKeyFileInfoBytes.length);
        System.arraycopy(numbersss, 0, bytes, privateKeyFileInfoBytes.length, 18);
        System.arraycopy(privateKeyFileFormatBytes, 0, bytes, privateKeyFileInfoBytes.length+18, privateKeyFileFormatBytes.length);

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Oluşturulan İmzalı Dosyayı Kaydet");
        fileChooser.setInitialFileName("imzali_dosya");
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
    private void processMenuForSignButtonFileValidateEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSignValidate = fileChooser.showOpenDialog(stage);
        if (selectedFileSignValidate != null) {
            processMenuForSignButtonFileValidateEnter.setDisable(true);
            processMenuForSignButtonFileValidateEnterActivate.setDisable(false);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSign.setEditable(false);
            validateFileSignatureForSign.setEditable(false);
            validateFileMessageForSign.clear();
            selectedFileSignValidateName = selectedFileSignValidate.getName();
            validateFileMessageForSign.appendText("Seçtiğiniz Dosya:\n" + selectedFileSignValidateName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSignButtonFileValidateEnter.setDisable(false);
            processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSign.setEditable(false);
            validateFileSignatureForSign.setEditable(false);
            validateFileMessageForSign.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSignButtonFileValidateEnterActivate() {
        processMenuForSignButtonFileValidateEnter.setDisable(false);
        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSignButtonFileValidate.setDisable(false);
        processMenuForSignButtonFileValidateActivate.setDisable(true);
        validateFileMessageForSign.setEditable(false);
        validateFileSignatureForSign.setEditable(false);
        validateFileMessageForSign.clear();
    }

    @FXML
    private void processMenuForSignButtonFileSignedEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileSignSigned = fileChooser.showOpenDialog(stage);
        if (selectedFileSignSigned != null) {
            processMenuForSignButtonFileSignedEnter.setDisable(true);
            processMenuForSignButtonFileSignedEnterActivate.setDisable(false);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSign.setEditable(false);
            validateFileSignatureForSign.setEditable(false);
            validateFileSignatureForSign.clear();
            selectedFileSignSignedName = selectedFileSignSigned.getName();
            validateFileSignatureForSign.appendText("Seçtiğiniz Dosya:\n" + selectedFileSignSignedName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileAlternativeName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForSignButtonFileSignedEnter.setDisable(false);
            processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
            processMenuForSignButtonFileValidate.setDisable(false);
            processMenuForSignButtonFileValidateActivate.setDisable(true);
            validateFileMessageForSign.setEditable(false);
            validateFileSignatureForSign.setEditable(false);
            validateFileSignatureForSign.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForSignButtonFileSignedEnterActivate() {
        processMenuForSignButtonFileSignedEnter.setDisable(false);
        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSignButtonFileValidate.setDisable(false);
        processMenuForSignButtonFileValidateActivate.setDisable(true);
        validateFileMessageForSign.setEditable(false);
        validateFileSignatureForSign.setEditable(false);
        validateFileSignatureForSign.clear();
    }

    @FXML
    private void processMenuForSignButtonFileValidate() {
        if (selectedFileSignValidate != null) {
            byte[] fileBytesValidate;
            try {
                fileBytesValidate = Files.readAllBytes(selectedFileSignValidate.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] fileFormat = selectedFileSignValidateName.split("\\.");
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
                fileBytesSignature = Files.readAllBytes(selectedFileSignSigned.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String userInputValidateKey = validateFileKeyForSign.getText();

            try {
                validateContentBytes = Algoritmalar.startFile(algoritma, null, "Doğrula", fileBytesValidateFinal, fileBytesSignature, userInputValidateKey);
            } catch (Exception error) {
                showErrorMessage("Girilen Genel Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }


            if (validateContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
                alertEntering.showAndWait();
                processMenuForSignButtonFileValidateEnter.setDisable(false);
                processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                processMenuForSignButtonFileSignedEnter.setDisable(false);
                processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                processMenuForSignButtonFileValidate.setDisable(false);
                processMenuForSignButtonFileValidateActivate.setDisable(true);
                validateFileMessageForSign.setEditable(false);
                validateFileSignatureForSign.setEditable(false);
                validateFileKeyForSign.setEditable(true);
            } else {
                if (bytesToHex(validateContentBytes).equals("3131")) {
                    Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                    alertEntering.setHeaderText("Dikkat");
                    alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                    alertEntering.showAndWait();
                    processMenuForSignButtonFileValidateEnter.setDisable(true);
                    processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                    processMenuForSignButtonFileSignedEnter.setDisable(true);
                    processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                    processMenuForSignButtonFileValidate.setDisable(true);
                    processMenuForSignButtonFileValidateActivate.setDisable(false);
                    validateFileMessageForSign.setEditable(false);
                    validateFileSignatureForSign.setEditable(false);
                    validateFileKeyForSign.setEditable(false);
                }
                if (bytesToHex(validateContentBytes).equals("31")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Sorun Yok");
                    alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                    alertEntering.showAndWait();
                    processMenuForSignButtonFileValidateEnter.setDisable(true);
                    processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
                    processMenuForSignButtonFileSignedEnter.setDisable(true);
                    processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
                    processMenuForSignButtonFileValidate.setDisable(true);
                    processMenuForSignButtonFileValidateActivate.setDisable(false);
                    validateFileMessageForSign.setEditable(false);
                    validateFileSignatureForSign.setEditable(false);
                    validateFileKeyForSign.setEditable(false);
                }
            }
        }
    }

    @FXML
    private void processMenuForSignButtonFileValidateActivate() {
        processMenuForSignButtonFileValidateEnter.setDisable(false);
        processMenuForSignButtonFileValidateEnterActivate.setDisable(true);
        processMenuForSignButtonFileSignedEnter.setDisable(false);
        processMenuForSignButtonFileSignedEnterActivate.setDisable(true);
        processMenuForSignButtonFileValidate.setDisable(false);
        processMenuForSignButtonFileValidateActivate.setDisable(true);
        validateFileMessageForSign.setEditable(false);
        validateFileSignatureForSign.setEditable(false);
        validateFileKeyForSign.setEditable(true);
    }

    public static void showErrorMessage(String message){
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
}
