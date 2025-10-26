package org.example.gui;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import org.example.algoritmalar.Algoritmalar;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.ResourceBundle;

public class AsymmetricController implements Initializable {

    private String algoritma;
    public VBox mainMenu;
    public Stage stage;

    public Label encryptKeyInfo;
    public byte[] encryptKeyInfoBytes;
    public byte[] publicKeyInfoBytes;
    public byte[] publicKeyfileFormatBytes;
    public Label decryptionInfo;
    public Label decryptKeyInfo;
    public byte[] decryptKeyInfoBytes;
    public Label encryptedMessageInfo;
    public String encryptionContent;
    public byte[] encryptionContentBytes;
    public String decryptinContent;
    public byte[] decryptionContentBytes;
    public String keysContent;
    public byte[] keysContentBytes;

    public File selectedFileAsymmetricEncrypt;
    public String selectedFileAsymmetricEncryptName;
    public File selectedFileAsymmetricDecrypt;
    public String selectedFileAsymmetricDecryptName;


    // Bilgilendirme Tab
    @FXML
    private TextArea asymmetricExplanation;
    @FXML
    private Button processMenuForAsymmetricButtonBack;

    // Metin Anahtarları Oluşturma Tab
    @FXML
    private Label keysExplanation;
    @FXML
    private Label encryptKeyInfoLabel;
    @FXML
    private Label decryptKeyInfoLabel;
    @FXML
    private Button processMenuForAsymmetricButtonGenerateKeys;
    @FXML
    private Button processMenuForAsymmetricButtonGenerateKeysActivate;
    @FXML
    private Button copyEncryptKeyButtonForAsymmetric;
    @FXML
    private Button copyDecryptKeyButtonForAsymmetric;

    // Metin Şifreleme Tab
    @FXML
    private Label encryptMessageExplanation;
    @FXML
    private Label encryptKeyExplanation;
    @FXML
    private Label encryptedMessageInfoLabel;
    @FXML
    private TextArea encryptMessageForAsymmetric;
    @FXML
    private TextArea encryptKeyForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonEncrypt;
    @FXML
    private Button processMenuForAsymmetricButtonEncryptActivate;
    @FXML
    private Button copyEncryptedMessageButtonForAsymmetric;

    // Metin Çözme Tab
    @FXML
    private Label decryptMessageExplanation;
    @FXML
    private Label decryptKeyExplanation;
    @FXML
    private Label decryptionInfoLabel;
    @FXML
    private TextArea decryptMessageForAsymmetric;
    @FXML
    private TextArea decryptKeyForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonDecrypt;
    @FXML
    private Button processMenuForAsymmetricButtonDecryptActivate;
    @FXML
    private Button copyDecryptedMessageButtonForAsymmetric;

    // Dosya Anahtarları Oluşturma Tab
    @FXML
    private Button processMenuForAsymmetricButtonGenerateKeysFile;
    @FXML
    private Button copyEncryptKeyFileButtonForAsymmetric;
    @FXML
    private Button copyDecryptKeyFileButtonForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonGenerateKeysFileActivate;

    // Dosya Şifreleme Tab
    @FXML
    private Label encryptInfoLabel;
    @FXML
    private TextArea encryptFileMessageForAsymmetric;
    @FXML
    private TextArea encryptFileKeyForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonFileEncrypt;
    @FXML
    private Button processMenuForAsymmetricButtonFileEncryptActivate;
    @FXML
    private Button saveEncryptFileButtonForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonFileEncryptEnter;
    @FXML
    private Button processMenuForAsymmetricButtonFileEncryptEnterActivate;

    // Dosya Çözme Tab
    @FXML
    private Label decryptInfoLabel;
    @FXML
    private TextArea decryptFileMessageForAsymmetric;
    @FXML
    private TextArea decryptFileKeyForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonFileDecrypt;
    @FXML
    private Button processMenuForAsymmetricButtonFileDecryptActivate;
    @FXML
    private Button saveDecryptFileButtonForAsymmetric;
    @FXML
    private Button processMenuForAsymmetricButtonFileDecryptEnter;
    @FXML
    private Button processMenuForAsymmetricButtonFileDecryptEnterActivate;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        processMenuForAsymmetricButtonBack.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
        processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonEncrypt.setDisable(false);
        processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonDecrypt.setDisable(false);
        processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
        encryptMessageForAsymmetric.setEditable(true);
        encryptKeyForAsymmetric.setEditable(true);
        decryptMessageForAsymmetric.setEditable(true);
        decryptKeyForAsymmetric.setEditable(true);
        encryptFileMessageForAsymmetric.setEditable(false);
        encryptFileKeyForAsymmetric.setEditable(true);
        decryptFileMessageForAsymmetric.setEditable(false);
        decryptFileKeyForAsymmetric.setEditable(true);
        copyEncryptKeyButtonForAsymmetric.setVisible(false);
        copyEncryptKeyFileButtonForAsymmetric.setVisible(false);
        copyDecryptKeyButtonForAsymmetric.setVisible(false);
        copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
        copyEncryptedMessageButtonForAsymmetric.setVisible(false);
        saveEncryptFileButtonForAsymmetric.setVisible(false);
        copyDecryptedMessageButtonForAsymmetric.setVisible(false);
        saveDecryptFileButtonForAsymmetric.setVisible(false);
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
    private void processMenuForAsymmetricButtonBack() {
        processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
        processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonEncrypt.setDisable(false);
        processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonDecrypt.setDisable(false);
        processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
        encryptMessageForAsymmetric.clear();
        encryptMessageForAsymmetric.setEditable(true);
        encryptKeyForAsymmetric.clear();
        encryptKeyForAsymmetric.setEditable(true);
        decryptMessageForAsymmetric.clear();
        decryptMessageForAsymmetric.setEditable(true);
        decryptKeyForAsymmetric.clear();
        decryptKeyForAsymmetric.setEditable(true);
        encryptFileMessageForAsymmetric.clear();
        encryptFileMessageForAsymmetric.setEditable(false);
        encryptFileKeyForAsymmetric.clear();
        encryptFileKeyForAsymmetric.setEditable(false);
        decryptFileMessageForAsymmetric.clear();
        decryptFileMessageForAsymmetric.setEditable(false);
        decryptFileKeyForAsymmetric.clear();
        decryptFileKeyForAsymmetric.setEditable(false);
        copyEncryptKeyButtonForAsymmetric.setVisible(false);
        copyDecryptKeyButtonForAsymmetric.setVisible(false);
        copyEncryptedMessageButtonForAsymmetric.setVisible(false);
        saveEncryptFileButtonForAsymmetric.setVisible(false);
        copyDecryptedMessageButtonForAsymmetric.setVisible(false);
        saveDecryptFileButtonForAsymmetric.setVisible(false);
        selectedFileAsymmetricEncrypt = null;
        selectedFileAsymmetricDecrypt = null;

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

    // Metin Anahtarları Oluşturma Tab
    @FXML
    private void processMenuForAsymmetricButtonGenerateKeys() {
        try {
            keysContent = Algoritmalar.startMessage(algoritma, "Anahtar", "Anahtar", "Anahtar", "Anahtar", "Anahtar");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
        String[] keysInfoContent = keysContent.split("\n");


        encryptKeyInfo = new Label(keysInfoContent[0]);
        String[] parts1 = encryptKeyInfo.getText().split("! ");
        decryptKeyInfo = new Label(keysInfoContent[1]);
        String[] parts2 = decryptKeyInfo.getText().split("! ");
        processMenuForAsymmetricButtonGenerateKeys.setDisable(true);
        processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(false);
        copyEncryptKeyButtonForAsymmetric.setVisible(true);
        copyDecryptKeyButtonForAsymmetric.setVisible(true);
    }

    @FXML
    private void processMenuForAsymmetricButtonGenerateKeysActivate() {
        processMenuForAsymmetricButtonGenerateKeys.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysActivate.setDisable(true);
        copyEncryptKeyButtonForAsymmetric.setVisible(false);
        copyDecryptKeyButtonForAsymmetric.setVisible(false);
    }

    @FXML
    private void copyEncryptKeyButtonForAsymmetric() {
        String[] encryptKey = encryptKeyInfo.getText().split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(encryptKey[1]);
        clipboard.setContent(content);

        Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        encryptKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
        encryptKeyCopy.showAndWait();
    }

    @FXML
    private void copyDecryptKeyButtonForAsymmetric() {
        String[] decryptKey = decryptKeyInfo.getText().split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(decryptKey[1]);
        clipboard.setContent(content);

        Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        encryptKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
        encryptKeyCopy.showAndWait();
    }

    // Metin Şifreleme Tab
    @FXML
    private void processMenuForAsymmetricButtonEncrypt() {
        String userInputEncryptMessage = encryptMessageForAsymmetric.getText();
        String userInputEncryptKey = encryptKeyForAsymmetric.getText();
        try {
            encryptionContent = Algoritmalar.startMessage(algoritma, userInputEncryptMessage, userInputEncryptKey, "Şifrele", "Şifrele", "Şifrele");
        } catch (Exception error) {
            showErrorMessage("Şifrelemek İstediğiniz Metin Çok Büyük ya da Girilen Genel Anahtar Hatalıdır.");
            throw new RuntimeException(error);
        }
        String[] encryptInfoContent = encryptionContent.split("\n");

        if (encryptionContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Metni ve Genel Anahtarı Girin");
            alertEntering.showAndWait();
            processMenuForAsymmetricButtonEncrypt.setDisable(false);
            processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
            encryptMessageForAsymmetric.setEditable(true);
            encryptKeyForAsymmetric.setEditable(true);
            copyEncryptedMessageButtonForAsymmetric.setVisible(false);
        }

        else {
            encryptedMessageInfo = new Label(encryptInfoContent[0]);
            String[] parts1 = encryptedMessageInfo.getText().split("! ");
            processMenuForAsymmetricButtonEncrypt.setDisable(true);
            processMenuForAsymmetricButtonEncryptActivate.setDisable(false);
            encryptMessageForAsymmetric.setEditable(false);
            encryptKeyForAsymmetric.setEditable(false);
            copyEncryptedMessageButtonForAsymmetric.setVisible(true);
        }
    }

    @FXML
    private void processMenuForAsymmetricButtonEncryptActivate() {
        processMenuForAsymmetricButtonEncrypt.setDisable(false);
        processMenuForAsymmetricButtonEncryptActivate.setDisable(true);
        encryptMessageForAsymmetric.setEditable(true);
        encryptKeyForAsymmetric.setEditable(true);
        copyEncryptedMessageButtonForAsymmetric.setVisible(false);
    }

    @FXML
    private void copyEncryptedMessageButtonForAsymmetric() {
        String[] message = encryptedMessageInfo.getText().split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(message[1]);
        clipboard.setContent(content);

        Alert messageEncrypted = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypted.setHeaderText("Şifreli Mesaj Kopyalandı");
        messageEncrypted.showAndWait();
    }

    // Metin Çözme Tab
    @FXML
    private void processMenuForAsymmetricButtonDecrypt() {
        String userInputDecryptMessage = decryptMessageForAsymmetric.getText();
        String userInputDecryptKey = decryptKeyForAsymmetric.getText();
        try {
            decryptinContent = Algoritmalar.startMessage(algoritma, "Çöz", "Çöz", userInputDecryptMessage, "Çöz", userInputDecryptKey);
        } catch (Exception error) {
            showErrorMessage("Girilen Şifreli Metin ya da Özel Anahtar Hatalıdır.");
            throw new RuntimeException(error);
        }

        if (decryptinContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Metni ve Özel Anahtarı Girin");
            alertEntering.showAndWait();
            processMenuForAsymmetricButtonDecrypt.setDisable(false);
            processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
            decryptMessageForAsymmetric.setEditable(true);
            decryptKeyForAsymmetric.setEditable(true);
            copyDecryptedMessageButtonForAsymmetric.setVisible(false);
        }

        else {
            decryptionInfo = new Label(decryptinContent);
            String[] parts1 = decryptionInfo.getText().split("! ");
            processMenuForAsymmetricButtonDecrypt.setDisable(true);
            processMenuForAsymmetricButtonDecryptActivate.setDisable(false);
            decryptMessageForAsymmetric.setEditable(false);
            decryptKeyForAsymmetric.setEditable(false);
            copyDecryptedMessageButtonForAsymmetric.setVisible(true);
        }
    }

    @FXML
    private void processMenuForAsymmetricButtonDecryptActivate() {
        processMenuForAsymmetricButtonDecrypt.setDisable(false);
        processMenuForAsymmetricButtonDecryptActivate.setDisable(true);
        decryptMessageForAsymmetric.setEditable(true);
        decryptKeyForAsymmetric.setEditable(true);
    }

    @FXML
    private void copyDecryptedMessageButtonForAsymmetric() {
        String[] message = decryptionInfo.getText().split("Şifresi çözülmüş metin oluşturuldu! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(message[1]);
        clipboard.setContent(content);

        Alert messageDecryption = new Alert(Alert.AlertType.INFORMATION);
        messageDecryption.setHeaderText("Şifresi Çözülmüş Mesaj Kopyalandı");
        messageDecryption.showAndWait();
    }

    // Dosya Anahtarları Oluşturma Tab
    @FXML
    private void processMenuForAsymmetricButtonGenerateKeysFile() {
        try {
            keysContentBytes = Algoritmalar.startFile(algoritma, null, "Anahtar", null, null, "Anahtar");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
        String keysInfoContent = bytesToHex(keysContentBytes);
        String[] partsPublicAndPrivate = keysInfoContent.split("012345677654321031012345677654321031");

        encryptKeyInfoBytes = hexToBytes(partsPublicAndPrivate[0]);
        Label encryptKeyInfoLabel = new Label("Genel anahtar oluşturuldu!");
        decryptKeyInfoBytes = hexToBytes(partsPublicAndPrivate[1]);
        Label decryptKeyInfoLabel = new Label("Özel anahtar oluşturuldu!");
        processMenuForAsymmetricButtonGenerateKeysFile.setDisable(true);
        processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(false);
        copyEncryptKeyFileButtonForAsymmetric.setVisible(true);
        copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
    }

    @FXML
    private void processMenuForAsymmetricButtonGenerateKeysFileActivate() {
        processMenuForAsymmetricButtonGenerateKeysFile.setDisable(false);
        processMenuForAsymmetricButtonGenerateKeysFileActivate.setDisable(true);
        copyEncryptKeyFileButtonForAsymmetric.setVisible(false);
        copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
    }

    @FXML
    private void copyEncryptKeyFileButtonForAsymmetric() {
        String encryptKey = bytesToHex(encryptKeyInfoBytes);
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(encryptKey);
        clipboard.setContent(content);

        Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        encryptKeyCopy.setHeaderText("Genel Anahtar Kopyalandı");
        encryptKeyCopy.showAndWait();
    }

    @FXML
    private void copyDecryptKeyFileButtonForAsymmetric() {
        String decryptKey = bytesToHex(decryptKeyInfoBytes);
        String fileFormat = bytesToHex(publicKeyfileFormatBytes);
        String decryptKeyAndFormat = decryptKey + ":" + fileFormat;

        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(decryptKeyAndFormat);
        clipboard.setContent(content);

        Alert encryptKeyCopy = new Alert(Alert.AlertType.INFORMATION);
        encryptKeyCopy.setHeaderText("Özel Anahtar Kopyalandı");
        encryptKeyCopy.showAndWait();
    }

    // Dosya Şifreleme Tab
    @FXML
    private void processMenuForAsymmetricButtonFileEncryptEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileAsymmetricEncrypt = fileChooser.showOpenDialog(stage);
        if (selectedFileAsymmetricEncrypt != null) {
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(false);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            encryptFileMessageForAsymmetric.setEditable(false);
            encryptFileKeyForAsymmetric.setEditable(true);
            encryptFileMessageForAsymmetric.clear();
            selectedFileAsymmetricEncryptName = selectedFileAsymmetricEncrypt.getName();
            encryptFileMessageForAsymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileAsymmetricEncryptName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            encryptFileMessageForAsymmetric.setEditable(false);
            encryptFileKeyForAsymmetric.setEditable(true);
            encryptFileMessageForAsymmetric.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForAsymmetricButtonFileEncryptEnterActivate() {
        processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
        encryptFileMessageForAsymmetric.setEditable(false);
        encryptFileKeyForAsymmetric.setEditable(true);
        encryptFileMessageForAsymmetric.clear();
    }

    @FXML
    private void processMenuForAsymmetricButtonFileEncrypt() {
        if (selectedFileAsymmetricEncrypt != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileAsymmetricEncrypt.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] fileFormat = selectedFileAsymmetricEncryptName.split("\\.");
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


            String userInputKey = encryptFileKeyForAsymmetric.getText();

            try {
                encryptionContentBytes = Algoritmalar.startFile(algoritma, fileBytesAll, userInputKey, null, null, "Şifrele");
            } catch (Exception error) {
                showErrorMessage("Girilen Dosya ya da Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (bytesToHex(encryptionContentBytes).equals("31")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Dosya Şifrelenemiyor");
                alertEntering.setContentText("Girilen Dosya Çok Büyük");
                alertEntering.showAndWait();
                throw new RuntimeException("Girilen Dosya Çok Büyük");
            }

            if (encryptionContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(false);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
                encryptFileMessageForAsymmetric.setEditable(false);
                encryptFileKeyForAsymmetric.setEditable(true);
                saveEncryptFileButtonForAsymmetric.setVisible(false);
            }

            else {
                String keyAndFormat = bytesToHex(encryptionContentBytes);
                String[] parts = keyAndFormat.split("012345677654321031");
                publicKeyInfoBytes = hexToBytes(parts[0]);
                publicKeyfileFormatBytes = hexToBytes(parts[1]);
                processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonFileEncrypt.setDisable(true);
                processMenuForAsymmetricButtonFileEncryptActivate.setDisable(false);
                encryptFileMessageForAsymmetric.setEditable(false);
                encryptFileKeyForAsymmetric.setEditable(false);
                copyDecryptKeyFileButtonForAsymmetric.setVisible(true);
                saveEncryptFileButtonForAsymmetric.setVisible(true);
            }
        }
        else {
            processMenuForAsymmetricButtonFileEncryptEnter.setDisable(true);
            processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(false);
            processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
            processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
            encryptFileMessageForAsymmetric.setEditable(false);
            encryptFileKeyForAsymmetric.setEditable(true);
            saveEncryptFileButtonForAsymmetric.setVisible(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForAsymmetricButtonFileEncryptActivate() {
        processMenuForAsymmetricButtonFileEncryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonFileEncrypt.setDisable(false);
        processMenuForAsymmetricButtonFileEncryptActivate.setDisable(true);
        encryptFileMessageForAsymmetric.setEditable(false);
        encryptFileKeyForAsymmetric.setEditable(true);
        copyDecryptKeyFileButtonForAsymmetric.setVisible(false);
        saveEncryptFileButtonForAsymmetric.setVisible(false);
    }

    @FXML
    private void saveEncryptFileButtonForAsymmetric() {
        byte[] bytes = publicKeyInfoBytes;
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Oluşturulan Şifreli Dosyayı Kaydet");
        fileChooser.setInitialFileName("sifreli_dosya");
        FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("Şifrelenmiş Dosyalar", "*.bin");
        fileChooser.getExtensionFilters().add(fileFormat);
        fileChooser.getSelectedExtensionFilter();
        File file = fileChooser.showSaveDialog(stage);
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("Şifreli Dosya Kaydedildi");
        messageEncrypt.showAndWait();
    }

    // Dosya Çözme Tab
    @FXML
    private void processMenuForAsymmetricButtonFileDecryptEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileAsymmetricDecrypt = fileChooser.showOpenDialog(stage);
        if (selectedFileAsymmetricDecrypt != null) {
            processMenuForAsymmetricButtonFileDecryptEnter.setDisable(true);
            processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(false);
            processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
            decryptFileMessageForAsymmetric.setEditable(false);
            decryptFileKeyForAsymmetric.setEditable(true);
            decryptFileMessageForAsymmetric.clear();
            selectedFileAsymmetricDecryptName = selectedFileAsymmetricDecrypt.getName();
            decryptFileMessageForAsymmetric.appendText("Seçtiğiniz Dosya:\n" + selectedFileAsymmetricDecryptName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
            decryptFileMessageForAsymmetric.setEditable(false);
            decryptFileKeyForAsymmetric.setEditable(true);
            decryptFileMessageForAsymmetric.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForAsymmetricButtonFileDecryptEnterActivate() {
        processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
        decryptFileMessageForAsymmetric.setEditable(false);
        decryptFileKeyForAsymmetric.setEditable(true);
        decryptFileMessageForAsymmetric.clear();
    }

    @FXML
    private void processMenuForAsymmetricButtonFileDecrypt() {
        if (selectedFileAsymmetricDecrypt != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileAsymmetricDecrypt.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            String userInputDecryptKey = decryptFileKeyForAsymmetric.getText();

            try {
                decryptionContentBytes = Algoritmalar.startFile(algoritma, null, "Çöz", fileBytes, null, userInputDecryptKey);
            } catch (Exception error) {
                showErrorMessage("Girilen Dosya ya da Anahtar Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (decryptionContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifresinin Çözülmesini İstediğiniz Şifreli Dosyayı ve Anahtarı Girin");
                alertEntering.showAndWait();
                processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
                processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
                decryptFileMessageForAsymmetric.setEditable(false);
                decryptFileKeyForAsymmetric.setEditable(true);
                saveDecryptFileButtonForAsymmetric.setVisible(false);
            }

            else {
                Label decryptInfoLabel = new Label("Dosya çözüldü!");
                processMenuForAsymmetricButtonFileDecryptEnter.setDisable(true);
                processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
                processMenuForAsymmetricButtonFileDecrypt.setDisable(true);
                processMenuForAsymmetricButtonFileDecryptActivate.setDisable(false);
                decryptFileMessageForAsymmetric.setEditable(false);
                decryptFileKeyForAsymmetric.setEditable(false);
                saveDecryptFileButtonForAsymmetric.setVisible(true);
            }
        }
        else {
            processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
            processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
            processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
            decryptFileMessageForAsymmetric.setEditable(false);
            decryptFileKeyForAsymmetric.setEditable(true);
            saveDecryptFileButtonForAsymmetric.setVisible(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı ve Anahtarı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForAsymmetricButtonFileDecryptActivate() {
        processMenuForAsymmetricButtonFileDecryptEnter.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptEnterActivate.setDisable(true);
        processMenuForAsymmetricButtonFileDecrypt.setDisable(false);
        processMenuForAsymmetricButtonFileDecryptActivate.setDisable(true);
        decryptFileMessageForAsymmetric.setEditable(false);
        decryptFileKeyForAsymmetric.setEditable(true);
        saveDecryptFileButtonForAsymmetric.setVisible(false);
    }

    @FXML
    private void saveDecryptFileButtonForAsymmetric() {
        String separate = bytesToHex(decryptionContentBytes);
        String[] parts = separate.split("012345677654321031");

        byte[] keyInfoBytes = hexToBytes(parts[0]);
        byte[] fileFormatBytes = hexToBytes(parts[1]);

        byte[] bytes = keyInfoBytes;
        byte[] fileNameFormatBytes = fileFormatBytes;
        String fileNameFormat = new String(fileNameFormatBytes, StandardCharsets.UTF_8);

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Çözülmüş Dosyayı Kaydet");
        fileChooser.setInitialFileName("cozulmus_dosya");
        FileChooser.ExtensionFilter fileFormat = new FileChooser.ExtensionFilter("Şifrelenmiş Dosyalar", "*." + fileNameFormat);
        fileChooser.getExtensionFilters().add(fileFormat);
        fileChooser.getSelectedExtensionFilter();
        File file = fileChooser.showSaveDialog(stage);
        try {
            Files.write(file.toPath(), bytes);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        Alert messageEncrypt = new Alert(Alert.AlertType.INFORMATION);
        messageEncrypt.setHeaderText("Şifresi Çözülmüş Dosya Kaydedildi");
        messageEncrypt.showAndWait();
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