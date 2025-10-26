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

public class HashController implements Initializable {

    private String algoritma;
    public VBox mainMenu;
    public Stage stage;

    public String hashInfo;
    public String hashContent;
    public byte[] hashContentBytes;
    public String matchContent;
    public byte[] matchContentBytes;

    public File selectedFileHashHash;
    public String selectedFileHashHashName;
    public File selectedFileHashMatch;
    public String selectedFileHashMatchName;

    // Bilgilendirme Tab
    @FXML
    private TextArea hashExplanation;
    @FXML
    private Button processMenuForHashButtonBack;

    // Metin Hashleme Tab
    @FXML
    private Label hashMessageExplanation;
    @FXML
    private TextArea hashMessageForHash;
    @FXML
    private Button processMenuForHashButtonHash;
    @FXML
    private Button processMenuForHashButtonHashActivate;
    @FXML
    private Button copyHashButtonForHash;
    @FXML
    private Label hashInfoLabel;

    // Metin Doğrulama Tab
    @FXML
    private Label matchMessageExplanation;
    @FXML
    private Label hashExplanationLabel;
    @FXML
    private TextArea matchMessageForHash;
    @FXML
    private TextArea hashForHash;
    @FXML
    private Button processMenuForHashButtonMatch;
    @FXML
    private Button processMenuForHashButtonMatchActivate;

    // Dosya Hashleme Tab
    @FXML
    private TextArea hashFileMessageForHash;
    @FXML
    private Button processMenuForHashButtonFileHash;
    @FXML
    private Button processMenuForHashButtonFileHashActivate;
    @FXML
    private Button copyHashFileButtonForHash;
    @FXML
    private Button processMenuForHashButtonFileHashEnter;
    @FXML
    private Button processMenuForHashButtonFileHashEnterActivate;

    // Dosya Doğrulama Tab
    @FXML
    private TextArea matchFileMessageForHash;
    @FXML
    private TextArea hashFileForHash;
    @FXML
    private Button processMenuForHashButtonFileMatch;
    @FXML
    private Button processMenuForHashButtonFileMatchActivate;
    @FXML
    private Button processMenuForHashButtonFileMatchEnter;
    @FXML
    private Button processMenuForHashButtonFileMatchEnterActivate;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        processMenuForHashButtonBack.setDisable(false);
        processMenuForHashButtonFileHashEnter.setDisable(false);
        processMenuForHashButtonFileHashEnterActivate.setDisable(true);
        processMenuForHashButtonHash.setDisable(false);
        processMenuForHashButtonHashActivate.setDisable(true);
        processMenuForHashButtonFileHash.setDisable(false);
        processMenuForHashButtonFileHashActivate.setDisable(true);
        processMenuForHashButtonFileMatchEnter.setDisable(false);
        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
        processMenuForHashButtonMatch.setDisable(false);
        processMenuForHashButtonMatchActivate.setDisable(true);
        processMenuForHashButtonFileMatch.setDisable(false);
        processMenuForHashButtonFileMatchActivate.setDisable(true);
        hashMessageForHash.setEditable(true);
        matchMessageForHash.setEditable(true);
        hashForHash.setEditable(true);
        hashFileMessageForHash.setEditable(false);
        matchFileMessageForHash.setEditable(false);
        hashFileForHash.setEditable(true);
        copyHashButtonForHash.setVisible(false);
        copyHashFileButtonForHash.setVisible(false);
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
    private void processMenuForHashButtonBack() {
        processMenuForHashButtonFileHashEnter.setDisable(false);
        processMenuForHashButtonFileHashEnterActivate.setDisable(true);
        processMenuForHashButtonHash.setDisable(false);
        processMenuForHashButtonHashActivate.setDisable(true);
        processMenuForHashButtonFileHash.setDisable(false);
        processMenuForHashButtonFileHashActivate.setDisable(true);
        processMenuForHashButtonFileMatchEnter.setDisable(false);
        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
        processMenuForHashButtonMatch.setDisable(false);
        processMenuForHashButtonMatchActivate.setDisable(true);
        processMenuForHashButtonFileMatch.setDisable(false);
        processMenuForHashButtonFileMatchActivate.setDisable(true);
        hashMessageForHash.clear();
        hashMessageForHash.setEditable(true);
        matchMessageForHash.clear();
        matchMessageForHash.setEditable(true);
        hashForHash.clear();
        hashForHash.setEditable(true);
        hashFileMessageForHash.clear();
        hashFileMessageForHash.setEditable(false);
        matchFileMessageForHash.clear();
        matchFileMessageForHash.setEditable(false);
        hashFileForHash.clear();
        hashFileForHash.setEditable(true);
        copyHashButtonForHash.setVisible(false);
        copyHashFileButtonForHash.setVisible(false);
        selectedFileHashHash = null;
        selectedFileHashMatch = null;

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
    private void processMenuForHashButtonHash() {
        String userInputHashMessage = hashMessageForHash.getText();
        try {
            hashContent = Algoritmalar.startMessage(algoritma, userInputHashMessage, "Hasle", "Hashle", "Hashle", "Hashle");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
        String[] hashInfoContent = hashContent.split("\n");

        if (hashContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Hashlenmesini İstediğiniz Metni Girin");
            alertEntering.showAndWait();
            processMenuForHashButtonHash.setDisable(false);
            processMenuForHashButtonHashActivate.setDisable(true);
            hashMessageForHash.setEditable(true);
            copyHashButtonForHash.setVisible(false);
        }

        else {
            hashInfo = hashInfoContent[0];
            processMenuForHashButtonHash.setDisable(true);
            processMenuForHashButtonHashActivate.setDisable(false);
            hashMessageForHash.setEditable(false);
            copyHashButtonForHash.setVisible(true);
        }
    }

    @FXML
    private void processMenuForHashButtonHashActivate() {
        processMenuForHashButtonHash.setDisable(false);
        processMenuForHashButtonHashActivate.setDisable(true);
        hashMessageForHash.setEditable(true);
        copyHashButtonForHash.setVisible(false);
    }

    @FXML
    private void copyHashButtonForHash() {
        String[] hash = hashInfo.split("! ");
        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(hash[1]);
        clipboard.setContent(content);

        Alert hashCopy = new Alert(Alert.AlertType.INFORMATION);
        hashCopy.setHeaderText("Hash Kopyalandı");
        hashCopy.showAndWait();
    }

    @FXML
    private void processMenuForHashButtonMatch() {
        String userInputMatch = matchMessageForHash.getText();
        String userInputHash = hashForHash.getText();
        try {
            matchContent = Algoritmalar.startMessage(algoritma, "Doğrula", "Doğrula", userInputMatch, "Doğrula", userInputHash);
        } catch (Exception error) {
            showErrorMessage("Girilen Hash Hatalıdır.");
            throw new RuntimeException(error);
        }

        if (matchContent.equals("Giriş Yapılmadı.")) {
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
            alertEntering.showAndWait();
            processMenuForHashButtonMatch.setDisable(false);
            processMenuForHashButtonMatchActivate.setDisable(true);
            matchMessageForHash.setEditable(true);
            hashForHash.setEditable(true);
        }

        else {
            if (matchContent.equals("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)")) {
                Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                alertEntering.setHeaderText("Dikkat");
                alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                alertEntering.showAndWait();
                processMenuForHashButtonMatch.setDisable(true);
                processMenuForHashButtonMatchActivate.setDisable(false);
                matchMessageForHash.setEditable(false);
                hashForHash.setEditable(false);
            }
            if (matchContent.equals("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)")) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Sorun Yok");
                alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                alertEntering.showAndWait();
                processMenuForHashButtonMatch.setDisable(true);
                processMenuForHashButtonMatchActivate.setDisable(false);
                matchMessageForHash.setEditable(false);
                hashForHash.setEditable(false);
            }
        }
    }

    @FXML
    private void processMenuForHashButtonMatchActivate() {
        processMenuForHashButtonMatch.setDisable(false);
        processMenuForHashButtonMatchActivate.setDisable(true);
        matchMessageForHash.setEditable(true);
        hashForHash.setEditable(true);
    }

    @FXML
    private void processMenuForHashButtonFileHashEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileHashHash = fileChooser.showOpenDialog(stage);
        if (selectedFileHashHash != null) {
            processMenuForHashButtonFileHashEnter.setDisable(true);
            processMenuForHashButtonFileHashEnterActivate.setDisable(false);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            hashFileMessageForHash.setEditable(false);
            hashFileMessageForHash.clear();
            selectedFileHashHashName = selectedFileHashHash.getName();
            hashFileMessageForHash.appendText("Seçtiğiniz Dosya:\n" + selectedFileHashHashName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForHashButtonFileHashEnter.setDisable(false);
            processMenuForHashButtonFileHashEnterActivate.setDisable(true);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            hashFileMessageForHash.setEditable(false);
            hashFileMessageForHash.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForHashButtonFileHashEnterActivate() {
        processMenuForHashButtonFileHashEnter.setDisable(false);
        processMenuForHashButtonFileHashEnterActivate.setDisable(true);
        processMenuForHashButtonFileHash.setDisable(false);
        processMenuForHashButtonFileHashActivate.setDisable(true);
        hashFileMessageForHash.setEditable(false);
        hashFileMessageForHash.clear();
    }

    @FXML
    private void processMenuForHashButtonFileHash() {
        if (selectedFileHashHash != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileHashHash.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            try {
                hashContentBytes = Algoritmalar.startFile(algoritma, fileBytes, "Hashle", null, null, "Hashle");
            } catch (Exception error) {
                throw new RuntimeException(error);
            }

            if (hashContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
                alertEntering.showAndWait();
                processMenuForHashButtonFileHashEnter.setDisable(false);
                processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(false);
                processMenuForHashButtonFileHashActivate.setDisable(true);
                hashFileMessageForHash.setEditable(false);
            }

            else {
                processMenuForHashButtonFileHashEnter.setDisable(true);
                processMenuForHashButtonFileHashEnterActivate.setDisable(true);
                processMenuForHashButtonFileHash.setDisable(true);
                processMenuForHashButtonFileHashActivate.setDisable(false);
                hashFileMessageForHash.setEditable(false);
                copyHashFileButtonForHash.setVisible(true);
            }
        }
        else {
            processMenuForHashButtonFileHashEnter.setDisable(false);
            processMenuForHashButtonFileHashEnterActivate.setDisable(true);
            processMenuForHashButtonFileHash.setDisable(false);
            processMenuForHashButtonFileHashActivate.setDisable(true);
            hashFileMessageForHash.setEditable(false);
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForHashButtonFileHashActivate() {
        processMenuForHashButtonFileHashEnter.setDisable(false);
        processMenuForHashButtonFileHashEnterActivate.setDisable(true);
        processMenuForHashButtonFileHash.setDisable(false);
        processMenuForHashButtonFileHashActivate.setDisable(true);
        hashFileMessageForHash.setEditable(true);
        copyHashFileButtonForHash.setVisible(false);
    }

    @FXML
    private void copyHashFileButtonForHash() {
        String[] fileFormat = selectedFileHashHashName.split("\\.");
        byte[] fileFormatBytes;
        try {
            fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
        } catch (UnsupportedEncodingException ee) {
            throw new RuntimeException(ee);
        }

        String keyInfoHex = bytesToHex(hashContentBytes);
        String fileFormatHex = bytesToHex(fileFormatBytes);
        String finalKeyHex = keyInfoHex + ":" + fileFormatHex;

        Clipboard clipboard = Clipboard.getSystemClipboard();
        ClipboardContent content = new ClipboardContent();
        content.putString(finalKeyHex);
        clipboard.setContent(content);

        Alert keyCopy = new Alert(Alert.AlertType.INFORMATION);
        keyCopy.setHeaderText("Hash Kopyalandı");
        keyCopy.showAndWait();
    }

    @FXML
    private void processMenuForHashButtonFileMatchEnter() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Dosya Seç");
        selectedFileHashMatch = fileChooser.showOpenDialog(stage);
        if (selectedFileHashMatch != null) {
            processMenuForHashButtonFileMatchEnter.setDisable(true);
            processMenuForHashButtonFileMatchEnterActivate.setDisable(false);
            processMenuForHashButtonFileMatch.setDisable(false);
            processMenuForHashButtonFileMatchActivate.setDisable(true);
            matchFileMessageForHash.setEditable(false);
            matchFileMessageForHash.clear();
            selectedFileHashMatchName = selectedFileHashMatch.getName();
            matchFileMessageForHash.appendText("Seçtiğiniz Dosya:\n" + selectedFileHashMatchName);
            //Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            //alertEntering.setHeaderText("Giriş Başarılı");
            //alertEntering.setContentText("Seçtiğiniz Dosya:\n" + selectedFileName);
            //alertEntering.showAndWait();
        }
        else {
            processMenuForHashButtonFileMatchEnter.setDisable(false);
            processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
            processMenuForHashButtonFileMatch.setDisable(false);
            processMenuForHashButtonFileMatchActivate.setDisable(true);
            matchFileMessageForHash.setEditable(false);
            matchFileMessageForHash.clear();
            Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
            alertEntering.setHeaderText("Giriş Yapılmadı");
            alertEntering.setContentText("Lütfen Şifrelenmesini İstediğiniz Dosyayı Girin");
            alertEntering.showAndWait();
        }
    }

    @FXML
    private void processMenuForHashButtonFileMatchEnterActivate() {
        processMenuForHashButtonFileMatchEnter.setDisable(false);
        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
        processMenuForHashButtonFileMatch.setDisable(false);
        processMenuForHashButtonFileMatchActivate.setDisable(true);
        matchFileMessageForHash.setEditable(false);
        matchFileMessageForHash.clear();
    }

    @FXML
    private void processMenuForHashButtonFileMatch() {
        if (selectedFileHashMatch != null) {
            byte[] fileBytes;
            try {
                fileBytes = Files.readAllBytes(selectedFileHashMatch.toPath());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            String[] fileFormat = selectedFileHashMatchName.split("\\.");
            byte[] fileFormatBytes;
            try {
                fileFormatBytes = fileFormat[fileFormat.length - 1].getBytes("UTF-8");
            } catch (UnsupportedEncodingException ee) {
                throw new RuntimeException(ee);
            }

            byte[] numbers = new byte[] {0x01, 0x23, 0x45, 0x67, 0x76, 0x54, 0x32, 0x10, 0x31};
            byte[] fileBytesFinal = new byte[fileBytes.length+9+fileFormatBytes.length];
            System.arraycopy(fileBytes, 0, fileBytesFinal, 0, fileBytes.length);
            System.arraycopy(numbers, 0, fileBytesFinal, fileBytes.length, 9);
            System.arraycopy(fileFormatBytes, 0, fileBytesFinal, fileBytes.length+9, fileFormatBytes.length);

            String userInputHash = hashFileForHash.getText();

            try {
                matchContentBytes = Algoritmalar.startFile(algoritma, null, "Doğrula", fileBytesFinal, null, userInputHash);
            } catch (Exception error) {
                showErrorMessage("Girilen Hash Hatalıdır.");
                throw new RuntimeException(error);
            }

            if (matchContentBytes == null) {
                Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                alertEntering.setHeaderText("Giriş Yapılmadı");
                alertEntering.setContentText("Lütfen Şüphelendiğiniz Metni ve Hashi Girin");
                alertEntering.showAndWait();
                processMenuForHashButtonFileMatchEnter.setDisable(false);
                processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                processMenuForHashButtonFileMatch.setDisable(false);
                processMenuForHashButtonFileMatchActivate.setDisable(true);
                hashFileMessageForHash.setEditable(false);
                hashFileForHash.setEditable(true);
            } else {
                if (bytesToHex(matchContentBytes).equals("3131")) {
                    Alert alertEntering = new Alert(Alert.AlertType.WARNING);
                    alertEntering.setHeaderText("Dikkat");
                    alertEntering.setContentText("Eşleşme Gerçekleşmedi. (Elinizdeki Orijinal Metin Değil.)");
                    alertEntering.showAndWait();
                    processMenuForHashButtonFileMatchEnter.setDisable(true);
                    processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                    processMenuForHashButtonFileMatch.setDisable(true);
                    processMenuForHashButtonFileMatchActivate.setDisable(false);
                    matchFileMessageForHash.setEditable(false);
                    hashFileForHash.setEditable(false);
                }
                if (bytesToHex(matchContentBytes).equals("31")) {
                    Alert alertEntering = new Alert(Alert.AlertType.INFORMATION);
                    alertEntering.setHeaderText("Sorun Yok");
                    alertEntering.setContentText("Eşleşme Gerçekleşti. (Elinizdeki Orijinal Metin.)");
                    alertEntering.showAndWait();
                    processMenuForHashButtonFileMatchEnter.setDisable(true);
                    processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
                    processMenuForHashButtonFileMatch.setDisable(true);
                    processMenuForHashButtonFileMatchActivate.setDisable(false);
                    matchFileMessageForHash.setEditable(false);
                    hashFileForHash.setEditable(false);
                }
            }
        }
    }

    @FXML
    private void processMenuForHashButtonFileMatchActivate() {
        processMenuForHashButtonFileMatchEnter.setDisable(false);
        processMenuForHashButtonFileMatchEnterActivate.setDisable(true);
        processMenuForHashButtonFileMatch.setDisable(false);
        processMenuForHashButtonFileMatchActivate.setDisable(true);
        matchFileMessageForHash.setEditable(false);
        hashFileForHash.setEditable(true);
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