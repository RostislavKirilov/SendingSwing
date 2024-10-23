import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class DigitalSignatureApp extends JFrame {
    private JButton uploadButton;
    private JButton selectSignatureButton;
    private JButton sendButton;

    private List<File> selectedFiles = new ArrayList<>();
    private File signatureFile;
    private String password;

    private static final int N = 5; 

    private JProgressBar progressBar;
    private JTextArea logArea;

    public DigitalSignatureApp() {
        setTitle("Digital Signature Application");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        uploadButton = new JButton("Качи файлове");
        selectSignatureButton = new JButton("Избери електронен подпис");
        sendButton = new JButton("Подпиши и изпрати към API");

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logArea);

        uploadButton.addActionListener(new UploadAction());
        selectSignatureButton.addActionListener(new SelectSignatureAction());
        sendButton.addActionListener(new SendAction());

        JPanel buttonPanel = new JPanel(new GridLayout(1, 3, 10, 10));
        buttonPanel.add(uploadButton);
        buttonPanel.add(selectSignatureButton);
        buttonPanel.add(sendButton);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
        mainPanel.add(buttonPanel, BorderLayout.NORTH);
        mainPanel.add(progressBar, BorderLayout.SOUTH);
        mainPanel.add(logScrollPane, BorderLayout.CENTER);

        add(mainPanel);
    }

    private class UploadAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setMultiSelectionEnabled(true);
            int option = fileChooser.showOpenDialog(DigitalSignatureApp.this);
            if (option == JFileChooser.APPROVE_OPTION) {
                File[] files = fileChooser.getSelectedFiles();
                selectedFiles.clear();
                for (File file : files) {
                    selectedFiles.add(file);
                }
                log("Качени файлове: " + selectedFiles.size());
                JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Качени файлове: " + selectedFiles.size());
            }
        }
    }

    private class SelectSignatureAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Избери електронен подпис (PKCS#12 файл)");
            int option = fileChooser.showOpenDialog(DigitalSignatureApp.this);
            if (option == JFileChooser.APPROVE_OPTION) {
                signatureFile = fileChooser.getSelectedFile();
                log("Избран електронен подпис: " + signatureFile.getAbsolutePath());
                JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Избран електронен подпис: " + signatureFile.getName());
            }
        }
    }

    private class SendAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (selectedFiles.isEmpty()) {
                JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Няма качени файлове.");
                return;
            }
            if (signatureFile == null) {
                JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Не е избран електронен подпис.");
                return;
            }

            password = JOptionPane.showInputDialog(DigitalSignatureApp.this, "Въведете парола за електронния подпис:");
            if (password == null || password.isEmpty()) {
                JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Паролата е задължителна.");
                return;
            }

            SignatureAndSendTask task = new SignatureAndSendTask(selectedFiles, signatureFile, password);
            task.execute();
        }
    }

    private class SignatureAndSendTask extends SwingWorker<Void, String> {
        private List<File> filesToSign;
        private File signatureFile;
        private String password;

        public SignatureAndSendTask(List<File> files, File signatureFile, String password) {
            this.filesToSign = new ArrayList<>(files);
            this.signatureFile = signatureFile;
            this.password = password;
        }

        @Override
        protected Void doInBackground() {
            try {
                // Инициализиране на Bouncy Castle
                Security.addProvider(new BouncyCastleProvider());

                // Зареждане на ключовете от електронния подпис
                KeyStore keystore = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(signatureFile)) {
                    keystore.load(fis, password.toCharArray());
                }

                String alias = null;
                // Избор на първия алиас
                for (String a : java.util.Collections.list(keystore.aliases())) {
                    alias = a;
                    break;
                }

                if (alias == null) {
                    publish("Не може да се намери алиас в ключовия магазин.");
                    return null;
                }

                PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
                Certificate certificate = keystore.getCertificate(alias);
                if (privateKey == null || certificate == null) {
                    publish("Не може да се намери частен ключ или сертификат.");
                    return null;
                }

                List<File> signedFiles = new ArrayList<>();
                int totalFiles = filesToSign.size();
                int count = 0;

                for (File file : filesToSign) {
                    count++;
                    publish("Подписване на файл: " + file.getName() + " (" + count + "/" + totalFiles + ")");
                    File signedFile = signFile(file, privateKey, certificate);
                    signedFiles.add(signedFile);
                    int progress = (int) ((count / (double) totalFiles) * 50); // 50% за подписване
                    setProgress(progress);
                }

                // Изпращане към API
                publish("Изпращане на подписаните файлове към API...");
                sendToAPI(signedFiles);
                setProgress(100);
                publish("Файловете бяха успешно подписани и изпратени към API.");
            } catch (Exception ex) {
                ex.printStackTrace();
                publish("Възникна грешка: " + ex.getMessage());
            }
            return null;
        }

        @Override
        protected void process(List<String> chunks) {
            for (String message : chunks) {
                log(message);
            }
        }

        @Override
        protected void done() {
            JOptionPane.showMessageDialog(DigitalSignatureApp.this, "Процесът приключи. Проверете логовете за детайли.");
        }
    }

    private File signFile(File inputFile, PrivateKey privateKey, Certificate certificate) throws Exception {

        byte[] fileData = readFileToByteArray(inputFile);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(sha256Signer, (X509Certificate) certificate));

        generator.addCertificate(new JcaX509CertificateHolder((X509Certificate) certificate));

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(fileData);
        CMSSignedData signedData = generator.generate(cmsData, true);

        File signedFile = new File(inputFile.getParent(), inputFile.getName() + ".p7s");
        try (FileOutputStream fos = new FileOutputStream(signedFile)) {
            fos.write(signedData.getEncoded());
        }

        return signedFile;
    }

    private byte[] readFileToByteArray(File file) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        }
    }

    private void sendToAPI(List<File> files) throws Exception {
        String apiUrl = "https://testss.free.beeceptor.com";

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost uploadFile = new HttpPost(apiUrl);
            MultipartEntityBuilder builder = MultipartEntityBuilder.create();
            for (File file : files) {
                builder.addPart("files", new FileBody(file));
            }
            HttpEntity multipart = builder.build();
            uploadFile.setEntity(multipart);

            try (CloseableHttpResponse response = httpClient.execute(uploadFile)) {
                HttpEntity responseEntity = response.getEntity();
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == 200 || statusCode == 201) {
                    log("Файловете бяха успешно изпратени към API. Статус код: " + statusCode);
                } else {
                    throw new IOException("Неуспешен отговор от API: " + statusCode);
                }
            }
        }
    }
    private void log(String message) {
        logArea.append(message + "\n");
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> {
            DigitalSignatureApp app = new DigitalSignatureApp();
            app.setVisible(true);
        });
    }
}
