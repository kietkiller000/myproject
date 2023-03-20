/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package cd3aeschuanchuanchuan1;

import cd3aeschuanchuanchuan.*;
import cd3aeschuanchuan.*;
import cd3aeschuan.*;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

/**
 *
 * @author Admin
 */
public class AES_Demo extends javax.swing.JFrame {

    /**
     * Creates new form AES_Demo
     */
    public AES_Demo() {
        initComponents();
        setLocationRelativeTo(this);
    }

    // Đọc file
    public static byte[] keygeneration(int num) throws Exception {

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(num);
        SecretKey key = generator.generateKey();
        return key.getEncoded();

    }

    public static String readFile(String fileName) {
        InputStream inStream = null;
        String fileContent = "";

        try {
            inStream = new FileInputStream(fileName);

            int fileSize = inStream.available();
            for (int i = 0; i < fileSize; i++) {
                fileContent += (char) inStream.read();
            }

        } catch (Exception e) {
            System.err.println("File not found: " + fileName);
        } finally {
            try {
                if (inStream != null) {
                    inStream.close();
                }
            } catch (Exception ex) {
                System.err.println("Error while closing File I/O: " + ex);
            }
        }

        return fileContent;
    }

    // Ghi file
    public static void writeFile(String fileName, String fileContent) {
        OutputStream outStream = null;
        try {
            outStream = new FileOutputStream(fileName);

            byte[] fileContentBytes = fileContent.getBytes();

            outStream.write(fileContentBytes);

        } catch (Exception e) {
            System.err.println("Error while writing into file " + fileName + ": " + e);
        } finally {
            try {
                if (outStream != null) {
                    outStream.close();
                }
            } catch (Exception ex) {
                System.err.println("Error while closing File I/O: " + ex);
            }
        }
    }

//    public void writeFile(String fileName, String fileContent) {
//        Writer writer = null;
//        try {
////        File inputFile = jFileChooser2.getSelectedFile();
//                File SaveFile = jFileChooser2.getSelectedFile();
//                Path path = Paths.get(SaveFile.getAbsolutePath());
//                SaveFile = new File(jFileChooser2.getSelectedFile() + "/decryptedimage.jpg");
//                FileOutputStream fos = new FileOutputStream(SaveFile);
//                fos.write(fileContent);
//                fos.flush();
//                fos.close();
//        
////            writer = new OutputStreamWriter(new FileOutputStream(fileName), "UTF-8");
////
////            writer.write(fileContent);
//
//        } catch (Exception e) {
//            System.err.println("Error while writing into file " + fileName + ": " + e);
//        } finally {
//            try {
//                if (writer != null) {
//                    writer.close();
//                }
//            } catch (Exception ex) {
//                System.err.println("Error while closing File I/O: " + ex);
//            }
//        }
//    }
    // Hàm lấy tên file từ path
    public static String getFileName(String filePath) {

        String[] split = filePath.split("\\/");

        return split[split.length - 1];
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSeparator1 = new javax.swing.JSeparator();
        jLabel3 = new javax.swing.JLabel();
        btn_decryptText = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        txt_server = new javax.swing.JTextField();
        jLabel8 = new javax.swing.JLabel();
        txt_portdecrypt = new javax.swing.JTextField();
        filler1 = new javax.swing.Box.Filler(new java.awt.Dimension(0, 0), new java.awt.Dimension(0, 0), new java.awt.Dimension(0, 0));
        jPanel1 = new javax.swing.JPanel();
        btn_randomkey = new javax.swing.JButton();
        txt_inputkey = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        port = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jComboBox1 = new javax.swing.JComboBox<>();
        jLabel4 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        btn_encryptText = new javax.swing.JButton();
        status = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        cb_typekey = new javax.swing.JComboBox<>();
        jTextField4 = new javax.swing.JTextField();
        jButton3 = new javax.swing.JButton();
        jLabel10 = new javax.swing.JLabel();
        status2 = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(204, 255, 51));

        jLabel3.setFont(new java.awt.Font("Segoe UI", 0, 36)); // NOI18N
        jLabel3.setText("DOWLOAD FILE");

        btn_decryptText.setBackground(new java.awt.Color(255, 255, 51));
        btn_decryptText.setFont(new java.awt.Font("Segoe UI", 0, 24)); // NOI18N
        btn_decryptText.setText("GET FILE...");
        btn_decryptText.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_decryptTextActionPerformed(evt);
            }
        });

        jLabel7.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jLabel7.setText("Server:");

        jLabel8.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jLabel8.setText("Port:");

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));

        btn_randomkey.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        btn_randomkey.setText("Random Key");
        btn_randomkey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_randomkeyActionPerformed(evt);
            }
        });

        jLabel5.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jLabel5.setText("Input Key:");

        jButton1.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jButton1.setText("Choose file");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel6.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jLabel6.setText("Port:");

        jComboBox1.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jComboBox1.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "128", "192", "256" }));
        jComboBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBox1ActionPerformed(evt);
            }
        });

        jLabel4.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jLabel4.setText("Key:");

        jLabel9.setFont(new java.awt.Font("Segoe UI", 0, 36)); // NOI18N
        jLabel9.setForeground(new java.awt.Color(102, 0, 255));
        jLabel9.setText("MÃ HÓA AES");

        btn_encryptText.setBackground(new java.awt.Color(153, 255, 0));
        btn_encryptText.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        btn_encryptText.setText("Transfer File");
        btn_encryptText.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_encryptTextActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jLabel1.setText("Key Type:");

        cb_typekey.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        cb_typekey.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Base64", "Ascii" }));

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(69, 69, 69)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 74, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 52, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(28, 28, 28)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(port, javax.swing.GroupLayout.PREFERRED_SIZE, 102, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 40, Short.MAX_VALUE)
                        .addComponent(btn_encryptText, javax.swing.GroupLayout.PREFERRED_SIZE, 225, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(status, javax.swing.GroupLayout.PREFERRED_SIZE, 116, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(62, 62, 62))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(94, 94, 94)
                                .addComponent(jLabel1)
                                .addGap(32, 32, 32)
                                .addComponent(cb_typekey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(txt_inputkey, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 292, Short.MAX_VALUE)
                                    .addComponent(jTextField1, javax.swing.GroupLayout.Alignment.LEADING))
                                .addGap(18, 18, 18)
                                .addComponent(btn_randomkey)))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(242, 242, 242)
                .addComponent(jLabel9, javax.swing.GroupLayout.PREFERRED_SIZE, 269, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(34, 34, 34)
                .addComponent(jLabel9, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 63, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(cb_typekey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(32, 32, 32)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txt_inputkey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5)
                    .addComponent(btn_randomkey, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(36, 36, 36)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel6)
                            .addComponent(port, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(status))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btn_encryptText, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(14, 14, 14))))
        );

        jButton3.setFont(new java.awt.Font("Segoe UI", 0, 18)); // NOI18N
        jButton3.setText("Save folder");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jLabel10.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        jLabel10.setText("Status:");

        status2.setEditable(false);
        status2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                status2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(filler1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btn_decryptText, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(140, 140, 140))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(120, 120, 120)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(23, 23, 23))
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(jLabel8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addGap(89, 89, 89)))
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(txt_portdecrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 199, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(txt_server, javax.swing.GroupLayout.PREFERRED_SIZE, 199, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(jTextField4)))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(status2, javax.swing.GroupLayout.PREFERRED_SIZE, 337, javax.swing.GroupLayout.PREFERRED_SIZE))))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(164, 164, 164)
                                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 269, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
            .addGroup(layout.createSequentialGroup()
                .addGap(75, 75, 75)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 1045, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(22, 22, 22)
                        .addComponent(filler1, javax.swing.GroupLayout.PREFERRED_SIZE, 359, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(22, 22, 22)
                                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(txt_server, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel7))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(txt_portdecrypt, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel8))
                                .addGap(21, 21, 21)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jButton3))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel10)
                                    .addComponent(status2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(btn_decryptText, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(33, 85, Short.MAX_VALUE)))
                        .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 13, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(50, 50, 50))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    JFileChooser jFileChooser1 = new JFileChooser();
    JFileChooser jFileChooser2 = new JFileChooser();
    private void btn_decryptTextActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_decryptTextActionPerformed

        int r = 0;
        try {

            Socket clientSocket = new Socket(txt_server.getText(), Integer.parseInt(txt_portdecrypt.getText()));
            DataInputStream fromServer = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream toServer = new DataOutputStream(clientSocket.getOutputStream());

            String key = fromServer.readUTF();
            System.out.println("chh_log key crypto -->" + key);
//            String fileName = fromServer.readUTF();
//            System.out.println("file name: "+fileName);
            //
            System.out.println("Waiting for file.");

            // Lấy đường dẫn file gửi từ server
            String fName = fromServer.readUTF();

            // Đọc file đã mã hóa từ server
            String encryptedFile = "";
            String line;
            while (!(line = fromServer.readUTF()).equalsIgnoreCase("")) {

                encryptedFile += line;

                if (line.isEmpty()) {
                    break;
                }
            }

            System.out.println("ENCRYPTED FILE:" + encryptedFile);
            //Lấy tên file
            String fileLoc = fName.split(Pattern.quote(File.separator))[fName.split(Pattern.quote(File.separator)).length - 1];
            // Giải mã file
//                        System.out.println("File saved in:"+fileLoc);
            if (cb_typekey.getSelectedItem().toString().equals("Base64")) {
                if (Base64.getDecoder().decode(key).length == 16) {
                    r = 10;
                } else if (Base64.getDecoder().decode(key).length == 24) {
                    r = 12;
                } else if (Base64.getDecoder().decode(key).length == 32) {
                    r = 14;
                }
            }else if (cb_typekey.getSelectedItem().toString().equals("Ascii")){
                if (key.length() == 16) {
                    r = 10;
                } else if (key.length() == 24) {
                    r = 12;
                } else if (key.length() == 32) {
                    r = 14;
                }
            }
            byte[] decryptedFile = decryptFile(encryptedFile, key, r);
//            String decryptedFile = AES.decrypt(Base64.getDecoder().decode(encryptedFile),Base64.getDecoder().decode(key),10);
            System.out.println("DECRYPTED FILE:" + decryptedFile);

            // Ghi đoạn văn đã giải mã vào file
//            writeFile(fileLoc, decryptedFile);
            File inputFile = jFileChooser1.getSelectedFile();
            inputFile = new File(jFileChooser2.getSelectedFile() + "/"+fileLoc);
            FileOutputStream fos = new FileOutputStream(inputFile);
            fos.write(decryptedFile);
            fos.flush();
            fos.close();
            status2.setText("File download complete. Saved in ./nguyendat.txt");
            // Thông báo
            System.out.println("File download complete. Saved in ./" + fileLoc + "\n");

        } catch (Exception e) {
            System.err.println("Error while creating/reading server socket: " + e);
        }
    }//GEN-LAST:event_btn_decryptTextActionPerformed
    public byte[] decryptFile(String encryptedText, String secretKey, int r) {
//        return new String(new AES(secretKey.getBytes()).ECB_decrypt(Base64.getDecoder().decode(encryptedText)));
            byte[] keys = null ;
          if (cb_typekey.getSelectedItem().toString().equals("Base64")) {
               keys = Base64.getDecoder().decode(secretKey);
            }else if (cb_typekey.getSelectedItem().toString().equals("Ascii")){
               keys = secretKey.getBytes();
            }
        return (AES.decrypt(Base64.getDecoder().decode(encryptedText), keys, r));
    }
    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        jFileChooser2.setCurrentDirectory(new java.io.File("."));
        jFileChooser2.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int returnVal = jFileChooser2.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = jFileChooser2.getSelectedFile();
            if (!file.canRead()) {
                file.setReadable(true);
            }
            // display file name in text field
            jTextField4.setText(file.getAbsolutePath());

        } else {
            System.out.println("You must choose a save directory.");
        }
    }//GEN-LAST:event_jButton3ActionPerformed

    private void btn_encryptTextActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_encryptTextActionPerformed
      
        String keyType = cb_typekey.getSelectedItem().toString();
        double t;
        String data = "";
        try {
            // Khởi tạo server socket
            int p = Integer.parseInt(port.getText().toString());
            System.out.println(p);
            ServerSocket serverSocket = new ServerSocket(p);

            // Khởi tạo logger cho tiến trình
            Logger threadLogger = Logger.getLogger("serverLogger");
            System.out.println("Server is reading file. Wait until finished!");
            // Đọc file cần gửi
            try {
                // the line that reads the image file
                File inputFile = jFileChooser1.getSelectedFile();
                BufferedReader reader = new BufferedReader(new FileReader(inputFile));
                String line = reader.readLine();
                while (line != null) {
                    data += line;
                    line = reader.readLine();
                }
                //            System.out.println(data);
                reader.close();
            } //work with the image here ...
            catch (IOException e) {
                System.out.println(e.getMessage());

            }
            String fileContent = data;

            if (!fileContent.equalsIgnoreCase("")) {
                // Lấy file name
                String fileName = getFileName(jTextField1.getText().toString());

                System.out.println("Serving clients on port " + port.getText().toString() + ". Now you can get file from clients");

                while (true) {
                    Socket clientSocket = serverSocket.accept();

                    // Khởi tạo 1 tiến trình cho client mới
                    Thread thread = new Thread(new ServerProtocol(clientSocket, threadLogger, fileName, fileContent, txt_inputkey.getText(),keyType));
                    thread.start();
                    threadLogger.info("Created and started new thread " + thread.getName() + " for client.");
                }
            } else {
                System.err.println("File not found.");
            }
        } catch (Exception e) {
        }
    }//GEN-LAST:event_btn_encryptTextActionPerformed

    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed

    }//GEN-LAST:event_jComboBox1ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        int returnVal = jFileChooser1.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = jFileChooser1.getSelectedFile();
            if (!file.canRead()) {
                file.setReadable(true);
            }

            // display file name in text field
            jTextField1.setText(file.getAbsolutePath());

        } else {
            System.out.println("You must choose a file.");
        }
    }//GEN-LAST:event_jButton1ActionPerformed

    private void btn_randomkeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_randomkeyActionPerformed
        byte[] k = null;
        try {
            //        byte[] k = new byte[16];
            //         byte[] k = new byte[24];
            int a = Integer.parseInt(jComboBox1.getSelectedItem().toString());
            switch (a) {
                case 128:
                k = new byte[16];
                k = keygeneration(128);
                break;
                case 192:
                k = new byte[24];
                k = keygeneration(192);
                break;
                case 256:
                k = new byte[32];
                k = keygeneration(256);
                break;
                default:
                break;
            }

            //            StringBuilder sb = new StringBuilder();
            //            for (int i = 0; i < k.length; i++) {
                //                sb.append(k[i]);
                //                if (i < k.length - 1) {
                    //                    sb.append(",");
                    //                }
                //            }
            //            String result = sb.toString();
            String keyString = Base64.getEncoder().encodeToString(k); // Chuyển đổi khóa bí mật sang chuỗi Base64
            txt_inputkey.setText(keyString);
            System.out.println(keyString);

            System.out.println("dia chi khoa: " + k); //địa chỉ tham chiếu của mảng byte chứa giá trị khóa bí mật
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }//GEN-LAST:event_btn_randomkeyActionPerformed

    private void status2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_status2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_status2ActionPerformed
    // Chuyển một mảng byte thành một chuỗi hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }//    public static String decryptFile(String encryptedText, String secretKey) {
//        return new String(encrypt);
////        return new String(new AES(secretKey.getBytes()).ECB_decrypt(Base64.getDecoder().decode(encryptedText)));
//    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(AES_Demo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(AES_Demo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(AES_Demo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(AES_Demo.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new AES_Demo().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btn_decryptText;
    private javax.swing.JButton btn_encryptText;
    private javax.swing.JButton btn_randomkey;
    private javax.swing.JComboBox<String> cb_typekey;
    private javax.swing.Box.Filler filler1;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton3;
    private javax.swing.JComboBox<String> jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField4;
    private javax.swing.JTextField port;
    private javax.swing.JLabel status;
    private javax.swing.JTextField status2;
    private javax.swing.JTextField txt_inputkey;
    private javax.swing.JTextField txt_portdecrypt;
    private javax.swing.JTextField txt_server;
    // End of variables declaration//GEN-END:variables
}