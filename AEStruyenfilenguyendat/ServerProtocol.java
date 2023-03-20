package cd3aeschuanchuanchuan1;

import cd3aeschuanchuanchuan.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;


// class để cho 1 server chạy multi thread
public class ServerProtocol implements Runnable {

    // Gửi max 256 byte
    private static final int MAXBYTE = 256;

    private Socket clientSocket;
    private Logger threadLogger;
    private String fileName;
    private String fileContent;
    private String key;
    private String keytype;
    private AES cipher;

    
    public ServerProtocol(Socket socket, Logger logger, String fName, String fContent, String key, String keytype) {
        this.clientSocket = socket;
        this.threadLogger = logger;
        this.fileName = fName;
        this.fileContent = fContent;
        this.key = key;
        this.keytype = keytype;
//        this.cipher = new AES(key.getBytes());
    }

    // Xử lý thread của client
    public void handleClient(Socket clientSocket, Logger threadLogger, String fileName, String fileContent) {
        int r = 0;
        try {
            DataOutputStream toClient = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream fromClient = new DataInputStream(clientSocket.getInputStream());

            threadLogger.log(Level.INFO, "Sending process started.");

            toClient.writeUTF(key);
            
            // Gửi tên file
            toClient.writeUTF(fileName);
            // Mã hóa nội dung file
             if (keytype.equals("Base64")) {
                if (Base64.getDecoder().decode(key).length == 16) {
                    r = 10;
                } else if (Base64.getDecoder().decode(key).length == 24) {
                    r = 12;
                } else if (Base64.getDecoder().decode(key).length == 32) {
                    r = 14;
                }
            }else if (keytype.equals("Ascii")){
                if (key.length() == 16) {
                    r = 10;
                } else if (key.length() == 24) {
                    r = 12;
                } else if (key.length() == 32) {
                    r = 14;
                }
            }
            String encryptedFile = encryptFile(fileContent,key,r);

            byte[][] split;
            // chia nhỏ filethành các gói có sizê max là 256 bit
            if((split = chunkArray(encryptedFile.getBytes(), MAXBYTE)) != null) {

                for(int i = 0; i < split.length; i++) {
                    // Gửi packet
                    toClient.writeUTF(new String(split[i]));
                }
            }

            toClient.writeUTF("");

            toClient.flush();

            threadLogger.log(Level.INFO, "Sending process complete. " + split.length + " total packages sent.");


        } catch(Exception e) {
            threadLogger.log(Level.WARNING, "Error while creating output stream " + e);
        }

    }

    public String encryptFile(String plainText,String key, int r) {
           byte[] keys = null ;
          if (keytype.equals("Base64")) {
               keys = Base64.getDecoder().decode(key);
            }else if (keytype.equals("Ascii")){
               keys = key.getBytes();
            }
        return Base64.getEncoder().encodeToString(AES.encrypt(plainText.getBytes(), keys, r));
    }

    public void run() {
        handleClient(clientSocket, threadLogger, fileName, fileContent);
    }

    public static byte[][] chunkArray(byte[] array, int chunkSize) {
        int numOfChunks = (int)Math.ceil((double)array.length / chunkSize);
        byte[][] output = new byte[numOfChunks][];

        for(int i = 0; i < numOfChunks; ++i) {
            int start = i * chunkSize;
            int length = Math.min(array.length - start, chunkSize);

            byte[] temp = new byte[length];

            System.arraycopy(array, start, temp, 0, length);

            output[i] = temp;
        }

        return output;
    }

}
