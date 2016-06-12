/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package duthientan.mmanm.com;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author DuThienTan
 */
public class CipherRSA implements CipherP {

    PublicKey publicKey;
    PrivateKey privateKey;

    @Override
    public void setKey(String keyString) {
        try {
            ObjectInputStream inputStream = null;
            inputStream = new ObjectInputStream(new FileInputStream(keyString + "/public.key"));
            publicKey = (PublicKey) inputStream.readObject();
            inputStream = new ObjectInputStream(new FileInputStream(keyString + "/private.key"));
            privateKey = (PrivateKey) inputStream.readObject();
        } catch (IOException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void encrypt(String filePath) {
        try {
            Cipher ecipher = Cipher.getInstance("RSA");
            ecipher.init(Cipher.ENCRYPT_MODE, publicKey);
            Path path = Paths.get(filePath);
            String encryptFilePath = path.getParent().toString() + "/" + "RSA" + "_" + path.getFileName().toString();
            byte[] data = Files.readAllBytes(path);
            byte[] textEncrypted=null;
            int chunkSize = 245;
            if(data.length < 245){
                textEncrypted = ecipher.doFinal(data);  
            }
            else {
                for(int i = 0; i < data.length; i += chunkSize){
                    byte [] segment = Arrays.copyOfRange(data, i, i+chunkSize > data.length? data.length: i+chunkSize); 
                    byte [] segmentEncrypted = ecipher.doFinal(segment);
                    textEncrypted = ArrayUtils.addAll(textEncrypted, segmentEncrypted);
                }  
            }
            FileOutputStream fos = new FileOutputStream(encryptFilePath);
            fos.write(textEncrypted);
            fos.close();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void decrypt(String filePath) {
        try {
            Cipher decipher = Cipher.getInstance("RSA");
            decipher.init(Cipher.DECRYPT_MODE, privateKey);
            Path path = Paths.get(filePath);
            String decryptFilePath = filePath.replace("RSA" + "_", "");
            byte[] data = Files.readAllBytes(path);
            byte[] textDncrypted=null;
            int chunkSize = 256;
            if(data.length < 256){
                textDncrypted = decipher.doFinal(data);  
            }
            else {
                for(int i = 0; i < data.length; i += chunkSize){
                    byte [] segment = Arrays.copyOfRange(data, i, i+chunkSize > data.length? data.length: i+chunkSize); 
                    byte [] segmentEncrypted = decipher.doFinal(segment);
                    textDncrypted = ArrayUtils.addAll(textDncrypted, segmentEncrypted);
                }  
            }
            FileOutputStream fos = new FileOutputStream(decryptFilePath);
            fos.write(textDncrypted);
            fos.close();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
