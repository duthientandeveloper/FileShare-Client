/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package duthientan.mmanm.com;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author DuThienTan
 */
public class CipherAES implements CipherP {

    SecretKeySpec sKS;

    @Override
    public void setKey(String keyString) {
        try {
            byte[] key = keyString.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            sKS = new SecretKeySpec(key, "AES");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void encrypt(String filePath) {
        try {
            Cipher ecipher = Cipher.getInstance("AES");
            ecipher.init(Cipher.ENCRYPT_MODE, sKS);
            Path path = Paths.get(filePath);
            String encryptFilePath = path.getParent().toString() + "/" + "AES" + "_" + path.getFileName().toString();
            byte[] data = Files.readAllBytes(path);
            byte[] textEncrypted = ecipher.doFinal(data);
            FileOutputStream fos = new FileOutputStream(encryptFilePath);
            fos.write(textEncrypted);
            fos.close();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void decrypt(String filePath) {
        try {
            Cipher decipher = Cipher.getInstance("AES");
            decipher.init(Cipher.DECRYPT_MODE, sKS);
            Path path = Paths.get(filePath);
            String decryptFilePath = filePath.replace("AES" + "_", "");
            byte[] data = Files.readAllBytes(path);
            byte[] textDncrypted = decipher.doFinal(data);
            FileOutputStream fos = new FileOutputStream(decryptFilePath);
            fos.write(textDncrypted);
            fos.close();
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
