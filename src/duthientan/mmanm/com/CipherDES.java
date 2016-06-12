/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package duthientan.mmanm.com;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 *
 * @author DuThienTan
 */
public class CipherDES implements CipherP {

    public SecretKey key;

    @Override
    public void setKey(String keyString) {
        try {
            DESKeySpec dks = new DESKeySpec(keyString.getBytes());
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            key = skf.generateSecret(dks);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CipherDES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void encrypt(String filePath) {
        try {
            Cipher ecipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE, key);
            Path path = Paths.get(filePath);
            String encryptFilePath = path.getParent().toString() + "/" + "DES" + "_" + path.getFileName().toString();
            byte[] data = Files.readAllBytes(path);
            byte[] textEncrypted = ecipher.doFinal(data);
            FileOutputStream fos = new FileOutputStream(encryptFilePath);
            fos.write(textEncrypted);
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

    @Override
    public void decrypt(String filePath) {
        try {
            Cipher decipher = Cipher.getInstance("DES");
            decipher.init(Cipher.DECRYPT_MODE, key);
            Path path = Paths.get(filePath);
            String decryptFilePath = filePath.replace("DES" + "_", "");
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
