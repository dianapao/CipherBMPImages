
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher {
    public static byte[] encrypt(byte[] plainText, String encryptionKey, String iv) throws Exception {
        //String llave = "holaestaeslallav";
        //String iv = "1234567891123456";
        byte [] ibB = iv.getBytes("UTF-8");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv.getBytes("UTF-8")));
        return cipher.doFinal(plainText);
    }
    
    /*public static byte[] decrypt(byte[] plainText, String encryptionKey, String iv) throws Exception {
        byte [] ibB = iv.getBytes("UTF-8");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv.getBytes("UTF-8")));
        return cipher.doFinal(plainText);
    }*/
    
    private SecretKeySpec crearClave(String clave) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte[] claveEncriptacion = clave.getBytes("UTF-8");
        
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        
        claveEncriptacion = sha.digest(claveEncriptacion);
        claveEncriptacion = Arrays.copyOf(claveEncriptacion, 16);
        
        SecretKeySpec secretKey = new SecretKeySpec(claveEncriptacion, "AES");

        return secretKey;
    }
    
    public byte[] encryptECB(byte[] plainText, String claveSecreta) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKey = this.crearClave(claveSecreta);
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        //byte[] dataEncrypt = datos.getBytes("UTF-8");
        byte[] bytesEncrypted = cipher.doFinal(plainText);

        return bytesEncrypted;
    }
    
    /*public byte[] decryptECB(byte[] plainText, String originalSecretPass) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKey = this.crearClave(originalSecretPass);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        //byte[] bytesEncryped = Base64.getDecoder().decode(dataEncrypted.trim());
        byte[] dataDecrypted = cipher.doFinal(plainText);
        
        return dataDecrypted;
    }*/
    
}
