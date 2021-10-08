
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
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
import javax.imageio.ImageIO;
import javax.swing.JFileChooser;

public class AESFunction {
    /**
   * RGB SIZE IS 3 (RED, GREEN, BLUE).
   */
  private static final int RGB_SIZE = 3;

  /**
   * Byte shifter for SIGNED->UNSIGNED.
   */
  private static final int BSHIFT = 0xFF;

  /**
   * Solution sample in main.
   * 
   * @param args
   *          ignored args
   */
  
    
    public static byte[] encrypt(byte[] plainText, String encryptionKey) throws Exception {
        //String llave = "holaestaeslallav";
        String iv = "1234567891123456";
        byte [] ibB = iv.getBytes("UTF-8");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv.getBytes("UTF-8")));
        return cipher.doFinal(plainText);
    }
    
    
  public static void main(String[] args) {
    try {
        JFileChooser openFile = new JFileChooser();
        int oF = openFile.showOpenDialog(null);
      BufferedImage image;
      int width;
      int height;

      File input = openFile.getSelectedFile();
      String fileName = input.getName();
      String path = input.getAbsolutePath();
        System.out.println("Name: " + fileName + ", path: " + path);
      
      image = ImageIO.read(input);
      width = image.getWidth();
      height = image.getHeight();

      byte[] t = new byte[width * height * RGB_SIZE];
      int index = 0;

      // fill the table t with RGB values;
      int k=0;
      for (int i = 0; i < height; i++) {

        for (int j = 0; j < width; j++) {

          Color c = new Color(image.getRGB(j, i));
          System.out.println("\n [" + k + "]: " +c.getRed() + " , " 
                                + c.getGreen()  + " , " + c.getBlue() );

          // As byte is SIGNED in Java overflow will occur for values > 127
          byte r = (byte) c.getRed();
          byte g = (byte) c.getGreen();
          byte b = (byte) c.getBlue();

          t[index++] = r;
          t[index++] = g;
          t[index++] = b;
        }
      }
      

      
      byte ans[] = encrypt(t, "holaestaeslallav");
      
      
      // Re-create image with table-encrypted RGB values
      BufferedImage newImage = new BufferedImage(width, height,
          BufferedImage.TYPE_3BYTE_BGR);
      index = 0;
      for (int i = 0; i < height; i++) {

        for (int j = 0; j < width; j++) {

          // Need to deal with values < 0 so binary AND with 0xFF
          // Java 8 provides Byte.toUnsignedInt but I am from the old school ;-)
          int r = ans[index++] & BSHIFT;
          int g = ans[index++] & BSHIFT;
          int b = ans[index++] & BSHIFT;

          Color newColor = new Color(r, g, b);
          newImage.setRGB(j, i, newColor.getRGB());

        }
      }
      // write the output image
      int dotIndex = fileName.lastIndexOf('.');
        fileName = fileName.substring(0, dotIndex);
      String ruta = input.getParent();
      ruta += "\\" + fileName + "_DDDDDDD" + ".bmp";
      File output = new File(ruta);
      ImageIO.write(newImage, "bmp", output);

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
