package gentian.crypt;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author nobody
 */
public final class GentianCrypt {

    public static final int AES = 1;
    public static final int Serpent = 2;
    public static final int Twofish = 3;
    static Random r = new Random();
    // http://stackoverflow.com/questions/992019/java-256bit-aes-encryption
    // http://www.java2s.com/Tutorial/Java/0490__Security/Createa192bitsecretkeyfromrawbytes.htm

    public static final byte[] encrypt(byte[] keyRaw, byte[] iv, byte[] text, boolean padding) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        return encrypt(keyRaw, iv, text, padding, AES);
    }

    public static final byte[] encrypt(byte[] keyRaw, byte[] iv, byte[] text, boolean padding, int algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        SecretKeySpec skey =null;
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        Cipher ecipher = null;
        if (padding) {
            switch (algorithm) {
                case (Serpent):

                ecipher = Cipher.getInstance("Serpent/CBC/PKCS5Padding");
                skey = new SecretKeySpec(keyRaw, "Serpent");

                break;

                case(Twofish) :
                ecipher = Cipher.getInstance("Twofish/CBC/PKCS5Padding");
                skey = new SecretKeySpec(keyRaw, "Twofish");
                break;

                default:
                ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                skey = new SecretKeySpec(keyRaw, "AES");
                break;
            }
        } else {
            switch(algorithm) {
                case Serpent:
                ecipher = Cipher.getInstance("Serpent/CBC/NoPadding");
                skey = new SecretKeySpec(keyRaw, "Serpent");
                break;

                case Twofish:
                ecipher = Cipher.getInstance("Twofish/CBC/NoPadding");
                skey = new SecretKeySpec(keyRaw, "Twofish");
                break;

                default:
                ecipher = Cipher.getInstance("AES/CBC/NoPadding");
                skey = new SecretKeySpec(keyRaw, "AES");
                break;
            }
        }

        // CBC requires an initialization vector
        ecipher.init(Cipher.ENCRYPT_MODE, skey, paramSpec);
  //      System.out.println(ecipher.getAlgorithm()+" "+skey.getAlgorithm());
        return ecipher.doFinal(text);
    }

    public static final byte[] decrypt(byte[] keyRaw, byte[] iv, byte[] text, boolean padding) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        return decrypt(keyRaw, iv, text, padding,AES);
    }
    public static final byte[] decrypt(byte[] keyRaw, byte[] iv, byte[] text, boolean padding,int algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKeySpec skey =null;
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        Cipher dcipher = null;
        if (padding) {
            switch (algorithm) {
                case (Serpent):

                dcipher = Cipher.getInstance("Serpent/CBC/PKCS5Padding");
                skey = new SecretKeySpec(keyRaw, "Serpent");
                break;

                case(Twofish) :
                dcipher = Cipher.getInstance("Twofish/CBC/PKCS5Padding");
                skey = new SecretKeySpec(keyRaw, "Twofish");
                break;

                default:
                dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                skey = new SecretKeySpec(keyRaw, "AES");
                break;
            }
        } else {
            switch(algorithm) {
                case Serpent:
                dcipher = Cipher.getInstance("Serpent/CBC/NoPadding");
                skey = new SecretKeySpec(keyRaw, "Serpent");
                break;

                case Twofish:
                dcipher = Cipher.getInstance("Twofish/CBC/NoPadding");
                skey = new SecretKeySpec(keyRaw, "Twofish");
                break;

                default:
                dcipher = Cipher.getInstance("AES/CBC/NoPadding");
                skey = new SecretKeySpec(keyRaw, "AES");
                break;
            }
        }

        // CBC requires an initialization vector
        dcipher.init(Cipher.DECRYPT_MODE, skey, paramSpec);
//        System.out.println(dcipher.getAlgorithm()+" "+skey.getAlgorithm());
        return dcipher.doFinal(text);
    }

    public static byte[] createIV() {
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[16];
        r.nextBytes(iv);
        /*ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DataOutputStream dout = new DataOutputStream(bout);

        try {
        for (int i = 0; i < 4; i++) {
        dout.writeInt(r.nextInt());
        dout.flush();
        }

        } catch (IOException ex) {
        throw new RuntimeException("IV generation failed");
        }
        byte[] iv = bout.toByteArray();
        /*System.out.print("IV: ");
        for (byte b :iv ) {
        System.out.print (b);
        }
        System.out.println("");*/
        //System.out.println("Iv length: "+iv.length);*/
        return iv;
    }
}
