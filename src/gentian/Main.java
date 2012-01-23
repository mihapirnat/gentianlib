package gentian;

import gentian.crypt.GentianCrypt;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.util.logging.Level;
import java.util.logging.Logger;
import gentian.crypt.GentianEnvelope;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import gentian.crypt.GentianKeyProvider;
import gentian.crypt.UnwrapException;
import gentian.crypt.WrapException;
import gentian.crypt.keyprovider.DirectoryGentianKeyProvider;
import gentian.crypt.keyprovider.ZipGentianKeyProvider;
import gentian.util.Base64;
import java.io.FileOutputStream;
import java.security.Security;
import java.util.ArrayList;

/**
 *
 * @author nobody
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, FileNotFoundException, IOException, InvalidAlgorithmParameterException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        testAlgorithm("AES", GentianCrypt.AES);
        testAlgorithm("Serpent", GentianCrypt.Serpent);
        testAlgorithm("Twofish", GentianCrypt.Twofish);
        testGentian();
        
    }

    private static void testAlgorithm(String text, int algorithm) throws UnsupportedEncodingException {
        try {
            System.out.println(text);
            byte[] key = new byte[32];
            key[1] = 3;
            key[2] = 7;
            byte[] iv = new byte[16];
            byte[] plain = "This is a test".getBytes("utf-8");
            System.out.println("plaintext:" + Base64.encodeToString(plain, false));
            byte[] cipher = GentianCrypt.encrypt(key, iv, GentianCrypt.encrypt(key, iv, plain, true, algorithm), false, algorithm);
            System.out.println("chipetext:" + Base64.encodeToString(cipher, false));
            byte[] plain2 = GentianCrypt.decrypt(key, iv, GentianCrypt.decrypt(key, iv, cipher, false, algorithm), true, algorithm);
            System.out.println("plaintext:" + Base64.encodeToString(plain2, false));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private static void testGentian() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, FileNotFoundException, IOException {
        // TODO code application logic here
        String textSample = "This section defines the security algorithm requirements for Java SE 6 implementations. These requirements are intended to improve the interoperability of Java SE 6 implementations and applications that use these algorithms.";
        System.out.println("Example cleartext: " + textSample);
        

        ZipGentianKeyProvider provider = null, provider1 = null, provider2 = null;
        byte[][] aes = new byte[2][32];
        aes[0][1] = 3;
        aes[1][1] = 8;
        File f = new File("masterkeys");
        /*if (f.exists()) {
            provider = new ZipGentianKeyProvider(f, aes);
        } else {*/

            try {
                provider = new ZipGentianKeyProvider(f, 1, aes);
            } catch (UnwrapException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (WrapException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        //}
        File f2 = new File("slavekeys");
        /*if (f2.exists()) {
            provider1 = new ZipGentianKeyProvider(f2, provider, 3, 0, null);
        } else {*/

            try {
                provider1 = new ZipGentianKeyProvider(f2, 1, provider, 3, 0, null);
            } catch (UnwrapException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (WrapException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        //}


        File f3 = new File("slavekeys3");
            try {
                provider2 = new ZipGentianKeyProvider(f3, 1, provider1, 3, 0, null);
            } catch (UnwrapException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            } catch (WrapException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        try {

        ArrayList<String> testLines=new ArrayList<String>();
        for (int i=0;i<1000;i++) {
            byte[] text = textSample.getBytes("utf-8");
            long time = System.currentTimeMillis();
            System.out.println("Plain text length: " + text.length + " bytes");
            GentianEnvelope.DEBUG = false;
            byte[] wrapped = GentianEnvelope.wrap(provider2, text, 6, 0, 0);
            String wrapBase64 = Base64.encodeToString(wrapped, false);
            System.out.println("Crypt text length: " + wrapped.length + " bytes, %16=" + (wrapped.length % 16));
            System.out.println("Final package: " + wrapBase64.length() + " " + wrapBase64);
            testLines.add(wrapBase64);
        }

            System.out.println("Let's unwrap..");
            provider = new ZipGentianKeyProvider(f, aes);
             provider1 = new ZipGentianKeyProvider(f2, provider, 3, 0, null);
             provider2 = new ZipGentianKeyProvider(f3, provider1, 3, 0, null);
            //
            //File sf = new File("slavewithoutmaster");
            //provider1.recrypt(new FileOutputStream(sf), null, null, 0, 0);


            //provider1 = new ZipGentianKeyProvider(sf, null);

for (String wrapBase64:testLines) {
            byte[] clearText = GentianEnvelope.unwrap(provider2, Base64.decode(wrapBase64), 6, 0);

            


            System.out.println("Cleartext: " + new String(clearText, "utf-8"));
}
provider1.wipe();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
