package gentian.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import gentian.util.Base64;

/**
 *
 * @author nobody
 */
public class GentianKey {

    public final byte[] id;
    public final String idString;
    private byte[] rawKey;

    @Override
    protected void finalize() throws Throwable {
        wipe();

        try {
            super.finalize();
        } catch (Exception e) {
        }
    }

    public void wipe() {
        SecureRandom r = new SecureRandom();

        if (rawKey != null) {
            for (int n = 1; n < 10; n++) {
                byte[] wipe = new byte[rawKey.length];
                r.nextBytes(wipe);
                for (int i = 0; i < rawKey.length; i++) {
                    rawKey[i] = wipe[i];
                }
                
            }
        } else if (loader != null) {
            loader.wipe();
        }



    }
    private KeyLoader loader;

    public GentianKey(
            byte[] id) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(256); // 192 and 256 bits may not be available
        // Generate the secret key specs.


        if (id == null) {

            SecureRandom r = new SecureRandom();


            this.id = new byte[4];
            r.nextBytes(this.id);


        } else {
            this.id = id;


        }
        this.idString = toString(this.id);


        SecretKey skey = kgen.generateKey();


        byte[] generatedKey = skey.getEncoded();
        //System.out.println("Generated key size: "+generatedKey.length);


        this.rawKey = new byte[generatedKey.length];
        SecureRandom r = new SecureRandom();


        byte[] xor = new byte[generatedKey.length];
        r.nextBytes(xor);


        for (int i = 0; i
                < generatedKey.length; i++) {
            rawKey[i] = (byte) (generatedKey[i] ^ xor[i]);


        }
        //System.out.println("Generated key: "+Base64.encodeToString(rawKey, false));
    }

    public GentianKey(
            byte[] id, KeyLoader loader) {
        this.id = id;


        this.idString = toString(this.id);


        this.loader = loader;


    }
    public byte[] getRawKeyCopy() throws IOException, UnwrapException {
        byte[] orig=getRawKey();
        byte[] copy =new byte[orig.length];
        for (int i=0;i<copy.length;i++) {
            copy[i]=orig[i];
        }
        return copy;
    }
    public byte[] getRawKey() throws IOException, UnwrapException {
        if (rawKey != null) {
            return rawKey;


        } else if (loader != null) {
            return loader.loadRaw();


        }
        return null;



    }

    @Override
    public String toString() {
        return idString;


    }

    private String toString(byte[] id) {

        return Base64.encodeToString(id, false);




    }

    public void unLoad(KeyLoader keyLoader) {
        this.rawKey = null;


        this.loader = keyLoader;





    }

    public abstract static class KeyLoader {

        public KeyLoader() {
        }

        protected abstract byte[] loadRaw() throws IOException, UnwrapException;

        protected byte[] readStream(InputStream in, boolean close) throws IOException {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int count = 0, read = 0;
            byte[] buffer = new byte[4096];
            int len = 0;
            while ((read = in.read(buffer)) != -1) {
                if (read > 0) {
                    bout.write(buffer, 0, read);
                    len += read;
                }
            }
            if (close) {
                in.close();
            }
            bout.flush();
            byte[] bytes = bout.toByteArray();
            bout.close();
            return bytes;
        }

        public abstract void wipe();
    }
}
