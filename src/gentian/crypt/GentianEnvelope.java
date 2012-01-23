package gentian.crypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import gentian.util.Base64;
import static gentian.util.Util.*;

/**
 *
 * @author nobody
 */
public final class GentianEnvelope {
    public static boolean AUTOWIPE=true;
    static final int[] ALGORITHM = new int[]{GentianCrypt.AES, GentianCrypt.Serpent, GentianCrypt.Twofish};
    public static boolean DEBUG = false;

    public static byte[] wrap(GentianKeyProvider provider, byte[] text, int ttl, int saltLength, int timeDelay) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnwrapException, NoSuchProviderException {
        return wrap(provider, text, ttl, saltLength, timeDelay, true);
    }

    public static byte[] wrap(GentianKeyProvider provider, byte[] text, int ttl, int saltLength, int timeDelay, boolean padding) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnwrapException, NoSuchProviderException {
        if (ttl <= 0) {
            return text;
        }

        if (timeDelay > 0) {
            Random rt = new Random();

            Random rt2 = new Random();
            try {
                Thread.sleep(rt.nextInt(timeDelay), rt2.nextInt(999999));
            } catch (InterruptedException ex) {
                Logger.getLogger(GentianEnvelope.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        byte[] nextEnvelope = wrap(provider, text, ttl - 1, saltLength, timeDelay, padding);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        GentianKey key = provider.pickKey();
        if (DEBUG) {
            System.out.println("Next key: " + key.idString);
        }

        bout.write(key.id);
        byte[] iv = GentianCrypt.createIV();
        bout.write(iv);
        SecureRandom r = new SecureRandom();
        int sl = 16 - key.id.length;

        byte[] salt = new byte[sl];
        r.nextBytes(salt);


        if (DEBUG) {
            System.out.println("Rounding to %16==0");
        }
        bout.write(salt);

        bout.flush();

        if (DEBUG) {
            System.out.println("ttl " + ttl + " so far: " + bout.toByteArray().length);
            System.out.println("ttl: " + ttl + " sl=" + sl + "nextEnvelope %16 " + (nextEnvelope.length % 16));
        }

        if (ttl == 1) {
            bout.write(GentianCrypt.encrypt(key.getRawKey(), iv, nextEnvelope, padding, ALGORITHM[ttl % ALGORITHM.length]));
        } else {
            bout.write(GentianCrypt.encrypt(key.getRawKey(), iv, nextEnvelope, false, ALGORITHM[ttl % ALGORITHM.length]));
        }
        wipe(iv);
        wipe(nextEnvelope);
        bout.flush();
        byte[] ret = bout.toByteArray();
        if (DEBUG) {
            System.out.println("Envelope wrap=" + ttl + " " + Base64.encodeToString(ret, false));
            System.out.println("envelope ttl=" + ttl + " %16=" + (ret.length % 16));
        }

        return ret;
    }

    public static byte[] unwrap(GentianKeyProvider provider, byte[] text, int ttl, int saltLength) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnwrapException {
        return unwrap(provider, text, ttl, saltLength, true);
    }

    public static byte[] unwrap(GentianKeyProvider provider, byte[] text, int ttl, int saltLength, boolean padding) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnwrapException {
        if (ttl <= 0) {
            return text;
        }
        int i = 0;
        int kb = provider.keyIdBytes();

        byte[] keyId = new byte[kb];
        for (i = 0; i < kb; i++) {
            keyId[i] = text[i];
        }
        if (DEBUG) {
            System.out.println("Keycode: " + Base64.encodeToString(keyId, false));
        }
        GentianKey key = provider.getKey(keyId);
        if (DEBUG) {
            System.out.println("Used key " + key.idString);
        }
        byte[] iv = new byte[16];
        int limit = kb + 16;
        for (i = kb; i < limit; i++) {
            iv[i - kb] = text[i];
        }
        byte[] unwrapped = null;
        try {
            if (ttl == 1) {
                unwrapped = GentianCrypt.decrypt(key.getRawKey(), iv, copyOfRange(text, 32, text.length), padding, ALGORITHM[ttl % ALGORITHM.length]);
            } else {
                if (DEBUG) {
                    System.out.println("Text %16: " + (text.length % 16));
                }
                unwrapped = GentianCrypt.decrypt(key.getRawKey(), iv, copyOfRange(text, 32, text.length), false, ALGORITHM[ttl % ALGORITHM.length]);
            }
            wipe(text);

        } catch (Exception e) {
            throw new UnwrapException("Unwrapping failed for key: " + Base64.encodeToString(keyId, false) + " keycode " + Base64.encodeToString(keyId, false), e);
        }
        int sl = 8 - key.id.length;
        byte[] unsalted = null;
        if (ttl == 1) {
            sl = saltLength;

            byte[] u2 = copyOfRange(unwrapped, sl, unwrapped.length);
            if (sl > 0) {
                wipe(unsalted);
            }
            unsalted = u2;
        } else {
            unsalted = unwrapped;//Arrays.copyOfRange(unwrapped, 32, unwrapped.length);
        }
        if (DEBUG) {
            System.out.println("Unwrapped: " + Base64.encodeToString(unwrapped, false));
        }
        return unwrap(provider, unsalted, ttl - 1, saltLength, padding);
    }

    private static void wipe(final byte[] data) {
        if (AUTOWIPE) {
        new Thread() {

            @Override
            public void run() {

                SecureRandom r = new SecureRandom();
                if (data != null) {
                    byte[] wipe = new byte[data.length];
                    for (int n = 1; n < 10; n++) {
                        r.nextBytes(wipe);
                        for (int i = 0; i < data.length; i++) {
                            data[i] = wipe[i];
                        }

                    }
                }
            }
        }.start();
        }
//        System.out.print("Envelope Temp data wiped:"+data.length);
    }
}
