/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package gentian.crypt.keyprovider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import gentian.crypt.GentianEnvelope;
import gentian.crypt.GentianKey;
import gentian.crypt.GentianKeyProvider;
import gentian.crypt.UnwrapException;
import gentian.crypt.WrapException;
import gentian.util.Base64;
import static gentian.util.Util.*;

/**
 *
 * @author nobody
 */
public class DirectoryGentianKeyProvider extends AbstractGentianKeyProvider {

    final File directory;
    private GentianKeyProvider provider;
    private final int wrapCount;
    private int seedLength;

    public DirectoryGentianKeyProvider(File directory) throws NoSuchAlgorithmException {
        this.directory = directory;
        wrapCount = 0;
        loadKeys();
    }

    private void loadKeys() {
        File[] files = directory.listFiles();

        for (File f : files) {
            String base64Name = f.getName().replace("-", "/");
            byte[] id = Base64.decode(base64Name);
            GentianKey key = new GentianKey(id, new DirectoryKeyLoader(f));
            keys.add(key);
            keyById.put(key.idString, key);
        }
        if (files.length > 65536) {
            keyIdBytes = 3;
        } else if (files.length > 256) {
            keyIdBytes = 2;
        } else {
            keyIdBytes = 1;
        }

    }

    public DirectoryGentianKeyProvider(File directory, GentianKeyProvider provider, int wrapCount, int seedLength) throws NoSuchAlgorithmException {
        this.directory = directory;
        this.provider = provider;
        this.wrapCount = wrapCount;
        this.seedLength = seedLength;
        loadKeys();
    }

    public DirectoryGentianKeyProvider(File directory, int initNumberByteKeys) throws NoSuchAlgorithmException, FileNotFoundException, IOException, UnwrapException, WrapException {
        this(directory, initNumberByteKeys, null, 0, 0);
    }

    public DirectoryGentianKeyProvider(File directory, int initNumberByteKeys, GentianKeyProvider provider, int wrapCount, int seedLength) throws NoSuchAlgorithmException, FileNotFoundException, IOException, UnwrapException, WrapException {
        this.directory = directory;
        this.provider = provider;
        this.wrapCount = wrapCount;

        if (initNumberByteKeys > 3) {
            throw new RuntimeException("1-3 initNumberByteKeys supported");
        }

        int initNumberKeys = 1 << (initNumberByteKeys * 8);
        System.out.println("Initing " + initNumberKeys + " keys.");
        List<byte[]> fileNames = createFileNames(initNumberByteKeys);
        for (int i = 0; i < initNumberKeys; i++) {

            GentianKey key = new GentianKey(copyOfRange(fileNames.get(i), 4 - initNumberByteKeys, 4));
            keys.add(key);
            keyById.put(key.idString, key);

            String fileName = Base64.encodeToString(key.id, false).replace("/", "-");
            //System.out.println("Generating key: "+fileName);
            File f = new File(directory, fileName);
            FileOutputStream fout = new FileOutputStream(f);

            if (provider == null) {
                fout.write(key.getRawKey());
            } else {
                try {
                    fout.write(GentianEnvelope.wrap(provider, key.getRawKey(), wrapCount, seedLength, 0, false));
                } catch (UnwrapException e) {
                    throw e;
                } catch (Exception e) {
                    throw new WrapException("Wrapping key failed", e);
                }

            }
            fout.flush();

            fout.close();
            //key.unLoad(new DirectoryKeyLoader(f));
        }


    }

    public boolean wipe(int pass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private class DirectoryKeyLoader extends GentianKey.KeyLoader {

        private File file;

        private DirectoryKeyLoader(File file) {
            this.file = file;
        }
        byte[] read;

        @Override
        protected byte[] loadRaw() throws FileNotFoundException, IOException, UnwrapException {
            if (read != null) {
                return read;
            }
            FileInputStream fin = new FileInputStream(file);
            byte[] read = readStream(fin, true);
            if (provider == null) {
                return read;
            } else {
                try {
                    read = GentianEnvelope.unwrap(provider, read, wrapCount, seedLength, false);
                    return read;
                } catch (Exception e) {
                    throw new UnwrapException("Unwrap key failed", e);
                }

            }
        }

        @Override
        public void wipe() {
            SecureRandom r = new SecureRandom();
            if (read != null) {
                byte[] wipe = new byte[read.length];
                for (int n = 1; n < 10; n++) {
                    r.nextBytes(wipe);
                    for (int i = 0; i < read.length; i++) {
                        read[i] = wipe[i];
                    }

                }
            }
        }
    }
}



