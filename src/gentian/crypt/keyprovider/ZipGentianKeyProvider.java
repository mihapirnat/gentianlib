/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package gentian.crypt.keyprovider;

import gentian.crypt.GentianCrypt;
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
import java.io.BufferedInputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import static gentian.util.Util.*;

/**
 *
 * @author miha
 */
public class ZipGentianKeyProvider extends AbstractGentianKeyProvider {

    final File zip;
    private GentianKeyProvider provider;
    private final int wrapCount;
    private int seedLength;
    byte[][] cryptKeys;

    public void wipe() {
        SecureRandom r = new SecureRandom();
        for (int n = 1; n < 50; n++) {
            if (cryptKeys != null) {
                for (byte[] b : cryptKeys) {
                    byte[] wipe = new byte[b.length];
                    r.nextBytes(wipe);
                    for (int i = 0; i < b.length; i++) {
                        b[i] = wipe[i];
                    }
                }
            }
        }
        for (GentianKey key : keys) {
            key.wipe();
        }
        System.out.println("Zip provider keys wiped");
    }

    @Override
    protected void finalize() throws Throwable {
        wipe();


        try {
            super.finalize();
        } catch (Exception e) {
        }
    }

    /**
     *
     * @param zip ZIP file to load keys from
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public ZipGentianKeyProvider(File zip) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        this.zip = zip;
        wrapCount = 0;
        loadKeys();
    }

    /**
     *
     * @param zip ZIP file to load keys from
     * @param keys additional encryption by AES-256 keys, can be null
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public ZipGentianKeyProvider(File zip, byte[][] keys) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        this.zip = zip;
        this.cryptKeys = keys;
        wrapCount = 0;
        loadKeys();
    }

    private ZipGentianKeyProvider(ArrayList<GentianKey> keys, HashMap<String, GentianKey> keyById, int keyIdBytes) {
        for (GentianKey key : keys) {
            this.keys.add(key);
        }
        for (String id : keyById.keySet()) {
            this.keyById.put(id, keyById.get(id));
        }
        this.keyIdBytes = keyIdBytes;
        this.wrapCount = 0;
        this.zip = null;
    }

    private void loadKeys() throws FileNotFoundException, IOException {


        FileInputStream fis = new FileInputStream(zip);

        ZipInputStream zis = new ZipInputStream(new BufferedInputStream(fis));
        ZipEntry entry;

        while ((entry = zis.getNextEntry()) != null) {

            String base64Name = entry.getName().replace("-", "/");
            byte[] id = Base64.decode(base64Name);
            GentianKey key = new GentianKey(id, new ZipKeyLoader(zis));
            keys.add(key);
            keyById.put(key.idString, key);

        }
        if (keys.size() > 65536) {
            keyIdBytes = 3;
        } else if (keys.size() > 256) {
            keyIdBytes = 2;
        } else {
            keyIdBytes = 1;
        }
        System.out.println("key id bytes: " + keyIdBytes);
        zis.close();
    }

    /**
     *
     * @param zip ZIP file to load keys with
     * @param provider Decrypt keys using provider
     * @param wrapCount Number of envelopes used
     * @param seedLength Envelope seed
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public ZipGentianKeyProvider(File zip, GentianKeyProvider provider, int wrapCount, int seedLength) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        this.zip = zip;
        this.provider = provider;
        this.wrapCount = wrapCount;
        this.seedLength = seedLength;
        loadKeys();
    }

    /**
     *
     * @param zip ZIP file to load keys with
     * @param provider Decrypt keys using provider
     * @param wrapCount Number of envelopes used
     * @param seedLength Envelope seed
     * @param keys additional encryption by AES-256 keys, can be null
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public ZipGentianKeyProvider(File zip, GentianKeyProvider provider, int wrapCount, int seedLength, byte[][] keys) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        this.zip = zip;
        this.provider = provider;
        this.wrapCount = wrapCount;
        this.seedLength = seedLength;
        this.cryptKeys = keys;
        loadKeys();
    }

    /**
     *
     * @param zip ZIP file to save keys to
     * @param initNumberByteKeys key id bytes 1-3: 1: 256, 2: 65536 ...
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws UnwrapException
     * @throws WrapException
     */
    public ZipGentianKeyProvider(File zip, int initNumberByteKeys) throws NoSuchAlgorithmException, FileNotFoundException, IOException, UnwrapException, WrapException {
        this(zip, initNumberByteKeys, null, 0, 0, null);
    }

    /**
     *
     * @param zip ZIP file to save keys to
     * @param initNumberByteKeys key id bytes 1-3: 1: 256, 2: 65536 ...
     * @param cryptKeys additional encryption by AES-256 keys, can be null
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws UnwrapException
     * @throws WrapException
     */
    public ZipGentianKeyProvider(File zip, int initNumberByteKeys, byte[][] cryptKeys) throws NoSuchAlgorithmException, FileNotFoundException, IOException, UnwrapException, WrapException {
        this(zip, initNumberByteKeys, null, 0, 0, cryptKeys);
    }

    /**
     *
     * @param zip ZIP file to save keys to
     * @param initNumberByteKeys key id bytes 1-3: 1: 256, 2: 65536 ...
     * @param provider Decrypt keys using provider
     * @param wrapCount Number of envelopes used
     * @param seedLength Envelope seed
     * @param cryptKeys additional encryption by AES-256 keys, can be null
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws UnwrapException
     * @throws WrapException
     */
    public ZipGentianKeyProvider(File zip, int initNumberByteKeys, GentianKeyProvider provider, int wrapCount, int seedLength, byte[][] cryptKeys) throws NoSuchAlgorithmException, FileNotFoundException, IOException, UnwrapException, WrapException {
        this.zip = zip;
        this.cryptKeys = cryptKeys;
        this.provider = provider;
        this.wrapCount = wrapCount;

        if (initNumberByteKeys > 3) {
            throw new RuntimeException("1-3 initNumberByteKeys supported");
        }

        int initNumberKeys = 1 << (initNumberByteKeys * 8);
        keyIdBytes = initNumberByteKeys;
        System.out.println("Initing " + initNumberKeys + " keys.");
        List<byte[]> fileNames = createFileNames(initNumberByteKeys);
        for (int i = 0; i < initNumberKeys; i++) {

            GentianKey key = new GentianKey(copyOfRange(fileNames.get(i), 4 - initNumberByteKeys, 4));

            keys.add(key);
            keyById.put(key.idString, key);
        }
        FileOutputStream fout = new FileOutputStream(zip);
        save(fout, this.provider, this.cryptKeys);
    }

    private void save(OutputStream out, GentianKeyProvider provider, byte[][] cryptKeys) throws IOException, NoSuchAlgorithmException, UnwrapException, WrapException {
        int initNumberByteKeys = keyIdBytes;
        int initNumberKeys = 1 << (initNumberByteKeys * 8);
        ZipOutputStream zout = new ZipOutputStream(out);

        for (int i = 0; i < initNumberKeys; i++) {
            GentianKey key = keys.get(i);
            String fileName = Base64.encodeToString(key.id, false).replace("/", "-");
            //System.out.println("Generating key: "+fileName);


            if (provider == null) {
                ZipEntry entry = new ZipEntry(fileName);
                zout.putNextEntry(entry);
                byte[] text = key.getRawKey();
                if (cryptKeys != null) {
                    for (int x = cryptKeys.length - 1; x >= 0; x--) {
                        byte[] b = cryptKeys[x];
                        try {
                            text = GentianCrypt.encrypt(b, new byte[16], text, false);
                        } catch (NoSuchPaddingException ex) {
                            Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IllegalBlockSizeException ex) {
                            Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (BadPaddingException ex) {
                            Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (InvalidKeyException ex) {
                            Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (InvalidAlgorithmParameterException ex) {
                            Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchProviderException ex) {
                            Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
                zout.write(text);
            } else {
                try {
                    ZipEntry entry = new ZipEntry(fileName);
                    zout.putNextEntry(entry);
                    byte[] text = GentianEnvelope.wrap(provider, key.getRawKeyCopy(), wrapCount, seedLength, 0, false);
                    if (cryptKeys != null) {
                        for (int x = cryptKeys.length - 1; x >= 0; x--) {
                            byte[] b = cryptKeys[x];
                            try {
                                text = GentianCrypt.encrypt(b, new byte[16], text, false);
                            } catch (NoSuchPaddingException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (IllegalBlockSizeException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (BadPaddingException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (InvalidKeyException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (InvalidAlgorithmParameterException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                    }
                    zout.write(text);
                } catch (UnwrapException e) {
                    throw e;
                } catch (Exception e) {
                    throw new WrapException("Wrapping key failed", e);
                }

            }
            //key.unLoad(new DirectoryKeyLoader(f));
        }
        zout.flush();

        zout.close();

    }

    public boolean wipe(int pass) {
        return wipeFile(zip, pass);
    }

    private class ZipKeyLoader extends GentianKey.KeyLoader {

        private ZipInputStream zin;
        byte[] read;
        byte[] raw;

        private ZipKeyLoader(ZipInputStream zin) {
            this.zin = zin;
            try {
                preLoadRaw();
            } catch (IOException ex) {
                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnwrapException ex) {
                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        protected void preLoadRaw() throws IOException, UnwrapException {

            read = readStream(zin, false);


        }

        @Override
        protected byte[] loadRaw() throws FileNotFoundException, IOException, UnwrapException {
            if (this.raw == null) {
                if (provider == null) {
                    this.raw = read;
                    if (cryptKeys != null) {
                        for (byte[] b : cryptKeys) {
                            try {
                                this.raw = GentianCrypt.decrypt(b, new byte[16], this.raw, false);
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (NoSuchPaddingException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (IllegalBlockSizeException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (BadPaddingException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (InvalidKeyException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (InvalidAlgorithmParameterException ex) {
                                Logger.getLogger(ZipGentianKeyProvider.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                    }
                } else {
                    try {
                        this.raw = GentianEnvelope.unwrap(provider, read, wrapCount, seedLength, false);
                        if (cryptKeys != null) {
                            for (byte[] b : cryptKeys) {
                                this.raw = GentianCrypt.decrypt(b, new byte[16], this.raw, false);
                            }
                        }
                    } catch (Exception e) {
                        throw new UnwrapException("Unwrap key failed", e);
                    }

                }
                this.read = null;
            }
            return this.raw;
        }

        @Override
        public void wipe() {
            try {
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
                if (raw != null) {
                    byte[] wipe = new byte[raw.length];
                    for (int n = 1; n < 10; n++) {

                        r.nextBytes(wipe);

                        for (int i = 0; i < raw.length; i++) {

                            raw[i] = wipe[i];
                        }
                    }
                }
            } catch (Exception e) {
            }

        }
    }

    public void recrypt(OutputStream out, GentianKeyProvider provider, byte[][] cryptKeys, int wrapCount, int seedLength) throws IOException, NoSuchAlgorithmException, UnwrapException, WrapException {
        //ZipGentianKeyProvider clone =new ZipGentianKeyProvider(keys,keyById,keyIdBytes);
        save(out, provider, cryptKeys);
    }
}
