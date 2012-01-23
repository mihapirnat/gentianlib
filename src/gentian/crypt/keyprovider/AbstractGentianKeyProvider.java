/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package gentian.crypt.keyprovider;

import gentian.crypt.GentianEnvelope;
import gentian.crypt.GentianKey;
import gentian.crypt.GentianKeyProvider;
import gentian.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
/**
 *
 * @author miha
 */
public abstract class AbstractGentianKeyProvider implements GentianKeyProvider {

    final Random r = new Random();
    int keyIdBytes;
    int lastKeyIndex = -1;
    final ArrayList<GentianKey> keys = new ArrayList<GentianKey>();
    final HashMap<String, GentianKey> keyById = new HashMap<String, GentianKey>();

    public GentianKey pickKey() {
        int candidate;
        while ((candidate = r.nextInt(keys.size())) == lastKeyIndex) {
        }
        lastKeyIndex = candidate;
        return keys.get(lastKeyIndex);
    }

    public GentianKey getKey(byte[] keyId) {
        return keyById.get(Base64.encodeToString(keyId, false));
    }

    public abstract boolean wipe(int pass);

    public int keyIdBytes() {
        return keyIdBytes;
    }

    protected List<byte[]> createFileNames(int initNumberByteKeys) throws IOException {
        int initNumberKeys = 1 << (initNumberByteKeys * 8);
        ArrayList<byte[]> fileNames = new ArrayList<byte[]>(initNumberByteKeys);
        for (int i = 0; i < initNumberKeys; i++) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(4);
            DataOutputStream dout = new DataOutputStream(bout);

            dout.writeInt(i);
            dout.close();
            byte[] idbytes = bout.toByteArray();
            fileNames.add(idbytes);
        }
        SecureRandom rsh = new SecureRandom();
        int shuffleRounds = 8;
        byte[] shuffleSeeds = new byte[8 * shuffleRounds];
        rsh.nextBytes(shuffleSeeds);
        DataInputStream shuffleSeedStream = new DataInputStream(new ByteArrayInputStream(shuffleSeeds));
        for (int i = 0; i < shuffleRounds; i++) {
            long seed = shuffleSeedStream.readLong();
            
            Random rshuf = new Random(seed);
            Collections.shuffle(fileNames, rshuf);
        }
        return fileNames;
    }

    public static boolean wipeFile(File f,int pass) {
        try {
            long targetL = f.length();
            for (int i = 0; i < pass; i++) {
                FileOutputStream fout = new FileOutputStream(f);
                TestGentianKeyProvider testProvider = new TestGentianKeyProvider();
                SecureRandom secr = new SecureRandom();
                final int BLOCK = 4096;
                byte[] randB = new byte[BLOCK];
                long count = 0;
                while (count < targetL) {
                    byte[] wrap = GentianEnvelope.wrap(testProvider, randB, 3, 0, 0);
                    if (count + BLOCK < targetL) {
                        fout.write(wrap);
                        count += BLOCK;
                    } else {
                        long diff = targetL - count;
                        fout.write(wrap, (int) (BLOCK - diff), (int) diff);
                        count = targetL;
                    }
                }
                fout.close();
            }
            f.delete();
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
}
