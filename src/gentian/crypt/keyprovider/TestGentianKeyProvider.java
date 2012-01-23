
package gentian.crypt.keyprovider;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;
import gentian.crypt.GentianKey;
import gentian.crypt.GentianKeyProvider;
import gentian.util.Base64;

/**
 *
 * @author nobody
 */
public class TestGentianKeyProvider implements GentianKeyProvider {

    final ArrayList<GentianKey> keys = new ArrayList<GentianKey>();
    final HashMap<String, GentianKey> keyById = new HashMap<String, GentianKey>();
    final Random r = new Random();

    public TestGentianKeyProvider() throws NoSuchAlgorithmException {
        for (int i = 0; i < 256; i++) {
            GentianKey key = new GentianKey(null);
            keys.add(key);
            keyById.put(key.idString, key);
        }

    }

    public GentianKey pickKey() {
        return keys.get(r.nextInt(keys.size()));
    }

    public GentianKey getKey(byte[] keyId) {
        return keyById.get(Base64.encodeToString(keyId, false));
    }

    public boolean wipe(int pass) {
        return true;
    }

    public int keyIdBytes() {
        return 1;
    }
}
