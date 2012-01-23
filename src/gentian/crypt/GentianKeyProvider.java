package gentian.crypt;

/**
 *
 * @author miha
 */
public interface GentianKeyProvider {

    public GentianKey pickKey();

    public GentianKey getKey(byte[] keyId);
    public int keyIdBytes();
    public boolean wipe(int pass);

}
