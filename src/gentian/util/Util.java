/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package gentian.util;

/**
 *
 * @author miha
 */
public class Util {
public static byte[] copyOfRange(byte[] source,int start,int end) {
        int len=end-start;
        byte[] b = new byte[len];
        for (int i=0; i<len;i++) {
            b[i]=source[start+i];
        }
        return b;
    }
}
