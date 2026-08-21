package org.jboss.pnc.buildagent.common;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class ArraysTest {

    @Test
    public void charIntstoBytes() {
        String string = "x对于绑定\uFFFD";
        int[] ints = new int[string.length()];

        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            ints[i] = ((int) c);
        }

        byte[] bytes = Arrays.charIntstoBytes(ints, StandardCharsets.UTF_8);

        String reEncoded = new String(bytes, StandardCharsets.UTF_8);
        System.out.println(reEncoded);
        Assert.assertEquals(string, reEncoded);

    }
}