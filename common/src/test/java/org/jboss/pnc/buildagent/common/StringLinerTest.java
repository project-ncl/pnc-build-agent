package org.jboss.pnc.buildagent.common;

import org.junit.Assert;
import org.junit.Test;

public class StringLinerTest {
    @Test
    public void shouldSplitStringOnLines() {
        StringLiner stringLiner = new StringLiner();

        stringLiner.append("aa");
        String line = stringLiner.nextLine();
        Assert.assertNull(line);

        stringLiner.append("\r\n");
        line = stringLiner.nextLine();
        Assert.assertEquals("aa", line);

        stringLiner.append("bb\n");
        line = stringLiner.nextLine();
        Assert.assertEquals("bb", line);

        stringLiner.append("cc\r");
        line = stringLiner.nextLine();
        Assert.assertEquals("cc", line);

        stringLiner.append("dd");
        line = stringLiner.nextLine();
        Assert.assertNull(line);

        stringLiner.append("\n");
        line = stringLiner.nextLine();
        Assert.assertEquals("dd", line);
    }
}
