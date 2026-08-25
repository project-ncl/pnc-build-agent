package org.jboss.pnc.buildagent.server.logging;

import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class LogMatcherTest {

    private static Logger logger = LoggerFactory.getLogger(LogMatcherTest.class);

    @Test
    public void testMatching() {
        Pattern searchPattern = Pattern.compile("nee+dle");
        LogMatcher logMatcher = new LogMatcher(searchPattern);

        Assert.assertFalse("Empty matcher shouldn't find anything", logMatcher.isMatched());

        logMatcher.append("Hay");
        logMatcher.append("stack.\n");
        Assert.assertFalse("No needle in the first haystack", logMatcher.isMatched());

        logMatcher.append("Haystack ne");
        logMatcher.append("e");
        logMatcher.append("e");
        logMatcher.append("e");
        logMatcher.append("dl");
        logMatcher.append("e");
        logMatcher.append("in th");
        logMatcher.append("e");
        logMatcher.append("haystack.\nHaystack.");

        Assert.assertTrue("There should be a a long needle among the haystacks.", logMatcher.isMatched());
    }

    @Test
    public void testMultilineMatching() {
        Pattern searchPattern = Pattern.compile("nee+dle");
        LogMatcher logMatcher = new LogMatcher(searchPattern);

        Assert.assertFalse("Empty matcher shouldn't find anything", logMatcher.isMatched());

        logMatcher.append("Haystack.\nThere is no nedle (!) in this haystack.\nNeither in this one.\nBut it");
        Assert.assertFalse("No needle in the first three haystacks", logMatcher.isMatched());

        logMatcher.append(
                "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\n" +
                        "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\n"
                        +
                        "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\n"
                        +
                        "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\n"
                        +
                        "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\n"
                        +
                        "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nneedle\nHaystack.\nHaystack.\nHaystack.\n"
                        +
                        "Haystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\nHaystack.\n");

        Assert.assertTrue("There should be a needle among the many haystacks.", logMatcher.isMatched());
    }

    @Test
    public void testNotEndedLine() {
        Pattern searchPattern = Pattern.compile("nee+dle");
        LogMatcher logMatcher = new LogMatcher(searchPattern);

        Assert.assertFalse("Empty matcher shouldn't find anything", logMatcher.isMatched());

        logMatcher.append("Haystack needle.");

        Assert.assertTrue("There should be a needle found even when line is not ended.", logMatcher.isMatched());
    }
}
