package org.jboss.pnc.buildagent.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.function.Consumer;

/**
 * Consumer bytes and calls consumer when new line byte is appended.
 *
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class LineConsumer {

    private static final Logger logger = LoggerFactory.getLogger(LineConsumer.class);

    private static final byte LF = 0xA;
    private Consumer<String> lineConsumer;
    private Charset charset;

    private ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);

    /**
     *
     * @param onLine A consumer which is called when new line is appended using.
     * @param charset
     * @throws UnsupportedEncodingException
     */
    public LineConsumer(Consumer<String> onLine, Charset charset) throws UnsupportedEncodingException {
        this.lineConsumer = onLine;
        this.charset = charset;
        if (!Charset.availableCharsets().values().contains(charset)) {
            throw new UnsupportedEncodingException();
        }
    }

    public void append(byte[] bytes) {
        for (byte b : bytes) {
            buffer.write(b);
            if (b == LF) {
                try {
                    lineConsumer.accept(buffer.toString(charset.name()));
                } catch (UnsupportedEncodingException e) {
                    //it must be supported, it's checked in the constructor
                    logger.error("", e);
                }
                buffer.reset();
            }
        }
    }

    /**
     * Call onLine consumer with the remaining string in the buffer.
     */
    public void flush() {
        try {
            if (buffer.size() > 0) { //flush if there is something in the buffer
                lineConsumer.accept(buffer.toString(charset.name()));
            }
        } catch (UnsupportedEncodingException e) {
            //it must be supported, it's checked in the constructor
            e.printStackTrace();
        }
        buffer.reset();
    }
}
