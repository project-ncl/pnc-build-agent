package org.jboss.pnc.buildagent.common;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:matejonnet@gmail.opecom">Matej Lazar</a>
 */
public class LineConsumerTest {

    private static Logger logger = LoggerFactory.getLogger(LineConsumer.class);

    @Test
    public void shouldConvertBytesToStringLines() throws UnsupportedEncodingException, InterruptedException {
        String input = "A home : 家\nSecond line\r\nThird Line\nAnother line\nSome more text.";

        int size = 10;
        List<byte[]> inputs = slicedBytes(input, size);

        ArrayBlockingQueue<String> results = new ArrayBlockingQueue(10);

        Consumer<String> onLine = (line) -> {
            results.add(line);
        };
        LineConsumer lineReader = new LineConsumer(onLine, StandardCharsets.UTF_8);
        inputs.forEach(bytesSlice -> {
            lineReader.append(bytesSlice);
        });
        lineReader.flush();

        String line = results.poll(100, TimeUnit.MILLISECONDS);
        logger.info("Line: {}", line);
        Assert.assertEquals("A home : 家\n", line);

        line = results.poll(100, TimeUnit.MILLISECONDS);
        logger.info("Line: {}", line);
        Assert.assertEquals("Second line\r\n", line);

        line = results.poll(100, TimeUnit.MILLISECONDS);
        logger.info("Line: {}", line);
        Assert.assertNotNull(line);

        line = results.poll(100, TimeUnit.MILLISECONDS);
        logger.info("Line: {}", line);
        Assert.assertNotNull(line);

        line = results.poll(100, TimeUnit.MILLISECONDS);
        logger.info("Line: {}", line);
        Assert.assertEquals("Some more text.", line);

        line = results.poll(100, TimeUnit.MILLISECONDS);
        logger.info("Line: '{}'", line);
        Assert.assertNull(line);

    }

    private List<byte[]> slicedBytes(String input, int sliceSize) {
        List<byte[]> inputs = new ArrayList<>();
        ByteBuffer inputBuffer = ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(sliceSize);
        int added = 0;
        while (inputBuffer.hasRemaining()) {
            byte b = inputBuffer.get();
            buffer.write(b);
            added++;
            if (added == sliceSize) {
                inputs.add(buffer.toByteArray());
                buffer.reset();
                added=0;
            }
        }
        //last chunk (smaller than sliceSize)
        if (added > 0) {
            inputs.add(buffer.toByteArray());
        }
        return inputs;
    }
}