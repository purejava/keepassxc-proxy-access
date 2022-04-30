package org.keepassxc;

import org.json.JSONException;
import org.json.JSONObject;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.Future;

public class WindowsConnection extends Connection {

    private static final Logger log = LoggerFactory.getLogger(WindowsConnection.class);

    private final int BUFFER_SIZE = 8192;
    private AsynchronousFileChannel pipe;
    private final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
    private final Charset charset = StandardCharsets.UTF_8;
    private final CharsetDecoder charsetDecoder = charset.newDecoder();
    private final CharBuffer charBuffer = CharBuffer.allocate(BUFFER_SIZE);

    /**
     * Connect to the KeePassXC proxy via a Windows named pipe the proxy has opened.
     *
     * @throws IOException Connecting to the proxy failed due to technical reasons or the proxy wasn't started.
     */
    @Override
    public void connect() throws IOException {
        try {
            Path path = Paths.get("\\\\.\\pipe\\" + PROXY_NAME + "_" + System.getenv("USERNAME"));
            pipe = AsynchronousFileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE);
        } catch (IOException e) {
            log.error("Cannot connect to proxy. Is KeepassXC started?");
            throw e;
        }
        try {
            lauchMessagePublisher();
            changePublicKeys();
        } catch (KeepassProxyAccessException e) {
            log.error(e.toString(), e.getCause());
        }
    }

    @Override
    protected void sendCleartextMessage(String msg) throws IOException {
        if (pipe.isOpen()) {
            log.trace("Sending message: {}", msg);
            pipe.write(ByteBuffer.wrap(msg.getBytes(StandardCharsets.UTF_8)), 0);
        } else {
            throw new IOException("Pipe closed");
        }
    }

    @Override
    protected JSONObject getCleartextResponse() {
        var raw = new StringBuilder();
        long position = 0;
        Future<Integer> operation = pipe.read(buffer, position);
        while (!operation.isDone());
        buffer.flip();
        charsetDecoder.decode(buffer, charBuffer, true);
        charBuffer.flip();
        raw.append(charBuffer);
        buffer.compact();
        charBuffer.clear();
        log.trace("Reading message: {}", raw);
        try {
            var s = raw.toString();
            // Test, if we received more than one message with the last read
            if (s.length() - s.replace("}", "").length() > 1) throw new JSONException("");
            return new JSONObject(raw.toString());
        } catch (JSONException e) {
            log.error("Message corrupted. Received: {}", raw);
            return new JSONObject();
        }
    }

    @Override
    protected boolean isConnected() {
        return null != pipe && pipe.isOpen();
    }

    @Override
    public void close() throws Exception {
        if (null != messagePublisher) messagePublisher.doStop();
        executorService.shutdown();
        if (isConnected()) pipe.close();
    }
}
