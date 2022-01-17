package org.keepassxc;

import org.apache.commons.lang3.SystemUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;

public class LinuxMacConnection extends Connection {

    private static final Logger log = LoggerFactory.getLogger(LinuxMacConnection.class);

    private final int BUFFER_SIZE = 1024;
    private SocketChannel socket;
    private final UnixDomainSocketAddress socketAddress;
    private final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
    private final Charset charset = StandardCharsets.UTF_8;
    private final CharsetDecoder charsetDecoder = charset.newDecoder();
    private final CharBuffer charBuffer = CharBuffer.allocate(BUFFER_SIZE);

    public LinuxMacConnection() {
        var socketPath = getSocketPath();
        this.socketAddress = UnixDomainSocketAddress.of(socketPath + "/" + PROXY_NAME);
    }

    /**
     * Connect to the KeePassXC proxy via a Unix Domain Sockets (AF_UNIX)
     * the proxy has opened.
     *
     * @throws IOException Connecting to the proxy failed due to technical reasons or the proxy wasn't started.
     */
    @Override
    public void connect() throws IOException {
        try {
            socket = SocketChannel.open(socketAddress);
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
        log.trace("Sending message: {}", msg);
        socket.write(ByteBuffer.wrap(msg.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    protected JSONObject getCleartextResponse() {
        var raw = new StringBuilder();
        while (true) {
            try {
                if (socket.read(buffer) == -1) break;
            } catch (IOException e) {
                log.error(e.toString(), e.getCause());
                return new JSONObject();
            }
            buffer.flip();
            charsetDecoder.decode(buffer, charBuffer, true);
            charBuffer.flip();
            raw.append(charBuffer);
            buffer.compact();
            if (charBuffer.toString().contains("}")) {
                charBuffer.clear();
                break;
            } else {
                charBuffer.clear();
            }
        }
        log.trace("Reading message: {}", raw);
        try {
            return new JSONObject(raw.toString());
        } catch (JSONException e) {
            log.error("Message corrupted. Received: {}", raw);
            return new JSONObject();
        }
    }

    /**
     * Get the os-specific directory, where runtime files and sockets are kept.
     *
     * @return The socket path.
     */
    private String getSocketPath() {
        if (SystemUtils.IS_OS_LINUX) {
            var path = System.getenv("XDG_RUNTIME_DIR");
            if (null == path) path = System.getenv("TMPDIR");
            return (null == path) ? "/tmp" : path;
        }
        if (SystemUtils.IS_OS_MAC_OSX) {
            return System.getenv("TMPDIR");
        } else {
            // unknown OS
            return "-";
        }
    }

    @Override
    protected boolean isConnected() {
        return null!= socket && socket.isOpen();
    }

    @Override
    public void close() throws Exception {
        messagePublisher.doStop();
        executorService.shutdown();
        socket.close();
    }
}
