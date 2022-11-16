package org.keepassxc;

import org.apache.commons.lang3.SystemUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
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
    private UnixDomainSocketAddress socketAddress;
    private final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
    private final Charset charset = StandardCharsets.UTF_8;
    private final CharsetDecoder charsetDecoder = charset.newDecoder();
    private final CharBuffer charBuffer = CharBuffer.allocate(BUFFER_SIZE);

    private static final String FLATPAK_PATH = "/app/org.keepassxc.KeePassXC";
    private static final String SNAP_PATH = System.getProperty("user.home") + "/snap/keepassxc/common";

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
        if (socket.isOpen()) {
            log.trace("Sending message: {}", msg);
            socket.write(ByteBuffer.wrap(msg.getBytes(StandardCharsets.UTF_8)));
        } else {
            throw new IOException("Socket closed");
        }
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
            var s = raw.toString();
            // Test, if we received more than one message with the last read
            if (s.length() - s.replace("}", "").length() > 1) throw new JSONException("");
            return new JSONObject(raw.toString());
        } catch (JSONException e) {
            log.error("Message corrupted. Received: {}", raw);
            return new JSONObject();
        }
    }

    /**
     * Get the os-specific and KeePassXC installation-specific directory, where runtime files and sockets are kept.
     *
     * @return The socket path.
     */
    private String getSocketPath() {
        if (SystemUtils.IS_OS_LINUX) {
            var type = KindOfKeePassXC.determineType();
            if (type.isEmpty()) {
                return getXDGPath();
            } else {
                switch (type.get()) {
                    case Repo, AppImage -> {
                        return getXDGPath();
                    }
                    case Flatpak -> {
                        log.debug("Using XDG_RUNTIME_DIR" + FLATPAK_PATH);
                        return System.getenv("XDG_RUNTIME_DIR") + FLATPAK_PATH;
                    }
                    case Snap -> {
                        log.debug("Using " + SNAP_PATH);
                        return SNAP_PATH;
                    }
                }
            }
        }
        if (SystemUtils.IS_OS_MAC_OSX) {
            return System.getenv("TMPDIR");
        } else {
            // unknown OS
            return "-";
        }
    }

    /**
     * Find the XDG_RUNTIME_DIR KeePassXC is using.
     * When installed from a repo or run as an AppImage, it depends on the KeePassXC version, where it creates its socket:
     * KeePassXC <2.7.2 create it in the XDG_RUNTIME_DIR
     * KeePassXC 2.7.2+ create it in XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/
     *
     * @return The correct socket path.
     */
    private String getXDGPath() {
        var path = System.getenv("XDG_RUNTIME_DIR");
        log.debug("Checking if XDG_RUNTIME_DIR exists ...");
        if (null == path) {
            log.debug("Unable to find XDG_RUNTIME_DIR");
            path = System.getenv("TMPDIR");
            log.debug("Using TEMPDIR");
            return (null == path) ? "/tmp" : path;
        } else {
            var flatpakPath = new File(path + FLATPAK_PATH);
            if (flatpakPath.exists()) {
                log.debug("Using XDG_RUNTIME_DIR" + FLATPAK_PATH);
                return path + FLATPAK_PATH;
            } else {
                log.debug("Using XDG_RUNTIME_DIR");
                return path;
            }
        }
    }

    @Override
    protected boolean isConnected() {
        return null != socket && socket.isOpen();
    }

    @Override
    public void terminateConnection() throws IOException {
        if (isConnected()) socket.close();
    }

    @Override
    public void close() throws Exception {
        if (null != messagePublisher) messagePublisher.doStop();
        executorService.shutdown();
        if (isConnected()) socket.close();
    }
}
