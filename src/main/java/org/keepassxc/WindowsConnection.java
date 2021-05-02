package org.keepassxc;

import org.json.JSONObject;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

public class WindowsConnection extends Connection {

    private static final Logger log = LoggerFactory.getLogger(WindowsConnection.class);

    private RandomAccessFile pipe;

    /**
     * Connect to the KeePassXC proxy via a Windows named pipe the proxy has opened.
     *
     * @throws IOException Connecting to the proxy failed due to technical reasons or the proxy wasn't started.
     */
    @Override
    public void connect() throws IOException {
        try {
            this.pipe = new RandomAccessFile("\\\\.\\pipe\\" + PROXY_NAME + "_" + System.getenv("USERNAME"),
                    "rw");
        } catch (FileNotFoundException e) {
            log.error("Cannot connect to proxy. Is KeepassXC started?");
            throw e;
        }
        try {
            changePublicKeys();
        } catch (KeepassProxyAccessException e) {
            log.error(e.toString(), e.getCause());
        }
    }

    @Override
    protected void sendCleartextMessage(String msg) throws IOException {
        log.trace("Sending message: {}", msg);
        pipe.write(msg.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected JSONObject getCleartextResponse() throws IOException {
        int c;
        String raw = "";
        do {
            c = pipe.read();
            raw += (char) c;
        } while (c != 125); // end of transmission
        log.trace("Reading message: {}", raw);
        return new JSONObject(raw);
    }

    @Override
    protected boolean isConnected() {
        return null != pipe;
    }

    @Override
    public void close() throws Exception {
        pipe.close();
    }
}
