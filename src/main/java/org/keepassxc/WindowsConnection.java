package org.keepassxc;

import org.json.JSONException;
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
            pipe = new RandomAccessFile("\\\\.\\pipe\\" + PROXY_NAME + "_" + System.getenv("USERNAME"),
                    "rw");
        } catch (FileNotFoundException e) {
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
        pipe.write(msg.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected JSONObject getCleartextResponse() {
        int c;
        var raw = "";
        do {
            try {
                c = pipe.read();
                raw += (char) c;
            } catch (IOException e) {
                log.error(e.toString(), e.getCause());
                return new JSONObject();
            }
        } while (c != 125); // end of transmission
        log.trace("Reading message: {}", raw);
        try {
            return new JSONObject(raw);
        } catch (JSONException e) {
            log.error("Message corrupted. Received: {}", raw);
            return new JSONObject();
        }
    }

    @Override
    protected boolean isConnected() {
        return null != pipe;
    }

    @Override
    public void close() throws Exception {
        messagePublisher.doStop();
        executorService.shutdown();
        pipe.close();
    }
}
