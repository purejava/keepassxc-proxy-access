package org.keepassxc;

import org.json.JSONObject;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

public class WindowsConnection extends Connection {

    static final Logger log = LoggerFactory.getLogger(WindowsConnection.class);

    private RandomAccessFile pipe;

    /**
     * Connect to the KeePassXC proxy via a Windows named pipe the proxy has opened.
     *
     * @throws IOException Connecting to the proxy failed due to technical reasons or the proxy wasn't started.
     * @throws KeepassProxyAccessException It was impossible to exchange new public keys with the proxy.
     */
    @Override
    public void connect() throws IOException, KeepassProxyAccessException {
        try {
            this.pipe = new RandomAccessFile("\\\\.\\pipe\\" + PROXY_NAME + "_" + System.getenv("USERNAME"),
                    "rw");
        } catch (IOException e) {
            log.error("Cannot connect to proxy. Is KeepassXC started?");
            throw e;
        }

        changePublibKeys();
    }

    @Override
    protected void sendCleartextMessage(String msg) throws IOException {
        pipe.write(msg.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected JSONObject getCleartextResponse() throws IOException {
        byte[] buf = new byte[4096];
        int read = pipe.read(buf);
        return new JSONObject(new String(buf, 0, read, StandardCharsets.UTF_8));
    }

    @Override
    public void close() throws Exception {
        pipe.close();
    }
}
