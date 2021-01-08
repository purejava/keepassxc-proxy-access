package org.purejava;

import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.Box;
import org.apache.commons.lang3.SystemUtils;
import org.json.JSONObject;
import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Establishes a connection to KeePassXC via its build-in proxy.
 * .connect() and .associate() need to ba called to create the connection.
 */
public class Connection implements AutoCloseable {

    static final Logger log = LoggerFactory.getLogger(Connection.class);

    private AFUNIXSocket socket;
    private OutputStream os;
    private InputStream is;
    private String socketPath;
    private Box box;
    private final Box.KeyPair keyPair;
    private final byte[] random24;
    private final String clientID;
    private Map<String, String> map;
    private String nonce;
    private String pubicKeyB64;
    private final File socketFile;

    public Connection() {

        keyPair = Box.keyPair();
        pubicKeyB64 = Base64.getEncoder().encodeToString(keyPair.getPublicKey());
        random24 = TweetNaclFast.randombytes(24);
        byte[] array = new byte[24];
        new Random().nextBytes(array);
        clientID = new String(array, StandardCharsets.UTF_8);
        nonce = Base64.getEncoder().encodeToString(random24);
        socketPath = getSocketPath();
        socketFile = new File(new File(socketPath),
                "/org.keepassxc.KeePassXC.BrowserServer");

    }

    /**
     * Connect to the KeePassXC proxy via a Unix Domain Sockets (AF_UNIX)
     * the proxy has opened.
     *
     * @throws IOException Connecting to the proxy failed due to technical reasons or the proxy wasn't started.
     * @throws KeepassProxyAccessException It was impossible to exchange new public keys with the proxy.
     */
    public void connect() throws IOException, KeepassProxyAccessException {
        try {
            socket = AFUNIXSocket.newInstance();
            socket.connect(new AFUNIXSocketAddress(socketFile));
            os = socket.getOutputStream();
            is = socket.getInputStream();
        } catch (SocketException e) {
            log.error("Cannot connect to proxy. Is KeepassXC started?");
            throw e;
        }

        // Send change-public-keys request
        map = new HashMap<>();
        map.put("action", "change-public-keys");
        map.put("publicKey", pubicKeyB64);
        map.put("nonce", nonce);
        map.put("clientID", clientID);

        sendCleartextMessage(jsonTxt(map));
        JSONObject response = getCleartextResponse();

        if (!response.has("success")) {
            throw new KeepassProxyAccessException("Unable to exchange new public keys");
        }

        // Store box for further communication
        box = new Box(response.getString("publicKey").getBytes(StandardCharsets.UTF_8), keyPair.getSecretKey());

        // Increment nonce by 1
        int newNonce = ByteBuffer.wrap(nonce.getBytes()).getInt() + 1;
        ByteBuffer dbuf = ByteBuffer.allocate(24).putInt(newNonce);
        nonce = Base64.getEncoder().encodeToString(dbuf.array());
    }

    /**
     * Send an unencrypted message to the proxy.
     * The proxy accepts messages in the JSON data format.
     *
     * @param msg The message to be sent. The key "action" describes the request to the proxy.
     * @throws IOException Sending failed due to technical reasons.
     */
    private void sendCleartextMessage(String msg) throws IOException {
        byte[] buf = new byte[4096];
        os.write(msg.getBytes(StandardCharsets.UTF_8));
        os.flush();
    }

    /**
     * Receive an unencrypted message from the proxy.
     * The proxy sends messages in the JSON data format.
     *
     * @return The received message. It contains the key "success" when the request to the proxy could be processed.
     * @throws IOException Retrieving failed due to technical reasons.
     */
    private JSONObject getCleartextResponse() throws IOException {
        byte[] buf = new byte[4096];
        int read = is.read(buf);
        return new JSONObject(new String(buf, 0, read, StandardCharsets.UTF_8));
    }

    /**
     * Get a String representation of the JSON object.
     *
     * @param keysValues The keys/values defining the JSON object.
     * @return String representation of the JSON object.
     */
    private String jsonTxt(Map<String, String> keysValues) {
        return new JSONObject(keysValues).toString();
    }

    /**
     * Get the os-specific directory, where runtime files and sockets are kept.
     *
     * @return The socket path.
     */
    private String getSocketPath() {
        if (SystemUtils.IS_OS_LINUX) {
            return System.getenv("XDG_RUNTIME_DIR");
        }
        if (SystemUtils.IS_OS_MAC_OSX) {
            return System.getenv("TEMPDIR");
        }
        if (SystemUtils.IS_OS_WINDOWS) {
            return "/tmp";
        } else {
            // unknown OS
            return "-";
        }
    }

    @Override
    public void close() throws Exception {
        is.close();
        os.close();
        socket.close();
    }
}
