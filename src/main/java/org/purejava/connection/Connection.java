package org.purejava.connection;

import com.iwebpp.crypto.TweetNaclFast;
import org.json.JSONObject;
import org.purejava.KeepassProxyAccessException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Establishes a connection to KeePassXC via its build-in proxy.
 * .connect() and .associate() need to ba called to create the connection.
 */
public abstract class Connection implements AutoCloseable {

    protected TweetNaclFast.Box box;
    protected TweetNaclFast.Box.KeyPair keyPair;
    protected byte[] random24;
    protected String clientID;
    protected Map<String, String> map;
    protected String nonce;
    protected String pubicKeyB64;
    protected final String PROXY_NAME = "org.keepassxc.KeePassXC.BrowserServer";

    public Connection() {
        keyPair = TweetNaclFast.Box.keyPair();
        pubicKeyB64 = Base64.getEncoder().encodeToString(keyPair.getPublicKey());
        random24 = TweetNaclFast.randombytes(24);
        byte[] array = new byte[24];
        new Random().nextBytes(array);
        clientID = new String(array, StandardCharsets.UTF_8);
        nonce = Base64.getEncoder().encodeToString(random24);
    }

    public abstract void connect() throws IOException, KeepassProxyAccessException;

    /**
     * Send an unencrypted message to the proxy.
     * The proxy accepts messages in the JSON data format.
     *
     * @param msg The message to be sent. The key "action" describes the request to the proxy.
     * @throws IOException Sending failed due to technical reasons.
     */
    protected abstract void sendCleartextMessage(String msg) throws IOException;

    /**
     * Receive an unencrypted message from the proxy.
     * The proxy sends messages in the JSON data format.
     *
     * @return The received message.
     * @throws IOException Retrieving failed due to technical reasons.
     */
    protected abstract JSONObject getCleartextResponse() throws IOException;

    /**
     * Send an encrypted message to the proxy.
     * The proxy accepts messages in the JSON data format.
     *
     * @param msg The message to be sent. The key "action" describes the request to the proxy.
     * @throws IOException Sending failed due to technical reasons.
     */
    public void sendEncryptedMessage(Map<String, String> msg) throws IOException {
        String strMsg = jsonTxt(msg);
        String encrypted = Base64.getEncoder().encodeToString(box.box(strMsg.getBytes(), nonce.getBytes()));
        map = new HashMap<>();
        map.put("action", msg.get("action"));
        map.put("message", encrypted);
        map.put("nonce", nonce);
        map.put("clientID", clientID);
        sendCleartextMessage(jsonTxt(map));
        incrementNonce();
    }

    /**
     * Receive an encrypted message from the proxy.
     * The proxy sends messages in the JSON data format.
     *
     * @return The received message.
     * @throws IOException Retrieving failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to process the requested action.
     */
    public JSONObject getEncryptedResponse() throws IOException, KeepassProxyAccessException {
        JSONObject response = getCleartextResponse();
        if (response.has("error")) {
            throw new KeepassProxyAccessException("Error on receiving response");
        }
        byte[] serverNonce = Base64.getDecoder().decode(response.getString("nonce"));
        String decrypted = Arrays.toString(box.open(
                Base64.getDecoder().decode(response.getString("message")),
                serverNonce));
        JSONObject decryptedResponse = new JSONObject(decrypted);
        if (!decryptedResponse.has("success")) {
            throw new KeepassProxyAccessException("Processing of action failed");
        }
        return decryptedResponse;
    }

    /**
     * Get a String representation of the JSON object.
     *
     * @param keysValues The keys/values defining the JSON object.
     * @return String representation of the JSON object.
     */
    protected String jsonTxt(Map<String, String> keysValues) {
        return new JSONObject(keysValues).toString();
    }

    /**
     * This initially exchanges public keys between KeepassXC and this application
     *
     * @throws IOException Connection to the proxy failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to exchange new public keys with the proxy.
     */
    protected void changePublibKeys() throws IOException, KeepassProxyAccessException {
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
        box = new TweetNaclFast.Box(response.getString("publicKey").getBytes(StandardCharsets.UTF_8), keyPair.getSecretKey());

        incrementNonce();
    }

    /**
     * Increment nonce by 1
     */
    protected void incrementNonce() {
        int newNonce = ByteBuffer.wrap(nonce.getBytes()).getInt() + 1;
        ByteBuffer dbuf = ByteBuffer.allocate(24).putInt(newNonce);
        nonce = Base64.getEncoder().encodeToString(dbuf.array());
    }

    @Override
    public abstract void close() throws Exception;
}
