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

    private TweetNaclFast.Box box;
    private TweetNaclFast.Box.KeyPair keyPair;
    private TweetNaclFast.Box.KeyPair idKeyPair;
    private byte[] random24;
    private String clientID;
    private Map<String, String> map;
    private String nonce;
    private String associate_id;
    protected final String PROXY_NAME = "org.keepassxc.KeePassXC.BrowserServer";

    public Connection() {
        keyPair = TweetNaclFast.Box.keyPair();
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
    private void sendEncryptedMessage(Map<String, String> msg) throws IOException {
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
    private JSONObject getEncryptedResponse() throws IOException, KeepassProxyAccessException {
        JSONObject response = getCleartextResponse();
        if (response.has("error")) {
            throw new KeepassProxyAccessException(response.getString("error"));
        }
        byte[] serverNonce = Base64.getDecoder().decode(response.getString("nonce"));
        String decrypted = Arrays.toString(box.open(
                Base64.getDecoder().decode(response.getString("message")),
                serverNonce));
        JSONObject decryptedResponse = new JSONObject(decrypted);
        if (!decryptedResponse.has("success")) {
            throw new KeepassProxyAccessException(response.getString("error"));
        }
        return decryptedResponse;
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
        map.put("publicKey", encodePublicKey(keyPair));
        map.put("nonce", nonce);
        map.put("clientID", clientID);

        sendCleartextMessage(jsonTxt(map));
        JSONObject response = getCleartextResponse();

        if (!response.has("success")) {
            throw new KeepassProxyAccessException(response.getString("error"));
        }

        // Store box for further communication
        box = new TweetNaclFast.Box(response.getString("publicKey").getBytes(StandardCharsets.UTF_8), keyPair.getSecretKey());

        incrementNonce();
    }

    public void associate() throws IOException, KeepassProxyAccessException {
        idKeyPair = TweetNaclFast.Box.keyPair();
        // Send associate request
        map = new HashMap<>();
        map.put("action", "associate");
        map.put("key", encodePublicKey(keyPair));
        map.put("idKey", encodePublicKey(idKeyPair));

        sendEncryptedMessage(map);
        JSONObject response = getEncryptedResponse();

        associate_id = response.getString("id");
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
     * Increment nonce by 1
     */
    private void incrementNonce() {
        int newNonce = ByteBuffer.wrap(nonce.getBytes()).getInt() + 1;
        ByteBuffer dbuf = ByteBuffer.allocate(24).putInt(newNonce);
        nonce = Base64.getEncoder().encodeToString(dbuf.array());
    }

    /**
     * Base64 encode public key.
     *
     * @param key The secret and public key to retrieve the public key from.
     * @return Base64 encoded public key.
     */
    private String encodePublicKey(TweetNaclFast.Box.KeyPair key) {
        return Base64.getEncoder().encodeToString(key.getPublicKey());
    }

    @Override
    public abstract void close() throws Exception;
}
