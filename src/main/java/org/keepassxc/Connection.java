package org.keepassxc;

import com.iwebpp.crypto.TweetNaclFast;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.purejava.Credentials;
import org.purejava.KeepassProxyAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Establishes a connection to KeePassXC via its build-in proxy.
 * .connect() and .associate() need to ba called to create the connection.
 */
public abstract class Connection implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Connection.class);
    private PropertyChangeSupport support;

    private TweetNaclFast.Box box;
    private Optional<Credentials> credentials;
    private String clientID;
    private byte[] nonce;

    protected final String PROXY_NAME = "org.keepassxc.KeePassXC.BrowserServer";
    private final String NOT_CONNECTED = "Not connected to KeePassXC. Call connect().";
    private final String KEYEXCHANGE_MISSING = "Public keys need to be exchanged. Call changePublicKeys().";
    private final String MISSING_CLASS = "Credentials have not been initialized";

    public Connection() {
        byte[] array = new byte[24];
        new Random().nextBytes(array);
        clientID = b64encode(array);
        nonce = TweetNaclFast.randombytes(24);
        credentials = Optional.empty();
        support = new PropertyChangeSupport(this);
    }

    public void addPropertyChangeListener(PropertyChangeListener pcl) {
        support.addPropertyChangeListener(pcl);
    }

    public void removePropertyChangeListener(PropertyChangeListener pcl) {
        support.removePropertyChangeListener(pcl);
    }

    public abstract void connect() throws IOException;

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
     * @throws IllegalStateException Connection was not initialized before.
     * @throws IOException           Sending failed due to technical reasons.
     */
    private void sendEncryptedMessage(Map<String, Object> msg) throws IOException {
        var unlockRequested = false;

        if (!isConnected()) {
            throw new IllegalStateException(NOT_CONNECTED);
        }

        var publicKey = credentials.orElseThrow(() -> new IllegalStateException(KEYEXCHANGE_MISSING)).getServerPublicKey();
        var keyPair = credentials.orElseThrow(() -> new IllegalStateException(KEYEXCHANGE_MISSING)).getOwnKeypair();

        if (msg.containsKey("triggerUnlock") && msg.get("triggerUnlock").equals("true")) {
            msg.remove("triggerUnlock");
            unlockRequested = true;
        }

        var strMsg = jsonTxt(msg);
        log.trace("Send - encrypting the following message: {}", strMsg);

        box = new TweetNaclFast.Box(publicKey, keyPair.getSecretKey());

        var encrypted = b64encode(box.box(strMsg.getBytes(), nonce));

        // Map.of can't be used here, because we need a mutable object
        var message = new HashMap<String, Object>();
        message.put("action", msg.get("action").toString());
        message.put("message", encrypted);
        message.put("nonce", b64encode(nonce));
        message.put("clientID", clientID);

        if (unlockRequested) {
            message.put("triggerUnlock", "true");
        }
        sendCleartextMessage(jsonTxt(message));

        incrementNonce();

    }

    /**
     * Receive an encrypted message from the proxy.
     * The proxy sends messages in the JSON data format.
     *
     * @param action The original request that was send to the proxy.
     * @return The received message.
     * @throws IOException                 Retrieving failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to process the requested action.
     */
    private JSONObject getEncryptedResponseAndDecrypt(String action) throws IOException, KeepassProxyAccessException {
        var response = getCleartextResponse();

        // Handle signals
        while (!response.has("error") && isSignal(response)) {
            log.info("Received signal {}", response.getString("action"));
            response = getCleartextResponse();
        }

        // Reading further messages from queue
        while (response.has("action") && !response.getString("action").equals(action)) {
            response = getCleartextResponse();
            if (isSignal(response)) {
                log.info("Received signal {}", response.getString("action"));
            }
        }

        if (response.has("error")) {
            throw new KeepassProxyAccessException("ErrorCode: " + response.getString("errorCode") + ", " + response.getString("error"));
        }

        var serverNonce = b64decode(response.getString("nonce").getBytes());
        var bMessage = box.open(b64decode(response.getString("message").getBytes()), serverNonce);

        if (bMessage == null) {
            throw new KeepassProxyAccessException("Error: message could not be decrypted");
        }

        var decrypted = new String(bMessage, StandardCharsets.UTF_8);
        log.trace("Decrypted message: {}", decrypted);
        var decryptedResponse = new JSONObject(decrypted);

        if (!decryptedResponse.has("success")) {
            throw new KeepassProxyAccessException("ErrorCode: " + response.getString("errorCode") + ", " + response.getString("error"));
        }

        return decryptedResponse;
    }

    private boolean isSignal(JSONObject response) {
        try {
            return response.has("action") && response.getString("action").equals("database-locked")
                    || response.has("action") && response.getString("action").equals("database-unlocked");
        } catch (JSONException je) {
            return false;
        }
    }

    /**
     * Exchange public keys between KeepassXC and this application.
     *
     * @throws IOException                 Connection to the proxy failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to exchange new public keys with the proxy.
     */
    protected void changePublicKeys() throws IOException, KeepassProxyAccessException {
        if (!isConnected()) {
            throw new IllegalStateException(NOT_CONNECTED);
        }

        var keyPair = TweetNaclFast.Box.keyPair();

        // Send change-public-keys request
        sendCleartextMessage(jsonTxt(Map.of(
                "action", "change-public-keys",
                "publicKey", b64encode(keyPair.getPublicKey()),
                "nonce", b64encode(nonce),
                "clientID", clientID
        )));
        var response = getCleartextResponse();

        if (!response.has("success")) {
            throw new KeepassProxyAccessException("ErrorCode: " + response.getString("errorCode") + ", " + response.getString("error"));
        }

        var publicKey = b64decode(response.getString("publicKey").getBytes());
        box = new TweetNaclFast.Box(publicKey, keyPair.getSecretKey());

        if (credentials.isEmpty()) {
            setCredentials(Optional.of(new Credentials()));
        }
        credentials.orElseThrow(() -> new IllegalStateException(MISSING_CLASS)).setOwnKeypair(keyPair);
        credentials.orElseThrow(() -> new IllegalStateException(MISSING_CLASS)).setServerPublicKey(publicKey);
        support.firePropertyChange("credentialsCreated", null, credentials);

        incrementNonce();

    }

    /**
     * Connects KeePassXC with a new client.
     *
     * @throws IllegalStateException       Connection was not initialized before.
     * @throws IOException                 Connecting KeePassXC with a new client failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to associate KeePassXC with a new client.
     */
    public void associate() throws IOException, KeepassProxyAccessException {
        var idKeyPair = TweetNaclFast.Box.keyPair();
        var keyPair = credentials.orElseThrow(() -> new IllegalStateException(KEYEXCHANGE_MISSING)).getOwnKeypair();

        // Send associate request
        sendEncryptedMessage(Map.of(
                "action", "associate",
                "key", b64encode(keyPair.getPublicKey()),
                "idKey", b64encode(idKeyPair.getPublicKey())
        ));
        var response = getEncryptedResponseAndDecrypt("associate");

        credentials.orElseThrow(() -> new IllegalStateException(MISSING_CLASS)).setAssociateId(response.getString("id"));
        credentials.orElseThrow(() -> new IllegalStateException(MISSING_CLASS)).setIdKeyPublicKey(idKeyPair.getPublicKey());
        support.firePropertyChange("associated", null, credentials);
    }

    /**
     * Request for receiving the database hash (SHA256) of the current active KeePassXC database.
     *
     * @return The database hash of the current active KeePassXC database.
     * @throws IOException                 Retrieving the hash failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to get the hash.
     */
    public String getDatabasehash() throws IOException, KeepassProxyAccessException {
        // Send get-databasehash request
        sendEncryptedMessage(Map.of("action", "get-databasehash"));
        var response = getEncryptedResponseAndDecrypt("get-databasehash");

        return response.getString("hash");
    }

    /**
     * Request for receiving the database hash (SHA256) of the current active KeePassXC database.
     * Sent together with a request to unlock the KeePassXC database.
     *
     * @param triggerUnlock When true, the KeePassXC application is brought to the front and unlock is requested from the user.
     * @return The database hash of the current active KeePassXC database.
     * @throws IOException                 Retrieving the hash failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to get the hash.
     */
    public String getDatabasehash(boolean triggerUnlock) throws IOException, KeepassProxyAccessException {
        // Send get-databasehash request with triggerUnlock, if needed
        var map = new HashMap<String, Object>(); // Map.of can't be used here, because we need a mutable object
        map.put("action", "get-databasehash");
        map.put("triggerUnlock", Boolean.toString(triggerUnlock));
        sendEncryptedMessage(map);
        var response = getEncryptedResponseAndDecrypt("get-databasehash");

        return response.getString("hash");
    }

    /**
     * Request for testing if the public IdKey and the public AssociateId are valid and enable this client
     * to talk to KeePassXC. With valid IDs, the client is considered associated with KeePassXC.
     * The test is positive when no exception is thrown.
     *
     * @param id  The identifier of the KeePassXC database connection to be tested.
     * @param key The public key of the idKeyPair to be tested.
     * @throws IOException                 Testing failed due to technical reasons.
     * @throws KeepassProxyAccessException It was impossible to perform the test.
     */
    public void testAssociate(String id, String key) throws IOException, KeepassProxyAccessException {
        // Send test-associate request
        sendEncryptedMessage(Map.of(
                "action", "test-associate",
                "id", id,
                "key", key
        ));
        getEncryptedResponseAndDecrypt("test-associate");

    }

    /**
     * Request credentials from KeePassXC databases for a given URL.
     *
     * @param url       The URL credentials are looked up for.
     * @param submitUrl URL that can be passed along amd gets added to entry properties.
     * @param httpAuth  Include database entries into search that are restricted to HTTP Basic Auth.
     * @param list      Id / key combinations identifying and granting access to KeePassXC databases.
     * @return An object that contains all found credentials together with additional information.
     * @throws IOException                 Requesting credentials failed due to technical reasons.
     * @throws KeepassProxyAccessException No credentials found for the given URL.
     */
    public JSONObject getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list) throws IOException, KeepassProxyAccessException {
        var array = new JSONArray();
        // Syntax check for list
        for (Map<String, String> m : list) {
            var o = new JSONObject(m);
            if (!(o.has("id") && o.has("key") && o.length() == 2)) {
                throw new KeepassProxyAccessException("JSON object key is malformed");
            }
            array.put(m);
        }

        // Send get-logins
        sendEncryptedMessage(Map.of(
                "action", "get-logins",
                "url", ensureNotNull(url),
                "submitUrl", ensureNotNull(submitUrl),
                "httpAuth", httpAuth,
                "keys", array
        ));
        return getEncryptedResponseAndDecrypt("get-logins");

    }

    /**
     * Request to store a new entry or update an existing entry in the current KeePassXC database.
     *
     * @param url       The URL to be saved. The title of the new entry is the hostname of the URL.
     * @param submitUrl URL that can be passed along amd gets added to entry properties.
     * @param id        An identifier for the KeePassXC database connection - ignored at the moment.
     * @param login     The username to be saved.
     * @param password  The password to be saved.
     * @param group     The group name to be used for new entries. Must contain something to use an existing group, but
     *                  the content is ignored, as a group is identified by the groupUuid. In case there is no group with
     *                  the given groupUuid, the standard group is used to store the entry.
     * @param groupUuid Identifier to decide, where to store the entry. For an existing group, the groupUuid must be
     *                  given, otherwise the standard group is used to store the entry.
     * @param uuid      Identifier whether an existing entry is updated or a new one is created. To update an existing entry,
     *                  its current uuid is required. If empty, a new entry is stored in the given groupUuid.
     * @return An object that contains the key "success" with the value "true" in case the request was successful.
     * @throws IOException                 The request to store credentials failed due to technical reasons.
     * @throws KeepassProxyAccessException Credentials could not be stored in the KeePassXC database.
     */
    public JSONObject setLogin(String url, String submitUrl, String id, String login, String password, String group, String groupUuid, String uuid) throws IOException, KeepassProxyAccessException {
        // Send set-login
        sendEncryptedMessage(Map.of(
                "action", "set-login",
                "url", ensureNotNull(url),
                "submitUrl", ensureNotNull(submitUrl),
                "id", ensureNotNull(id),
                "nonce", b64encode(nonce),
                "login", ensureNotNull(login),
                "password", ensureNotNull(password),
                "group", ensureNotNull(group),
                "groupUuid", ensureNotNull(groupUuid),
                "uuid", ensureNotNull(uuid)
        ));
        return getEncryptedResponseAndDecrypt("set-login");

    }

    /**
     * Request to retrieve all database groups together with their groupUuids.
     *
     * @return An object that contains the database groups and groupUuids.
     * @throws IOException                 The request to retrieve the groups failed due to technical reasons.
     * @throws KeepassProxyAccessException The groups could not be retrieved or there weren't any.
     */
    public JSONObject getDatabaseGroups() throws IOException, KeepassProxyAccessException {
        // Send get-database-groups
        sendEncryptedMessage(Map.of("action", "get-database-groups"));
        return getEncryptedResponseAndDecrypt("get-database-groups");

    }

    /**
     * Request to generate a password according to the password generator settings.
     *
     * @return The newly generated password.
     * @throws IOException                 The request to generate a password failed due to technical reasons.
     * @throws KeepassProxyAccessException The password could not be generated.
     */
    public JSONObject generatePassword() throws IOException, KeepassProxyAccessException {
        // Send generate-password request
        sendEncryptedMessage(Map.of(
                "action", "generate-password",
                "nonce", b64encode(nonce),
                "clientID", clientID
        ));
        return getEncryptedResponseAndDecrypt("generate-password");

    }

    /**
     * Request for locking the database from client.
     *
     * @return An object that contains the key "action" with the value "database-locked" in case the request was successful.
     * @throws IOException                 The request to lock the database failed due to technical reasons.
     * @throws KeepassProxyAccessException The database could not be locked.
     */
    public JSONObject lockDatabase() throws IOException, KeepassProxyAccessException {
        // Send lock-database request
        sendEncryptedMessage(Map.of("action", "lock-database"));
        return getEncryptedResponseAndDecrypt("lock-database");

    }

    /**
     * Request to create a new group for the given name or path. If the group already exists, its contents and
     * groupUuid stay untouched.
     *
     * @param path Name or path. A path of the format level1/level2 creates a group level1 on the root level and a
     *             group level2 as a child of level1.
     * @return Last part of the path name of the group that was created with its according groupUuid.
     * @throws IOException                 The request to create the group failed due to technical reasons.
     * @throws KeepassProxyAccessException The group could not be created.
     */
    public JSONObject createNewGroup(String path) throws IOException, KeepassProxyAccessException {
        // Send create-new-group request
        sendEncryptedMessage(Map.of(
                "action", "create-new-group",
                "groupName", ensureNotNull(path)
        ));
        return getEncryptedResponseAndDecrypt("create-new-group");

    }

    /**
     * Request the actual TOTP for the given entry, identified by its uuid. If TOTP is not configured for the entry,
     * an empty String is returned.
     *
     * @param uuid The uuid of the entry.
     * @return The TOTP for the entry or an empty String in case TOTP is not configured for that entry.
     * @throws IOException                 The request to get the TOTP for an entry failed due to technical reasons.
     * @throws KeepassProxyAccessException The TOTP could not be retrieved.
     */
    public JSONObject getTotp(String uuid) throws IOException, KeepassProxyAccessException {
        // Send get-totp request
        sendEncryptedMessage(Map.of(
                "action", "get-totp",
                "uuid", ensureNotNull(uuid)
        ));
        return getEncryptedResponseAndDecrypt("get-totp");

    }

    /**
     * Get a String representation of the JSON object.
     *
     * @param keysValues The keys/values defining the JSON object.
     * @return String representation of the JSON object.
     */
    private String jsonTxt(Map<String, Object> keysValues) {
        return new JSONObject(keysValues).toString();
    }

    /**
     * Increment nonce by 1
     */
    private void incrementNonce() {
        var newNonce = ByteBuffer.wrap(nonce).getInt() + 1;
        var dbuf = ByteBuffer.allocate(24).putInt(newNonce);
        nonce = dbuf.array();
    }

    /**
     * Base64 encode array of bytes and wrap as a String.
     *
     * @param bytes The data to be ecoded.
     * @return Base64 encoded String.
     */
    private String b64encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Base64 decode array of bytes.
     *
     * @param bytes The data to be decoded.
     * @return Base64 decoded data.
     */
    private byte[] b64decode(byte[] bytes) {
        return Base64.getDecoder().decode(bytes);
    }

    private String generateHEXUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private String ensureNotNull(String param) {
        return null == param ? "" : param;
    }

    // Getters and Setters
    public String getIdKeyPairPublicKey() {
        return credentials.map(value -> b64encode(value.getIdKeyPublicKey())).orElse("");
    }

    public String getAssociateId() {
        return credentials.map(Credentials::getAssociateId).orElse("");
    }

    public void setCredentials(Optional<Credentials> credentials) {
        this.credentials = credentials;
    }

    protected abstract boolean isConnected();

    @Override
    public abstract void close() throws Exception;
}
