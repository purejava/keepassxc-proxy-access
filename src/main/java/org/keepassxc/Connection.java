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
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Establishes a connection to KeePassXC via its build-in proxy.
 * .connect() and .associate() need to ba called to create the connection.
 */
public abstract class Connection implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(Connection.class);
    private final PropertyChangeSupport support;

    private TweetNaclFast.Box box;
    private Optional<Credentials> credentials;
    private final String clientID;
    private static final int nonceLength = 24;
    private byte[] nonce;

    final ExecutorService executorService = Executors.newFixedThreadPool(12);
    protected MessagePublisher messagePublisher;
    private final long QUEUE_CHECKING_INTERVAL_MS = 100;
    private final long SLOW_QUEUE_PROCESSING_MS = 500;
    private final ConcurrentLinkedQueue<JSONObject> queue = new ConcurrentLinkedQueue<>();

    private final int MAX_ERROR_COUNT = 4;
    private final int RECONNECT_DELAY_S = 15;
    private final AtomicReference<ScheduledFuture<?>> scheduledConnectCmd = new AtomicReference<>();

    private final long RESPONSE_DELAY_MS = 500;
    private final ScheduledExecutorService scheduler;

    private final int RESPONSE_TIMEOUT_S = 5;

    protected final String PROXY_NAME = "org.keepassxc.KeePassXC.BrowserServer";
    private static final String NOT_CONNECTED = "Not connected to KeePassXC. Call connect().";
    private static final String KEYEXCHANGE_MISSING = "Public keys need to be exchanged. Call changePublicKeys().";
    private static final String MISSING_CLASS = "Credentials have not been initialized";
    public static final String EXCEPTION_INFO = "Delaying association dialog response lookup due to https://github.com/keepassxreboot/keepassxc/issues/7099";

    private static final Set<String> REQUESTS_WITHOUT_MANUAL_USER_INPUT = Set.of(
            "change-public-keys","get-databasehash","test-associate","get-database-groups"
    );

    public Connection() {
        byte[] array = new byte[nonceLength];
        new Random().nextBytes(array);
        clientID = b64encode(array);
        nonce = TweetNaclFast.randombytes(nonceLength);
        credentials = Optional.empty();
        support = new PropertyChangeSupport(this);
        scheduler = Executors.newSingleThreadScheduledExecutor();
    }

    /**
     * The MessagePublisher listens on the connection to the KeePassXC database and adds messages
     * received to a queue.
     */
    class MessagePublisher implements Runnable {
        private boolean doStop = false;
        private int errorCount = 0;

        public synchronized void doStop() {
            this.doStop = true;
        }

        private synchronized boolean keepRunning() {
            return !this.doStop;
        }

        @Override
        public void run() {
            while (keepRunning()) {
                var response = getCleartextResponse();
                if (!response.isEmpty()) {
                    if (!isSignal(response)) LOG.trace("Response added to queue: {}", response);
                    queue.offer(response);
                    errorCount = 0;
                } else {
                    errorCount++;
                    if (errorCount > MAX_ERROR_COUNT) {
                        LOG.info("Too much errors - stopping MessagePublisher");
                        doStop();
                        try {
                            terminateConnection();
                        } catch (IOException e) {
                            LOG.error(e.toString(), e.getCause());
                        }
                        reconnect();
                    }
                }
            }
            LOG.debug("MessagePublisher stopped");
        }
    }

    class MessageConsumer implements Callable<JSONObject> {
        private final String action;
        private final byte[] nonce;

        /**
         * Check the queue of messages from the KeePassXC database for a message with a given action and nonce,
         * which is the answer to a request sent before and return the message.
         *
         * @param action We are searching for a message with a certain action and
         * @param nonce  a certain nonce.
         */
        public MessageConsumer(String action, byte[] nonce) {
            this.action = action;
            this.nonce = nonce;
        }

        @Override
        public JSONObject call() throws Exception {
            while (true) {
                var response = queue.peek();
                if (null == response) {
                    Thread.sleep(QUEUE_CHECKING_INTERVAL_MS);
                    continue;
                }
                if (isSignal(response)) {
                    queue.remove(response);
                    continue;
                }
                if (response.toString().equals("{}")) {
                    queue.remove(response);
                    LOG.trace("KeePassXC send an empty response: {}", response);
                    continue;
                }
                for (JSONObject message : queue) {
                    LOG.trace("Checking in queue message {}, looking for action '{}' and nonce {}", message, action, b64encode(incrementNonce(nonce)));
                    if (message.has("error") && message.getString("action").equals(action)) {
                        queue.remove(message);
                        LOG.trace("Found in and retrieved from queue: {}", message);
                        return message;
                    }
                    if (message.has("action")
                            && message.getString("action").equals(action)
                            && message.has("nonce")
                            && message.getString("nonce").equals(b64encode(incrementNonce(nonce)))) {
                        queue.remove(message);
                        LOG.trace("Retrieved from queue: {}", message);
                        return message;
                    }
                }
                Thread.sleep(SLOW_QUEUE_PROCESSING_MS);
            }
        }
    }

    void lauchMessagePublisher() {
        messagePublisher = new MessagePublisher();
        LOG.debug("MessagePublisher started");
        executorService.execute(messagePublisher);
    }

    /**
     * Tries to reconnect after a configured time in case connection to KeePassXC was lost.
     * It keeps on trying until a new connection could be established.
     */
    private void reconnect() {
        Runnable connect = () -> {
            try {
                this.connect();
            } catch (IOException e) {
                reconnect();
            }
        };
        var scheduledTask = scheduler.schedule(connect, RECONNECT_DELAY_S, TimeUnit.SECONDS);
        var previouslyScheduledTask = scheduledConnectCmd.getAndSet(scheduledTask);
        if (previouslyScheduledTask != null) {
            previouslyScheduledTask.cancel(false);
        }
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
     * Read a raw message ("as is") from the KeePassXC proxy. Blocks, until message could be read.
     *
     * @return The received raw message, therefore unencrypted.
     */
    protected abstract JSONObject getCleartextResponse();

    /**
     * Test, if the response is a "database-locked" or "database-unlocked" signal.
     *
     * @param response The response to check.
     * @return True, if the response is a signal, false otherwise.
     */
    private boolean isSignal(JSONObject response) {
        try {
            return response.has("action") && response.getString("action").equals("database-locked")
                    || response.has("action") && response.getString("action").equals("database-unlocked");
        } catch (JSONException je) {
            return false;
        }
    }

    /**
     * Send an encrypted message to the proxy.
     * The proxy accepts messages in the JSON data format.
     *
     * @param msg The message to be sent. The key "action" describes the request to the proxy.
     * @return The nonce that was used for this message.
     * @throws IllegalStateException Connection was not initialized before.
     * @throws IOException           Sending failed due to technical reasons.
     */
    private synchronized byte[] sendEncryptedMessage(Map<String, Object> msg) throws IOException {
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
        LOG.trace("Send - encrypting the following message: {}", strMsg);

        box = new TweetNaclFast.Box(publicKey, keyPair.getSecretKey());
        nonce = ramdomGenerateNonce();

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
        return nonce;

    }

    /**
     * Receive the encrypted message from the proxy that fits an action and decrypt it.
     * The proxy sends messages in the JSON data format.
     *
     * @param action The original request that was sent to the proxy.
     * @param nonce  The original nonce that was part of the request.
     * @return The received message, decrypted.
     * @throws KeepassProxyAccessException It was impossible to process the requested action.
     */
    private synchronized JSONObject getEncryptedResponseAndDecrypt(String action, byte[] nonce) throws KeepassProxyAccessException {
        var response = new JSONObject();

        try {
            // requests that don't require user input need to receive an answer within
            // the specified timeout
            if (REQUESTS_WITHOUT_MANUAL_USER_INPUT.contains(action)) {
                response = executorService.submit(new MessageConsumer(action, nonce)).get(RESPONSE_TIMEOUT_S, TimeUnit.SECONDS);
            } else {
                response = executorService.submit(new MessageConsumer(action, nonce)).get();
            }
        } catch (TimeoutException toe) {
            throw new KeepassProxyAccessException("Timeout for action '" + action + "'");
        } catch (InterruptedException | ExecutionException e) {
            LOG.error(e.toString(), e.getCause());
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
        LOG.trace("Decrypted message: {}", decrypted);
        var decryptedResponse = new JSONObject(decrypted);

        if (!decryptedResponse.has("success")) {
            throw new KeepassProxyAccessException("ErrorCode: " + response.getString("errorCode") + ", " + response.getString("error"));
        }

        return decryptedResponse;
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
        nonce = ramdomGenerateNonce();

        // Send change-public-keys request
        sendCleartextMessage(jsonTxt(Map.of(
                "action", "change-public-keys",
                "publicKey", b64encode(keyPair.getPublicKey()),
                "nonce", b64encode(nonce),
                "clientID", clientID
        )));

        var response = new JSONObject();

        try {
            response = executorService.submit(new MessageConsumer("change-public-keys", nonce)).get();
        } catch (InterruptedException | ExecutionException e) {
            LOG.error(e.toString(), e.getCause());
        }

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "associate",
                "key", b64encode(keyPair.getPublicKey()),
                "idKey", b64encode(idKeyPair.getPublicKey())
        ));

        // TODO:
        //  Revert after Qt bug is fixed:
        //  getEncryptedResponseAndDecrypt needs to be run delayed and more important:
        //  a KeepassProxyAccessException needs to be thrown to interrupt the current program flow
        //  otherwise bringing up the association dialog blocks due to a Qt bug,
        //  see https://github.com/keepassxreboot/keepassxc/issues/7099
        Runnable lookupResponse = () -> {
            JSONObject response = null;
            try {
                response = getEncryptedResponseAndDecrypt("associate", nonce);
            } catch (KeepassProxyAccessException e) {
                LOG.error(e.toString(), e.getCause());
            }
            assert response != null;
            credentials.orElseThrow(() -> new IllegalStateException(MISSING_CLASS)).setAssociateId(response.getString("id"));
            credentials.orElseThrow(() -> new IllegalStateException(MISSING_CLASS)).setIdKeyPublicKey(idKeyPair.getPublicKey());
            support.firePropertyChange("associated", null, credentials);
        };
        scheduler.schedule(lookupResponse, RESPONSE_DELAY_MS, TimeUnit.MILLISECONDS);
        throw new KeepassProxyAccessException(EXCEPTION_INFO);
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
        var nonce = sendEncryptedMessage(Map.of("action", "get-databasehash"));
        var response = getEncryptedResponseAndDecrypt("get-databasehash", nonce);

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
        var nonce = sendEncryptedMessage(map);
        var response = getEncryptedResponseAndDecrypt("get-databasehash", nonce);

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "test-associate",
                "id", id,
                "key", key
        ));
        getEncryptedResponseAndDecrypt("test-associate", nonce);

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "get-logins",
                "url", ensureNotNull(url),
                "submitUrl", ensureNotNull(submitUrl),
                "httpAuth", httpAuth,
                "keys", array
        ));
        return getEncryptedResponseAndDecrypt("get-logins", nonce);

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "set-login",
                "url", ensureNotNull(url),
                "submitUrl", ensureNotNull(submitUrl),
                "id", ensureNotNull(id),
                "login", ensureNotNull(login),
                "password", ensureNotNull(password),
                "group", ensureNotNull(group),
                "groupUuid", ensureNotNull(groupUuid),
                "uuid", ensureNotNull(uuid)
        ));
        return getEncryptedResponseAndDecrypt("set-login", nonce);

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
        var nonce = sendEncryptedMessage(Map.of("action", "get-database-groups"));
        return getEncryptedResponseAndDecrypt("get-database-groups", nonce);

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "generate-password",
                "clientID", clientID
        ));
        return getEncryptedResponseAndDecrypt("generate-password", nonce);

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
        var nonce = sendEncryptedMessage(Map.of("action", "lock-database"));
        return getEncryptedResponseAndDecrypt("lock-database", nonce);

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "create-new-group",
                "groupName", ensureNotNull(path)
        ));
        return getEncryptedResponseAndDecrypt("create-new-group", nonce);

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
        var nonce = sendEncryptedMessage(Map.of(
                "action", "get-totp",
                "uuid", ensureNotNull(uuid)
        ));
        return getEncryptedResponseAndDecrypt("get-totp", nonce);

    }

    /**
     * Request to delete an entry, identified by its uuid.
     *
     * @param uuid The uuid of the entry.
     * @return An object that contains the key "success" with the value "true" in case the request was successful.
     * @throws IOException                 The request to delete the entry failed due to technical reasons.
     * @throws KeepassProxyAccessException The entry could not be deleted.
     */
    public JSONObject deleteEntry(String uuid) throws IOException, KeepassProxyAccessException {
        // Send delete-entry request
        var nonce = sendEncryptedMessage(Map.of(
                "action", "delete-entry",
                "uuid", ensureNotNull(uuid)
        ));
        return getEncryptedResponseAndDecrypt("delete-entry", nonce);
    }

    /**
     * Request autotype from the KeePassXC database (KeePassXC 2.7.0 and newer).
     *
     * @param url The URL autotype is requested for.
     * @return An object that contains the key "success" with the value "true" in case the request was successful.
     * @throws IOException                 The autotype request failed due to technical reasons.
     * @throws KeepassProxyAccessException The request could not be processed.
     */
    public JSONObject requestAutotype(String url) throws IOException, KeepassProxyAccessException {
        // Send request-autotype request
        var nonce = sendEncryptedMessage(Map.of(
                "action", "request-autotype",
                "groupName", ensureNotNull(url)
        ));
        return getEncryptedResponseAndDecrypt("request-autotype", nonce);

    }

    public JSONObject passkeysRegister(String publicKey, String origin, List<Map<String, String>> list) throws IOException, KeepassProxyAccessException {
        var array = new JSONArray();
        // Syntax check for list
        for (Map<String, String> m : list) {
            var o = new JSONObject(m);
            if (!(o.has("id") && o.has("key") && o.length() == 2)) {
                throw new KeepassProxyAccessException("JSON object key is malformed");
            }
            array.put(m);
        }

        // Send passkeys-register request
        var nonce = sendEncryptedMessage(Map.of(
                "action", "passkeys-register",
                "publicKey", ensureNotNull(publicKey),
                "origin", ensureNotNull(origin),
                "keys", array
        ));
        return getEncryptedResponseAndDecrypt("passkeys-register", nonce);

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
     * Genrate a randomly generated nonce.
     *
     * @return The new nonce.
     */
    private byte[] ramdomGenerateNonce() {
        return TweetNaclFast.randombytes(nonceLength);
    }

    /**
     * Increment a nonce by 1 like in libsodium/utils.c
     *
     * @param nonce The nonce to be incremented.
     * @return nonce "+1".
     */
    private byte[] incrementNonce(byte[] nonce) {
        var c = 1;
        byte[] incrementedNonce = nonce.clone();

        for (int i = 0; i < nonce.length; i++) {
            c += (incrementedNonce[i] & 0xFF /*treat as unsigned*/);
            incrementedNonce[i] = (byte) c;
            c >>= 8;
        }

        return incrementedNonce;
    }

    /**
     * Base64 encode array of bytes and wrap as a String.
     *
     * @param bytes The data to be encoded.
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

    /**
     * Closes the socket or named pipe respectively.
     *
     * @throws IOException If an I/O error occurred.
     */
    public abstract void terminateConnection() throws IOException;

    /**
     * Closes the socket or named pipe respectively and shuts down the application.
     *
     * @throws Exception Something went wrong.
     */
    @Override
    public abstract void close() throws Exception;
}
