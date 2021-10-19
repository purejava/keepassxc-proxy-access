package org.purejava;

import org.apache.commons.lang3.SystemUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.keepassxc.Connection;
import org.keepassxc.LinuxMacConnection;
import org.keepassxc.WindowsConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class KeepassProxyAccess implements PropertyChangeListener {
    private static final Logger log = LoggerFactory.getLogger(KeepassProxyAccess.class);

    private Connection connection;
    private String fileLocation;
    private final String FILE_NAME = "keepass-proxy-access.dat";
    private final long SAVE_DELAY_MS = 1000;
    private final AtomicReference<ScheduledFuture<?>> scheduledSaveCmd = new AtomicReference<>();
    private final ScheduledExecutorService scheduler;

    public KeepassProxyAccess() {
        if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC_OSX) {
            connection = new LinuxMacConnection();
            fileLocation = System.getProperty("user.home");
            if (SystemUtils.IS_OS_LINUX) {
                fileLocation += "/.config/keepass-proxy-access/" + FILE_NAME;
            }
            if (SystemUtils.IS_OS_MAC_OSX) {
                fileLocation += "/Library/Application Support/keepass-proxy-access/" + FILE_NAME;
            }
        }
        if (SystemUtils.IS_OS_WINDOWS) {
            connection = new WindowsConnection();
            fileLocation = System.getenv("AppData") + "keepass-proxy-access/" + FILE_NAME;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor();
        connection.addPropertyChangeListener(this);
        Runtime.getRuntime().addShutdownHook(new Thread(() ->
                connection.removePropertyChangeListener(this)
        ));
        connection.setCredentials(loadCredentials());
    }

    /**
     * Loads the {@link org.purejava.Credentials Credentials} from disc, if available, to setup this library
     * so that it can be used to send requests to and receive requests from a KeePassXC database.
     * @see org.purejava.Credentials
     *
     * @return An Optional of the Credentials read from disc in case they are available, an empty Optional otherwise.
     */
    private Optional<Credentials> loadCredentials() {
        try (var fileIs = new FileInputStream(fileLocation);
             var objIs = new ObjectInputStream(fileIs)) {
            var c = (Credentials) objIs.readObject();
            return Optional.of(c);
        } catch (IOException | ClassNotFoundException e) {
            log.debug("Credentials could not be read from disc");
            return Optional.empty();
        }
    }


    /**
     * Saves {@link org.purejava.Credentials Credentials} in a delayed background thread to disc, as this is a time consuming
     * operation that might fail.
     * @see org.purejava.Credentials
     *
     * @param credentials An Optional of the Credentials to be saved.
     */
    private void scheduleSave(Optional<Credentials> credentials) {
        if (credentials.isEmpty()) {
            log.debug("Credentials are not present and won't be saved");
            return;
        }
        Runnable saveCommand = () -> this.saveCredentials(credentials);
        var scheduledTask = scheduler.schedule(saveCommand, SAVE_DELAY_MS, TimeUnit.MILLISECONDS);
        var previouslyScheduledTask = scheduledSaveCmd.getAndSet(scheduledTask);
        if (previouslyScheduledTask != null) {
            previouslyScheduledTask.cancel(false);
        }
    }

    /**
     * Saves {@link org.purejava.Credentials Credentials} to disc.
     * @see org.purejava.Credentials
     *
     * @param credentials An Optional of the Credentials to be saved.
     */
    private void saveCredentials(Optional<Credentials> credentials) {
        log.debug("Attempting to save credentials");
        try {
            var path = Path.of(fileLocation);
            Files.createDirectories(path.getParent());
            var tmpPath = path.resolveSibling(path.getFileName().toString() + ".tmp");
            try (var ops = Files.newOutputStream(tmpPath, StandardOpenOption.CREATE_NEW);
                 var objOps = new ObjectOutputStream(ops)) {
                objOps.writeObject(credentials.get());
                objOps.flush();
            }
            Files.move(tmpPath, path, StandardCopyOption.REPLACE_EXISTING);
            log.debug("Credentials saved");
        } catch (IOException e) {
            log.error("Credentials could not be saved to disc");
            log.error(e.toString(), e.getCause());
        }
    }

    /**
     * Convenience method to get the connection parameters that are required to identify the KeePassXC database.
     *
     * @return The entered associateID and returned IDKeyPublicKey stored on association.
     */
    public Map<String, String> exportConnection() {
        return Map.of("id", connection.getAssociateId(),
                "key", connection.getIdKeyPairPublicKey());
    }

    /**
     * Establish a connection to the KeePassXC proxy. This is required for every session.
     * The closing of the connection is handled automatically.
     * @see org.keepassxc.LinuxMacConnection
     * @see org.keepassxc.WindowsConnection
     *
     * @return True, if connecting to the proxy was successful, false, if connecting failed due to technical reasons
     * or the proxy wasn't started.
     */
    public boolean connect() {
        try {
            connection.connect();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Connects KeePassXC with a new client. This is required once, on connecting a new client to KeePassXC and
     * creates the public idKey and the public associateId.
     *
     * @return True, if it was possible to associate KeePassXC with a new client, false otherwise.
     */
    public boolean associate() {
        try {
            connection.associate();
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    /**
     * Checks, if this client has been associated with KeePassXC and if the association is still valid. To establish
     * a connection to KeePassXC, the public idKey and the public associateId are required. With these parameters,
     * {@link org.purejava.KeepassProxyAccess#testAssociate(String, String) testAssociate} is called to verify the
     * association. A valid association enables the client to send requests to and receive requests from KeePassXC.
     * @see org.purejava.KeepassProxyAccess#testAssociate(String, String)
     *
     * @return True, if a valid association with KeePassXC exists, false otherwise.
     */
    public boolean connectionAvailable() {
        return getIdKeyPairPublicKey() != null &&
               !getIdKeyPairPublicKey().isEmpty() &&
                getAssociateId() != null &&
                !getAssociateId().isEmpty() &&
                testAssociate(getAssociateId(), getIdKeyPairPublicKey());
    }

    /**
     * Request for testing if the public idKey and the public associateId are valid and enable this client
     * to talk to KeePassXC. With valid IDs, the client is considered associated with KeePassXC.
     *
     * @param id  The identifier of the KeePassXC database connection to be tested.
     * @param key The public key of the idKeyPair to be tested.
     * @return True, if the id and the key are valid, false otherwise.
     */
    public boolean testAssociate(String id, String key) {
        try {
            connection.testAssociate(id, key);
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    /**
     * Request for receiving the database hash (SHA256) of the current active KeePassXC database.
     * The request can be send in conjunction with an optional request to unlock the KeePassXC database.
     *
     * @param unlock When true, the KeePassXC application is brought to the front and unlock is requested from the user.
     * @return The database hash of the current active KeePassXC database in case the hash could be retrieved,
     * an empty String otherwise.
     */
    public String getDatabasehash(boolean... unlock) {
        try {
            if (unlock.length > 1) {
                throw new IllegalStateException("Invalid number of parameters for getDatabasehash(boolean... unlock)");
            }
            return switch (unlock.length) {
                case 0 -> connection.getDatabasehash();
                case 1 -> connection.getDatabasehash(unlock[0]);
                default -> "";
            };
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return "";
        }
    }

    /**
     * Request credentials from KeePassXC databases for a given URL.
     *
     * @param url       The URL credentials are looked up for.
     * @param submitUrl URL that can be passed along amd gets added to entry properties.
     * @param httpAuth  Include database entries into search that are restricted to HTTP Basic Auth.
     * @param list      Id / key combinations identifying and granting access to KeePassXC databases.
     * @return A Map that contains all found credentials together with additional information, in case credentials
     * were found, an empty Map otherwise.
     */
    public Map<String, Object> getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list) {
        try {
            return connection.getLogins(url, submitUrl, httpAuth, list).toMap();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return Map.of();
        }
    }

    /**
     * Checks, whether a login exists and a given password is stored in the KeePassXC databases. This method calls
     * {@link org.purejava.KeepassProxyAccess#getLogins(String, String, boolean, List) getLogins} to search
     * the KeePassXC databases.
     * @see org.purejava.KeepassProxyAccess#getLogins(String, String, boolean, List)
     *
     * @param url       The URL credentials are looked up for.
     * @param submitUrl URL that can be passed along amd gets added to entry properties.
     * @param httpAuth  Include database entries into search that are restricted to HTTP Basic Auth.
     * @param list      Id / key combinations identifying and granting access to KeePassXC databases.
     * @param password  Password to check.
     * @return ValidLogin The object describes whether a valid login exists for the given URL and whether the given password matches too.
     */
    public ValidLogin loginExists(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list, String password) {
        var response = getLogins(url, submitUrl, httpAuth, list);
        if (response.isEmpty()) {
            return new ValidLogin(false, null);
        }
        var array = (ArrayList<Object>) response.get("entries");
        for (Object o : array) {
            var credentials = (HashMap<String, Object>) o;
            if (credentials.get("password").equals(password)) return new ValidLogin(true, credentials.get("uuid").toString());
        }
        return new ValidLogin(true, null);
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
     * @return True, if the entry could be stored/updated, false otherwise.
     */
    public boolean setLogin(String url, String submitUrl, String id, String login, String password, String group, String groupUuid, String uuid) {
        try {
            var response = connection.setLogin(url, submitUrl, id, login, password, group, groupUuid, uuid);
            return response.has("success") && response.getString("success").equals("true");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    /**
     * Request to retrieve all database groups together with their groupUuids.
     *
     * @return An object that contains the database groups and groupUuids in case the request was successful, an empty object otherwise.
     */
    public JSONObject getDatabaseGroups() {
        try {
            return connection.getDatabaseGroups();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return new JSONObject();
        }
    }

    /**
     * Request to generate a password according to the password generator settings.
     *
     * @return The newly generated password in case the generation was successful, an empty String otherwise.
     */
    public String generatePassword() {
        try {
            var response = connection.generatePassword().getJSONArray("entries");
            return response.getJSONObject(0).getString("password");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return "";
        }
    }

    /**
     * Request for locking the database from client.
     *
     * @return True, if the database could be locked, false if something went wrong.
     */
    public boolean lockDatabase() {
        try {
            connection.lockDatabase();
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    /**
     * Request to create a new group for the given name or path. If the group already exists, its contents and
     * groupUuid stay untouched.
     *
     * @param path Name or path. A path of the format level1/level2 creates a group level1 on the root level and a
     *             group level2 as a child of level1.
     * @return A Map containing the last part of the path name of the group (key: "name") that was created with its according groupUuid (key: "uuid")
     * in case the group could be created, an empty Map otherwise.
     */
    public Map<String, String> createNewGroup(String path) {
        try {
            return getNewGroupId(connection.createNewGroup(path));
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return Map.of();
        }
    }

    /**
     * Request the actual TOTP for the given entry, identified by its uuid. If TOTP is not configured for the entry,
     * an empty String is returned.
     *
     * @param uuid The uuid of the entry.
     * @return The TOTP for the entry or an empty String in case TOTP is not configured for that entry or an error occurred.
     */
    public String getTotp(String uuid) {
        try {
            return connection.getTotp(uuid).getString("totp");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return "";
        }
    }

    /**
     * Request to delete an entry, identified by its uuid.
     *
     * @param uuid The uuid of the entry.
     * @return True, in case the entry could be deleted, false otherwise.
     */
    public boolean deleteEntry(String uuid) {
        try {
            var response = connection.deleteEntry(uuid);
            return response.has("success") && response.getString("success").equals("true");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    /**
     * Request autotype from the KeePassXC database (KeePassXC 2.7.0 and newer).
     *
     * @param url The URL autotype is requested for.
     * @return True, in case the request was successful, false otherwise.
     */
    public boolean requestAutotype(String url) {
        try {
            var response = connection.requestAutotype(url);
            return response.has("success") && response.getString("success").equals("true");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    /**
     * Extract the groupUuid for the newly created group.
     * Note: in case a group with the following path was created: level1/level2, only level2 gets returned as name.
     *
     * @param jo Input data to get processed.
     * @return Last part of the path name of the group that was created with its according groupUuid.
     */
    public Map<String, String> getNewGroupId(JSONObject jo) {
        return Map.of("name", jo.getString("name"),
                "uuid", jo.getString("uuid"));
    }

    /**
     * This recursively flattens a JSONObject that contains all groups of the KeePassXC database to a map
     * with key = group and value = groupUuid.
     *
     * @param groups Input data to get processed.
     * @return Groups with their according groupUuids.
     */
    public Map<String, String> databaseGroupsToMap(JSONObject groups) {
        if (groups.isEmpty()) {
            return Map.of();
        }
        var groupTree = new HashMap<String, String>();
        var m = groups.toMap();
        var n = (HashMap<String, Object>) m.get("groups");
        var rootGroups = (ArrayList<Object>) n.get("groups");
        var rootGroup = (HashMap<String, Object>) rootGroups.get(0);
        var children = (ArrayList<Object>) rootGroup.get("children");
        traverse(children, groupTree);
        return groupTree;
    }

    private void traverse(List<Object> children, Map<String, String> groups) {
        children.stream()
                .map(listItem -> (HashMap<String, Object>) listItem)
                .forEach(li -> {
                    var alc = (ArrayList<Object>) li.get("children");
                    if (alc.size() == 0) {
                        groups.put(li.get("name").toString(), li.get("uuid").toString());
                    } else {
                        groups.put(li.get("name").toString(), li.get("uuid").toString());
                        traverse(alc, groups);
                    }
                });
    }

    @Override
    public void propertyChange(PropertyChangeEvent event) {
        scheduleSave((Optional<Credentials>) event.getNewValue());
    }

    public String getIdKeyPairPublicKey() {
        return connection.getIdKeyPairPublicKey();
    }

    public String getAssociateId() {
        return connection.getAssociateId();
    }

    /**
     * Getter for the ScheduledExecutorService in case the service needs to be shutdown from outside this library.
     *
     * @return A reference to the ScheduledExecutorService.
     */
    public ScheduledExecutorService getScheduler() { return scheduler; }
}
