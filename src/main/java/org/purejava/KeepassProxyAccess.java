package org.purejava;

import org.apache.commons.lang3.SystemUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.keepassxc.Connection;
import org.keepassxc.LinuxMacConnection;
import org.keepassxc.WindowsConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
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
        connection.setCredentials(loadCredentials());
    }

    // TODO Add Javadoc
    private Optional<Credentials> loadCredentials() {
        try (FileInputStream fileIs = new FileInputStream(fileLocation);
             ObjectInputStream objIs = new ObjectInputStream(fileIs)) {
            Credentials c = (Credentials) objIs.readObject();
            return Optional.of(c);
        } catch (IOException | ClassNotFoundException e) {
            log.debug("Credentials could not be read from disc");
            return Optional.empty();
        }
    }

    // TODO Add Javadoc
    private void scheduleSave(Optional<Credentials> credentials) {
        if (credentials.isEmpty()) {
            log.debug("Credentials are not present and won't be saved");
            return;
        }
        Runnable saveCommand = () -> this.saveCredentials(credentials);
        ScheduledFuture<?> scheduledTask = scheduler.schedule(saveCommand, SAVE_DELAY_MS, TimeUnit.MILLISECONDS);
        ScheduledFuture<?> previouslyScheduledTask = scheduledSaveCmd.getAndSet(scheduledTask);
        if (previouslyScheduledTask != null) {
            previouslyScheduledTask.cancel(false);
        }
        scheduler.shutdown();
    }

    // TODO Add Javadoc
    private void saveCredentials(Optional<Credentials> credentials) {
        log.debug("Attempting to save credentials");
        try {
            Path path = Path.of(fileLocation);
            Files.createDirectories(path.getParent());
            Path tmpPath = path.resolveSibling(path.getFileName().toString() + ".tmp");
            try (OutputStream ops = Files.newOutputStream(tmpPath, StandardOpenOption.CREATE_NEW);
                 ObjectOutputStream objOps = new ObjectOutputStream(ops)) {
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
     * Convenience method to get the connection parameters that are required to identify the right KeePassXC database.
     *
     * @return The entered associateID and returned IDKeyPublicKey.
     */
    public Map<String, String> exportConnection() {
        return Map.of("id", connection.getAssociateId(),
                "key", connection.getIdKeyPairPublicKey());
    }

    public boolean connect() {
        try {
            connection.connect();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean associate() {
        try {
            connection.associate();
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    public boolean connectionAvailable() {
        return getIdKeyPairPublicKey() != null &&
               !getIdKeyPairPublicKey().isEmpty() &&
                getAssociateId() != null &&
                !getAssociateId().isEmpty() &&
                testAssociate(getAssociateId(), getIdKeyPairPublicKey());
    }

    public boolean testAssociate(String id, String key) {
        try {
            connection.testAssociate(id, key);
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    public String getDatabasehash() {
        try {
            return connection.getDatabasehash();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return "";
        }
    }

    public Map<String, Object> getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list) {
        try {
            return connection.getLogins(url, submitUrl, httpAuth, list).toMap();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return Map.of();
        }
    }

    public boolean loginExists(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list, String password) {
        Map<String, Object> response = getLogins(url, submitUrl, httpAuth, list);
        if (response.isEmpty()) {
            return false;
        }
        List<Object> array = (ArrayList<Object>) response.get("entries");
        for (Object o : array) {
            Map<String, Object> credentials = (HashMap<String, Object>) o;
            if (credentials.get("password").equals(password)) return true;
        }
        return false;
    }

    public boolean setLogin(String url, String submitUrl, String id, String login, String password, String group, String groupUuid, String uuid) {
        try {
            JSONObject response = connection.setLogin(url, submitUrl, id, login, password, group, groupUuid, uuid);
            return response.has("success") && response.getString("success").equals("true");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    public JSONObject getDatabaseGroups() {
        try {
            return connection.getDatabaseGroups();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            log.info(e.toString(), e.getCause());
            return new JSONObject();
        }
    }

    public String generatePassword() {
        try {
            JSONArray response = connection.generatePassword().getJSONArray("entries");
            return response.getJSONObject(0).getString("password");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return "";
        }
    }

    public boolean lockDatabase() {
        try {
            JSONObject response = connection.lockDatabase();
            return response.has("action") && response.getString("action").equals("database-locked");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return false;
        }
    }

    public Map<String, String> createNewGroup(String path) {
        try {
            return getNewGroupId(connection.createNewGroup(path));
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return Map.of();
        }
    }

    public String getTotp(String uuid) {
        try {
            return connection.getTotp(uuid).getString("totp");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            log.info(e.toString(), e.getCause());
            return "";
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
        Map<String, String> groupTree = new HashMap<>();
        Map<String, Object> m = groups.toMap();
        Map<String, Object> n = (HashMap<String, Object>) m.get("groups");
        List<Object> rootGroups = (ArrayList<Object>) n.get("groups");
        Map<String, Object> rootGroup = (HashMap<String, Object>) rootGroups.get(0);
        List<Object> children = (ArrayList<Object>) rootGroup.get("children");
        traverse(children, groupTree);
        return groupTree;
    }

    private void traverse(List<Object> children, Map<String, String> groups) {
        children.stream()
                .map(listItem -> (HashMap<String, Object>) listItem)
                .forEach(li -> {
                    List<Object> alc = (ArrayList<Object>) li.get("children");
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
}
