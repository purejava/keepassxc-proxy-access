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

import java.io.*;
import java.util.*;

public class KeepassProxyAccess {
    private static final Logger log = LoggerFactory.getLogger(KeepassProxyAccess.class);

    private Connection connection;

    public KeepassProxyAccess() {
        if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC_OSX) {
            connection = new LinuxMacConnection();
        }
        if (SystemUtils.IS_OS_WINDOWS) {
            connection = new WindowsConnection();
        }
    }

    // TODO Add Javadoc
    public Optional<Credentials> loadCredentials() {
        try (FileInputStream fileIs = new FileInputStream("keepass-proxy-access.dat");
             ObjectInputStream objIs = new ObjectInputStream(fileIs)) {
            Credentials c = (Credentials) objIs.readObject();
            return Optional.of(c);
        } catch (IOException | ClassNotFoundException e) {
            log.debug("Credentials could not be read from disc");
            return Optional.empty();
        }
    }

    // TODO Add Javadoc
    public void saveCredentials(Optional<Credentials> credentials) {
        if (!credentials.isPresent()) {
            return;
        }
        try (FileOutputStream ops = new FileOutputStream("keepass-proxy-access.dat");
             ObjectOutputStream objOps = new ObjectOutputStream(ops)) {
            objOps.writeObject(credentials.get());
            objOps.flush();
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

    public boolean changePublicKeys() {
        try {
            connection.changePublicKeys();
            return true;
        } catch (IOException | KeepassProxyAccessException e) {
            return false;
        }
    }

    public boolean associate() {
        try {
            connection.associate();
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            return false;
        }
    }

    public boolean connectionAvailable() {
        return getIdKeyPairPublicKey() != null &&
                getAssociateId() != null &&
                testAssociate(getAssociateId(), getIdKeyPairPublicKey());
    }

    public boolean testAssociate(String id, String key) {
        try {
            connection.testAssociate(id, key);
            return true;
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            return false;
        }
    }

    public String getDatabasehash() {
        try {
            return connection.getDatabasehash();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            return "";
        }
    }

    public Map<String, Object> getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list) {
        try {
            return connection.getLogins(url, submitUrl, httpAuth, list).toMap();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            return Map.of();
        }
    }

    public boolean setLogin(String url, String submitUrl, String id, String login, String password, String group, String groupUuid, String uuid) {
        try {
            JSONObject response = connection.setLogin(url, submitUrl, id, login, password, group, groupUuid, uuid);
            return response.has("success") && response.getString("success").equals("true");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            return false;
        }
    }

    public JSONObject getDatabaseGroups() {
        try {
            return connection.getDatabaseGroups();
        } catch (IOException | IllegalStateException | KeepassProxyAccessException e) {
            return new JSONObject();
        }
    }

    public String generatePassword() {
        try {
            JSONArray response = connection.generatePassword().getJSONArray("entries");
            return response.getJSONObject(0).getString("password");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            return "";
        }
    }

    public boolean lockDatabase() {
        try {
            JSONObject response = connection.lockDatabase();
            return response.has("action") && response.getString("action").equals("database-locked");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            return false;
        }
    }

    public Map<String, String> createNewGroup(String path) {
        try {
            return getNewGroupId(connection.createNewGroup(path));
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
            return Map.of();
        }
    }

    public String getTotp(String uuid) {
        try {
            return connection.getTotp(uuid).getString("totp");
        } catch (IOException | IllegalStateException | KeepassProxyAccessException | JSONException e) {
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

    public String getIdKeyPairPublicKey() {
        return connection.getIdKeyPairPublicKey();
    }

    public String getAssociateId() {
        return connection.getAssociateId();
    }
}
