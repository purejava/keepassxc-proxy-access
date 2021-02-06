package org.purejava;

import org.apache.commons.lang3.SystemUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.keepassxc.Connection;
import org.keepassxc.LinuxMacConnection;
import org.keepassxc.WindowsConnection;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeepassProxyAccess {

    private Connection connection;

    public KeepassProxyAccess() {
        if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC_OSX) {
            connection = new LinuxMacConnection();
        }
        if (SystemUtils.IS_OS_WINDOWS) {
            connection = new WindowsConnection();
        }
    }

    /**
     * Convenience method to get the connection parameters that are required to re-establish a connection.
     *
     * @return The agreed associateID and IDKeyPublicKey.
     */
    public Map<String, String> exportConnection() {
        Map<String, String> m = new HashMap<>();
        m.put("id", this.connection.getAssociateId());
        m.put("key", this.connection.getIdKeyPairPublicKey());
        return m;
    }

    public void connect() throws IOException, KeepassProxyAccessException {
        this.connection.connect();
    }

    public void associate() throws IOException, KeepassProxyAccessException {
        this.connection.associate();
    }

    public void testAssociate(String id, String key) throws IOException, KeepassProxyAccessException {
        this.connection.testAssociate(id, key);
    }

    public String getDatabasehash() throws IOException, KeepassProxyAccessException {
        return this.connection.getDatabasehash();
    }

    public Map<String, Object> getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list) throws IOException, KeepassProxyAccessException {
        return this.connection.getLogins(url, submitUrl, httpAuth, list).toMap();
    }

    public Map<String, Object> setLogin(String url, String submitUrl, String id, String login, String password, String group, String groupUuid, String uuid) throws IOException, KeepassProxyAccessException {
        return this.connection.setLogin(url, submitUrl, id, login, password, group, groupUuid, uuid).toMap();
    }

    public JSONObject getDatabaseGroups() throws IOException, KeepassProxyAccessException {
        return this.connection.getDatabaseGroups();
    }

    public String generatePassword() throws IOException, KeepassProxyAccessException {
        JSONArray response = this.connection.generatePassword().getJSONArray("entries");
        return response.getJSONObject(0).getString("password");
    }

    /**
     * This recursively flattens a JSONObject that contains all groups of the KeePassXC database to a map
     * with key = group and value = groupUuid.
     *
     * @param groups Input data to get processed.
     * @return Groups with their according groupUuids.
     */
    public Map<String, String> databaseGroupsToMap(JSONObject groups) {
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
        return this.connection.getIdKeyPairPublicKey();
    }

    public String getAssociate_id() {
        return this.connection.getAssociateId();
    }
}
