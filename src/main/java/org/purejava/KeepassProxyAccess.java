package org.purejava;

import org.apache.commons.lang3.SystemUtils;
import org.keepassxc.Connection;
import org.keepassxc.LinuxMacConnection;
import org.keepassxc.WindowsConnection;

import java.io.IOException;
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
        m.put("id", this.connection.getAssociate_id());
        m.put("key", this.connection.getIdKeyPairPublicKey());
        return m;
    }

    public void connect() throws IOException, KeepassProxyAccessException {
        this.connection.connect();
    }

    public void associate() throws IOException, KeepassProxyAccessException {
        this.connection.associate();
    }

    public void testAssociate() throws IOException, KeepassProxyAccessException {
        this.connection.testAssociate();
    }

    public String getDatabasehash() throws IOException, KeepassProxyAccessException {
        return this.connection.getDatabasehash();
    }

    public Map<String, Object> getLogins(String url, String submitUrl, boolean httpAuth, List<Map<String, String>> list) throws IOException, KeepassProxyAccessException {
        return this.connection.getLogins(url, submitUrl, httpAuth, list).toMap();
    }

    // Getters
    public String getIdKeyPairPublicKey() {
        return this.connection.getIdKeyPairPublicKey();
    }

    public String getAssociate_id() {
        return this.connection.getAssociate_id();
    }
}
