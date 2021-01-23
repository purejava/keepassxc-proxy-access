package org.purejava;

import org.apache.commons.lang3.SystemUtils;
import org.purejava.connection.Connection;
import org.purejava.connection.LinuxMacConnection;
import org.purejava.connection.WindowsConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeepassProxyAccess {

    static final Logger log = LoggerFactory.getLogger(KeepassProxyAccess.class);
    private Connection connection;

    public KeepassProxyAccess() {
        if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC_OSX) {
            connection = new LinuxMacConnection();
        }
        if (SystemUtils.IS_OS_WINDOWS) {
            connection = new WindowsConnection();
        }
    }

    public static void main(String[] args) throws IOException, KeepassProxyAccessException {
        KeepassProxyAccess kpa = new KeepassProxyAccess();
        kpa.connection.connect();
        kpa.connection.associate();
        log.info("Connected database has hash: {}", kpa.connection.getDatabasehash());
        kpa.connection.testAssociate();
        List<Map<String, String>> l = new ArrayList<>();
        Map<String, String> m = new HashMap<>();
        m.put("id", kpa.connection.getAssociate_id());
        m.put("key", kpa.connection.getIdKeyPairPublicKey());
        l.add(m);
        Map<String, Object> jo = kpa.connection.getLogins("https://github.com", null,false, l).toMap();
        log.info("Found entries for GitHub: {}", jo.toString());
    }
}
