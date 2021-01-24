package org.purejava;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class App {
    static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) throws IOException, KeepassProxyAccessException {
        KeepassProxyAccess kpa = new KeepassProxyAccess();
        kpa.connect();
        kpa.associate();
        log.info("Connected database has hash: {}", kpa.getDatabasehash());
        kpa.testAssociate(kpa.getAssociate_id(), kpa.getIdKeyPairPublicKey());
        List<Map<String, String>> l = new ArrayList<>();
        l.add(kpa.exportConnection());
        Map<String, Object> jo = kpa.getLogins("https://github.com", null, false, l);
        log.info("Found entries for GitHub: {}", jo.toString());
        Map<String, Object> output = kpa.setLogin("https://github.com", "https://github.com", null, "User", "Passsword", "Group", null, null);
        if (output.get("success").toString().equals("true")) {
            log.info("Credentials were successfully stored in database.");
        }
    }
}
