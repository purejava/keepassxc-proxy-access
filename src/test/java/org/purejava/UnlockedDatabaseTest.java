package org.purejava;

import org.json.JSONObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * For this test, KeePassXC should be started and unlocked.
 */
public class UnlockedDatabaseTest {
    private static final Logger LOG = LoggerFactory.getLogger(UnlockedDatabaseTest.class);

    private final KeepassProxyAccess kpa = new KeepassProxyAccess();

    @Test
    @Order(3)
    @DisplayName("Testing KeePassXC proxy functionality")
    public void shouldHaveNoErrors() throws InterruptedException {
        LOG.info("Please enter a name for the connection in the pop-up within 10 seconds");
        assertTrue(kpa.connect());
        // TODO:
        //  Revert after Qt bug is fixed
        //  This is false due to the workaround, although association succeeds
        assertFalse(kpa.associate());
        // TODO:
        //  Revert after Qt bug is fixed
        //  This compensates throwing a KeepassProxyAccessException in Connection#associate()
        Thread.sleep(10000L); // give me 10 seconds to enter a associate id
        assertTrue(null != kpa.getDatabasehash() && !kpa.getDatabasehash().isEmpty());
        assertTrue(kpa.testAssociate(kpa.getAssociateId(), kpa.getIdKeyPairPublicKey()));
        LOG.info("Please allow access to credentials");
        List<Map<String, String>> l = new ArrayList<>();
        l.add(kpa.exportConnection());
        assertTrue(kpa.getLogins("https://github.com", null, false, l).toString().contains("uuid=2aafee1a89fd435c8bad7df12bbaaa3e"));
        assertTrue(kpa.setLogin("https://github.com", "https://github.com", null, "User", "Passsword", "Group", null, null));
        assertTrue(kpa.databaseGroupsToMap(kpa.getDatabaseGroups()).toString().contains("KeePassXC-Browser Passwords"));
        assertFalse(kpa.generatePassword().isEmpty());
        LOG.info("Please allow to create new group");
        assertEquals(kpa.createNewGroup("Testgroup").get("name"), "Testgroup");
        assertTrue(null != kpa.getTotp("2aafee1a89fd435c8bad7df12bbaaa3e") && !kpa.getTotp("2aafee1a89fd435c8bad7df12bbaaa3e").isEmpty());
        LOG.info("Requesting autotype");
        assertTrue(kpa.requestAutotype("https://github.com"));
        LOG.info("Please allow to delete entry");
        assertTrue(kpa.deleteEntry("2aafee1a89fd435c8bad7df12bbaaa3e"));
        LOG.info("Please register the offered Passkey");
        String publicKey = "{\"attestation\":\"direct\",\"authenticatorSelection\":{\"requireResidentKey\":true,\"residentKey\":\"required\",\"userVerification\":\"preferred\"},\"challenge\":\"AICQS3rj6P-dIDb5if3OCte-Y7CEs_BEnpTgoasQRXg\",\"excludeCredentials\":[],\"extensions\":{\"credProps\":true},\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"}],\"rp\":{\"id\":\"passkey.org\",\"name\":\"Yubico Demo\"},\"timeout\":90000,\"user\":{\"displayName\":\"purejava\",\"id\":\"DEMO__9fX19ERU1P\",\"name\":\"purejava\"}}";
        JSONObject p = new JSONObject(publicKey);
        assertTrue(kpa.passkeysRegister(p, "https://passkey.org", l).getJSONObject("response").getString("clientDataJSON").equals("eyJjaGFsbGVuZ2UiOiJBSUNRUzNyajZQLWRJRGI1aWYzT0N0ZS1ZN0NFc19CRW5wVGdvYXNRUlhnIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvcmlnaW4iOiJodHRwczovL3Bhc3NrZXkub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"));
        LOG.info("Please deny to save changes");
        assertTrue(kpa.lockDatabase());
        assertTrue(kpa.shutdown());
    }
}
