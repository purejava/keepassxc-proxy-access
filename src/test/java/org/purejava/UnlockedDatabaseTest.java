package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * For this test, KeePassXC should be started and unlocked.
 */
public class UnlockedDatabaseTest {
    private static final Logger log = LoggerFactory.getLogger(UnlockedDatabaseTest.class);

    private KeepassProxyAccess kpa = new KeepassProxyAccess();

    @Test
    @Order(3)
    @DisplayName("Testing KeePassXC proxy functionality")
    public void shouldHaveNoErrors() {
        log.info("Please enter a name for the connection in the pop-up");
        assertTrue(kpa.connect());
        assertTrue(kpa.associate());
        assertTrue(null != kpa.getDatabasehash() && !kpa.getDatabasehash().isEmpty());
        assertTrue(kpa.testAssociate(kpa.getAssociateId(), kpa.getIdKeyPairPublicKey()));
        log.info("Please allow access to credentials");
        List<Map<String, String>> l = new ArrayList<>();
        l.add(kpa.exportConnection());
        assertTrue(kpa.getLogins("https://github.com", null, false, l).toString().contains("uuid=2aafee1a89fd435c8bad7df12bbaaa3e"));
        assertTrue(kpa.setLogin("https://github.com", "https://github.com", null, "User", "Passsword", "Group", null, null));
        assertTrue(kpa.databaseGroupsToMap(kpa.getDatabaseGroups()).toString().contains("KeePassXC-Browser Passwords"));
        assertTrue(null != kpa.generatePassword() && !kpa.generatePassword().isEmpty());
        log.info("Please allow to create new group");
        assertEquals(kpa.createNewGroup("Testgroup").get("name"), "Testgroup");
        assertTrue(null != kpa.getTotp("2aafee1a89fd435c8bad7df12bbaaa3e") && !kpa.getTotp("2aafee1a89fd435c8bad7df12bbaaa3e").isEmpty());
        log.info("Please deny to save changes");
        assertTrue(kpa.lockDatabase());
    }
}
