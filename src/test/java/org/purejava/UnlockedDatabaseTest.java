package org.purejava;

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
        LOG.info("Please deny to save changes");
        assertTrue(kpa.lockDatabase());
        assertTrue(kpa.shutdown());
    }
}
