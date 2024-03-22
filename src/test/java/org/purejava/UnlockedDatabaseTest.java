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
        assertFalse(kpa.isDatabaseLocked());
        // TODO:
        //  Revert after Qt bug is fixed
        //  This is false due to the workaround, although association succeeds
        assertFalse(kpa.associate());
        // TODO:
        //  Revert after Qt bug is fixed
        //  This compensates throwing a KeepassProxyAccessException in Connection#associate()
        Thread.sleep(10000L); // give me 10 seconds to enter a associate id
        assertTrue(kpa.getDatabasehash().isPresent());
        assertTrue(kpa.testAssociate(kpa.getAssociateId(), kpa.getIdKeyPairPublicKey()));
        LOG.info("Please allow access to credentials");
        List<Map<String, String>> l = new ArrayList<>();
        l.add(kpa.exportConnection());
        assertTrue(
            kpa.getLogins("https://github.com", null, false, l)
                .toString().contains("uuid=2aafee1a89fd435c8bad7df12bbaaa3e")
        );
        assertTrue(
            kpa.setLogin(
                "https://github.com",
                "https://github.com",
                null,
                "User",
                "Passsword",
                "Group",
                null,
                null
            )
        );
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
        String publicKey = "{\"attestation\":\"none\"," +
            "\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"}," +
            "\"challenge\":\"hJy53kwPc3OdqbkjXQ268VAiHGW-s0qH_MWYYIm_jfmCcK7jBuV1jTZ7mdChX-9uy0dBR3N9Ql7QpLqYr_0lNg\"," +
            "\"excludeCredentials\":[]," +
            "\"extensions\":{\"credProps\":true}," +
            "\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"}]," +
            "\"rp\":{\"id\":\"webauthn.io\",\"name\":\"webauthn.io\"}," +
            "\"timeout\":60000," +
            "\"user\":{\"displayName\":\"ralph@purejava.org\",\"id\":\"Y21Gc2NHaEFjSFZ5WldwaGRtRXViM0pu\",\"name\":\"ralph@purejava.org\"}}";
        JSONObject p = new JSONObject(publicKey);
        assertEquals(
            "eyJjaGFsbGVuZ2UiOiJoSnk1M2t3UGMzT2RxYmtqWFEyNjhWQWlIR1ctczBxSF9NV1lZSW1famZtQ2NLN2pCdVYxalRaN21kQ2hYLTl1eTBkQlIzTjlRbDdRcExxWXJfMGxOZyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
            kpa.passkeysRegister(p, "https://webauthn.io", l).getJSONObject("response").getString("clientDataJSON"));
        LOG.info("Please allow authenticate with the stored Passkey");
        publicKey = "{\"allowCredentials\":[]," +
            "\"challenge\":\"8rRycwlx8ZOczHfALOJR-ef9RmYBmNt7HQABHxpcSvM\"," +
            "\"rpId\":\"webauthn.io\"," +
            "\"timeout\":90000," +
            "\"userVerification\":\"preferred\"}";
        p = new JSONObject(publicKey);
        assertEquals(
            "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAAA",
            kpa.passkeysGet(p, "https://webauthn.io", l).getJSONObject("response").getString("authenticatorData")
        );
        LOG.info("Please deny to save changes");
        assertTrue(kpa.lockDatabase());
        assertTrue(kpa.shutdown());
    }
}
