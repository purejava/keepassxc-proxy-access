package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * For this test, KeePassXC should be started, but locked.
 */
public class LockedDatabaseTest {
    private final KeepassProxyAccess kpa = new KeepassProxyAccess();

    @Test
    @Order(2)
    @DisplayName("Testing connection over socket to KeePassXC")
    public void shouldHaveNoErrors() {
        assertTrue(kpa.connect());
        assertTrue(kpa.getDatabasehash().isEmpty());
        assertTrue(kpa.shutdown());
    }
}
