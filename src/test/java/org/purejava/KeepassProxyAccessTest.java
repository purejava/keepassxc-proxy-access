package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This test is designed to run within CI, where a KeePassXC database is not available.
 */
public class KeepassProxyAccessTest {
    private final KeepassProxyAccess kpa = new KeepassProxyAccess();

    @Test
    @Order(1)
    @DisplayName("Testing availability of a socket to KeePassXC")
    public void shouldHaveNoErrors() {
        assertFalse(kpa.connect());
        assertTrue(kpa.shutdown());
    }
}
