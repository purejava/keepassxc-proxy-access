package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * For this test, KeePassXC should be started, but locked.
 */
public class LockedDatabaseTest {
    private KeepassProxyAccess kpa = new KeepassProxyAccess();

    @Test
    @Order(2)
    @DisplayName("Testing connection over socket to KeePassXC")
    public void shouldThrowException() {
        Exception exception = assertThrows(KeepassProxyAccessException.class, () -> {
            kpa.connect();
            kpa.associate();
        });

        String expectedMessage = "ErrorCode: 1";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}
