package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import java.net.SocketException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This test is designed to run within CI, where a KeePassXC database is not available.
 */
public class KeepassProxyAccessTest {
    KeepassProxyAccess kpa = new KeepassProxyAccess();

    @Test
    @Order(1)
    @DisplayName("Testing availability of a socket to KeePassXC")
    public void shouldThrowException() {
        Exception exception = assertThrows(SocketException.class, () -> {
            kpa.connect();
            kpa.associate();
        });

        String expectedMessage = "No such file or directory";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}
