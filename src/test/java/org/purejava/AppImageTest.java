package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.keepassxc.KeePassXCType;
import org.keepassxc.KindOfKeePassXC;

import static org.junit.jupiter.api.Assertions.*;

/**
 * For this test, an KeePassXC AppImage should be started.
 */
public class AppImageTest {
    @Test
    @Order(7)
    @DisplayName("Testing KeePassXC installation type")
    public void shouldHaveNoErrors() {
        var type = KindOfKeePassXC.determineType();
        assertTrue(type.isPresent() && type.get().equals(KeePassXCType.AppImage));
    }
}
