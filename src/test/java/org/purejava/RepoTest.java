package org.purejava;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.keepassxc.KeePassXCType;
import org.keepassxc.KindOfKeePassXC;

import static org.junit.jupiter.api.Assertions.*;

/**
 * For this test, KeePassXC - installed from repository - should be started.
 */
public class RepoTest {
    @Test
    @Order(6)
    @DisplayName("Testing KeePassXC installation type")
    public void shouldHaveNoErrors() {
        var type = KindOfKeePassXC.determineType();
        assertTrue(type.isPresent() && type.get().equals(KeePassXCType.Repo));
    }
}
