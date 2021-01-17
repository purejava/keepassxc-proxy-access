package org.purejava;

import org.apache.commons.lang3.SystemUtils;
import org.purejava.connection.Connection;
import org.purejava.connection.LinuxMacConnection;
import org.purejava.connection.WindowsConnection;

import java.io.IOException;

public class KeepassProxyAccess {

    private Connection connection;

    public KeepassProxyAccess() {
        if (SystemUtils.IS_OS_LINUX || SystemUtils.IS_OS_MAC_OSX) {
            connection = new LinuxMacConnection();
        }
        if (SystemUtils.IS_OS_WINDOWS) {
            connection = new WindowsConnection();
        }
    }

    public static void main(String[] args) throws IOException, KeepassProxyAccessException {
        KeepassProxyAccess kpa = new KeepassProxyAccess();
        kpa.connection.connect();
        kpa.connection.associate();
    }
}
