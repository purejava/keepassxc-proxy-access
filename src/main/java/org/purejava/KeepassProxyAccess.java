package org.purejava;


import java.io.IOException;

public class KeepassProxyAccess {
    public static void main(String[] args) throws IOException, KeepassProxyAccessException {
        Connection conn = new Connection();
        conn.connect();
    }
}
