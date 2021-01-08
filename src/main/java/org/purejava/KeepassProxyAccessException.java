package org.purejava;

public class KeepassProxyAccessException extends Exception {
    public KeepassProxyAccessException(String message) {
        super(message);
    }

    public KeepassProxyAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
