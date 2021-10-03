package org.purejava;

import java.util.List;

/**
 * This holds the result of a call to {@link org.purejava.KeepassProxyAccess#loginExists(String, String, boolean, List, String)}
 * @see org.purejava.KeepassProxyAccess#loginExists(String, String, boolean, List, String)
 */
public class ValidLogin {
    private boolean found;
    private String uuid;

    /**
     * Does a valid login exist for the given URL? And does the given password match too?
     * @param found True, if an entry was found in the KeePassXC database for the given URL.
     * @param uuid  If found is true, this contains either the uuid, in case the given password matches
     *              the password already stored in the entry or null in case the given password does not match.
     */
    public ValidLogin(boolean found, String uuid) {
        this.found = found;
        this.uuid = uuid;
    }

    public boolean isFound() {
        return found;
    }

    public String getUuid() {
        return uuid;
    }
}
