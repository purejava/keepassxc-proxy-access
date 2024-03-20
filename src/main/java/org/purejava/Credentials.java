package org.purejava;

import com.iwebpp.crypto.TweetNaclFast;

import java.io.*;
import java.util.Optional;

/**
 * This holds the associateId and the public key part of the idKey that together form the credentials needed to
 * access a KeePassXC database. Credentials is intended to be saved to and read from disc.
 */
public class Credentials implements Serializable {
    private transient TweetNaclFast.Box.KeyPair ownKeypair;
    private byte[] secretKey;

    private byte[] serverPublicKey;

    private transient String associateId;
    private String aID;

    private transient byte[] idKeyPublicKey;
    private byte[] idKeyPub;

    @Serial
    private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
        ois.defaultReadObject();
        ownKeypair = TweetNaclFast.Box.keyPair_fromSecretKey(secretKey);
        setAssociateId(aID);
        setIdKeyPublicKey(idKeyPub);

    }

    @Serial
    private void writeObject(ObjectOutputStream oos) throws IOException {
        secretKey = ownKeypair.getSecretKey();
        aID = getAssociateId().orElse(null);
        idKeyPub = getIdKeyPublicKey();
        oos.defaultWriteObject();
    }

    // Getters and Setters
    public TweetNaclFast.Box.KeyPair getOwnKeypair() {
        return ownKeypair;
    }

    public void setOwnKeypair(TweetNaclFast.Box.KeyPair ownKeypair) {
        this.ownKeypair = ownKeypair;
    }

    public byte[] getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(byte[] serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public Optional<String> getAssociateId() {
        if (associateId == null || associateId.isEmpty())
            return Optional.empty();

        return Optional.of(associateId);
    }

    public void setAssociateId(String associateId) {
        if (associateId.isEmpty()) {
            this.associateId = null;
            return;
        }

        this.associateId = associateId;
    }

    public byte[] getIdKeyPublicKey() {
        return Optional.ofNullable(idKeyPublicKey).isEmpty() ? new byte[]{} : idKeyPublicKey;
    }

    public void setIdKeyPublicKey(byte[] idKeyPublicKey) {
        if (idKeyPublicKey.length == 0) {
            this.idKeyPublicKey = null;
            return;
        }

        this.idKeyPublicKey = idKeyPublicKey;
    }
}
