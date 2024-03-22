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

    private transient Optional<String> associateId;
    private String aID;

    private transient Optional<byte[]> idKeyPublicKey;
    private byte[] idKeyPub;

    public Credentials() {
        this.associateId = Optional.empty();
        this.idKeyPublicKey = Optional.empty();
    }

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
        aID = getAssociateId();
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

    public String getAssociateId() {
        return associateId.isEmpty() ? "" : associateId.get();
    }

    public void setAssociateId(String associateId) {
        if (associateId.isEmpty()) {
            this.associateId = Optional.empty();
        } else {
            this.associateId = Optional.of(associateId);
        }
    }

    public byte[] getIdKeyPublicKey() {
        return idKeyPublicKey.isEmpty() ? new byte[]{} : idKeyPublicKey.get();
    }

    public void setIdKeyPublicKey(byte[] idKeyPublicKey) {
        if (idKeyPublicKey.length == 0) {
            this.idKeyPublicKey = Optional.empty();
        } else {
            this.idKeyPublicKey = Optional.of(idKeyPublicKey);
        }
    }
}
