package org.purejava;

import com.iwebpp.crypto.TweetNaclFast;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

// TODO Add Javadoc
public class Credentials implements Serializable {
    private transient TweetNaclFast.Box.KeyPair ownKeypair;
    private byte[] secretKey;

    private byte[] serverPublicKey;

    private String associate_id;
    private byte[] idKeyPublicKey;

    private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
        ois.defaultReadObject();
        ownKeypair = TweetNaclFast.Box.keyPair_fromSecretKey(secretKey);

    }

    private void writeObject(ObjectOutputStream oos) throws IOException {
        secretKey = ownKeypair.getSecretKey();
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

    public String getAssociate_id() {
        return associate_id;
    }

    public void setAssociate_id(String associate_id) {
        this.associate_id = associate_id;
    }

    public byte[] getIdKeyPublicKey() {
        return idKeyPublicKey;
    }

    public void setIdKeyPublicKey(byte[] idKeyPublicKey) {
        this.idKeyPublicKey = idKeyPublicKey;
    }
}