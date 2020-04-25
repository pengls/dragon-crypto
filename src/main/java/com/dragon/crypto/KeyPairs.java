package com.dragon.crypto;

/**
 * @ClassName: KeyPairs
 * @Description: string type key pair
 * @Author: pengl
 * @Date: 2020/3/28 20:44
 * @Version V1.0
 */
public class KeyPairs {
    private String publicKey;
    private String privateKey;

    public KeyPairs(){}

    public KeyPairs(String publicKey, String privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
