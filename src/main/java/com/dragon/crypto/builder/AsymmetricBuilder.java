package com.dragon.crypto.builder;

/**
 * @ClassName: SymmetricBuilder
 * @Description: SymmetricBuilder AES/DES/3DES
 * @Author: pengl
 * @Date: 2020/6/8 19:43
 * @Version V1.0
 */
public class AsymmetricBuilder extends BasicBuilder<AsymmetricBuilder> {
    private String publicKey;
    private String privateKey;

    public AsymmetricBuilder publicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public AsymmetricBuilder privateKey(String privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
