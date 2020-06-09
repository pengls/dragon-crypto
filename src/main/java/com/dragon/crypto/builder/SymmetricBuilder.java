package com.dragon.crypto.builder;

/**
 * @ClassName: SymmetricBuilder
 * @Description: SymmetricBuilder AES/DES/3DES
 * @Author: pengl
 * @Date: 2020/6/8 19:43
 * @Version V1.0
 */
public class SymmetricBuilder extends BasicBuilder<SymmetricBuilder>{
    private String iv;
    private WorkModel workModel;
    private Padding padding;

    public SymmetricBuilder iv(String iv){
        this.iv = iv;
        return this;
    }

    public SymmetricBuilder workModel(WorkModel workModel){
        this.workModel = workModel;
        return this;
    }

    public SymmetricBuilder padding(Padding padding){
        this.padding = padding;
        return this;
    }

    public String getIv() {
        return iv;
    }

    public WorkModel getWorkModel() {
        return workModel;
    }

    public Padding getPadding() {
        return padding;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public void setWorkModel(WorkModel workModel) {
        this.workModel = workModel;
    }

    public void setPadding(Padding padding) {
        this.padding = padding;
    }

    public enum WorkModel {
        ECB,
        CBC,
        PCBC,
        CTR,
        CTS,
        CFB,
        CFB128,
        OFB,
        OFB128,
        GCM
    }

    public enum Padding {
        /**
         * this padding model, The original must be a multiple of 8
         */
        NoPadding,
        /**
         * Every encrypted ciphertext is the same
         */
        PKCS5Padding,
        /**
         * Every encrypted ciphertext 50% is the same
         */
        ISO10126Padding
    }
}
