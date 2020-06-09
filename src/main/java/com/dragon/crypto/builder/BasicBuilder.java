package com.dragon.crypto.builder;

/**
 * @ClassName: BasicBuilder
 * @Description: BasicBuilder
 * @Author: pengl
 * @Date: 2020/6/8 19:40
 * @Version V1.0
 */
public class BasicBuilder<T extends BasicBuilder> {
    private byte[] data;
    private String key;

    public T data(byte[] data){
        this.data = data;
        return (T)this;
    }

    public T key(String key){
        this.key = key;
        return (T)this;
    }

    public byte[] getData() {
        return data;
    }

    public String getKey() {
        return key;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
