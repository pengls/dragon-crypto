package com.dragon.crypto.builder;

/**
 * @ClassName: BasicBuilder
 * @Description: BasicBuilder
 * @Author: pengl
 * @Date: 2020/6/8 19:40
 * @Version V1.0
 */
public class PBEBuilder extends BasicBuilder<PBEBuilder> {
    private int cycleTimes;
    private String salt;

    public PBEBuilder cycleTimes(int cycleTimes) {
        this.cycleTimes = cycleTimes;
        return this;
    }

    public PBEBuilder salt(String salt) {
        this.salt = salt;
        return this;
    }

    public int getCycleTimes() {
        return cycleTimes;
    }

    public String getSalt() {
        return salt;
    }

    public void setCycleTimes(int cycleTimes) {
        this.cycleTimes = cycleTimes;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
