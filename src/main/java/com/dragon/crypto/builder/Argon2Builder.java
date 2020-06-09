package com.dragon.crypto.builder;

/**
 * @ClassName: Argon2Builder
 * @Description: Argon2Builder
 * @Author: pengl
 * @Date: 2020/6/9 12:49
 * @Version V1.0
 */
public class Argon2Builder{
    private String pass;
    private String data;
    private int saltLength;
    private int hashLength;
    private int iterations;
    private int memory;
    private int parallelism;
    private String salt;

    public Argon2Builder pass(String pass){
        this.pass = pass;
        return this;
    }

    public Argon2Builder data(String data){
        this.data = data;
        return this;
    }

    public Argon2Builder saltLength(int saltLength){
        this.saltLength = saltLength;
        return this;
    }

    public Argon2Builder hashLength(int hashLength){
        this.hashLength = hashLength;
        return this;
    }

    public Argon2Builder iterations(int iterations){
        this.iterations = iterations;
        return this;
    }

    public Argon2Builder memory(int memory){
        this.memory = memory;
        return this;
    }

    public Argon2Builder parallelism(int parallelism){
        this.saltLength = parallelism;
        return this;
    }

    public Argon2Builder salt(String salt){
        this.salt = salt;
        return this;
    }

    public int getSaltLength() {
        return saltLength;
    }

    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }

    public int getHashLength() {
        return hashLength;
    }

    public void setHashLength(int hashLength) {
        this.hashLength = hashLength;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public int getMemory() {
        return memory;
    }

    public void setMemory(int memory) {
        this.memory = memory;
    }

    public int getParallelism() {
        return parallelism;
    }

    public void setParallelism(int parallelism) {
        this.parallelism = parallelism;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getPass() {
        return pass;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
