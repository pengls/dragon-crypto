package com.dragon.crypto;

import com.dragon.crypto.builder.PBEBuilder;
import com.dragon.crypto.builder.SymmetricBuilder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * @ClassName: JmhTest
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/6/3 14:04
 * @Version V1.0
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(2)
@Threads(2)
@State(Scope.Thread)
public class JmhTest {
    static String str = "!@#$%^&*()_+~（）abc 中文";
    static String key = "(3)_&*uiku@..!123";
    static String iv = "K*&^%09P..iqx";
    //@Benchmark
    public void hmacSHA256(){
       Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.HmacSHA256).encrypt(str.getBytes()));
    }
    //@Benchmark
    public void md5(){
        Hex.encodeHexString(CryptoFactory.getCrypto(Algorithm.MD5).encrypt(str.getBytes()));
    }
    //@Benchmark
    public void des(){
        Crypto des = CryptoFactory.getCrypto(Algorithm.DES);
        System.out.println(Base64.encodeBase64String(des.encrypt(new SymmetricBuilder().data(str.getBytes()))));
    }
    //@Benchmark
    public void des3(){
        Crypto des = CryptoFactory.getCrypto(Algorithm.DES3);
        System.out.println(Base64.encodeBase64String(des.encrypt(new SymmetricBuilder().data(str.getBytes()))));
    }
    @Benchmark
    public void aes(){
        Crypto aes = CryptoFactory.getCrypto(Algorithm.AES);
        String miwen = Base64.encodeBase64String(aes.encrypt(new SymmetricBuilder().data(str.getBytes()).key(key).iv(iv).workModel(SymmetricBuilder.WorkModel.GCM).padding(SymmetricBuilder.Padding.NoPadding)));
        System.out.println("指定KEY,IV,工作模式,填充方式解密：" + new String(aes.decrypt(new SymmetricBuilder().data(Base64.decodeBase64(miwen.getBytes(StandardCharsets.UTF_8))).key(key)
                .iv(iv).workModel(SymmetricBuilder.WorkModel.GCM).padding(SymmetricBuilder.Padding.NoPadding)), StandardCharsets.UTF_8));
    }
    //@Benchmark
    public void pBEWithMd5AndDes(){
        Crypto pbe = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndDes);
        Base64.encodeBase64(pbe.encrypt(new PBEBuilder().data(str.getBytes()).key("sdsddssd").salt("sdsdsds2")));
    }
    //@Benchmark
    public void pBEWithMd5AndTripleDES(){
        Crypto pbe = CryptoFactory.getCrypto(Algorithm.PBEWithMd5AndTripleDES);
        System.out.println(Base64.encodeBase64String(pbe.encrypt(new PBEBuilder().data(str.getBytes()).key("sdsddssd").salt("sdsdsds2"))));
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(JmhTest.class.getSimpleName())
                //.output("D:\\jmh.log")
                .build();
        new Runner(opt).run();
    }
}
