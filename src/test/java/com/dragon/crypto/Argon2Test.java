package com.dragon.crypto;

import com.dragon.crypto.builder.Argon2Builder;
import org.junit.Test;

/**
 * @ClassName: Argon2Test
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/6/9 13:21
 * @Version V1.0
 */
public class Argon2Test extends Perform{
    @Test
    public void t1(){
        String pass = "Pass123456";
        String hash = Argon2Helper.hash_2d(pass, 1);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2d(hash, pass, 1));

        hash = Argon2Helper.hash_2i(pass, 1);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2i(hash, pass, 1));

        hash = Argon2Helper.hash_2Id(pass, 1);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2Id(hash, pass, 1));
    }

    @Test
    public void t2(){
        String data = "Pass123456";
        String hash = Argon2Helper.hash_2d(data, 2);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2d(hash, data, 2));

        hash = Argon2Helper.hash_2i(data, 2);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2i(hash, data, 2));

        hash = Argon2Helper.hash_2Id(data, 2);
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2Id(hash, data, 2));
    }

    @Test
    public void t3(){
        String data = "Pass123456";
        String hash = Argon2Helper.hash_2Id(new Argon2Builder().data(data).parallelism(1));
        System.out.println(hash);
        System.out.println(Argon2Helper.verify_2Id(hash, data, 2));

    }
}
