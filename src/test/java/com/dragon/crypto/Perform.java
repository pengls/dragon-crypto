package com.dragon.crypto;

import org.junit.After;
import org.junit.Before;

/**
 * @ClassName: Perform
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/4/26 22:30
 * @Version V1.0
 */
public class Perform {
    long bg;
    long end;

    @Before
    public void befor() {
        bg = System.currentTimeMillis();
    }

    @After
    public void after() {
        end = System.currentTimeMillis();
        System.out.println("----------all times:>>>" + (end - bg) + " ms");
    }
}
