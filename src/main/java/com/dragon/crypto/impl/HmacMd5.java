package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.HmacCrypto;

/**
 * @ClassName: HmacMd5
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/3/27 21:31
 * @Version V1.0
 */
public class HmacMd5 extends HmacCrypto {
    @Override
    public Algorithm current() {
        return Algorithm.HmacMD5;
    }
}
