package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.HmacCrypto;

/**
 * @ClassName: HmacSha256
 * @Description: HmacSha256
 * @Author: pengl
 * @Date: 2020/3/27 21:31
 * @Version V1.0
 */
public class HmacSha256 extends HmacCrypto {
    @Override
    public Algorithm current() {
        return Algorithm.HmacSHA256;
    }
}
