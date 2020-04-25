package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.SymmetricCrypto;

/**
 * @ClassName: Des3Ecb
 * @Description: 3 DES , the key size must > 24
 * @Author: pengl
 * @Date: 2020/3/28 11:00
 * @Version V1.0
 */
public class Des3 extends SymmetricCrypto {
    @Override
    public Algorithm current() {
        return Algorithm.DES3;
    }
}
