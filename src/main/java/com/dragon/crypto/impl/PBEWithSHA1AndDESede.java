package com.dragon.crypto.impl;

import com.dragon.crypto.Algorithm;
import com.dragon.crypto.PBECrypto;

/**
 * @ClassName: PBEWithMd5AndDes
 * @Description: TODO
 * @Author: pengl
 * @Date: 2020/3/28 17:08
 * @Version V1.0
 */
public class PBEWithSHA1AndDESede extends PBECrypto {
    @Override
    public Algorithm current() {
        return Algorithm.PBEWithSHA1AndDESede;
    }
}
