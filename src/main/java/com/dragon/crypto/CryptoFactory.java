package com.dragon.crypto;

import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @ClassName: CryptoFactory
 * @Description: 加密工具类
 * @Author: pengl
 * @Date: 2020/3/26 20:03
 * @Version V1.0
 */
public final class CryptoFactory {
    private static final Logger LOG = LoggerFactory.getLogger(CryptoFactory.class);
    private static final String PACKAGE_NAME = "com.dragon.crypto";

    private CryptoFactory() {
    }

    private static Map<Algorithm, Crypto> cryptoMap = null;

    static {
        Reflections reflections = new Reflections(PACKAGE_NAME);
        Set<Class<? extends Crypto>> subClasses = reflections.getSubTypesOf(Crypto.class);
        if (!Utils.isEmpty(subClasses)) {
            //filter the abstract class
            subClasses = subClasses.stream().filter(c -> !Modifier.isAbstract(c.getModifiers())).collect(Collectors.toSet());
            cryptoMap = new HashMap<>(subClasses.size(), 1);
            for (Class<? extends Crypto> cryptoClass : subClasses) {
                try {
                    Crypto crypto = cryptoClass.newInstance();
                    cryptoMap.put(crypto.current(), crypto);
                } catch (Exception e) {
                    LOG.error("Crypto instanced error: {}", e);
                }
            }
        }
    }

    /**
     * @MethodName: getCrypto
     * @Description: getCrypto by algorithm
     * @Author: pengl
     * @Date: 2020/3/28 10:30
     * @Version V1.0
     */
    public static Crypto getCrypto(Algorithm algorithm) {
        if (null == cryptoMap) {
            throw new CryptoException("Crypto Impl Not Found !");
        }
        Crypto inst = cryptoMap.get(algorithm);
        if(inst == null){
            throw new CryptoException("Algorithm Not Support !");
        }
        return inst;
    }

}
