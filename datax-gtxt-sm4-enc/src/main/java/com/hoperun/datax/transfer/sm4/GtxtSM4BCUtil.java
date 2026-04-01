/*
 * Ant Group
 * Copyright (c) 2004-2026 All Rights Reserved.
 */
package com.hoperun.datax.transfer.sm4;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;


public class GtxtSM4BCUtil {

    private static final String PREFIX = "jm@";
    private static final String SUFFIX = "@jm";
    private static final String IDENTIFIER = "jm";
    private static final String IDENTIFIER_SYMBOL = "@";

    /**
     * 示例密钥，需替换为自己的密钥
     */
    private static final String SM4_KEY = "30313233343536373839303132333435";

    private static final String ALGORITHM = "SM4/ECB/PKCS5Padding";
    private static final String ALGORITHM_NAME = "SM4";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * SM4加密ECB模式
     * @param plaintext 明文
     * @return 加密后的密文
     */
    public static String encryptEcb(String plaintext) {
        if (null == plaintext || plaintext.length() == 0) {
            return plaintext;
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(Hex.decode(SM4_KEY), ALGORITHM_NAME);
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            String encryptHex = Hex.toHexString(encrypted);
            StringBuilder sb = new StringBuilder();
            sb.append(PREFIX).append(encryptHex).append(SUFFIX);
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SM4加密失败", e);
        }
    }

    /**
     * SM4加密ECB模式
     * @param plaintext 明文
     * @return 加密后的密文
     */
    public static String encryptEcb(String plaintext,String privateKey) {
        if (null == plaintext || plaintext.length() == 0) {
            return plaintext;
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(Hex.decode(privateKey), ALGORITHM_NAME);
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            String encryptHex = Hex.toHexString(encrypted);
            StringBuilder sb = new StringBuilder();
            sb.append(PREFIX).append(encryptHex).append(SUFFIX);
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SM4加密失败", e);
        }
    }

    /**
     * SM4解密ECB模式
     * @param ciphertext 密文
     * @return 解密后的明文
     */
    public static String decryptEcb(String ciphertext) {
        if (null == ciphertext || ciphertext.length() == 0) {
            return ciphertext;
        }
        String[] split = ciphertext.split(IDENTIFIER_SYMBOL);
        if (split.length != 3) {
            return ciphertext;
        }
        if (IDENTIFIER.equals(split[0]) && IDENTIFIER.equals(split[2])) {
            try {
                SecretKeySpec secretKey = new SecretKeySpec(Hex.decode(SM4_KEY), ALGORITHM_NAME);
                Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] decrypted = cipher.doFinal(Hex.decode(split[1]));
                return new String(decrypted, "UTF-8");
            } catch (Exception e) {
                throw new RuntimeException("SM4解密失败", e);
            }
        } else {
            return ciphertext;
        }
    }
}
