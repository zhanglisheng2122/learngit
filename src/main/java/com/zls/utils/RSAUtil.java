package com.zls.utils;


import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;


/***
 * *   功能描述：RSA 加密验签工具类
 ***/
public class RSAUtil {

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * RSA私钥
     */
    private static final String RSA_PRIVATE_KEY= "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIIbWzlOSk2ZJbJbuLfAZMp4DPmJdYRbmMnFhRiUtHK0+oG01lt+Z0W5APQhl3PyD1FA3vEyHwymWgaoJCUgRi2EZOneMiU1O/XxM1T3v5Dgj0AcvpSgk93ULW6u6IK8yLdWr9ussZHqvEu/BKpjwP0CBz+p7M7jszOyGJg6++MZAgMBAAECgYBjsWSIF5ZVuViqPx/eJNzWS4DdoFdc0PbU/LWMbT2Le2NMCe4Kc2Pch/LUHf04Ca10/DkYJeimv7zRxvrTO9SpIBxe1O4mVPAxRwjvALHM+ecdWi6V9sYYPFcm4MvCgyPWbKvNT0pxvlvRzKiPwHx/9bW6yJt/lvTUu4eSCbC7gQJBAO7iaJj9dFAI20PPwKSpLGEZYgosdayQSqdJ88XXU8pz3EbNDaIpkepbWubyjmglj74RIFfKyRhTMen9z2nNrOkCQQCLbcMSehoyUpzyfqTRbdp4Jkxsu2xTr3xDZhoTmG78k4/R5lUqOdrAl1gyJ0imciMIxDd7qKQnCvnaRZvaPuaxAkBwvpTlWAIUYAm0eJIQZPPYJBW8fX1QY42IZQPTpSwbyhD1rYO4vGvssw81HteNWeT8rLKaHNBKVcGiETNaWUM5AkBby+w+4f0VXKbQUOkaqYTIzg5LGCp9/m+FwFcyx41q5Ywu2cMAhg6r9fivLIX8b/D4+Ja+540L14IgXuv5iKhBAkEA3jwQcY8IRs+vjp8ANWFk1Y8LtH8yff7vrH1U/faMFFaXpsFr3K7+NW2M6FPto+1yeAD0QtAnjOUclId0XgRtoQ==";
    /**
     * RSA公钥
     */
    private static final String RSA_PUBLIC_KEY= "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCG1s5TkpNmSWyW7i3wGTKeAz5iXWEW5jJxYUYlLRytPqBtNZbfmdFuQD0IZdz8g9RQN7xMh8MploGqCQlIEYthGTp3jIlNTv18TNU97+Q4I9AHL6UoJPd1C1uruiCvMi3Vq/brLGR6rxLvwSqY8D9Agc/qezO47MzshiYOvvjGQIDAQAB";

    /**
     * 不参与签名参数
     */
    private static final String excludeKey = "sign";


    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.decodeBase64(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 获取公钥
     *
     * @param publicKey 公钥字符串
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.decodeBase64(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * RSA加密
     *
     * @param data 待加密数据
     * @param publicKey 公钥
     * @return
     */
    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int inputLen = data.getBytes().length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
        // 加密后的字符串
        return new String(Base64.encodeBase64String(encryptedData));
    }

    /**
     * RSA解密
     *
     * @param data 待解密数据
     * @param privateKey 私钥
     * @return
     */
    public static String decrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] dataBytes = Base64.decodeBase64(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 签名
     *
     * @param data 待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(key);
        signature.update(data.getBytes());
        return new String(Base64.encodeBase64(signature.sign()));
    }

    /**
     * 验签
     *
     * @param srcData 原始字符串
     * @param publicKey 公钥
     * @param sign 签名
     * @return 是否验签通过
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(key);
        signature.update(srcData.getBytes());
        return signature.verify(Base64.decodeBase64(sign.getBytes()));
    }

    /**
     * 对map进行签名
     * @param mapData
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static String sign(Map<String, String> mapData, PrivateKey privateKey) throws Exception {
        return sign(getStr(mapData), privateKey);
    }

    /**
     * 签名验证
     * @param mapData 参数map
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    public static boolean verify(Map<String, String> mapData, PublicKey publicKey) throws Exception {
        String sign = mapData.remove(excludeKey);
        if (sign == null || sign.length() < 1) {
            throw new RuntimeException("参数缺少签名");
        }
        return verify(getStr(mapData), publicKey, sign);
    }

    /**
     * 接口请求参数转字符串
     * @param parms
     * @return
     */
    public static String getStr(Map<String, String> parms) {
        parms.remove(excludeKey);
        TreeMap<String, String> sortParms = new TreeMap<>();
        sortParms.putAll(parms);
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : parms.entrySet()) {
            builder.append(entry.getKey());
            builder.append("=");
            builder.append(entry.getValue());
            builder.append("&");
        }
        if (builder.length() > 1) {
            builder.setLength(builder.length() - 1);
        }
        return builder.toString();
    }




    public static void main(String[] args) {
        try {
            // 生成密钥对
            System.out.println("私钥:" + RSA_PRIVATE_KEY);
            System.out.println("公钥:" + RSA_PUBLIC_KEY);
            // RSA加密
            String data = "{\"method\":\"marketGatewayTest\",\"sign\":\"1234234\",\"format\":\"json\",\"des_key\":\"0\",\"biz_data\":\"{\\\"name\\\":\\\"test\\\"}\",\"sign_type\":\"RSA\",\"biz_enc\":\"1\",\"app_id\":\"123456\",\"version\":\"1.0\",\"timestamp\":\"2019-02-21 14:38:00\"}{\"method\":\"marketGatewayTest\",\"sign\":\"1234234\",\"format\":\"json\",\"des_key\":\"0\",\"biz_data\":\"{\\\"name\\\":\\\"test\\\"}\",\"sign_type\":\"RSA\",\"biz_enc\":\"1\",\"app_id\":\"123456\",\"version\":\"1.0\",\"timestamp\":\"2019-02-21 14:38:00\"}";
            String encryptData = encrypt(data, getPublicKey(RSA_PUBLIC_KEY));
            System.out.println("加密后内容:" + encryptData);
            // RSA解密
            String decryptData = decrypt(encryptData, getPrivateKey(RSA_PRIVATE_KEY));
            System.out.println("解密后内容:" + decryptData);
            Map<String,String> mapData = new HashMap<>();
            mapData.put("format","json");
            mapData.put("biz_data","2321321323");
            // RSA签名
            String sign = sign(mapData, getPrivateKey(RSA_PRIVATE_KEY));
            mapData.put("sign",sign);
            // RSA验签
            boolean result = verify(mapData, getPublicKey(RSA_PUBLIC_KEY));
            System.out.println("验签结果:" + result);
        } catch (Exception e) {
            System.out.print("加解密异常" + e.getMessage());
        }
    }
}