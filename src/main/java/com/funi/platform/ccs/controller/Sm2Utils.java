package com.funi.platform.ccs.controller;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public abstract class Sm2Utils {

    //SM2算法名
    public static final String ALGORITHM_NAME = "EC";

    //摘要算法名
    public static final String DIGEST_ALGORITHM = "SM3withSm2";

    //默认编码字符集
    public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    static {
        BCProviderManager.register();
    }

    /**
     * 证书密钥转换(私钥)
     *
     * @param privateKey 证书私钥
     * @return 私钥
     */
    public static PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        byte[] encodedKey = Base64.getDecoder().decode(privateKey);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
    }

    /**
     * 证书密钥转换(公钥)
     *
     * @param publicKey 证书公钥
     * @return 公钥
     */
    public static PublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        byte[] encodedKey = Base64.getDecoder().decode(publicKey);
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    /**
     * SM2加密算法
     *
     * @param publicKey 公钥
     * @param data      明文数据
     * @return 加密结果字符串, 16进制
     */
    public static String encrypt(PublicKey publicKey, String data) throws InvalidCipherTextException {
        ECPublicKeyParameters ecPublicKeyParameters = null;
        //获取椭圆曲线规格,由ecc参数决定
        if (publicKey instanceof BCECPublicKey) {
            BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec ecParameterSpec = bcecPublicKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());
            ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), ecDomainParameters);
        } else if (publicKey instanceof JCEECPublicKey) {
            JCEECPublicKey jceecPublicKey = (JCEECPublicKey) publicKey;
            ECParameterSpec parameters = jceecPublicKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN());
            ecPublicKeyParameters = new ECPublicKeyParameters(jceecPublicKey.getQ(), ecDomainParameters);
        }
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] in = data.getBytes(DEFAULT_CHARSET);
        byte[] arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
        return Hex.toHexString(arrayOfBytes);
    }

    /**
     * SM2解密算法
     *
     * @param privateKey 私钥
     * @param cipherData 密文数据
     * @return 解密结果
     */
    public static String decrypt(PrivateKey privateKey, String cipherData) throws InvalidCipherTextException {
        byte[] cipherDataByte = Hex.decode(cipherData);
        ECPrivateKeyParameters ecPrivateKeyParameters = null;
        //获取椭圆曲线规格,由ecc参数决定
        if (privateKey instanceof BCECPrivateKey) {
            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
            ECParameterSpec ecParameterSpec = bcecPrivateKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());

            ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), ecDomainParameters);
        } else if (privateKey instanceof JCEECPrivateKey) {
            JCEECPrivateKey jceecPrivateKey = (JCEECPrivateKey) privateKey;
            ECParameterSpec parameters = jceecPrivateKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN());
            ecPrivateKeyParameters = new ECPrivateKeyParameters(jceecPrivateKey.getD(), ecDomainParameters);
        }
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
        return new String(arrayOfBytes, DEFAULT_CHARSET);
    }

    /**
     * 获取签名,16进制字符串
     *
     * @param privateKey 私钥
     * @param sourceData 待签名原文
     * @return 16进制字符串
     */
    public static String sign(PrivateKey privateKey, String sourceData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // 生成SM2sign with sm3 签名验签算法实例
        Signature signature = Signature.getInstance(DIGEST_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        // 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
        // 写入签名原文到算法中
        signature.update(sourceData.getBytes(DEFAULT_CHARSET));
        // 计算签名值
        byte[] sign = signature.sign();
        return Hex.toHexString(sign);
    }

    /**
     * 签名验证
     *
     * @param publicKey  公钥
     * @param sourceData 签名原文
     * @param signData   签名结果
     * @return 验证签名结果, true为验签成功, false为验签失败
     */
    public static boolean verifySign(PublicKey publicKey, String sourceData, String signData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] sourceByte = sourceData.getBytes(DEFAULT_CHARSET);
        byte[] signByte = Hex.decode(signData);
        //签名对象获取
        Signature signature = Signature.getInstance(DIGEST_ALGORITHM);
        // 验签需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
        // 写入待验签的签名原文到算法中
        signature.update(sourceByte);
        //验证
        return signature.verify(signByte);
    }

}

