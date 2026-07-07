package com.funi.paas.sdk.is.utils;

import com.funi.platform.ccs.controller.Sm2Utils;

public class KeyPairCheckDemo {
    public static void main(String[] args) {
        String publicKeyCert = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEaM3WFv8c7D52+F+B8m3eaiJuLdQU" +
                "g1owD2BKmznSEX4wNmlsHO1WhCyfvBznHObau4Dzm5Cn08eK1krTj3DXPQ==";
        String privateKeyCert = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgHmFJhdqXYiIwt2kJ" +
                "AJ9sgrdpegDnu1zMZrZ6eBNSwjKhRANCAARozdYW/xzsPnb4X4Hybd5qIm4t1BSD" +
                "WjAPYEqbOdIRfjA2aWwc7VaELJ+8HOcc5tq7gPObkKfTx4rWStOPcNc9";

        try {
            boolean matched = Sm2Utils.isKeyPairMatched(publicKeyCert, privateKeyCert);
            if (matched) {
                System.out.println("公私钥校验通过：当前公钥和私钥是正确成对的。");
            } else {
                System.out.println("公私钥校验失败：当前公钥和私钥不是一对，请检查客户端密钥配置。");
            }
        } catch (Exception e) {
            System.out.println("公私钥校验异常：请检查公钥、私钥是否为正确的证书格式。");
            System.out.println(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
