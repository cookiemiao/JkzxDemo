package com.funi.paas.sdk.is.utils;

import com.funi.platform.ccs.controller.Sm2Utils;

public class KeyPairCheckDemo {
    public static void main(String[] args) {
        String publicKeyCert = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEY1dYjLmMvTA7ioBzuou5o6e4S8e2" +
                "zvYwaVZ+Fdt8bFJfifEOh2TUqVPD/QnTQqqqxuUTvW6YB0/if5sWTJ8yRg==";
        String privateKeyCert = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgd9slOhHR13hR9F/v" +
                "tuD+3jlhVybHzzDN6Xw1qynaGOuhRANCAAS1U1k0nSD8HlwThwN4a6BxcJ8pEHCM" +
                "7YGPjHsapN2+r/SI7vRrzldWVJc5V1s0KgL6xWQA4z2q5SMDM1Dsip6H";

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
