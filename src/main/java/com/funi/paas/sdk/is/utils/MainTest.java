package com.funi.paas.sdk.is.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.funi.platform.ccs.controller.Sm2Utils;
import org.apache.http.HttpEntity;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class MainTest {

    public static void main(String[] args) throws Exception {
        //访问接口的resource路径
        String resource = "/CCSInterface/publicCAS/OAAndJWProvider/getCurrentUserForFullLifeCycle";
        //公钥
        String publicKeyCert = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEgrILNcEDqUta/bM4ULYQQRj87Smi" +
                "8CFnu7NfA+8FIL4SrsGlKRGZvlMysEQ20fs3pTa0AYoC1yWioVgvywq+kg==";
        //私钥
        String privateKeyCert = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgMAS63RrZpxMP9OYN" +
                "ez7E1PvZ6i6WmL6H8y6Yz+ZDQ0ShRANCAASCsgs1wQOpS1r9szhQthBBGPztKaLw" +
                "IWe7s18D7wUgvhKuwaUpEZm+UzKwRDbR+zelNrQBigLXJaKhWC/LCr6S";
        Map<String, String> signData = new HashMap<>();
        signData.put("Resource", resource);
        //客户端appid
        signData.put("X-Open-App-Key", "8763485702555107328");
        signData.put("X-Open-Request-Id", UUID.randomUUID().toString());
        signData.put("X-Open-Timestamp", System.currentTimeMillis() + "");
        signData.put("X-Open-Version", "1.0.0");//默认：1.0.0
        //构建待签名文本
        StringBuilder signDataText = new StringBuilder();
        List<String> keys = new ArrayList<>(signData.keySet());
        //key排序
        Collections.sort(keys);
        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            String value = signData.get(key);
            signDataText.append(i == 0 ? "" : "&").append(key).append("=").append(value);
        }
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            //公私钥转换
            PublicKey publicKey = Sm2Utils.getPublicKey(publicKeyCert);
            PrivateKey privateKey = Sm2Utils.getPrivateKey(privateKeyCert);
            //计算签名
            String sign = Sm2Utils.sign(privateKey, signDataText.toString());
            HttpPost httpPost = new HttpPost("https://paasis.funi365.com" + resource);
            httpPost.addHeader("Content-Type", "application/json;charset=UTF-8");
            httpPost.addHeader("X-Open-Sign", sign);
            for (Map.Entry<String, String> entry : signData.entrySet()) {
                httpPost.addHeader(entry.getKey(), entry.getValue());
            }
            // 请求参数
            Map<String, Object> dataMap = new LinkedHashMap<>();
            ObjectMapper mapper = new ObjectMapper();
            //请求体json字符串（明文）
            String requestBody = mapper.writeValueAsString(dataMap);
            // 打印请求明文
            System.out.println("====== Request Body (plain) ======");
            System.out.println(requestBody);

            String encryptData = Sm2Utils.encrypt(publicKey, requestBody);
            httpPost.setEntity(new StringEntity(encryptData, StandardCharsets.UTF_8));

            // 打印请求头
            System.out.println("====== Request Headers ======");
            for (Header header : httpPost.getAllHeaders()) {
                System.out.println(header.getName() + ": " + header.getValue());
            }
            // 打印加密后的请求体
            System.out.println("====== Request Body (encrypted) ======");
            System.out.println(encryptData);

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                // 打印响应头
                System.out.println("====== Response Headers ======");
                for (Header header : response.getAllHeaders()) {
                    System.out.println(header.getName() + ": " + header.getValue());
                }

                //返回响应内容
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                System.out.println("====== Response Body (raw) ======");
                System.out.println(responseBody);

                //解析json
                Map<String, String> responseObj = mapper.readValue(responseBody, Map.class);
                //OPEN-1000为请求成功
                if ("OPEN-1000".equals(responseObj.get("code"))) {
                    String data = responseObj.get("data");
                    //响应报文解密
                    String decryptData = Sm2Utils.decrypt(privateKey, data);
                    System.out.println("====== Response Body (decrypted data) ======");
                    System.out.println(decryptData);
                } else {
                    System.out.println("调用失败，响应内容：" + responseBody);
                }
                HttpClientUtils.closeQuietly(response);
            }
        }
    }
}
