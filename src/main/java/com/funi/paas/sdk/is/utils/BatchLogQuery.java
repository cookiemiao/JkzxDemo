package com.funi.paas.sdk.is.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.funi.platform.ccs.controller.Sm2Utils;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class BatchLogQuery {
    private static final String RESOURCE = "/jkzx/apinterface/log/cursorList";
    private static final String APP_KEY = "8755471635089522688";
    private static final String URL = "https://blmp.cdzjryb.com/qsmzq-all-api/isgateway-api" + RESOURCE;
    private static final String PUBLIC_KEY_CERT = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE8MgQH37jUb1aSP4ODS/3cKvDW6lR"
            + "IsYbSmQjzErpFedc1Aq5x905HA98O5/IATGdFdusjQv9YDGKlVy60mWtvA==";
    private static final String PRIVATE_KEY_CERT = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEY2xgUZ0DEnvGUFP"
            + "4SyzMVX4m3wm5wWRmy5+TsLkwk+hRANCAATwyBAffuNRvVpI/g4NL/dwq8NbqVEi"
            + "xhtKZCPMSukV51zUCrnH3TkcD3w7n8gBMZ0V26yNC/1gMYqVXLrSZa28";

    private static final List<String> ROUTE_CODES = Arrays.asList(
            "10", "10", "7", "10015", "10016", "10001", "10002", "3", "16", "45", "46", "187", "192",
            "195", "196", "197", "198", "199", "230", "232", "258", "449", "451", "452", "453", "454",
            "455", "456", "457", "458", "492", "493", "495", "503", "504", "505", "524", "526", "527",
            "529", "549", "563", "564", "575", "587", "590", "594", "639", "645", "646", "648", "649",
            "653", "656", "657", "661", "666", "669", "672", "673", "674", "675", "686", "690", "691",
            "692", "693", "697", "720", "727", "803", "816", "831", "832", "833", "834", "835", "841",
            "848", "849", "850", "851", "854", "865", "866", "867", "868", "870", "871", "1100", "1101",
            "1102", "1103", "1145", "1146", "1151", "1152", "1155", "1169", "1200", "1202", "1208",
            "1209", "1210", "1211", "1212", "1213", "1216", "1217", "1219", "1220", "1224", "1226",
            "1227", "1228", "1229", "1277", "1278", "1279", "1280", "1281", "1282", "1283", "1284",
            "1416", "1498", "1505", "1506", "1507", "1509", "1510", "1525", "1526", "1527", "1528",
            "1535", "1538", "1539", "1581", "1583", "1592", "1597", "1857", "2113", "2121", "2200",
            "2864", "2865", "2866", "10033", "10088", "10089", "10090", "10091", "10092", "10093",
            "10094", "10095", "10096", "10097", "10098", "10099", "10100", "10101", "10102", "10103",
            "10104", "10105", "10106", "10108", "10109", "10110", "10111", "10112", "10114", "10115",
            "10116", "10117", "10118", "10119", "10120", "10121", "10122", "10125", "10127", "10132",
            "10133", "10136", "10140", "10176", "10177", "10178", "10179", "10180", "10181", "10196",
            "10200", "10202", "10107", "10307", "10308", "10311", "10312", "10313", "10348", "10398",
            "10437", "10471", "10488", "10492", "10493", "10501", "10502", "10753", "10754", "10755",
            "10756", "10757", "10758", "10759"
    );

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        PublicKey publicKey = Sm2Utils.getPublicKey(PUBLIC_KEY_CERT);
        PrivateKey privateKey = Sm2Utils.getPrivateKey(PRIVATE_KEY_CERT);
        LocalDate end = LocalDate.of(2026, 7, 6);
        LocalDate start = end.minusDays(4);
        String startTime = start.format(DateTimeFormatter.ISO_LOCAL_DATE) + " 00:00:00";
        String endTime = end.format(DateTimeFormatter.ISO_LOCAL_DATE) + " 23:59:59";

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(10000)
                .setConnectionRequestTimeout(10000)
                .setSocketTimeout(45000)
                .build();

        Set<String> routeCodes = new LinkedHashSet<>(ROUTE_CODES);
        List<Result> results = new ArrayList<>();
        System.out.println("查询时间范围: " + startTime + " ~ " + endTime);
        System.out.println("接口号数量(去重): " + routeCodes.size());

        try (CloseableHttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(requestConfig).build()) {
            ExecutorService executor = Executors.newFixedThreadPool(8);
            CompletionService<Result> completionService = new ExecutorCompletionService<>(executor);
            for (String routeCode : routeCodes) {
                completionService.submit(() -> queryRoute(httpClient, mapper, publicKey, privateKey, routeCode, startTime, endTime));
            }
            try {
                for (int i = 0; i < routeCodes.size(); i++) {
                    Future<Result> future = completionService.take();
                    Result result = future.get();
                    results.add(result);
                    System.out.println(result);
                }
            } finally {
                executor.shutdownNow();
            }
        }

        System.out.println("====== 调用量大于0的接口号 ======");
        for (Result result : results) {
            if (result.hasCalls) {
                System.out.println(result.routeCode + "\t" + result.summary);
            }
        }
    }

    private static Result queryRoute(CloseableHttpClient httpClient, ObjectMapper mapper, PublicKey publicKey,
                                     PrivateKey privateKey, String routeCode, String startTime, String endTime) {
        try {
            Map<String, String> signData = buildSignData();
            String sign = Sm2Utils.sign(privateKey, buildSignText(signData));

            Map<String, Object> dataMap = new LinkedHashMap<>();
            dataMap.put("routeCode", routeCode);
            dataMap.put("requestDate", Arrays.asList(startTime, endTime));
            dataMap.put("pageSize", 2);

            HttpPost httpPost = new HttpPost(URL);
            httpPost.addHeader("Content-Type", "application/json;charset=UTF-8");
            httpPost.addHeader("X-Open-Sign", sign);
            for (Map.Entry<String, String> entry : signData.entrySet()) {
                httpPost.addHeader(entry.getKey(), entry.getValue());
            }
            String requestBody = mapper.writeValueAsString(dataMap);
            httpPost.setEntity(new StringEntity(Sm2Utils.encrypt(publicKey, requestBody), StandardCharsets.UTF_8));

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                HttpEntity entity = response.getEntity();
                String responseBody = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                Map<String, Object> responseObj = mapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {
                });
                if (!"OPEN-1000".equals(responseObj.get("code"))) {
                    return Result.error(routeCode, "网关失败: " + responseBody);
                }
                Object encryptedData = responseObj.get("data");
                if (!(encryptedData instanceof String)) {
                    return Result.error(routeCode, "网关无data: " + responseBody);
                }
                String decryptData = Sm2Utils.decrypt(privateKey, (String) encryptedData);
                Map<String, Object> businessObj = mapper.readValue(decryptData, new TypeReference<Map<String, Object>>() {
                });
                Boolean success = asBoolean(businessObj.get("success"));
                if (success != null && !success) {
                    return Result.error(routeCode, "业务失败: " + businessObj.get("message"), true);
                }
                Object data = businessObj;
                Integer total = findTotal(data);
                int fetched = countFetchedRows(data);
                boolean hasCalls = total != null ? total > 0 : fetched > 0;
                String summary = total != null ? "total=" + total : "fetched=" + fetched;
                return Result.ok(routeCode, hasCalls, summary);
            }
        } catch (Exception e) {
            return Result.error(routeCode, e.getClass().getSimpleName() + ": " + e.getMessage(), false);
        }
    }

    private static Map<String, String> buildSignData() {
        Map<String, String> signData = new HashMap<>();
        signData.put("Resource", RESOURCE);
        signData.put("X-Open-App-Key", APP_KEY);
        signData.put("X-Open-Request-Id", UUID.randomUUID().toString());
        signData.put("X-Open-Timestamp", System.currentTimeMillis() + "");
        signData.put("X-Open-Version", "1.0.0");
        return signData;
    }

    private static String buildSignText(Map<String, String> signData) {
        StringBuilder signDataText = new StringBuilder();
        List<String> keys = new ArrayList<>(signData.keySet());
        Collections.sort(keys);
        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            signDataText.append(i == 0 ? "" : "&").append(key).append("=").append(signData.get(key));
        }
        return signDataText.toString();
    }

    private static Boolean asBoolean(Object value) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.valueOf((String) value);
        }
        return null;
    }

    private static Integer findTotal(Object value) {
        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            for (String key : Arrays.asList("total", "count", "totalCount", "recordsTotal")) {
                Object total = map.get(key);
                if (total instanceof Number) {
                    return ((Number) total).intValue();
                }
                if (total instanceof String) {
                    try {
                        return Integer.parseInt((String) total);
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
            for (Object child : map.values()) {
                Integer total = findTotal(child);
                if (total != null) {
                    return total;
                }
            }
        }
        return null;
    }

    private static int countFetchedRows(Object value) {
        if (value instanceof List) {
            return ((List<?>) value).size();
        }
        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            for (String key : Arrays.asList("records", "list", "rows", "items", "data")) {
                Object rows = map.get(key);
                if (rows instanceof List) {
                    return ((List<?>) rows).size();
                }
            }
            for (Object child : map.values()) {
                int count = countFetchedRows(child);
                if (count > 0) {
                    return count;
                }
            }
        }
        return 0;
    }

    private static class Result {
        private final String routeCode;
        private final boolean hasCalls;
        private final String summary;
        private final String error;
        private final boolean fallbackCandidate;
        private final String note;

        private Result(String routeCode, boolean hasCalls, String summary, String error,
                       boolean fallbackCandidate, String note) {
            this.routeCode = routeCode;
            this.hasCalls = hasCalls;
            this.summary = summary;
            this.error = error;
            this.fallbackCandidate = fallbackCandidate;
            this.note = note;
        }

        private static Result ok(String routeCode, boolean hasCalls, String summary) {
            return new Result(routeCode, hasCalls, summary, null, false, null);
        }

        private static Result error(String routeCode, String error) {
            return error(routeCode, error, false);
        }

        private static Result error(String routeCode, String error, boolean fallbackCandidate) {
            return new Result(routeCode, false, "", error, fallbackCandidate, null);
        }

        private boolean shouldFallback() {
            return error != null && fallbackCandidate;
        }

        private Result withFallbackFrom(String originalError) {
            return new Result(routeCode, hasCalls, summary, error, false, "半年查询失败，已改查最近5天；原错误: " + originalError);
        }

        @Override
        public String toString() {
            String suffix = note == null ? "" : "\t" + note;
            if (error != null) {
                return routeCode + "\tERROR\t" + error + suffix;
            }
            return routeCode + "\t" + (hasCalls ? ">0" : "=0") + "\t" + summary + suffix;
        }
    }
}
