# JkzxDemo

Funi 接口总线接入示例，包含 SM2 加解密、签名验签、公私钥成对校验示例。

## 公私钥成对校验

修改 `KeyPairCheckDemo` 中的 `publicKeyCert` 和 `privateKeyCert` 为客户端实际使用的公钥、私钥，然后执行：

```bash
mvn -q -Dexec.mainClass=com.funi.paas.sdk.is.utils.KeyPairCheckDemo exec:java
```

输出 `公私钥校验通过` 表示当前公钥和私钥是正确成对的；输出 `公私钥校验失败` 表示不是一对，需要检查客户端密钥配置。

## 默认接口调用示例

```bash
mvn -q exec:java
```
