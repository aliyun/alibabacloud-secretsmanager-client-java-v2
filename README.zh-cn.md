![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# 阿里云凭据管家 Java客户端V2

[![GitHub version](https://badge.fury.io/gh/aliyun%2Falibabacloud-secretsmanager-client-java-v2.svg)](https://badge.fury.io/gh/aliyun%2Falibabacloud-secretsmanager-client-java-v2)
[![Build Status](https://travis-ci.org/aliyun/alibabacloud-secretsmanager-client-java-v2.svg?branch=master)](https://travis-ci.org/aliyun/alibabacloud-secretsmanager-client-java-v2)

阿里云凭据管家 Java客户端V2可以使Java开发者快速使用阿里云凭据。你可以通过***Maven***快速使用。

*其他语言版本: [English](README.md), [简体中文](README.zh-cn.md)*

- [阿里云凭据管家 Java客户端V2主页]()
- [Issues](https://github.com/aliyun/alibabacloud-secretsmanager-client-java-v2/issues)
- [Release](https://github.com/aliyun/alibabacloud-secretsmanager-client-java-v2/releases)

## 许可证

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)

## 优势

* 支持用户快速集成获取凭据信息
* 支持阿里云凭据管家内存和文件两种缓存凭据机制
* 支持凭据名称相同场景下的跨地域容灾
* 支持默认规避策略和用户自定义规避策略

## 软件要求

- Java 1.8 或以上版本
- Maven

## 安装

可以通过Maven的方式在项目中使用凭据管家 Java客户端V2。导入方式如下:

```
<dependency>
    <groupId>com.aliyun</groupId>
    <artifactId>alibabacloud-secretsmanager-client-v2</artifactId>
    <version>2.0.0</version>
</dependency>
```

## 构建

你可以从Github检出代码通过下面的maven命令进行构建。

```
mvn clean install -DskipTests -Dgpg.skip=true
```

## 示例代码

### 一般用户代码

* 通过系统环境变量或配置文件(secretsmanager.properties)
  构建客户端([系统环境变量设置详情](README_environment.zh-cn.md)、[配置文件设置详情](README_config.zh-cn.md))

```Java
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;

public class CacheClientEnvironmentSample {

    public static void main(String[] args) {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newClient();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```

* 通过自定义配置文件(可自定义文件名称或文件路径名称)构建客户端([配置文件设置详情](README_config.zh-cn.md))

```Java
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;

public class CacheClientCustomConfigFileSample {

    public static void main(String[] args) {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCustomConfigFile("#customConfigFileName#").build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }
}
```

* 通过指定参数(accessKey、accessSecret、regionId等)构建客户端

```Java
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CredentialsProviderUtils;

public class CacheClientSimpleParametersSample {

    public static void main(String[] args) {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCredentialsProvider(CredentialsProviderUtils
                            .withAccessKey(System.getenv("#accessKeyId#"), System.getenv("#accessKeySecret#"))).withRegion("#regionId#").build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```

* 通过指定阿里云默认凭据链参数构建客户端。更多信息请参考 [阿里云默认凭据链](https://help.aliyun.com/zh/sdk/developer-reference/v2-manage-access-credentials#3cb4c2e29d9hk)。

```Java
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;

public class CacheClientDefaultCredentialChainSample {

    public static void main(String[] args) {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCredentialsProvider(new DefaultCredentialsProvider()).withRegion("#regionId#").build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}

```

* 通过指定参数(roleArn、oidcProviderArn、oidcTokenFilePath等)构建客户端

```Java
import com.aliyun.credentials.provider.OIDCRoleArnCredentialProvider;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CredentialsProviderUtils;

public class CacheClientOIDCParametersSample {

    public static void main(String[] args) {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                            BaseSecretManagerClientBuilder.standard()
                                    .withCredentialsProvider(
                                            OIDCRoleArnCredentialProvider.builder()
                                                    .roleArn("#roleArn#")
                                                    .oidcProviderArn("#oidcProviderArn#")
                                                    .oidcTokenFilePath("#oidcTokenFilePath#")
                                                    .build())
                                    .withRegion("#regionId#")
                                    .build())
                    .build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```

### 定制化用户代码

* 使用自定义参数或用户自己实现

```Java
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.cache.FileCacheSecretStoreStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.service.DefaultRefreshSecretStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.service.FullJitterBackoffStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CredentialsProviderUtils;

public class CacheClientDetailParametersSample {

    public static void main(String[] args) {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(BaseSecretManagerClientBuilder.standard()
                            .withCredentialsProvider(CredentialsProviderUtils.withAccessKey(System.getenv("#accessKeyId#"), System.getenv("#accessKeySecret#")))
                            .withRegion("#regionId#")
                            .withBackoffStrategy(new FullJitterBackoffStrategy(3, 2000, 10000)).build())
                    .withCacheSecretStrategy(new FileCacheSecretStoreStrategy("#cacheSecretPath#", true, "#salt#"))
                    .withRefreshSecretStrategy(new DefaultRefreshSecretStrategy("#ttlName#"))
                    .withCacheStage("#stage#")
                    .withSecretTTL("#secretName#", 1 * 60 * 1000l)
                    .withSecretTTL("#secretName1#", 2 * 60 * 1000l).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```

## 常见问题 FAQ

### 1. 出现 "cannot find the built-in ca certificate for region[$regionId], please provide the caFilePath parameter." 错误怎么办？

**问题原因：** SDK 中该地域内置的 CA 证书不存在。

**解决方案：**
1. 请更新 SDK 到最新版本。

2. 如果已更新到最新版本仍然报此错误，可以下载最新的CA证书（CA证书可在[密钥管理服务](https://yundun.console.aliyun.com/?spm=5176.12818093.ProductAndResource--ali--widget-product-recent.dre3.3be916d0yK6Zzx&p=kms#/keyStore/list/base/) - 实例管理 - 实例详情 页面下载），并传入CA证书路径参数。具体方式如下：

**方式一：编码方式传递 CA 证书路径**
```Java
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.v2.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CredentialsProviderUtils;

public class CacheClientWithCaCertificateSample {
    public static void main(String[] args) {
        try {
            // 创建包含 CA 证书路径的 RegionInfo
            RegionInfo regionInfo = new RegionInfo();
            regionInfo.setRegionId("#regionId#");
            regionInfo.setEndpoint("#kmsInstanceEndpoint#"); // 指定 KMS 实例地址
            regionInfo.setCaFilePath("#caFilePath#"); // 指定 CA 证书文件路径
            
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard()
                            .withCredentialsProvider(CredentialsProviderUtils.withAccessKey(
                                    System.getenv("#accessKeyId#"), 
                                    System.getenv("#accessKeySecret#")))
                            .addRegion(regionInfo) // 使用带 CA 证书路径的 RegionInfo
                            .build())
                    .build();
            // ... 使用 client
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```

**方式二：通过配置文件方式传递 CA 证书路径**
在 `secretsmanager.properties` 配置文件中添加 `caFilePath` 参数：
```
# 关联的KMS服务地域，包含CA证书路径和实例地址
cache_client_region_id=[{"regionId":"<regionId>","endpoint":"<kmsInstanceId>.cryptoservice.kms.aliyuncs.com","caFilePath":"<ca证书文件路径>"}]
```

**方式三：通过环境变量方式传递 CA 证书路径**
参考 [环境变量配置说明](README_environment.zh-cn.md)，在环境变量配置中添加 CA 证书路径参数：
```
# 关联的KMS服务地域，包含CA证书路径和实例地址
cache_client_region_id=[{"regionId":"<regionId>","endpoint":"<kmsInstanceId>.cryptoservice.kms.aliyuncs.com","caFilePath":"<ca证书文件路径>"}]
```