![](https://aliyunsdk-pages.alicdn.com/icons/AlibabaCloud.svg)

# Alibaba Secrets Manager Client V2 for Java

[![GitHub version](https://badge.fury.io/gh/aliyun%2Falibabacloud-secretsmanager-client-java.svg)](https://badge.fury.io/gh/aliyun%2Falibabacloud-secretsmanager-client-java)
[![Build Status](https://travis-ci.org/aliyun/alibabacloud-secretsmanager-client-java.svg?branch=master)](https://travis-ci.org/aliyun/alibabacloud-secretsmanager-client-java)

Alibaba Secrets Manager Client V2 for Java enables Java developers to easily work with Aliyun KMS Secrets. You can get started in minutes using ***Maven*** .

*Read this in other languages: [English](README.md), [简体中文](README.zh-cn.md)*

- [Alibaba Secrets Manager Client V2 Homepage]()
- [Issues](https://github.com/aliyun/alibabacloud-secretsmanager-client-java-v2/issues)
- [Release](https://github.com/aliyun/alibabacloud-secretsmanager-client-java-v2/releases)

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)

## Features
* Provide quick integration capability to gain secret information
* Provide Alibaba secrets cache ( memory cache or encryption file cache )
* Provide tolerated disaster by the secrets with the same secret name and secret data in different regions
* Provide default backoff strategy and user-defined backoff strategy

## Requirements

- Java 1.8 or later
- Maven

## Install

The recommended way to use the Aliyun Secrets Manager Client V2 for Java in your project is to consume it from Maven. Import as follows:

```
<dependency>
    <groupId>com.aliyun</groupId>
    <artifactId>alibabacloud-secretsmanager-client-v2</artifactId>
    <version>2.0.0</version>
</dependency>
```

## Build

Once you check out the code from GitHub, you can build it using Maven. Use the following command to build:

```
mvn clean install -DskipTests -Dgpg.skip=true
```

## Sample Code

### Ordinary User Sample Code

* Build Secrets Manager Client by system environment variables or configuration file (secretsmanager.properties) ([system environment variables setting for details](README_environment.md),[configure configuration details](README_config.md))   

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

* Build Secrets Manager Client by a custom configuration file (you can customize the file name or file path name) ([Profile Setting Details](README_config.md))

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

*  Build Secrets Manager Client by the given parameters(accessKey, accessSecret, regionId, etc)

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
* Build Secrets Manager Client by Aliyun default credential chain. For more information, please refer to [Aliyun default credential chain](https://help.aliyun.com/zh/sdk/developer-reference/v2-manage-access-credentials#3cb4c2e29d9hk).

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
                    BaseSecretManagerClientBuilder.standard().withCredentialsProvider().withRegion("#regionId#").build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println(secretInfo);
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```
*  Build Secrets Manager Client by the given parameters(roleArn、oidcProviderArn、oidcTokenFilePath, etc)

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

### Particular User Sample Code
* Use custom parameters or customized implementation

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

## FAQ

### 1. How to resolve "cannot find the built-in ca certificate for region[$regionId], please provide the caFilePath parameter." error?

**Error Cause:** The built-in CA certificate for this region does not exist in the SDK.

**Solution:**
1. Please update the SDK to the latest version.

2. If you still encounter this error after updating to the latest version, you can download the latest CA certificate (CA certificates can be downloaded at [Key Management Service](https://yundun.console.aliyun.com/?spm=5176.12818093.ProductAndResource--ali--widget-product-recent.dre3.3be916d0yK6Zzx&p=kms#/keyStore/list/base/) - Instances - Instance Details page) and pass in the CA certificate path parameter. The specific methods are as follows:

**Method 1: Passing CA certificate path via coding**
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
            // Create RegionInfo with CA certificate path
            RegionInfo regionInfo = new RegionInfo();
            regionInfo.setRegionId("#regionId#");
            regionInfo.setEndpoint("#kmsInstanceEndpoint#"); // Specify KMS instance endpoint
            regionInfo.setCaFilePath("#caFilePath#"); // Specify CA certificate file path
            
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard()
                            .withCredentialsProvider(CredentialsProviderUtils.withAccessKey(
                                    System.getenv("#accessKeyId#"), 
                                    System.getenv("#accessKeySecret#")))
                            .addRegion(regionInfo) // Using RegionInfo with CA certificate path
                            .build())
                    .build();
            // ... use client
        } catch (CacheSecretException e) {
            e.printStackTrace();
        }
    }
}
```

**Method 2: Passing CA certificate path via configuration file**
Add `caFilePath` parameter in the `secretsmanager.properties` configuration file:
```properties
# KMS service region with CA certificate path and endpoint
cache_client_region_id=[{"regionId":"<regionId>","endpoint":"<kmsInstanceId>.cryptoservice.kms.aliyuncs.com","caFilePath":"<ca certificate file path>"}]
```

**Method 3: Passing CA certificate path via environment variables**
Refer to [Environment Variable Configuration Instructions](README_environment.md) and add the CA certificate path parameter in the environment variable configuration:
```properties
# KMS service region with CA certificate path and endpoint
cache_client_region_id=[{"regionId":"<regionId>","endpoint":"<kmsInstanceId>.cryptoservice.kms.aliyuncs.com","caFilePath":"<ca certificate file path>"}]
```