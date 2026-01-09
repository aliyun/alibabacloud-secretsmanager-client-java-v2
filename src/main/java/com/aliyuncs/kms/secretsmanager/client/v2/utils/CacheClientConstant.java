package com.aliyuncs.kms.secretsmanager.client.v2.utils;

public interface CacheClientConstant {

    /**
     * 模块名称
     */
    String MODE_NAME = "SecretsManagerClientV2";

    /**
     * 项目版本
     */
    String PROJECT_VERSION = "2.0.0";

    /**
     * Secrets Manager Client Java V2的User Agent
     */
    String USER_AGENT_OF_SECRETS_MANAGER_V2_JAVA = "alibabacloud-secretsmanager-client-java-v2";

    /**
     * 凭据文本数据类型
     */
    String TEXT_DATA_TYPE = "text";

    /**
     * 凭据二进制数据类型
     */
    String BINARY_DATA_TYPE = "binary";

    /**
     * 当前stage
     */
    String STAGE_ACS_CURRENT = "ACSCurrent";

    /**
     * 随机密钥字节长度
     */
    int RANDOM_KEY_LENGTH = 32;

    /**
     * 随机IV字节长度
     */
    int IV_LENGTH = 16;

    /**
     * 默认最大重试次数
     */
    long DEFAULT_RETRY_MAX_ATTEMPTS = 5L;

    /**
     * 默认重试间隔时间(毫秒)
     */
    long DEFAULT_RETRY_INITIAL_INTERVAL_MILLS = 2000L;

    /**
     * 默认最大等待时间
     */
    long DEFAULT_CAPACITY = 10000L;

    /**
     * 请求等待时间(毫秒)
     */
    long REQUEST_WAITING_TIME = 2 * 60 * 1000L;

    /**
     * 监控间隔时间(毫秒)
     */
    long MONITOR_INTERVAL = 5 * 60 * 1000;

    /**
     * 默认协议
     */
    String DEFAULT_PROTOCOL = "https";

    /**
     * KMS服务Socket连接超时错误码
     */
    String SDK_READ_TIMEOUT = "connect timed out";

    /**
     * TeaException 欠费errorCode
     */
    String TEA_EXCEPTION_ERROR_CODE_FORBIDDEN_IN_DEBT_OVER_DUE = "Forbidden.InDebtOverdue";

    /**
     * TeaException 欠费errorCode
     */
    String TEA_EXCEPTION_ERROR_CODE_FORBIDDEN_IN_DEBT = "Forbidden.InDebt";

    /**
     * 地域ID配置键名
     */
    String VARIABLE_CACHE_CLIENT_REGION_ID_KEY = "cache_client_region_id";

    /**
     * 凭据类型配置键名
     */
    String VARIABLE_CREDENTIALS_TYPE_KEY = "credentials_type";

    /**
     * AccessKey ID配置键名
     */
    String VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY = "credentials_access_key_id";

    /**
     * AccessKey Secret配置键名
     */
    String VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY = "credentials_access_secret";

    /**
     * 角色名称配置键名
     */
    String VARIABLE_CREDENTIALS_ROLE_NAME_KEY = "credentials_role_name";

    /**
     * OIDC角色会话过期时间配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_DURATION_SECONDS_KEY = "credentials_duration_seconds";

    /**
     * OIDC凭证ARN配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_PROVIDER_ARN_KEY = "credentials_oidc_provider_arn";

    /**
     * OIDC令牌文件路径配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_TOKEN_FILE_PATH_KEY = "credentials_oidc_token_file_path";
    /**
     * OIDC角色会话名称配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_ROLE_SESSION_NAME_KEY = "credentials_role_session_name";

    /**
     * OIDC角色ARN配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_ROLE_ARN_KEY = "credentials_role_arn";

    /**
     * OIDC策略配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_POLICY_KEY = "credentials_policy";

    /**
     * OIDC sts地域ID配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_STS_REGION_ID_KEY = "credentials_sts_region_id";

    /**
     * OIDC sts域名配置键名
     */
    String VARIABLE_CREDENTIALS_OIDC_STS_ENDPOINT_KEY = "credentials_sts_endpoint";

    /**
     * 地域域名配置键名
     */
    String VARIABLE_REGION_ENDPOINT_NAME_KEY = "endpoint";

    /**
     * 地域ID配置键名
     */
    String VARIABLE_REGION_REGION_ID_NAME_KEY = "regionId";

    /**
     * VPC配置键名
     */
    String VARIABLE_REGION_VPC_NAME_KEY = "vpc";

    /**
     * CA文件路径配置键名
     */
    String VARIABLE_REGION_CA_FILE_PATH_NAME_KEY = "caFilePath";

    /**
     * 凭据配置文件名称
     */
    String CREDENTIALS_PROPERTIES_CONFIG_NAME = "secretsmanager.properties";

    /**
     * 配置来源类型标识
     */
    String SOURCE_TYPE_CONFIG = "config";

    /**
     * 环境变量来源类型标识
     */
    String SOURCE_TYPE_ENV = "env";

    /**
     * 凭据参数缺失错误信息模板
     */
    String CHECK_PARAM_ERROR_MESSAGE = "%s credentials missing required parameters[%s].";

    /**
     * 实例网关域名后缀
     */
    String INSTANCE_GATEWAY_DOMAIN_SUFFIX = "cryptoservice.kms.aliyuncs.com";
}
