package com.aliyuncs.kms.secretsmanager.client.v2.model;

import com.aliyuncs.kms.secretsmanager.client.v2.utils.ByteBufferUtils;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CacheClientConstant;

import java.io.Serializable;
import java.nio.ByteBuffer;

public class SecretInfo implements Serializable, Cloneable {

    /**
     * 凭据名称
     */
    private String secretName;

    /**
     * 凭据版本ID
     */
    private String versionId;

    /**
     * 凭据值
     */
    private String secretValue;

    /**
     * 凭据字节缓冲值
     */
    private ByteBuffer secretValueByteBuffer;

    /**
     * 凭据数据类型
     */
    private String secretDataType;

    /**
     * 凭据创建时间
     */
    private String createTime;

    /**
     * 凭据类型
     */
    private String secretType;
    /**
     * 凭据自动轮转配置
     */
    private String automaticRotation;
    /**
     * 凭据扩展配置
     */
    private String extendedConfig;
    /**
     * 凭据轮转间隔时间
     */
    private String rotationInterval;
    /**
     * 凭据下次轮转日期
     */
    private String nextRotationDate;

    public SecretInfo() {
        // do nothing
    }

    public SecretInfo(String secretName, String versionId, String secretValue, String secretDataType, String createTime) {
        this.secretName = secretName;
        this.versionId = versionId;
        this.secretValue = secretValue;
        this.secretDataType = secretDataType;
        this.createTime = createTime;
    }

    public SecretInfo(String secretName, String versionId, String secretValue, String secretDataType, String createTime, String secretType, String automaticRotation, String extendedConfig, String rotationInterval, String nextRotationDate) {
        this.secretName = secretName;
        this.versionId = versionId;
        this.secretValue = secretValue;
        this.secretDataType = secretDataType;
        this.createTime = createTime;
        this.secretType = secretType;
        this.automaticRotation = automaticRotation;
        this.extendedConfig = extendedConfig;
        this.rotationInterval = rotationInterval;
        this.nextRotationDate = nextRotationDate;
    }

    public SecretInfo(String secretName, String versionId, String secretValue, ByteBuffer secretValueByteBuffer, String secretDataType, String createTime) {
        this.secretName = secretName;
        this.versionId = versionId;
        this.secretValue = secretValue;
        this.secretValueByteBuffer = secretValueByteBuffer;
        this.secretDataType = secretDataType;
        this.createTime = createTime;
    }

    public SecretInfo(String secretName, String versionId, String secretValue, ByteBuffer secretValueByteBuffer, String secretDataType, String createTime, String secretType, String automaticRotation, String extendedConfig, String rotationInterval, String nextRotationDate) {
        this.secretName = secretName;
        this.versionId = versionId;
        this.secretValue = secretValue;
        this.secretValueByteBuffer = secretValueByteBuffer;
        this.secretDataType = secretDataType;
        this.createTime = createTime;
        this.secretType = secretType;
        this.automaticRotation = automaticRotation;
        this.extendedConfig = extendedConfig;
        this.rotationInterval = rotationInterval;
        this.nextRotationDate = nextRotationDate;
    }

    public String getSecretName() {
        return secretName;
    }

    public String getVersionId() {
        return versionId;
    }

    public String getSecretValue() {
        return secretValue;
    }

    public String getSecretDataType() {
        return secretDataType;
    }

    public String getCreateTime() {
        return createTime;
    }

    public void setSecretName(String secretName) {
        this.secretName = secretName;
    }

    public void setVersionId(String versionId) {
        this.versionId = versionId;
    }

    public void setSecretValue(String secretValue) {
        this.secretValue = secretValue;
    }

    public void setSecretDataType(String secretDataType) {
        this.secretDataType = secretDataType;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public String getRotationInterval() {
        return this.rotationInterval;
    }

    public void setRotationInterval(String rotationInterval) {
        this.rotationInterval = rotationInterval;
    }

    public String getNextRotationDate() {
        return this.nextRotationDate;
    }

    public void setNextRotationDate(String nextRotationDate) {
        this.nextRotationDate = nextRotationDate;
    }

    public String getSecretType() {
        return this.secretType;
    }

    public void setSecretType(String secretType) {
        this.secretType = secretType;
    }

    public String getAutomaticRotation() {
        return this.automaticRotation;
    }

    public void setAutomaticRotation(String automaticRotation) {
        this.automaticRotation = automaticRotation;
    }

    public String getExtendedConfig() {
        return this.extendedConfig;
    }

    public void setExtendedConfig(String extendedConfig) {
        this.extendedConfig = extendedConfig;
    }

    public ByteBuffer getSecretValueByteBuffer() {
        if (CacheClientConstant.BINARY_DATA_TYPE.equals(secretDataType)) {
            return ByteBufferUtils.convertStringToByte(secretValue);
        }
        return this.secretValueByteBuffer;
    }

    @Override
    public SecretInfo clone() {
        try {
            return (SecretInfo) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "SecretInfo{" +
                "secretName='" + secretName + '\'' +
                ", versionId='" + versionId + '\'' +
                ", secretValue='***'" + '\'' +
                ", secretDataType='" + secretDataType + '\'' +
                ", createTime='" + createTime + '\'' +
                ", secretType='" + secretType + '\'' +
                ", automaticRotation='" + automaticRotation + '\'' +
                ", extendedConfig='" + extendedConfig + '\'' +
                ", rotationInterval='" + rotationInterval + '\'' +
                ", nextRotationDate='" + nextRotationDate + '\'' +
                '}';
    }
}
