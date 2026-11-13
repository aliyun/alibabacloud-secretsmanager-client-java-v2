package com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger;

public interface Exchanger {
    ExchangeResult exchangeCredential(String identity) throws Exception;
}
