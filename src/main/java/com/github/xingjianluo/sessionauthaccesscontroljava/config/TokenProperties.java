package com.github.xingjianluo.sessionauthaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 凭证（访问凭证 / 续期凭证）相关的本地配置。
 */
@ConfigurationProperties(prefix = "app.security.token")
public class TokenProperties {

    /** HMAC 签名密钥，仅用于本地演示。 */
    private String secret = "local-demo-secret-key-change-me";

    /** 访问凭证有效期（秒）。 */
    private long accessTtlSeconds = 900;

    /** 续期凭证有效期（秒）。 */
    private long refreshTtlSeconds = 86400;

    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }

    public long getAccessTtlSeconds() { return accessTtlSeconds; }
    public void setAccessTtlSeconds(long accessTtlSeconds) { this.accessTtlSeconds = accessTtlSeconds; }

    public long getRefreshTtlSeconds() { return refreshTtlSeconds; }
    public void setRefreshTtlSeconds(long refreshTtlSeconds) { this.refreshTtlSeconds = refreshTtlSeconds; }
}
