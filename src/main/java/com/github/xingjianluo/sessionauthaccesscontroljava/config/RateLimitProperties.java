package com.github.xingjianluo.sessionauthaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 频率限制配置：登录失败与凭证续期分别计数，账号与来源两个维度独立计数。
 */
@ConfigurationProperties(prefix = "app.security.rate-limit")
public class RateLimitProperties {

    /** 同一账号在一个窗口内允许的登录尝试次数。 */
    private int loginMaxAttempts = 5;

    /** 登录计数窗口（秒）。 */
    private long loginWindowSeconds = 60;

    /** 同一账号在一个窗口内允许的续期次数。 */
    private int refreshMaxAttempts = 20;

    /** 续期计数窗口（秒）。 */
    private long refreshWindowSeconds = 60;

    public int getLoginMaxAttempts() { return loginMaxAttempts; }
    public void setLoginMaxAttempts(int loginMaxAttempts) { this.loginMaxAttempts = loginMaxAttempts; }

    public long getLoginWindowSeconds() { return loginWindowSeconds; }
    public void setLoginWindowSeconds(long loginWindowSeconds) { this.loginWindowSeconds = loginWindowSeconds; }

    public int getRefreshMaxAttempts() { return refreshMaxAttempts; }
    public void setRefreshMaxAttempts(int refreshMaxAttempts) { this.refreshMaxAttempts = refreshMaxAttempts; }

    public long getRefreshWindowSeconds() { return refreshWindowSeconds; }
    public void setRefreshWindowSeconds(long refreshWindowSeconds) { this.refreshWindowSeconds = refreshWindowSeconds; }
}
