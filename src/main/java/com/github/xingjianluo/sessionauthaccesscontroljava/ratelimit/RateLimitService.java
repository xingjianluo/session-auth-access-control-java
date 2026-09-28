package com.github.xingjianluo.sessionauthaccesscontroljava.ratelimit;

import com.github.xingjianluo.sessionauthaccesscontroljava.config.RateLimitProperties;
import org.springframework.stereotype.Component;

import java.time.Clock;

/**
 * 限流编排：登录与续期使用相互独立的计数器，账号与来源两个维度也相互独立。
 *
 * <ul>
 *   <li>登录：先做“前置检查”（不计数，避免被拦截的探测请求污染窗口），
 *       账密校验后再把本次尝试计入两个维度；登录成功立即清零账号维度，
 *       正常用户偶发输错密码不会被误伤。</li>
 *   <li>续期：来源维度始终参与（畸形凭证解不出账号时也能拦住来源刷接口）；
 *       账号维度仅在能解出账号时参与。</li>
 * </ul>
 *
 * <p>“短时间高频”由固定窗口刻画，窗口过后自动恢复，见 {@link FixedWindowRateLimiter}。
 */
@Component
public class RateLimitService {

    private final FixedWindowRateLimiter loginByUser;
    private final FixedWindowRateLimiter loginBySource;
    private final FixedWindowRateLimiter refreshByUser;
    private final FixedWindowRateLimiter refreshBySource;

    public RateLimitService(RateLimitProperties properties, Clock clock) {
        this.loginByUser = new FixedWindowRateLimiter(
                properties.getLoginMaxAttempts(), properties.getLoginWindowSeconds(), clock);
        this.loginBySource = new FixedWindowRateLimiter(
                properties.getLoginMaxAttempts() * 4, properties.getLoginWindowSeconds(), clock);
        this.refreshByUser = new FixedWindowRateLimiter(
                properties.getRefreshMaxAttempts(), properties.getRefreshWindowSeconds(), clock);
        this.refreshBySource = new FixedWindowRateLimiter(
                properties.getRefreshMaxAttempts() * 4, properties.getRefreshWindowSeconds(), clock);
    }

    /** 登录前置检查（不计数）：账号 / 来源任一维度已超限即拒绝。 */
    public boolean checkLoginAllowed(String username, String source) {
        if (loginByUser.remaining(userKey(username)) <= 0) {
            return false;
        }
        return loginBySource.remaining(sourceKey(source)) > 0;
    }

    /** 记录一次登录尝试（前置检查通过后调用），两个维度同时计数。 */
    public RateLimitDecision recordLoginAttempt(String username, String source) {
        RateLimitDecision byUser = loginByUser.checkAndIncrement(userKey(username));
        RateLimitDecision bySource = loginBySource.checkAndIncrement(sourceKey(source));
        // 前置检查保证不会超限；防御性地把两个维度的结论合并
        return byUser == RateLimitDecision.ALLOWED && bySource == RateLimitDecision.ALLOWED
                ? RateLimitDecision.ALLOWED : RateLimitDecision.REJECTED;
    }

    /** 登录成功后清零账号维度计数，避免正常用户被历史失败影响。 */
    public void resetLogin(String username) {
        loginByUser.reset(userKey(username));
    }

    /** 续期前置检查：username 为 null（解不出账号）时只看来源维度。 */
    public boolean checkRefreshAllowed(String username, String source) {
        if (username != null && refreshByUser.remaining(userKey(username)) <= 0) {
            return false;
        }
        return refreshBySource.remaining(sourceKey(source)) > 0;
    }

    /** 记录一次续期请求，两个维度同时计数（username 可为 null）。 */
    public RateLimitDecision recordRefreshAttempt(String username, String source) {
        RateLimitDecision bySource = refreshBySource.checkAndIncrement(sourceKey(source));
        RateLimitDecision byUser = username == null
                ? RateLimitDecision.ALLOWED
                : refreshByUser.checkAndIncrement(userKey(username));
        return byUser == RateLimitDecision.ALLOWED && bySource == RateLimitDecision.ALLOWED
                ? RateLimitDecision.ALLOWED : RateLimitDecision.REJECTED;
    }

    /** 观察用：登录账号维度剩余次数。 */
    public int loginRemainingByUser(String username) {
        return loginByUser.remaining(userKey(username));
    }

    /** 观察用：登录来源维度剩余次数。 */
    public int loginRemainingBySource(String source) {
        return loginBySource.remaining(sourceKey(source));
    }

    /** 观察用：续期账号维度剩余次数。 */
    public int refreshRemainingByUser(String username) {
        return username == null ? refreshByUser.remaining(null) : refreshByUser.remaining(userKey(username));
    }

    /** 观察用：续期来源维度剩余次数。 */
    public int refreshRemainingBySource(String source) {
        return refreshBySource.remaining(sourceKey(source));
    }

    private String userKey(String username) {
        return "u:" + (username == null ? "" : username);
    }

    private String sourceKey(String source) {
        return "s:" + (source == null || source.isBlank() ? "unknown" : source);
    }
}
