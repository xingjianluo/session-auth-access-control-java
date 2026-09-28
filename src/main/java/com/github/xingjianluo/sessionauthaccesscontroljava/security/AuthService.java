package com.github.xingjianluo.sessionauthaccesscontroljava.security;

import com.github.xingjianluo.sessionauthaccesscontroljava.ratelimit.RateLimitDecision;
import com.github.xingjianluo.sessionauthaccesscontroljava.ratelimit.RateLimitService;
import com.github.xingjianluo.sessionauthaccesscontroljava.session.Session;
import com.github.xingjianluo.sessionauthaccesscontroljava.session.SessionState;
import com.github.xingjianluo.sessionauthaccesscontroljava.session.SessionStore;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.TokenClaims;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.TokenService;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.TokenType;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.Verification;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.VerificationStatus;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserAccount;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserDirectory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * 认证编排：登录（多设备会话）、续期（轮换 + 重放检测）、退出、访问凭证解析。
 *
 * <p>可预期性保证：
 * <ul>
 *   <li>同一会话上的“续期 / 退出”判定全部在 {@link Session} 对象锁内完成，
 *       并发续期只有一个成功，其余看到轮换后的新 jti（REUSED）；</li>
 *   <li>退出后会话为 LOGGED_OUT，任何续期凭证都只能得到 LOGGED_OUT，不会恢复；</li>
 *   <li>旧续期凭证再次使用（重放）判定为 REUSED，同时撤销整个会话（连带新凭证失效）；</li>
 *   <li>角色不固化在凭证内，{@link #resolveAccess} 每次实时读取用户目录。</li>
 * </ul>
 */
@Service
public class AuthService {

    private final TokenService tokenService;
    private final SessionStore sessionStore;
    private final UserDirectory userDirectory;
    private final RateLimitService rateLimitService;
    private final AuditLogger auditLogger;
    private final Clock clock;

    public AuthService(TokenService tokenService, SessionStore sessionStore,
                       UserDirectory userDirectory, RateLimitService rateLimitService,
                       AuditLogger auditLogger, Clock clock) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
        this.userDirectory = userDirectory;
        this.rateLimitService = rateLimitService;
        this.auditLogger = auditLogger;
        this.clock = clock;
    }

    /**
     * 登录。
     *
     * <p>限流策略：先做不计数的前置检查（账号 / 来源任一超限 → RATE_LIMITED）；
     * 账密校验失败才把本次尝试计入两个维度；成功则清零账号维度计数，
     * 正常用户偶发输错不会被误伤。每次成功登录创建一个新会话（支持多设备）。
     */
    public LoginResult login(String username, String password, String source, String deviceLabel,
                             ResultSink<TokenPair> sink) {
        String identity = username == null ? "anonymous" : username;
        if (!rateLimitService.checkLoginAllowed(username, source)) {
            auditLogger.log(identity, "LOGIN_RATE_LIMIT", LoginResult.RATE_LIMITED.name(),
                    "remainingByUser=" + rateLimitService.loginRemainingByUser(username)
                            + " remainingBySource=" + rateLimitService.loginRemainingBySource(source));
            return LoginResult.RATE_LIMITED;
        }

        UserAccount account = userDirectory.findByUsername(username).orElse(null);
        if (account == null || !account.getPassword().equals(password)) {
            rateLimitService.recordLoginAttempt(username, source);
            auditLogger.log(identity, "LOGIN_CREDENTIAL", LoginResult.INVALID_CREDENTIALS.name(),
                    "source=" + source + " remainingByUser=" + rateLimitService.loginRemainingByUser(username));
            return LoginResult.INVALID_CREDENTIALS;
        }
        if (!account.isEnabled()) {
            rateLimitService.recordLoginAttempt(username, source);
            auditLogger.log(identity, "LOGIN_ACCOUNT_STATE", LoginResult.ACCOUNT_DISABLED.name(), null);
            return LoginResult.ACCOUNT_DISABLED;
        }

        // 成功：本次尝试不计入失败计数，并清掉历史失败计数
        rateLimitService.resetLogin(username);

        Instant now = clock.instant();
        Session session = new Session();
        session.setId(UUID.randomUUID().toString());
        session.setUsername(username);
        session.setDeviceLabel(deviceLabel == null ? "unknown-device" : deviceLabel);
        session.setCreatedAt(now);
        session.setState(SessionState.ACTIVE);

        TokenService.IssuedToken access = tokenService.issueAccess(username, session.getId());
        TokenService.IssuedToken refresh = tokenService.issueRefresh(username, session.getId());
        session.setCurrentRefreshJti(refresh.claims().jti());
        session.setRefreshExpiresAt(refresh.claims().expiresAt());
        sessionStore.save(session);

        if (sink != null) {
            sink.accept(new TokenPair(access.compact(), refresh.compact()));
        }
        auditLogger.log(username, "LOGIN_CREDENTIAL", LoginResult.SUCCESS.name(),
                "sessionId=" + session.getId() + " device=" + session.getDeviceLabel());
        return LoginResult.SUCCESS;
    }

    /**
     * 续期。成功时旧续期凭证立即作废并下发新凭证对（轮换）。
     *
     * <p>判定顺序：来源限流 → 凭证结构/签名/类型（这些情况下解不出可信账号，仅来源计数）
     * → 过期 → 账号限流 → 会话存在性 / 会话状态 / 轮换状态 / 账号状态。
     * 已退出（LOGGED_OUT）与被撤销（REVOKED）是不同结论；重放（REUSED）会撤销整个会话。
     */
    public RefreshOutcome refresh(String refreshToken, String source) {
        // 1. 来源维度前置检查（任何时候都拦得住来源刷接口）
        if (!rateLimitService.checkRefreshAllowed(null, source)) {
            auditLogger.log("unknown", "REFRESH_RATE_LIMIT", RefreshResult.RATE_LIMITED.name(),
                    "stage=pre-source remainingBySource=" + rateLimitService.refreshRemainingBySource(source));
            return RefreshOutcome.of(RefreshResult.RATE_LIMITED);
        }

        Verification verification = tokenService.verify(refreshToken, TokenType.REFRESH);
        if (!verification.isOk()) {
            // 凭证不可信：无法安全获得账号，只按来源维度计数
            rateLimitService.recordRefreshAttempt(null, source);
            RefreshResult result = mapVerification(verification.status());
            auditLogger.log("unknown", "REFRESH_TOKEN", result.name(),
                    "source=" + source + " status=" + verification.status());
            return RefreshOutcome.of(result);
        }

        TokenClaims claims = verification.claims();
        String identity = claims.subject();

        // 2. 账号维度前置检查（此时凭证签名有效，账号可信）
        if (!rateLimitService.checkRefreshAllowed(identity, source)) {
            auditLogger.log(identity, "REFRESH_RATE_LIMIT", RefreshResult.RATE_LIMITED.name(),
                    "stage=pre-user sessionId=" + claims.sessionId()
                            + " remainingByUser=" + rateLimitService.refreshRemainingByUser(identity));
            return RefreshOutcome.of(RefreshResult.RATE_LIMITED);
        }
        RateLimitDecision recorded = rateLimitService.recordRefreshAttempt(identity, source);
        if (recorded == RateLimitDecision.REJECTED) {
            auditLogger.log(identity, "REFRESH_RATE_LIMIT", RefreshResult.RATE_LIMITED.name(),
                    "stage=record sessionId=" + claims.sessionId());
            return RefreshOutcome.of(RefreshResult.RATE_LIMITED);
        }

        // 3. 会话级判定，全部放在会话锁内，保证并发续期/退出结论确定
        Session session = sessionStore.findById(claims.sessionId()).orElse(null);
        if (session == null) {
            auditLogger.log(identity, "REFRESH_SESSION", RefreshResult.SESSION_NOT_FOUND.name(),
                    "sessionId=" + claims.sessionId());
            return RefreshOutcome.of(RefreshResult.SESSION_NOT_FOUND);
        }

        TokenPair newPair;
        RefreshResult result;
        synchronized (session) {
            SessionState state = session.getState();
            if (state == SessionState.LOGGED_OUT) {
                auditLogger.log(identity, "REFRESH_SESSION_STATE", RefreshResult.LOGGED_OUT.name(),
                        "sessionId=" + session.getId());
                return RefreshOutcome.of(RefreshResult.LOGGED_OUT);
            }
            if (state == SessionState.REVOKED) {
                auditLogger.log(identity, "REFRESH_SESSION_STATE", RefreshResult.REVOKED.name(),
                        "sessionId=" + session.getId());
                return RefreshOutcome.of(RefreshResult.REVOKED);
            }

            // 会话内的轮换判定：当前 jti 才是有效凭证
            if (session.getCurrentRefreshJti() == null
                    || !session.getCurrentRefreshJti().equals(claims.jti())) {
                boolean everUsed = session.getUsedRefreshJtis().contains(claims.jti());
                // 重放旧凭证：撤销整个会话，盗取到的新凭证也一并失效
                session.setState(SessionState.REVOKED);
                result = everUsed ? RefreshResult.REUSED : RefreshResult.REVOKED;
                auditLogger.log(identity, "REFRESH_ROTATION", result.name(),
                        "sessionId=" + session.getId() + " presentedJti=" + claims.jti()
                                + " expectedJti=" + session.getCurrentRefreshJti());
                return RefreshOutcome.of(result);
            }

            UserAccount account = userDirectory.findByUsername(identity).orElse(null);
            if (account == null || !account.isEnabled()) {
                auditLogger.log(identity, "REFRESH_ACCOUNT_STATE", RefreshResult.ACCOUNT_DISABLED.name(),
                        "sessionId=" + session.getId());
                return RefreshOutcome.of(RefreshResult.ACCOUNT_DISABLED);
            }

            // 轮换：旧 jti 入历史，签发新凭证对，更新当前 jti
            session.getUsedRefreshJtis().add(claims.jti());
            TokenService.IssuedToken newAccess = tokenService.issueAccess(identity, session.getId());
            TokenService.IssuedToken newRefresh = tokenService.issueRefresh(identity, session.getId());
            session.setCurrentRefreshJti(newRefresh.claims().jti());
            session.setRefreshExpiresAt(newRefresh.claims().expiresAt());
            newPair = new TokenPair(newAccess.compact(), newRefresh.compact());
            result = RefreshResult.SUCCESS;
        }
        sessionStore.save(session);
        auditLogger.log(identity, "REFRESH_ROTATION", RefreshResult.SUCCESS.name(),
                "sessionId=" + session.getId() + " rotatedJti=" + claims.jti()
                        + " newJti=" + newPair.refreshToken().length() + "chars");
        return new RefreshOutcome(result, newPair);
    }

    /**
     * 退出：会话置为 LOGGED_OUT。之后该会话的访问凭证立即失效，
     * 续期凭证只能得到 LOGGED_OUT，不能再恢复。
     *
     * @return true 表示会话存在且被置为退出；false 表示找不到会话
     */
    public boolean logout(String accessToken) {
        Verification verification = tokenService.verify(accessToken, TokenType.ACCESS);
        if (!verification.isOk()) {
            auditLogger.log("unknown", "LOGOUT_TOKEN", "REJECTED",
                    "status=" + verification.status());
            return false;
        }
        TokenClaims claims = verification.claims();
        Session session = sessionStore.findById(claims.sessionId()).orElse(null);
        if (session == null) {
            auditLogger.log(claims.subject(), "LOGOUT_SESSION", "REJECTED",
                    "sessionId=" + claims.sessionId());
            return false;
        }
        synchronized (session) {
            // 幂等：已经是 LOGGED_OUT/REVOKED 也按成功语义返回，但已退出会话不会被重新激活
            session.setState(SessionState.LOGGED_OUT);
        }
        auditLogger.log(claims.subject(), "LOGOUT_SESSION", "LOGGED_OUT",
                "sessionId=" + session.getId());
        return true;
    }

    /**
     * 解析访问凭证并装配当前请求身份。角色实时读取用户目录，
     * 因此角色被调整后，下一个请求立即按新角色判定。
     */
    public AccessResolution resolveAccess(String accessToken) {
        Verification verification = tokenService.verify(accessToken, TokenType.ACCESS);
        if (!verification.isOk()) {
            auditLogger.log("unknown", "ACCESS_TOKEN", "REJECTED",
                    "status=" + verification.status());
            return AccessResolution.invalid(mapAccessVerification(verification.status()));
        }
        TokenClaims claims = verification.claims();
        Session session = sessionStore.findById(claims.sessionId()).orElse(null);
        if (session == null) {
            auditLogger.log(claims.subject(), "ACCESS_SESSION", "REJECTED", "session-not-found");
            return AccessResolution.invalid(AccessInvalidReason.SESSION_NOT_FOUND);
        }
        synchronized (session) {
            if (session.getState() == SessionState.LOGGED_OUT) {
                auditLogger.log(claims.subject(), "ACCESS_SESSION_STATE", "REJECTED", "logged-out");
                return AccessResolution.invalid(AccessInvalidReason.LOGGED_OUT);
            }
            if (session.getState() == SessionState.REVOKED) {
                auditLogger.log(claims.subject(), "ACCESS_SESSION_STATE", "REJECTED", "revoked");
                return AccessResolution.invalid(AccessInvalidReason.REVOKED);
            }
        }
        UserAccount account = userDirectory.findByUsername(claims.subject()).orElse(null);
        if (account == null || !account.isEnabled()) {
            auditLogger.log(claims.subject(), "ACCESS_ACCOUNT_STATE", "REJECTED", "disabled-or-missing");
            return AccessResolution.invalid(AccessInvalidReason.ACCOUNT_DISABLED);
        }
        Principal principal = new Principal(
                claims.subject(), claims.sessionId(), account.getRoles());
        auditLogger.log(claims.subject(), "ACCESS_TOKEN", "AUTHENTICATED",
                "sessionId=" + claims.sessionId() + " roles=" + account.getRoles());
        return AccessResolution.ok(principal);
    }

    private RefreshResult mapVerification(VerificationStatus status) {
        return switch (status) {
            case MALFORMED -> RefreshResult.MALFORMED;
            case BAD_SIGNATURE -> RefreshResult.BAD_SIGNATURE;
            case EXPIRED -> RefreshResult.EXPIRED;
            case WRONG_TYPE -> RefreshResult.WRONG_TYPE;
            case OK -> throw new IllegalStateException("OK must be handled by caller");
        };
    }

    private AccessInvalidReason mapAccessVerification(VerificationStatus status) {
        return switch (status) {
            case MALFORMED -> AccessInvalidReason.MALFORMED;
            case BAD_SIGNATURE -> AccessInvalidReason.BAD_SIGNATURE;
            case EXPIRED -> AccessInvalidReason.EXPIRED;
            case WRONG_TYPE -> AccessInvalidReason.WRONG_TYPE;
            case OK -> throw new IllegalStateException("OK must be handled by caller");
        };
    }

    /** 结果回调，登录成功时把凭证对交回调用方。 */
    @FunctionalInterface
    public interface ResultSink<T> {
        void accept(T value);
    }
}
