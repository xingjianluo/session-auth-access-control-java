package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 认证接口：登录 / 续期 / 退出。
 * 登录失败与续期都带频率限制，超限返回 429，窗口过期后自动恢复。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserStore userStore;
    private final TokenService tokenService;
    private final RateLimiter rateLimiter;
    private final int loginFailLimit;
    private final long loginFailWindowMillis;
    private final int refreshLimit;
    private final long refreshWindowMillis;

    public AuthController(UserStore userStore,
                          TokenService tokenService,
                          RateLimiter rateLimiter,
                          @Value("${auth.login-fail-limit:5}") int loginFailLimit,
                          @Value("${auth.login-fail-window-seconds:60}") long loginFailWindowSeconds,
                          @Value("${auth.refresh-limit:10}") int refreshLimit,
                          @Value("${auth.refresh-window-seconds:60}") long refreshWindowSeconds) {
        this.userStore = userStore;
        this.tokenService = tokenService;
        this.rateLimiter = rateLimiter;
        this.loginFailLimit = loginFailLimit;
        this.loginFailWindowMillis = loginFailWindowSeconds * 1000;
        this.refreshLimit = refreshLimit;
        this.refreshWindowMillis = refreshWindowSeconds * 1000;
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest body, HttpServletRequest request) {
        String username = body.username() == null ? "" : body.username();
        String ip = clientIp(request);
        String accountKey = "login-fail:acct:" + username;
        String sourceKey = "login-fail:src:" + ip;

        // 同一账号或同一来源任一超限即拒绝
        if (rateLimiter.currentCount(accountKey, loginFailWindowMillis) >= loginFailLimit
                || rateLimiter.currentCount(sourceKey, loginFailWindowMillis) >= loginFailLimit) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "RATE_LIMITED"));
        }

        if (!userStore.checkPassword(username, body.password())) {
            rateLimiter.tryAcquire(accountKey, loginFailLimit, loginFailWindowMillis);
            rateLimiter.tryAcquire(sourceKey, loginFailLimit, loginFailWindowMillis);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "BAD_CREDENTIALS"));
        }

        // 登录成功：清除该账号与该来源的失败计数，正常用户不被误伤
        rateLimiter.reset(accountKey);
        rateLimiter.reset(sourceKey);
        TokenPair tokens = tokenService.login(username);
        return ResponseEntity.ok(Map.of(
                "accessToken", tokens.accessToken(),
                "refreshToken", tokens.refreshToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest body, HttpServletRequest request) {
        String sourceKey = "refresh:src:" + clientIp(request);
        if (!rateLimiter.tryAcquire(sourceKey, refreshLimit, refreshWindowMillis)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "RATE_LIMITED"));
        }
        return switch (tokenService.refresh(body.refreshToken())) {
            case RefreshResult.Success success -> ResponseEntity.ok(Map.of(
                    "accessToken", success.tokens().accessToken(),
                    "refreshToken", success.tokens().refreshToken()));
            case RefreshResult.Failure failure -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "REFRESH_REJECTED", "reason", failure.name()));
        };
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String header) {
        String token = (header != null && header.startsWith("Bearer "))
                ? header.substring("Bearer ".length()).trim() : null;
        if (tokenService.checkAccessToken(token) instanceof AccessCheckResult.Valid valid) {
            tokenService.revokeSession(valid.sessionId());
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "UNAUTHENTICATED"));
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
