package com.github.xingjianluo.sessionauthaccesscontroljava.api;

import com.github.xingjianluo.sessionauthaccesscontroljava.security.AuthService;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.LoginResult;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.RefreshOutcome;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.RefreshResult;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.TokenPair;
import com.github.xingjianluo.sessionauthaccesscontroljava.web.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 登录 / 续期 / 退出接口。本接口组不要求访问凭证（无 @RequireRole）。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest body, HttpServletRequest request) {
        if (body == null || body.username() == null || body.password() == null) {
            throw new ApiException(400, "BAD_REQUEST", "username and password are required");
        }
        String source = resolveSource(request);
        TokenPair[] holder = new TokenPair[1];
        LoginResult result = authService.login(
                body.username(), body.password(), source, body.deviceLabel(), pair -> holder[0] = pair);
        return switch (result) {
            case SUCCESS -> tokenResponse(holder[0]);
            case INVALID_CREDENTIALS ->
                    throw new ApiException(401, "LOGIN_INVALID_CREDENTIALS", "invalid username or password");
            case ACCOUNT_DISABLED ->
                    throw new ApiException(403, "LOGIN_ACCOUNT_DISABLED", "account is disabled");
            case RATE_LIMITED ->
                    throw new ApiException(429, "LOGIN_RATE_LIMITED", "too many login attempts, try later");
        };
    }

    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody RefreshRequest body, HttpServletRequest request) {
        if (body == null || body.refreshToken() == null) {
            throw new ApiException(400, "BAD_REQUEST", "refreshToken is required");
        }
        String source = resolveSource(request);
        RefreshOutcome outcome = authService.refresh(body.refreshToken(), source);
        if (outcome.result() != RefreshResult.SUCCESS) {
            throw toRefreshException(outcome.result());
        }
        return tokenResponse(outcome.tokens());
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            throw new ApiException(401, "ACCESS_UNAUTHENTICATED", "authentication is required");
        }
        boolean ok = authService.logout(header.substring(BEARER_PREFIX.length()).trim());
        if (!ok) {
            throw new ApiException(401, "LOGOUT_SESSION_INVALID", "no active session for the token");
        }
        return Map.of("status", "logged_out");
    }

    private ApiException toRefreshException(RefreshResult result) {
        return switch (result) {
            case MALFORMED -> new ApiException(401, "REFRESH_MALFORMED", "refresh token is malformed");
            case BAD_SIGNATURE -> new ApiException(401, "REFRESH_BAD_SIGNATURE", "refresh token signature is invalid");
            case EXPIRED -> new ApiException(401, "REFRESH_EXPIRED", "refresh token has expired");
            case WRONG_TYPE -> new ApiException(401, "REFRESH_WRONG_TYPE", "token is not a refresh token");
            case SESSION_NOT_FOUND ->
                    new ApiException(404, "REFRESH_SESSION_NOT_FOUND", "session does not exist");
            case REVOKED -> new ApiException(401, "REFRESH_SESSION_REVOKED", "session has been revoked");
            case REUSED -> new ApiException(401, "REFRESH_REUSED", "refresh token has already been used");
            case LOGGED_OUT ->
                    new ApiException(401, "REFRESH_SESSION_LOGGED_OUT", "session has been logged out");
            case ACCOUNT_DISABLED ->
                    new ApiException(403, "REFRESH_ACCOUNT_DISABLED", "account is disabled");
            case RATE_LIMITED ->
                    new ApiException(429, "REFRESH_RATE_LIMITED", "too many refresh attempts, try later");
            case SUCCESS -> throw new IllegalStateException("SUCCESS must not be mapped to error");
        };
    }

    private Map<String, Object> tokenResponse(TokenPair pair) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", pair.accessToken());
        body.put("refreshToken", pair.refreshToken());
        body.put("tokenType", "Bearer");
        return body;
    }

    /**
     * 来源标识：优先读取显式头（便于本地测试模拟不同来源），否则使用对端地址。
     */
    private String resolveSource(HttpServletRequest request) {
        String explicit = request.getHeader("X-Client-Id");
        if (explicit != null && !explicit.isBlank()) {
            return explicit.trim();
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public record LoginRequest(String username, String password, String deviceLabel) {
    }

    public record RefreshRequest(String refreshToken) {
    }
}
