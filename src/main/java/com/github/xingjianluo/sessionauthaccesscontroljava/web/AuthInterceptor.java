package com.github.xingjianluo.sessionauthaccesscontroljava.web;

import com.github.xingjianluo.sessionauthaccesscontroljava.security.AccessInvalidReason;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.AccessResolution;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.AuditLogger;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.AuthService;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.Principal;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.RequireRole;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.EnumSet;

/**
 * 访问控制拦截器。
 *
 * <p>结论可区分：
 * <ul>
 *   <li>没有凭证 / 凭证无效 / 会话已退出或被撤销 / 账号停用 → 401（未认证），
 *       错误码随原因不同而不同（ACCESS_TOKEN_INVALID、ACCESS_SESSION_REVOKED 等）；</li>
 *   <li>已认证但缺少接口要求角色 → 403 FORBIDDEN_ROLE（越权）；</li>
 *   <li>角色每次实时读取，管理员调整角色后下一次请求立即按新角色判定。</li>
 * </ul>
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private static final String BEARER_PREFIX = "Bearer ";
    public static final String PRINCIPAL_ATTRIBUTE = "auth.principal";

    private final AuthService authService;
    private final AuditLogger auditLogger;

    public AuthInterceptor(AuthService authService, AuditLogger auditLogger) {
        this.authService = authService;
        this.auditLogger = auditLogger;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        RequireRole requireRole = resolveAnnotation(handlerMethod);
        String identity = "anonymous";

        // 没有 @RequireRole 的接口：公开访问，不需要登录
        if (requireRole == null) {
            auditLogger.log(identity, "ACCESS_PUBLIC", "ALLOWED",
                    request.getMethod() + " " + request.getRequestURI());
            return true;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            auditLogger.log(identity, "ACCESS_AUTHN", "REJECTED", "missing-bearer-token");
            throw new ApiException(401, "ACCESS_UNAUTHENTICATED", "authentication is required");
        }
        String accessToken = header.substring(BEARER_PREFIX.length()).trim();

        AccessResolution resolution = authService.resolveAccess(accessToken);
        if (!resolution.valid()) {
            throw unauthenticated(resolution.reason());
        }
        Principal principal = resolution.principal();
        request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
        identity = principal.username();

        EnumSet<Role> required = EnumSet.copyOf(Arrays.asList(requireRole.value()));
        boolean granted = principal.roles().stream().anyMatch(required::contains);
        if (!granted) {
            auditLogger.log(identity, "ACCESS_ROLE", "FORBIDDEN",
                    "required-any-of=" + required + " actual=" + principal.roles()
                            + " uri=" + request.getRequestURI());
            throw new ApiException(403, "FORBIDDEN_ROLE", "insufficient role");
        }

        auditLogger.log(identity, "ACCESS_ROLE", "ALLOWED",
                "matched-any-of=" + required + " uri=" + request.getRequestURI());
        return true;
    }

    private RequireRole resolveAnnotation(HandlerMethod handlerMethod) {
        RequireRole methodLevel = handlerMethod.getMethodAnnotation(RequireRole.class);
        if (methodLevel != null) {
            return methodLevel;
        }
        return handlerMethod.getBeanType().getAnnotation(RequireRole.class);
    }

    private ApiException unauthenticated(AccessInvalidReason reason) {
        String code = switch (reason) {
            case MALFORMED, BAD_SIGNATURE, WRONG_TYPE -> "ACCESS_TOKEN_INVALID";
            case EXPIRED -> "ACCESS_TOKEN_EXPIRED";
            case SESSION_NOT_FOUND -> "ACCESS_SESSION_NOT_FOUND";
            case LOGGED_OUT -> "ACCESS_SESSION_LOGGED_OUT";
            case REVOKED -> "ACCESS_SESSION_REVOKED";
            case ACCOUNT_DISABLED -> "ACCESS_ACCOUNT_DISABLED";
        };
        return new ApiException(401, code, "authentication failed: " + reason.name().toLowerCase());
    }
}
