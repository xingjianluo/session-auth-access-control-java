package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Set;

/**
 * 访问控制拦截器：
 * <ul>
 *   <li>未登录 / 凭证缺失 / 凭证无效 → 401，并区分具体原因；</li>
 *   <li>已登录但角色不足 → 403；</li>
 *   <li>角色在每次请求时实时读取，角色调整后立即生效。</li>
 * </ul>
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    public static final String ATTR_USERNAME = "auth.username";
    public static final String ATTR_SESSION_ID = "auth.sessionId";

    private final TokenService tokenService;
    private final UserStore userStore;

    public AuthInterceptor(TokenService tokenService, UserStore userStore) {
        this.tokenService = tokenService;
        this.userStore = userStore;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        RequireRole requireRole = method.getMethodAnnotation(RequireRole.class);
        if (requireRole == null) {
            requireRole = method.getBeanType().getAnnotation(RequireRole.class);
        }
        if (requireRole == null) {
            return true;
        }

        String header = request.getHeader("Authorization");
        String token = (header != null && header.startsWith("Bearer "))
                ? header.substring("Bearer ".length()).trim() : null;

        AccessCheckResult check = tokenService.checkAccessToken(token);
        switch (check) {
            case AccessCheckResult.Invalid invalid -> {
                // 401：未认证，reason 区分 缺失/格式错误/篡改/过期/会话已撤销
                writeJson(response, 401,
                        "{\"error\":\"UNAUTHENTICATED\",\"reason\":\"" + invalid.name() + "\"}");
                return false;
            }
            case AccessCheckResult.Valid valid -> {
                // 实时读取最新角色：会话有效期内角色被调整，后续请求立即按最新状态判定
                Set<Role> roles = userStore.getRoles(valid.username());
                for (Role required : requireRole.value()) {
                    if (roles.contains(required)) {
                        request.setAttribute(ATTR_USERNAME, valid.username());
                        request.setAttribute(ATTR_SESSION_ID, valid.sessionId());
                        return true;
                    }
                }
                // 403：已认证但越权
                writeJson(response, 403, "{\"error\":\"FORBIDDEN\"}");
                return false;
            }
        }
    }

    private void writeJson(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(body);
    }
}
