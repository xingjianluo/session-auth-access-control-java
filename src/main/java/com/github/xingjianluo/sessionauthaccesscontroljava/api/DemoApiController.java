package com.github.xingjianluo.sessionauthaccesscontroljava.api;

import com.github.xingjianluo.sessionauthaccesscontroljava.security.Principal;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.RequireRole;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;
import com.github.xingjianluo.sessionauthaccesscontroljava.web.AuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** 演示接口：公开 / 登录即可访问（USER 或 ADMIN）/ 仅管理员，三档权限。 */
@RestController
@RequestMapping("/api")
public class DemoApiController {

    /** 公开接口：无需登录。 */
    @GetMapping("/public/ping")
    public Map<String, Object> ping() {
        return Map.of("status", "ok");
    }

    /** 登录用户接口：USER / ADMIN 均可。 */
    @RequireRole({Role.USER, Role.ADMIN})
    @GetMapping("/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        Principal principal = (Principal) request.getAttribute(AuthInterceptor.PRINCIPAL_ATTRIBUTE);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", principal.username());
        body.put("sessionId", principal.sessionId());
        body.put("roles", principal.roles());
        return body;
    }

    /** 越权边界：仅 ADMIN 可访问，USER 访问应得到 403 FORBIDDEN_ROLE。 */
    @RequireRole(Role.ADMIN)
    @GetMapping("/admin/panel")
    public Map<String, Object> adminPanel(HttpServletRequest request) {
        Principal principal = (Principal) request.getAttribute(AuthInterceptor.PRINCIPAL_ATTRIBUTE);
        return Map.of("panel", "admin", "username", principal.username());
    }
}
