package com.github.xingjianluo.sessionauthaccesscontroljava.api;

import com.github.xingjianluo.sessionauthaccesscontroljava.auth.AuthInterceptor;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.RequireRole;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.Role;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ResourceController {

    @GetMapping("/api/public/hello")
    public Map<String, String> hello() {
        return Map.of("message", "hello");
    }

    @RequireRole(Role.USER)
    @GetMapping("/api/user/profile")
    public Map<String, String> profile(HttpServletRequest request) {
        return Map.of("username", String.valueOf(request.getAttribute(AuthInterceptor.ATTR_USERNAME)));
    }

    @RequireRole(Role.ADMIN)
    @GetMapping("/api/admin/stats")
    public Map<String, String> stats() {
        return Map.of("stats", "admin-only");
    }
}
