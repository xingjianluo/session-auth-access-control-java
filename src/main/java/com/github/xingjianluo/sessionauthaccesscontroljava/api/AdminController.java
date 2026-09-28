package com.github.xingjianluo.sessionauthaccesscontroljava.api;

import com.github.xingjianluo.sessionauthaccesscontroljava.security.RequireRole;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserDirectory;
import com.github.xingjianluo.sessionauthaccesscontroljava.web.ApiException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 角色管理：仅 ADMIN。调整角色是整体替换，之后该用户所有会话的后续请求
 * 都按最新角色判定（角色实时从用户目录读取，不依赖凭证过期）。
 */
@RestController
@RequestMapping("/api/admin/users")
public class AdminController {

    private final UserDirectory userDirectory;

    public AdminController(UserDirectory userDirectory) {
        this.userDirectory = userDirectory;
    }

    @RequireRole(Role.ADMIN)
    @PostMapping("/roles")
    public Map<String, Object> replaceRoles(@RequestBody RoleRequest body) {
        if (body == null || body.username() == null || body.roles() == null) {
            throw new ApiException(400, "BAD_REQUEST", "username and roles are required");
        }
        try {
            userDirectory.replaceRoles(body.username(), body.roles());
        } catch (IllegalArgumentException ex) {
            throw new ApiException(404, "USER_NOT_FOUND", ex.getMessage());
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("username", body.username());
        result.put("roles", body.roles());
        return result;
    }

    public record RoleRequest(String username, List<Role> roles) {
    }
}
