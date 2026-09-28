package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.TestClockConfig;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 访问控制边界（走完整 MVC 过滤链 + 拦截器）：
 * 未登录(401) / 越权(403) / 正常放行(200) 结论可区分；角色实时生效；多设备会话独立。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class AccessControlMvcTest {

    private static final Logger log = LoggerFactory.getLogger("AUTH-AUDIT-TEST");

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    private Tokens login(String username, String password, String clientId) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .header("X-Client-Id", clientId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", username, "password", password, "deviceLabel", clientId))))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        log.info("identity={} rule=LOGIN decision=SUCCESS detail=device={}", username, clientId);
        return new Tokens(body.get("accessToken").asText(), body.get("refreshToken").asText());
    }

    private MvcResult adminAdjustRoles(String adminAccess, String target, List<Role> roles) throws Exception {
        return mockMvc.perform(post("/api/admin/users/roles")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("username", target, "roles", roles))))
                .andReturn();
    }

    @Test
    @DisplayName("公开接口无需登录；受保护接口未带凭证得到 401 ACCESS_UNAUTHENTICATED")
    void publicVsUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/public/ping"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"));

        MvcResult profileNoToken = mockMvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        String code = objectMapper.readTree(profileNoToken.getResponse().getContentAsString()).get("code").asText();
        log.info("identity=anonymous rule=ACCESS_AUTHN decision=401 detail=code={}", code);
        assertTrue(code.equals("ACCESS_UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("USER 访问管理员接口得到 403 FORBIDDEN_ROLE，与 401 可区分")
    void userCannotAccessAdminEndpoint() throws Exception {
        Tokens alice = login("alice", "user123", "device-ac-1");

        // 自己的 profile 可以访问
        mockMvc.perform(get("/api/profile").header("Authorization", "Bearer " + alice.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));

        // 越权访问管理员接口：403 + 专属错误码
        MvcResult forbidden = mockMvc.perform(get("/api/admin/panel")
                        .header("Authorization", "Bearer " + alice.accessToken()))
                .andExpect(status().isForbidden())
                .andReturn();
        String code = objectMapper.readTree(forbidden.getResponse().getContentAsString()).get("code").asText();
        log.info("identity=alice rule=ACCESS_ROLE decision=403 detail=code={}", code);
        assertTrue(code.equals("FORBIDDEN_ROLE"));
    }

    @Test
    @DisplayName("ADMIN 可以访问管理员接口")
    void adminCanAccessAdminEndpoint() throws Exception {
        Tokens admin = login("admin", "admin123", "device-ac-admin");
        mockMvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + admin.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.panel").value("admin"));
        log.info("identity=admin rule=ACCESS_ROLE decision=200 detail=admin panel granted");
    }

    @Test
    @DisplayName("会话有效期内角色被调整：提权后新权限立即生效，降权后旧权限立即失效，无需重新登录")
    void roleChangeTakesEffectImmediately() throws Exception {
        Tokens admin = login("admin", "admin123", "device-ac-admin-2");
        Tokens bob = login("bob", "user123", "device-ac-bob");

        // 调整前：bob 是普通用户，访问管理面板 403
        mockMvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + bob.accessToken()))
                .andExpect(status().isForbidden());

        // 管理员把 bob 提升为 ADMIN
        MvcResult promote = adminAdjustRoles(admin.accessToken(), "bob", List.of(Role.ADMIN, Role.USER));
        org.junit.jupiter.api.Assertions.assertEquals(200, promote.getResponse().getStatus());

        // 同一张访问凭证，不重新登录：立刻可访问管理面板
        mockMvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + bob.accessToken()))
                .andExpect(status().isOk());
        log.info("identity=bob rule=ROLE_CHANGE decision=PROMOTED detail=same token now 200");

        // 再降权为空：旧权限立即失效
        MvcResult demote = adminAdjustRoles(admin.accessToken(), "bob", List.of());
        org.junit.jupiter.api.Assertions.assertEquals(200, demote.getResponse().getStatus());

        // 无任何角色：profile（要求 USER/ADMIN）与 panel（要求 ADMIN）都应 403
        mockMvc.perform(get("/api/profile").header("Authorization", "Bearer " + bob.accessToken()))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + bob.accessToken()))
                .andExpect(status().isForbidden());
        log.info("identity=bob rule=ROLE_CHANGE decision=DEMOTED detail=same token now 403 everywhere");

        // 复原，避免污染其它测试不必要的状态（每个测试方法共享上下文，角色存储是单例）
        adminAdjustRoles(admin.accessToken(), "bob", List.of(Role.USER));
    }

    @Test
    @DisplayName("伪造/篡改的访问凭证得到 401 ACCESS_TOKEN_INVALID，而非 403")
    void tamperedAccessTokenIsUnauthorized() throws Exception {
        Tokens alice = login("alice", "user123", "device-ac-tamper");
        String tampered = alice.accessToken().substring(0, alice.accessToken().length() - 3) + "AAA";

        MvcResult result = mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andReturn();
        String code = objectMapper.readTree(result.getResponse().getContentAsString()).get("code").asText();
        log.info("identity=alice rule=ACCESS_TOKEN decision=401 detail=code={}", code);
        assertTrue(code.equals("ACCESS_TOKEN_INVALID"));
    }

    @Test
    @DisplayName("退出登录后访问凭证立即失效：401 ACCESS_SESSION_LOGGED_OUT，且续期也被拒")
    void logoutInvalidatesAccessImmediately() throws Exception {
        Tokens alice = login("alice", "user123", "device-ac-logout");

        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + alice.accessToken()))
                .andExpect(status().isOk());

        MvcResult afterLogout = mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + alice.accessToken()))
                .andExpect(status().isUnauthorized())
                .andReturn();
        String code = objectMapper.readTree(afterLogout.getResponse().getContentAsString()).get("code").asText();
        log.info("identity=alice rule=ACCESS_SESSION_STATE decision=401 detail=code={}", code);
        assertTrue(code.equals("ACCESS_SESSION_LOGGED_OUT"));

        // 续期同样被拒：已退出会话不可恢复
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", alice.refreshToken()))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_SESSION_LOGGED_OUT"));
    }

    @Test
    @DisplayName("多设备登录：不同设备各自独立会话，一个设备退出不影响另一个设备")
    void multipleDevicesHaveIndependentSessions() throws Exception {
        Tokens phone = login("alice", "user123", "alice-phone");
        Tokens laptop = login("alice", "user123", "alice-laptop");

        org.junit.jupiter.api.Assertions.assertNotEquals(phone.accessToken(), laptop.accessToken());

        // 手机退出
        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + phone.accessToken()))
                .andExpect(status().isOk());

        // 手机访问被拒
        mockMvc.perform(get("/api/profile").header("Authorization", "Bearer " + phone.accessToken()))
                .andExpect(status().isUnauthorized());
        // 笔记本仍然可用
        mockMvc.perform(get("/api/profile").header("Authorization", "Bearer " + laptop.accessToken()))
                .andExpect(status().isOk());
        // 笔记本续期正常
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", laptop.refreshToken()))))
                .andExpect(status().isOk());
        log.info("identity=alice rule=MULTI_DEVICE decision=ISOLATED detail=phone logged out, laptop alive");
    }

    private record Tokens(String accessToken, String refreshToken) {
    }
}
