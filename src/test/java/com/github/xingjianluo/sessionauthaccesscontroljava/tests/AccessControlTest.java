package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.auth.Role;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.TokenPair;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.TokenService;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.UserStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AccessControlTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private UserStore userStore;

    @Test
    void unauthenticatedGets401() throws Exception {
        MvcResult r = mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("身份=匿名 规则=未登录访问用户接口 结论=401 {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("MISSING"));
    }

    @Test
    void tamperedTokenGets401() throws Exception {
        TokenPair pair = tokenService.login("alice");
        String bad = pair.accessToken() + "tamper";
        MvcResult r = mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + bad))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("身份=alice 规则=篡改访问令牌 结论=401 {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("TAMPERED"));
    }

    @Test
    void validUserTokenPasses() throws Exception {
        TokenPair pair = tokenService.login("alice");
        MvcResult r = mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk()).andReturn();
        log.info("身份=alice 规则=合法用户令牌 结论=200 {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("alice"));
    }

    @Test
    void nonAdminGets403() throws Exception {
        TokenPair pair = tokenService.login("bob");
        MvcResult r = mockMvc.perform(get("/api/admin/stats")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isForbidden()).andReturn();
        log.info("身份=bob(USER) 规则=越权访问管理接口 结论=403 {}", r.getResponse().getContentAsString());
        assertTrue(r.getResponse().getContentAsString().contains("FORBIDDEN"));
    }

    @Test
    void roleChangeTakesEffectImmediately() throws Exception {
        // bob 登录后，会话有效期内先被提升为 ADMIN，再被降回 USER
        TokenPair pair = tokenService.login("bob");
        String auth = "Bearer " + pair.accessToken();

        mockMvc.perform(get("/api/admin/stats").header("Authorization", auth))
                .andExpect(status().isForbidden());
        log.info("身份=bob 规则=提权前访问管理接口 结论=403");

        userStore.updateRoles("bob", Set.of(Role.USER, Role.ADMIN));
        MvcResult ok = mockMvc.perform(get("/api/admin/stats").header("Authorization", auth))
                .andExpect(status().isOk()).andReturn();
        log.info("身份=bob 规则=提权后访问管理接口 结论=200 {}", ok.getResponse().getContentAsString());

        userStore.updateRoles("bob", Set.of(Role.USER));
        MvcResult revoked = mockMvc.perform(get("/api/admin/stats").header("Authorization", auth))
                .andExpect(status().isForbidden()).andReturn();
        log.info("身份=bob 规则=降权后访问管理接口 结论=403 {}", revoked.getResponse().getContentAsString());
        assertEquals(403, revoked.getResponse().getStatus());
    }

    @Test
    void adminPasses() throws Exception {
        TokenPair pair = tokenService.login("admin");
        mockMvc.perform(get("/api/admin/stats")
                        .header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk());
        log.info("身份=admin 规则=管理员访问管理接口 结论=200");
    }

    @Test
    void publicEndpointNeedsNoAuth() throws Exception {
        mockMvc.perform(get("/api/public/hello")).andExpect(status().isOk());
        log.info("身份=匿名 规则=公开接口 结论=200");
    }
}
