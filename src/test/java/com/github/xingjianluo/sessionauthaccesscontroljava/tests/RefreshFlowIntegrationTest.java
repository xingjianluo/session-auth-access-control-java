package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 续期全链路：登录 → 续期 → 旧令牌重放(REUSED) → 退出 → 再续期(REVOKED)。 */
@SpringBootTest
@AutoConfigureMockMvc
class RefreshFlowIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshFlowIntegrationTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private com.github.xingjianluo.sessionauthaccesscontroljava.auth.RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter.clear();
    }

    private MvcResult refresh(String token, String ip) throws Exception {
        return mockMvc.perform(post("/auth/refresh")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + token + "\"}"))
                .andReturn();
    }

    @Test
    void fullRefreshLifecycle() throws Exception {
        String ip = "10.1.1.1";
        // 1. 登录
        MvcResult login = mockMvc.perform(post("/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pwd\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode tokens = MAPPER.readTree(login.getResponse().getContentAsString());
        String access = tokens.get("accessToken").asText();
        String oldRefresh = tokens.get("refreshToken").asText();
        log.info("身份=alice@{} 规则=登录 结论=200 取得令牌对", ip);

        // 2. 正常续期
        MvcResult ok = refresh(oldRefresh, ip);
        org.junit.jupiter.api.Assertions.assertEquals(200, ok.getResponse().getStatus());
        JsonNode newTokens = MAPPER.readTree(ok.getResponse().getContentAsString());
        String newRefresh = newTokens.get("refreshToken").asText();
        log.info("身份=alice@{} 规则=正常续期 结论=200 刷新令牌已轮换", ip);

        // 3. 旧刷新令牌重放
        MvcResult replay = refresh(oldRefresh, ip);
        log.info("身份=alice@{} 规则=旧刷新令牌重放 结论=401 {}", ip, replay.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertEquals(401, replay.getResponse().getStatus());
        assertTrue(replay.getResponse().getContentAsString().contains("REUSED"));

        // 4. 退出
        mockMvc.perform(post("/auth/logout").header("Authorization", "Bearer " + access))
                .andExpect(status().isNoContent());
        log.info("身份=alice@{} 规则=退出登录 结论=204 会话已撤销", ip);

        // 5. 退出后用最新刷新令牌也无法恢复
        MvcResult afterLogout = refresh(newRefresh, ip);
        log.info("身份=alice@{} 规则=退出后续期 结论=401 {}", ip, afterLogout.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertEquals(401, afterLogout.getResponse().getStatus());
        assertTrue(afterLogout.getResponse().getContentAsString().contains("REVOKED"));
    }
}
