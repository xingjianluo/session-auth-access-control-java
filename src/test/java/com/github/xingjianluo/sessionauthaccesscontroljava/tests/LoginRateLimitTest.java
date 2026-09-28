package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.auth.RateLimiter;
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

@SpringBootTest
@AutoConfigureMockMvc
class LoginRateLimitTest {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimitTest.class);

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter.clear();
    }

    private MvcResult login(String username, String password, String ip) throws Exception {
        return mockMvc.perform(post("/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andReturn();
    }

    @Test
    void repeatedFailuresAreLimitedAndOtherUsersUnaffected() throws Exception {
        String ip = "192.168.10.1";
        // 同一账号同一来源连续失败 5 次 → 401
        for (int i = 1; i <= 5; i++) {
            MvcResult r = login("alice", "wrong-" + i, ip);
            log.info("身份=alice@{} 规则=第{}次登录失败 结论={}", ip, i, r.getResponse().getStatus());
            org.junit.jupiter.api.Assertions.assertEquals(401, r.getResponse().getStatus());
        }
        // 第 6 次 → 429
        MvcResult limited = login("alice", "wrong-6", ip);
        log.info("身份=alice@{} 规则=第6次登录尝试 结论=429 {}", ip, limited.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertEquals(429, limited.getResponse().getStatus());
        assertTrue(limited.getResponse().getContentAsString().contains("RATE_LIMITED"));

        // 同一来源的其他人也被来源维度限制
        MvcResult sameSource = login("bob", "bob-pwd", ip);
        log.info("身份=bob@{} 规则=同一来源已超限 结论={}", ip, sameSource.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertEquals(429, sameSource.getResponse().getStatus());

        // 其他来源的正常用户不受影响
        MvcResult other = login("bob", "bob-pwd", "192.168.10.2");
        log.info("身份=bob@192.168.10.2 规则=正常来源 结论={}", other.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertEquals(200, other.getResponse().getStatus());
    }

    @Test
    void successfulLoginResetsFailureCount() throws Exception {
        String ip = "192.168.20.1";
        // 失败 4 次（未达上限）
        for (int i = 1; i <= 4; i++) {
            login("alice", "wrong", ip);
        }
        // 登录成功 → 失败计数清零
        MvcResult ok = login("alice", "alice-pwd", ip);
        log.info("身份=alice@{} 规则=失败后成功登录 结论={}", ip, ok.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertEquals(200, ok.getResponse().getStatus());

        // 再失败 4 次仍不应被限（计数已重置）
        for (int i = 1; i <= 4; i++) {
            MvcResult r = login("alice", "wrong", ip);
            org.junit.jupiter.api.Assertions.assertEquals(401, r.getResponse().getStatus());
        }
        log.info("身份=alice@{} 规则=成功后再失败4次 结论=未触发限流(计数已重置)", ip);
    }

    @Test
    void refreshIsRateLimitedPerSource() throws Exception {
        String ip = "192.168.30.1";
        int limited = 0;
        int total = 0;
        for (int i = 0; i < 12; i++) {
            MvcResult r = mockMvc.perform(post("/auth/refresh")
                            .header("X-Forwarded-For", ip)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"refreshToken\":\"invalid\"}"))
                    .andReturn();
            total++;
            if (r.getResponse().getStatus() == 429) {
                limited++;
            }
        }
        log.info("身份=src:{} 规则=高频续期{}次 结论=429出现{}次(限额=10)", ip, total, limited);
        org.junit.jupiter.api.Assertions.assertEquals(2, limited, "限额10，第11、12次应被限");
    }
}
