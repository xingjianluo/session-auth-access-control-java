package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.MutableClock;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.TestClockConfig;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserAccount;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserDirectory;
import java.util.EnumSet;
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

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 频率限制边界（HTTP 层）：登录失败与续期限流、账号/来源维度、自动恢复、
 * 成功登录清零、正常用户不误伤、并发计数精确。
 */
@SpringBootTest(properties = {
        "app.security.rate-limit.login-max-attempts=3",
        "app.security.rate-limit.login-window-seconds=60",
        "app.security.rate-limit.refresh-max-attempts=4",
        "app.security.rate-limit.refresh-window-seconds=60"
})
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class RateLimitMvcTest {

    private static final Logger log = LoggerFactory.getLogger("AUTH-AUDIT-TEST");

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Clock clock;
    @Autowired
    private UserDirectory userDirectory;

    private void registerUser(String username, String password) {
        userDirectory.register(new UserAccount(username, password, EnumSet.of(Role.USER)));
    }

    private MvcResult loginAttempt(String username, String password, String clientId) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .header("X-Client-Id", clientId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", username, "password", password, "deviceLabel", "t"))))
                .andReturn();
    }

    private String code(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("code").asText();
    }

    @Test
    @DisplayName("登录失败边界：前 3 次失败是 401，第 4 次起被限流 429 LOGIN_RATE_LIMITED")
    void loginFailuresAreLimitedAtBoundary() throws Exception {
        registerUser("ratelimit-user-a", "user123");
        // 前 3 次失败：401（计入计数但尚未超限）
        for (int i = 1; i <= 3; i++) {
            MvcResult result = loginAttempt("ratelimit-user-a", "wrong", "rl-src-1");
            assertEquals(401, result.getResponse().getStatus(), "第 " + i + " 次失败应是 401 而不是限流");
        }
        // 第 4 次：即使密码正确也被限流（前置检查拦截，账号维度）
        MvcResult blockedCorrectPassword = loginAttempt("ratelimit-user-a", "user123", "rl-src-1");
        assertEquals(429, blockedCorrectPassword.getResponse().getStatus());
        assertEquals("LOGIN_RATE_LIMITED", code(blockedCorrectPassword));

        log.info("identity=ratelimit-user-a rule=LOGIN_RATE_LIMIT decision=429 detail=4th attempt blocked even with correct password");
    }

    @Test
    @DisplayName("窗口过后自动恢复：被限流账号等待一个窗口后可重新登录")
    void loginLimitRecoversAfterWindow() throws Exception {
        registerUser("ratelimit-user-b", "user123");
        MutableClock mutableClock = (MutableClock) clock;
        for (int i = 0; i < 3; i++) {
            assertEquals(401, loginAttempt("ratelimit-user-b", "wrong", "rl-src-2").getResponse().getStatus());
        }
        assertEquals(429, loginAttempt("ratelimit-user-b", "wrong", "rl-src-2").getResponse().getStatus());

        mutableClock.advance(Duration.ofSeconds(61));
        MvcResult recovered = loginAttempt("ratelimit-user-b", "user123", "rl-src-2");
        assertEquals(200, recovered.getResponse().getStatus());
        log.info("identity=ratelimit-user-b rule=LOGIN_RATE_LIMIT decision=RECOVERED detail=after window correct login 200");
    }

    @Test
    @DisplayName("成功登录清零账号计数：正常用户偶发输错密码不会被锁；不同账号互不影响")
    void successfulLoginResetsAndDoesNotHarmNormalUser() throws Exception {
        registerUser("ratelimit-user-c", "user123");
        registerUser("ratelimit-user-d", "user123");
        // 用户 c：错 2 次（未到阈值），第 3 次输对 → 成功，计数清零
        assertEquals(401, loginAttempt("ratelimit-user-c", "wrong", "rl-src-3").getResponse().getStatus());
        assertEquals(401, loginAttempt("ratelimit-user-c", "wrong", "rl-src-3").getResponse().getStatus());
        assertEquals(200, loginAttempt("ratelimit-user-c", "user123", "rl-src-3").getResponse().getStatus());

        // 清零后：还能再承受 3 次失败（证明 reset 生效，而不是沿用旧计数）
        for (int i = 0; i < 3; i++) {
            assertEquals(401, loginAttempt("ratelimit-user-c", "wrong", "rl-src-3").getResponse().getStatus());
        }
        log.info("identity=ratelimit-user-c rule=LOGIN_RATE_LIMIT_RESET decision=ALLOWED detail=counter reset on success");

        // 不同账号互不影响：c 已用满，d 仍可正常登录
        assertEquals(200, loginAttempt("ratelimit-user-d", "user123", "rl-src-3").getResponse().getStatus());
        log.info("identity=ratelimit-user-d rule=RATE_LIMIT_ISOLATION decision=ALLOWED detail=other account unaffected");
    }

    @Test
    @DisplayName("来源维度限流：同一来源高频尝试不同账号，达到来源阈值后被 429")
    void sourceDimensionLimitsCredentialStuffing() throws Exception {
        // 来源阈值 = 账号阈值 * 4 = 12。用不同账号名打同一来源
        for (int i = 0; i < 12; i++) {
            int status = loginAttempt("spray-user-" + i, "wrong", "rl-shared-source").getResponse().getStatus();
            assertEquals(401, status, "第 " + (i + 1) + " 次应是认证失败");
        }
        MvcResult blocked = loginAttempt("spray-user-12", "wrong", "rl-shared-source");
        assertEquals(429, blocked.getResponse().getStatus());
        assertEquals("LOGIN_RATE_LIMITED", code(blocked));
        log.info("identity=spray-user-* rule=LOGIN_RATE_LIMIT_SOURCE decision=429 detail=credential spraying blocked");
    }

    @Test
    @DisplayName("续期限流：单账号短时间高频续期，超过阈值得到 429 REFRESH_RATE_LIMITED")
    void refreshIsRateLimited() throws Exception {
        // 先正常登录 alice 拿到一对凭证
        MvcResult login = loginAttempt("alice", "user123", "rl-refresh-src");
        assertEquals(200, login.getResponse().getStatus());
        JsonNode tokens = objectMapper.readTree(login.getResponse().getContentAsString());
        String refreshToken = tokens.get("refreshToken").asText();

        // refresh-max-attempts=4：同一张（已轮换后的）旧凭证前 4 次请求进入计数（业务结果是 REUSED 等，
        // 但只要没到限流阈值就不会是 429）。这里改用持续重复提交同一旧凭证来观察限流触发。
        int nonRateLimited = 0;
        int rateLimited = 0;
        for (int i = 0; i < 8; i++) {
            MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                            .header("X-Client-Id", "rl-refresh-src")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken))))
                    .andReturn();
            if (result.getResponse().getStatus() == 429) {
                rateLimited++;
            } else {
                nonRateLimited++;
            }
        }
        log.info("identity=alice rule=REFRESH_RATE_LIMIT decision=429 detail=nonLimited={} limited={}",
                nonRateLimited, rateLimited);
        assertTrue(rateLimited > 0, "高频续期必须出现 429");
        // 前 4 次不应被限流（首次 SUCCESS，后续 REUSED），第 5 次起 429
        assertEquals(4, nonRateLimited);
        assertEquals(4, rateLimited);
    }

    @Test
    @DisplayName("续期窗口自动恢复：限流后越过窗口，使用新凭证可正常续期")
    void refreshLimitRecoversAfterWindow() throws Exception {
        MutableClock mutableClock = (MutableClock) clock;
        MvcResult login = loginAttempt("bob", "user123", "rl-refresh-recover");
        assertEquals(200, login.getResponse().getStatus());
        JsonNode tokens = objectMapper.readTree(login.getResponse().getContentAsString());
        String firstRefresh = tokens.get("refreshToken").asText();

        // 打满 4 次额度
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/api/auth/refresh")
                    .header("X-Client-Id", "rl-refresh-recover")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(Map.of("refreshToken", firstRefresh)))).andReturn();
        }
        // 第 5 次被限流
        MvcResult blocked = mockMvc.perform(post("/api/auth/refresh")
                        .header("X-Client-Id", "rl-refresh-recover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", firstRefresh))))
                .andExpect(status().isTooManyRequests())
                .andReturn();
        assertEquals("REFRESH_RATE_LIMITED", code(blocked));

        // 越过窗口：来源与账号窗口都恢复。此时会话已因重放被撤销，
        // 重新登录拿新会话，再续期应当成功
        mutableClock.advance(Duration.ofSeconds(61));
        MvcResult reLogin = loginAttempt("bob", "user123", "rl-refresh-recover");
        assertEquals(200, reLogin.getResponse().getStatus());
        JsonNode newTokens = objectMapper.readTree(reLogin.getResponse().getContentAsString());
        MvcResult refreshAfterRecovery = mockMvc.perform(post("/api/auth/refresh")
                        .header("X-Client-Id", "rl-refresh-recover")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("refreshToken", newTokens.get("refreshToken").asText()))))
                .andExpect(status().isOk())
                .andReturn();
        log.info("identity=bob rule=REFRESH_RATE_LIMIT decision=RECOVERED detail=status={}",
                refreshAfterRecovery.getResponse().getStatus());
    }

    @Test
    @DisplayName("并发登录失败计数精确：40 个并发失败请求，恰好 3 次进入校验(401)，其余 429，计数不丢失不翻倍")
    void concurrentLoginCountingIsExact() throws Exception {
        int threads = 40;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger unauthorized = new AtomicInteger();
        AtomicInteger rateLimited = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    MvcResult result = loginAttempt("ratelimit-concurrent", "wrong", "rl-concurrent-src");
                    switch (result.getResponse().getStatus()) {
                        case 401 -> unauthorized.incrementAndGet();
                        case 429 -> rateLimited.incrementAndGet();
                        default -> other.incrementAndGet();
                    }
                } catch (Exception e) {
                    other.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("identity=ratelimit-concurrent rule=LOGIN_RATE_LIMIT_CONCURRENCY decision=EXACT detail=401={} 429={} other={}",
                unauthorized.get(), rateLimited.get(), other.get());

        assertEquals(0, other.get());
        assertEquals(3, unauthorized.get(), "并发下恰好 3 次失败进入校验，不能多也不能少");
        assertEquals(threads - 3, rateLimited.get());
    }
}
