package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.auth.AccessCheckResult;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.RefreshResult;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.SessionStore;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.TokenPair;
import com.github.xingjianluo.sessionauthaccesscontroljava.auth.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private MutableClock clock;
    private SessionStore sessionStore;
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        sessionStore = new SessionStore();
        tokenService = new TokenService(sessionStore, "test-secret",
                Duration.ofSeconds(60), Duration.ofSeconds(600), clock);
    }

    @Test
    void refreshSuccessRotatesTokens() {
        TokenPair pair = tokenService.login("alice");
        clock.advance(Duration.ofSeconds(30));

        RefreshResult result = tokenService.refresh(pair.refreshToken());
        log.info("身份=alice 规则=正常续期 结论={}", result);
        assertInstanceOf(RefreshResult.Success.class, result);

        TokenPair newPair = ((RefreshResult.Success) result).tokens();
        assertInstanceOf(AccessCheckResult.Valid.class,
                tokenService.checkAccessToken(newPair.accessToken()));
    }

    @Test
    void tamperedRefreshTokenIsRejected() {
        TokenPair pair = tokenService.login("alice");
        String tampered = pair.refreshToken().substring(0, pair.refreshToken().length() - 2) + "xx";

        RefreshResult result = tokenService.refresh(tampered);
        log.info("身份=alice 规则=篡改刷新令牌 结论={}", result);
        assertEquals(RefreshResult.Failure.TAMPERED, result);
    }

    @Test
    void expiredRefreshTokenIsRejected() {
        TokenPair pair = tokenService.login("alice");
        clock.advance(Duration.ofSeconds(601));

        RefreshResult result = tokenService.refresh(pair.refreshToken());
        log.info("身份=alice 规则=刷新令牌过期 结论={}", result);
        assertEquals(RefreshResult.Failure.EXPIRED, result);
    }

    @Test
    void loggedOutSessionCannotRefresh() {
        TokenPair pair = tokenService.login("alice");
        AccessCheckResult.Valid valid = (AccessCheckResult.Valid)
                tokenService.checkAccessToken(pair.accessToken());
        tokenService.revokeSession(valid.sessionId());

        RefreshResult result = tokenService.refresh(pair.refreshToken());
        log.info("身份=alice 规则=已退出会话续期 结论={}", result);
        assertEquals(RefreshResult.Failure.REVOKED, result);
    }

    @Test
    void reusedRefreshTokenIsDetected() {
        TokenPair pair = tokenService.login("alice");
        RefreshResult first = tokenService.refresh(pair.refreshToken());
        assertInstanceOf(RefreshResult.Success.class, first);

        // 旧刷新令牌再次使用 → 重复使用
        RefreshResult second = tokenService.refresh(pair.refreshToken());
        log.info("身份=alice 规则=重复使用旧刷新令牌 结论={}", second);
        assertEquals(RefreshResult.Failure.REUSED, second);
    }

    @Test
    void concurrentRefreshOnlyOneSucceeds() throws InterruptedException {
        TokenPair pair = tokenService.login("alice");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<RefreshResult> results = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    RefreshResult r = tokenService.refresh(pair.refreshToken());
                    synchronized (results) {
                        results.add(r);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        assertTrue(ready.await(5, TimeUnit.SECONDS));
        go.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        long successes = results.stream().filter(r -> r instanceof RefreshResult.Success).count();
        long reused = results.stream().filter(r -> r == RefreshResult.Failure.REUSED).count();
        log.info("身份=alice 规则={}并发续期 结论=成功{} 重复{}", threads, successes, reused);
        assertEquals(1, successes, "并发续期只能有一个成功");
        assertEquals(threads - 1, reused, "其余必须判定为重复使用");
    }

    @Test
    void multiDeviceSessionsAreIndependent() {
        TokenPair deviceA = tokenService.login("alice");
        TokenPair deviceB = tokenService.login("alice");

        // 设备 A 退出，不影响设备 B
        AccessCheckResult.Valid a = (AccessCheckResult.Valid)
                tokenService.checkAccessToken(deviceA.accessToken());
        tokenService.revokeSession(a.sessionId());

        assertEquals(RefreshResult.Failure.REVOKED, tokenService.refresh(deviceA.refreshToken()));
        RefreshResult bResult = tokenService.refresh(deviceB.refreshToken());
        log.info("身份=alice 规则=多设备互不影响 结论=设备B续期{}", bResult);
        assertInstanceOf(RefreshResult.Success.class, bResult);
    }

    @Test
    void expiredAccessTokenIsDistinguished() {
        TokenPair pair = tokenService.login("alice");
        clock.advance(Duration.ofSeconds(61));
        AccessCheckResult result = tokenService.checkAccessToken(pair.accessToken());
        log.info("身份=alice 规则=访问令牌过期 结论={}", result);
        assertEquals(AccessCheckResult.Invalid.EXPIRED, result);
    }
}
