package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.ratelimit.FixedWindowRateLimiter;
import com.github.xingjianluo.sessionauthaccesscontroljava.ratelimit.RateLimitDecision;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.MutableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 频率限制器：边界计数、窗口恢复、并发准确性、不同来源互不影响。 */
class FixedWindowRateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger("AUTH-AUDIT-TEST");

    private MutableClock clock() {
        return new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    }

    @Test
    @DisplayName("边界：窗口内恰好放行 maxAttempts 次，第 maxAttempts+1 次起拒绝，剩余计数正确")
    void boundaryAllowsExactlyMaxAttempts() {
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(5, 60, clock());

        for (int i = 1; i <= 5; i++) {
            RateLimitDecision decision = limiter.checkAndIncrement("user-1");
            assertEquals(RateLimitDecision.ALLOWED, decision, "第 " + i + " 次应放行");
        }
        RateLimitDecision sixth = limiter.checkAndIncrement("user-1");
        RateLimitDecision seventh = limiter.checkAndIncrement("user-1");

        log.info("identity=user-1 rule=RATE_LIMIT_BOUNDARY decision=ALLOWEDx5/REJECTEDx2 detail=remaining={}",
                limiter.remaining("user-1"));

        assertEquals(RateLimitDecision.REJECTED, sixth);
        assertEquals(RateLimitDecision.REJECTED, seventh);
        assertEquals(0, limiter.remaining("user-1"));
    }

    @Test
    @DisplayName("自动恢复：越过窗口后计数清零，被限流来源可以再次访问")
    void windowRollsOverAndRecovers() {
        MutableClock clock = clock();
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(3, 60, clock);

        for (int i = 0; i < 3; i++) {
            assertEquals(RateLimitDecision.ALLOWED, limiter.checkAndIncrement("src-1"));
        }
        assertEquals(RateLimitDecision.REJECTED, limiter.checkAndIncrement("src-1"), "窗口内应被限流");

        clock.advance(Duration.ofSeconds(60));
        RateLimitDecision afterWindow = limiter.checkAndIncrement("src-1");

        log.info("identity=src-1 rule=RATE_LIMIT_WINDOW decision=RECOVERED detail=after 60s remaining={}",
                limiter.remaining("src-1"));

        assertEquals(RateLimitDecision.ALLOWED, afterWindow);
        assertEquals(2, limiter.remaining("src-1"));
    }

    @Test
    @DisplayName("并发计数不丢失也不翻倍：100 个并发请求恰好放行 maxAttempts 个")
    void concurrentCountingIsExact() throws InterruptedException {
        int maxAttempts = 25;
        int threads = 100;
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(maxAttempts, 60, clock());

        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (limiter.checkAndIncrement("hot-key") == RateLimitDecision.ALLOWED) {
                        allowed.incrementAndGet();
                    } else {
                        rejected.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("identity=hot-key rule=RATE_LIMIT_CONCURRENCY decision=EXACT detail=threads={} allowed={} rejected={}",
                threads, allowed.get(), rejected.get());

        assertEquals(maxAttempts, allowed.get(), "并发下放行数量必须精确等于阈值，不能多也不能少");
        assertEquals(threads - maxAttempts, rejected.get());
        assertEquals(0, limiter.remaining("hot-key"));
    }

    @Test
    @DisplayName("reset 清零该键计数：模拟登录成功后正常用户不再被历史失败计数影响")
    void resetClearsCount() {
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(5, 60, clock());
        for (int i = 0; i < 4; i++) {
            limiter.checkAndIncrement("alice");
        }
        limiter.reset("alice");
        assertEquals(5, limiter.remaining("alice"));
        for (int i = 0; i < 5; i++) {
            assertEquals(RateLimitDecision.ALLOWED, limiter.checkAndIncrement("alice"));
        }
        log.info("identity=alice rule=RATE_LIMIT_RESET decision=ALLOWED detail=counter cleared after success");
    }

    @Test
    @DisplayName("不同 key 互不影响：一个来源被限流，其他来源保持正常（正常用户不误伤）")
    void keysAreIsolated() {
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(2, 60, clock());
        limiter.checkAndIncrement("attacker");
        limiter.checkAndIncrement("attacker");
        assertEquals(RateLimitDecision.REJECTED, limiter.checkAndIncrement("attacker"));

        assertEquals(RateLimitDecision.ALLOWED, limiter.checkAndIncrement("normal-user"));
        assertEquals(RateLimitDecision.ALLOWED, limiter.checkAndIncrement("normal-user"));
        log.info("identity=normal-user rule=RATE_LIMIT_ISOLATION decision=ALLOWED detail=attacker blocked, normal unaffected");
    }

    @Test
    @DisplayName("空闲键被惰性清理，限流器不会无限增长")
    void idleKeysAreEvicted() {
        MutableClock clock = clock();
        FixedWindowRateLimiter limiter = new FixedWindowRateLimiter(1, 5, clock);
        for (int i = 0; i < 100; i++) {
            limiter.checkAndIncrement("key-" + i);
        }
        clock.advance(Duration.ofSeconds(10));
        // 再来一批操作触发清理
        for (int i = 0; i < 200; i++) {
            limiter.checkAndIncrement("new-key-" + i);
        }
        log.info("identity=* rule=RATE_LIMIT_EVICTION decision=CLEANED detail=activeKeys={}",
                limiter.activeKeys());
        // 100 个旧键全部过期，新键不超过 200
        assertTrue(limiter.activeKeys() <= 200, "过期键应被清理，实际活跃键数=" + limiter.activeKeys());
    }
}
