package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.auth.RateLimiter;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterTest.class);

    @Test
    void limitIsEnforcedAndAutoRecovers() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        RateLimiter limiter = new RateLimiter(clock);
        String key = "login-fail:acct:alice";
        int limit = 5;
        long window = 60_000;

        for (int i = 1; i <= limit; i++) {
            assertTrue(limiter.tryAcquire(key, limit, window), "第" + i + "次应放行");
        }
        assertFalse(limiter.tryAcquire(key, limit, window), "超限后应拒绝");
        log.info("身份=alice 规则=窗口内第{}次请求 结论=拒绝(超限)", limit + 1);

        // 窗口过期后自动恢复
        clock.advance(Duration.ofMillis(window + 1));
        assertTrue(limiter.tryAcquire(key, limit, window), "窗口过期后应自动恢复");
        log.info("身份=alice 规则=窗口过期后请求 结论=放行(自动恢复)");
    }

    @Test
    void keysAreIndependent() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        RateLimiter limiter = new RateLimiter(clock);
        for (int i = 0; i < 5; i++) {
            limiter.tryAcquire("acct:alice", 5, 60_000);
        }
        assertFalse(limiter.tryAcquire("acct:alice", 5, 60_000));
        // 正常用户 bob 不被误伤
        assertTrue(limiter.tryAcquire("acct:bob", 5, 60_000));
        log.info("身份=bob 规则=他人超限 结论=放行(互不影响)");
    }

    @Test
    void concurrentCountingIsExact() throws InterruptedException {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-28T00:00:00Z"));
        RateLimiter limiter = new RateLimiter(clock);
        String key = "refresh:src:10.0.0.1";
        int limit = 100;
        int threads = 32;
        int perThread = 10; // 共 320 次请求，限额 100

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    for (int j = 0; j < perThread; j++) {
                        if (limiter.tryAcquire(key, limit, 60_000)) {
                            allowed.incrementAndGet();
                        }
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

        log.info("身份=src:10.0.0.1 规则={}线程×{}次并发 限额={} 结论=放行{}次",
                threads, perThread, limit, allowed.get());
        assertEquals(limit, allowed.get(), "并发下放行数必须恰好等于限额，不丢不超");
        assertEquals(limit, limiter.currentCount(key, 60_000));
    }
}
