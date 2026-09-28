package com.github.xingjianluo.sessionauthaccesscontroljava.ratelimit;

import java.time.Clock;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 固定窗口计数器。
 *
 * <p>并发正确性：每个 key 对应一个 {@link Counter}，计数自增在 Counter 内置锁内
 * “读窗口→判定→自增”一次完成，因此并发请求既不会丢失计数（check-then-act 竞态），
 * 也不会翻倍。窗口内恰好放行 {@code maxAttempts} 次，第 {@code maxAttempts+1} 次起拒绝。
 *
 * <p>自动恢复：当前时间越过窗口起点 + 窗口长度后，下一次操作自动开启新窗口并从 1 计数，
 * 无需外部调度，被限流的来源稍后即可自行恢复。
 *
 * <p>内存治理：过期键在周期性扫描中被惰性淘汰，避免长期运行后无限增长。
 */
public class FixedWindowRateLimiter {

    private final int maxAttempts;
    private final long windowSeconds;
    private final Clock clock;
    private final ConcurrentHashMap<String, Counter> counters = new ConcurrentHashMap<>();
    private final AtomicLong operations = new AtomicLong();

    /** 每处理若干次操作触发一次过期键清理。 */
    private static final long CLEANUP_INTERVAL = 64;

    public FixedWindowRateLimiter(int maxAttempts, long windowSeconds, Clock clock) {
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("maxAttempts must be positive");
        }
        if (windowSeconds <= 0) {
            throw new IllegalArgumentException("windowSeconds must be positive");
        }
        this.maxAttempts = maxAttempts;
        this.windowSeconds = windowSeconds;
        this.clock = clock;
    }

    /**
     * 对 key 记一次操作。窗口内第 1..maxAttempts 次为 {@link RateLimitDecision#ALLOWED}，
     * 之后为 {@link RateLimitDecision#REJECTED}。
     */
    public RateLimitDecision checkAndIncrement(String key) {
        long now = clock.instant().getEpochSecond();
        Counter counter = counters.computeIfAbsent(key, k -> new Counter(now));
        RateLimitDecision decision;
        synchronized (counter) {
            if (now - counter.windowStart >= windowSeconds) {
                // 进入新窗口：旧计数作废，自动恢复
                counter.windowStart = now;
                counter.count = 0;
            }
            counter.count++;
            decision = counter.count <= maxAttempts ? RateLimitDecision.ALLOWED : RateLimitDecision.REJECTED;
        }
        maybeCleanup(now);
        return decision;
    }

    /** 重置 key 的计数（登录成功时调用，避免正常用户被历史失败拖累）。 */
    public void reset(String key) {
        if (key != null) {
            counters.remove(key);
        }
    }

    /** 当前窗口剩余可放行次数（便于日志与测试观察）。 */
    public int remaining(String key) {
        long now = clock.instant().getEpochSecond();
        Counter counter = key == null ? null : counters.get(key);
        if (counter == null) {
            return maxAttempts;
        }
        synchronized (counter) {
            if (now - counter.windowStart >= windowSeconds) {
                return maxAttempts;
            }
            return Math.max(0, maxAttempts - counter.count);
        }
    }

    /** 仅供测试 / 日志观察：当前活跃键数量。 */
    public int activeKeys() {
        return counters.size();
    }

    private void maybeCleanup(long now) {
        if (operations.incrementAndGet() % CLEANUP_INTERVAL != 0) {
            return;
        }
        for (Iterator<Map.Entry<String, Counter>> it = counters.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Counter> entry = it.next();
            Counter counter = entry.getValue();
            synchronized (counter) {
                if (now - counter.windowStart >= windowSeconds) {
                    it.remove();
                }
            }
        }
    }

    /** 单个 key 的窗口计数；所有读写都在 this 锁内完成。 */
    private static final class Counter {
        private long windowStart;
        private int count;

        private Counter(long windowStart) {
            this.windowStart = windowStart;
            this.count = 0;
        }
    }
}
