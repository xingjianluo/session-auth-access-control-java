package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 固定窗口频率限制器，本地内存实现。
 *
 * <p>并发安全：每个 key 的窗口滚动与计数自增都在
 * {@link ConcurrentHashMap#compute} 的原子区间内完成，
 * 并发请求下计数不会丢失也不会翻倍。
 *
 * <p>自动恢复：窗口过期后计数清零，正常用户下一窗口即可继续访问。
 */
@Component
public class RateLimiter {

    private record Window(long windowStartMillis, int count) {
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Clock clock;

    public RateLimiter() {
        this(Clock.systemUTC());
    }

    /** 便于测试注入固定时钟。 */
    public RateLimiter(Clock clock) {
        this.clock = clock;
    }

    /**
     * 尝试为 key 占用一次配额。
     *
     * @return true 表示放行；false 表示本窗口内已超限
     */
    public boolean tryAcquire(String key, int limit, long windowMillis) {
        long now = clock.millis();
        boolean[] allowed = {false};
        windows.compute(key, (k, w) -> {
            if (w == null || now - w.windowStartMillis() >= windowMillis) {
                // 新窗口：自动恢复
                allowed[0] = true;
                return new Window(now, 1);
            }
            if (w.count() < limit) {
                allowed[0] = true;
                return new Window(w.windowStartMillis(), w.count() + 1);
            }
            return w; // 超限：计数不再增长
        });
        return allowed[0];
    }

    /** 当前窗口内已使用的配额（用于观察/测试）。 */
    public int currentCount(String key, long windowMillis) {
        Window w = windows.get(key);
        if (w == null || clock.millis() - w.windowStartMillis() >= windowMillis) {
            return 0;
        }
        return w.count();
    }

    /** 主动清除某个 key 的计数（例如登录成功后清除失败计数）。 */
    public void reset(String key) {
        windows.remove(key);
    }

    /** 清空全部计数（主要用于测试隔离）。 */
    public void clear() {
        windows.clear();
    }
}
