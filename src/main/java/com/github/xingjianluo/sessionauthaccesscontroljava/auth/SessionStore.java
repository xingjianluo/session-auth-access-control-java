package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地内存会话存储。每个会话对应一次登录（一个设备），
 * 同一账号可以同时存在多个会话（多设备登录）。
 */
@Component
public class SessionStore {

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public void save(Session session) {
        sessions.put(session.sessionId(), session);
    }

    public Session find(String sessionId) {
        return sessions.get(sessionId);
    }

    public List<Session> findByUsername(String username) {
        return sessions.values().stream()
                .filter(s -> s.username().equals(username))
                .toList();
    }

    /** 撤销会话（退出登录）。撤销后该会话的刷新令牌不再可用。 */
    public void revoke(String sessionId) {
        sessions.computeIfPresent(sessionId, (id, s) -> new Session(
                s.sessionId(), s.username(), s.createdAt(), s.refreshExpiresAt(),
                s.currentRefreshTokenHash(), true));
    }

    /**
     * 原子地比较并轮换刷新令牌：仅当会话当前认可的哈希与 expectedHash 一致时才替换。
     * 保证并发续期时只有一个请求能成功，其余会被识别为“重复使用”。
     *
     * @return true 表示轮换成功；false 表示哈希不匹配（旧令牌/重放）
     */
    public boolean compareAndRotateRefresh(String sessionId, String expectedHash, String newHash) {
        boolean[] ok = {false};
        sessions.computeIfPresent(sessionId, (id, s) -> {
            if (!s.revoked() && s.currentRefreshTokenHash().equals(expectedHash)) {
                ok[0] = true;
                return new Session(s.sessionId(), s.username(), s.createdAt(),
                        s.refreshExpiresAt(), newHash, false);
            }
            return s;
        });
        return ok[0];
    }
}
