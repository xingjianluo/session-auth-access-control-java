package com.github.xingjianluo.sessionauthaccesscontroljava.session;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话存储：本地内存实现，线程安全。
 *
 * <p>多设备登录时同一账号的每个设备各持有一个独立会话 id；会话对象内的
 * 续期轮换状态（当前 jti、已用 jti、退出标记）通过会话自身的锁保护，
 * 保证并发续期 / 退出时结论可预期。
 */
@Component
public class SessionStore {

    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();

    /** 创建或覆盖保存会话。 */
    public void save(Session session) {
        sessions.put(session.getId(), session);
    }

    /** 按会话 id 查找。 */
    public Optional<Session> findById(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.get(sessionId));
    }
}
