package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地内存用户库：不依赖任何外部中间件。
 * 角色随时可以调整，后续请求会读取到最新的角色集合。
 */
@Component
public class UserStore {

    private record Account(String username, String password, Set<Role> roles) {
    }

    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    public UserStore() {
        accounts.put("alice", new Account("alice", "alice-pwd", ConcurrentHashMap.newKeySet()));
        accounts.put("bob", new Account("bob", "bob-pwd", ConcurrentHashMap.newKeySet()));
        accounts.put("admin", new Account("admin", "admin-pwd", ConcurrentHashMap.newKeySet()));
        // 初始化默认角色（ConcurrentHashMap.newKeySet 支持后续在线调整）
        getRoles("alice").add(Role.USER);
        getRoles("bob").add(Role.USER);
        getRoles("admin").add(Role.USER);
        getRoles("admin").add(Role.ADMIN);
    }

    public UserRecord findByUsername(String username) {
        Account a = accounts.get(username);
        if (a == null) {
            return null;
        }
        synchronized (a.roles()) {
            return new UserRecord(a.username(), Set.copyOf(a.roles()));
        }
    }

    public boolean checkPassword(String username, String rawPassword) {
        Account a = accounts.get(username);
        return a != null && a.password().equals(rawPassword);
    }

    public boolean exists(String username) {
        return accounts.containsKey(username);
    }

    /** 返回的是实时角色集合，直接反映 {@link #updateRoles} 的调整。 */
    public Set<Role> getRoles(String username) {
        Account a = accounts.get(username);
        return a == null ? Set.of() : a.roles();
    }

    public record UserRecord(String username, Set<Role> roles) {
    }

    public void updateRoles(String username, Set<Role> roles) {
        Account a = accounts.get(username);
        if (a == null) {
            throw new IllegalArgumentException("用户不存在: " + username);
        }
        synchronized (a.roles()) {
            a.roles().clear();
            a.roles().addAll(roles);
        }
    }
}
