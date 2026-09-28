package com.github.xingjianluo.sessionauthaccesscontroljava.user;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地用户目录：内存存储，启动时写入演示账号，角色调整后访问判定立即生效。
 *
 * <p>角色不写入访问凭证，而是每次请求实时从这里读取：
 * {@link #replaceRoles} 以“整体替换”方式发布新角色集合（volatile 写），
 * 之后到达的请求一定看到最新角色，不会出现旧权限继续放行或新权限不生效。
 */
@Component
public class UserDirectory {

    private final ConcurrentHashMap<String, UserAccount> accounts = new ConcurrentHashMap<>();

    @PostConstruct
    public void seed() {
        put(new UserAccount("admin", "admin123", EnumSet.of(Role.ADMIN, Role.USER)));
        put(new UserAccount("alice", "user123", EnumSet.of(Role.USER)));
        put(new UserAccount("bob", "user123", EnumSet.of(Role.USER)));
        UserAccount disabled = new UserAccount("carol", "user123", EnumSet.of(Role.USER));
        disabled.setEnabled(false);
        put(disabled);
    }

    private void put(UserAccount account) {
        accounts.put(account.getUsername(), account);
    }

    /** 注册新账号（已存在则覆盖）。演示与测试使用。 */
    public void register(UserAccount account) {
        put(account);
    }

    public Optional<UserAccount> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(accounts.get(username));
    }

    /** 用新角色集合整体替换账号当前角色。账号不存在时抛出异常。 */
    public void replaceRoles(String username, List<Role> roles) {
        UserAccount account = accounts.get(username);
        if (account == null) {
            throw new IllegalArgumentException("user not found: " + username);
        }
        Set<Role> snapshot = roles == null || roles.isEmpty()
                ? Collections.emptySet()
                : Collections.unmodifiableSet(EnumSet.copyOf(roles));
        // volatile 写：下一次请求读取时立即看到新集合
        account.setRoles(snapshot);
    }
}
