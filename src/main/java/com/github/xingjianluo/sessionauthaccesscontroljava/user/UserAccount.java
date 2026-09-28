package com.github.xingjianluo.sessionauthaccesscontroljava.user;

import java.util.EnumSet;
import java.util.Set;

/** 用户账号。密码仅做本地演示，不依赖真实凭据体系。 */
public class UserAccount {

    private String username;
    private String password;
    private volatile Set<Role> roles = EnumSet.noneOf(Role.class);
    private volatile boolean enabled = true;

    public UserAccount() {
    }

    public UserAccount(String username, String password, Set<Role> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
}
