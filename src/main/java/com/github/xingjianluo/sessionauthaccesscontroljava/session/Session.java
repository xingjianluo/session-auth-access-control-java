package com.github.xingjianluo.sessionauthaccesscontroljava.session;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * 一次设备登录对应一个会话。多设备登录即同一账号存在多个 ACTIVE 会话。
 * 会话只保存续期凭证的轮换状态，访问凭证保持无状态。
 */
public class Session {

    private String id;
    private String username;
    private String deviceLabel;
    private Instant createdAt;
    private SessionState state = SessionState.ACTIVE;
    private String currentRefreshJti;
    private Instant refreshExpiresAt;
    private final Set<String> usedRefreshJtis = new HashSet<>();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getDeviceLabel() { return deviceLabel; }
    public void setDeviceLabel(String deviceLabel) { this.deviceLabel = deviceLabel; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public SessionState getState() { return state; }
    public void setState(SessionState state) { this.state = state; }

    public String getCurrentRefreshJti() { return currentRefreshJti; }
    public void setCurrentRefreshJti(String currentRefreshJti) { this.currentRefreshJti = currentRefreshJti; }

    public Instant getRefreshExpiresAt() { return refreshExpiresAt; }
    public void setRefreshExpiresAt(Instant refreshExpiresAt) { this.refreshExpiresAt = refreshExpiresAt; }

    public Set<String> getUsedRefreshJtis() { return usedRefreshJtis; }
}
