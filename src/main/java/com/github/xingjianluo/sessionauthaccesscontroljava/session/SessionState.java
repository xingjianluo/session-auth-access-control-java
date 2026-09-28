package com.github.xingjianluo.sessionauthaccesscontroljava.session;

/** 会话状态。退出 / 被撤销后不可恢复。 */
public enum SessionState {
    /** 活跃。 */
    ACTIVE,
    /** 用户主动退出。 */
    LOGGED_OUT,
    /** 检测到续期凭证重放，安全侧撤销。 */
    REVOKED
}
