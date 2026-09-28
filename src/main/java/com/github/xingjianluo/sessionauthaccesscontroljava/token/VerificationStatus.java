package com.github.xingjianluo.sessionauthaccesscontroljava.token;

/**
 * 凭证本身的校验结论。会话级别的结论（已撤销 / 重复使用 / 已退出）
 * 由会话存储在编排层另行判定。
 */
public enum VerificationStatus {
    OK,
    MALFORMED,
    BAD_SIGNATURE,
    EXPIRED,
    WRONG_TYPE
}
