package com.github.xingjianluo.sessionauthaccesscontroljava.token;

/** 凭证校验结果：状态 + 解析出的声明（失败时为 null）。 */
public record Verification(VerificationStatus status, TokenClaims claims) {

    public static Verification invalid(VerificationStatus status) {
        return new Verification(status, null);
    }

    public static Verification ok(TokenClaims claims) {
        return new Verification(VerificationStatus.OK, claims);
    }

    public boolean isOk() {
        return status == VerificationStatus.OK;
    }
}
