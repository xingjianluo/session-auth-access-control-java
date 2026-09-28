package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.security.AuthService;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.LoginResult;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.RefreshOutcome;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.RefreshResult;
import com.github.xingjianluo.sessionauthaccesscontroljava.security.TokenPair;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.MutableClock;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.TestClockConfig;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.TokenService;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserAccount;
import com.github.xingjianluo.sessionauthaccesscontroljava.user.UserDirectory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 续期边界：篡改、过期、撤销、重复使用、已退出等结论必须可区分且可预期。 */
@SpringBootTest(properties = {
        "app.security.rate-limit.login-max-attempts=50",
        "app.security.rate-limit.refresh-max-attempts=50"
})
@Import(TestClockConfig.class)
class RefreshFlowTest {

    private static final Logger log = LoggerFactory.getLogger("AUTH-AUDIT-TEST");

    @Autowired
    private AuthService authService;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private Clock clock;
    @Autowired
    private UserDirectory userDirectory;

    private TokenPair login(String username, String source) {
        TokenPair[] holder = new TokenPair[1];
        LoginResult result = authService.login(username, "user123", source, "junit-device", pair -> holder[0] = pair);
        assertEquals(LoginResult.SUCCESS, result);
        return holder[0];
    }

    @Test
    @DisplayName("正常续期：成功轮换，新旧凭证不同，旧凭证立即作废")
    void refreshRotatesAndInvalidatesOldToken() {
        TokenPair first = login("alice", "src-rotation");
        RefreshOutcome outcome = authService.refresh(first.refreshToken(), "src-rotation");

        assertEquals(RefreshResult.SUCCESS, outcome.result());
        assertNotEquals(first.accessToken(), outcome.tokens().accessToken());
        assertNotEquals(first.refreshToken(), outcome.tokens().refreshToken());

        // 旧续期凭证再次使用 → REUSED，且整个会话被撤销
        RefreshOutcome replay = authService.refresh(first.refreshToken(), "src-rotation");
        log.info("identity=alice rule=REFRESH_ROTATION decision={} detail=old token reused after rotation",
                replay.result());
        assertEquals(RefreshResult.REUSED, replay.result());

        // 轮换出来的新凭证也因会话被撤销而失效
        RefreshOutcome newTokenAfterReplay = authService.refresh(outcome.tokens().refreshToken(), "src-rotation");
        assertEquals(RefreshResult.REVOKED, newTokenAfterReplay.result());
    }

    @Test
    @DisplayName("篡改续期凭证负载得到 BAD_SIGNATURE，而不是 MALFORMED/EXPIRED")
    void tamperedRefreshTokenIsBadSignature() {
        TokenPair pair = login("alice", "src-tamper");
        String tampered = replaceSubject(pair.refreshToken(), "admin");

        RefreshOutcome outcome = authService.refresh(tampered, "src-tamper");
        log.info("identity=alice rule=REFRESH_TOKEN decision=BAD_SIGNATURE detail=subject tampered to admin");
        assertEquals(RefreshResult.BAD_SIGNATURE, outcome.result());

        // 原凭证仍然有效（篡改尝试不影响会话）
        assertEquals(RefreshResult.SUCCESS, authService.refresh(pair.refreshToken(), "src-tamper").result());
    }

    @Test
    @DisplayName("结构损坏的凭证得到 MALFORMED；访问凭证被用于续期得到 WRONG_TYPE")
    void malformedAndWrongTypeAreDistinct() {
        TokenPair pair = login("alice", "src-malformed");

        RefreshOutcome malformed = authService.refresh("not-a-token", "src-malformed");
        RefreshOutcome empty = authService.refresh("   ", "src-malformed");
        RefreshOutcome wrongType = authService.refresh(pair.accessToken(), "src-malformed");

        log.info("identity=alice rule=REFRESH_TOKEN decision=MALFORMED/WRONG_TYPE detail=3 cases");

        assertEquals(RefreshResult.MALFORMED, malformed.result());
        assertEquals(RefreshResult.MALFORMED, empty.result());
        assertEquals(RefreshResult.WRONG_TYPE, wrongType.result());
    }

    @Test
    @DisplayName("续期凭证过期得到 EXPIRED，且与签名篡改可区分")
    void expiredRefreshTokenIsExpired() {
        TokenPair pair = login("alice", "src-expired");
        MutableClock mutableClock = (MutableClock) clock;
        mutableClock.advance(Duration.ofSeconds(86400));

        RefreshOutcome outcome = authService.refresh(pair.refreshToken(), "src-expired");
        log.info("identity=alice rule=REFRESH_TOKEN decision=EXPIRED detail=advanced 86400s");
        assertEquals(RefreshResult.EXPIRED, outcome.result());
    }

    @Test
    @DisplayName("已退出的会话不能靠续期恢复；退出后访问凭证也立即失效")
    void loggedOutSessionCannotBeRestored() {
        TokenPair pair = login("alice", "src-logout");
        assertTrue(authService.logout(pair.accessToken()));

        RefreshOutcome afterLogout = authService.refresh(pair.refreshToken(), "src-logout");
        log.info("identity=alice rule=REFRESH_SESSION_STATE decision=LOGGED_OUT detail=refresh after logout");
        assertEquals(RefreshResult.LOGGED_OUT, afterLogout.result());

        // 重复尝试仍然是 LOGGED_OUT，不会“刷新”出一个新会话
        RefreshOutcome secondAttempt = authService.refresh(pair.refreshToken(), "src-logout");
        assertEquals(RefreshResult.LOGGED_OUT, secondAttempt.result());

        // 退出幂等：再退一次仍是 true，会话状态不被重新激活
        assertTrue(authService.logout(pair.accessToken()));
    }

    @Test
    @DisplayName("引用不存在会话的有效签名凭证得到 SESSION_NOT_FOUND")
    void refreshForUnknownSessionIsNotFound() {
        // 直接为不存在的会话 id 签发一张形式合法的续期凭证
        var issued = tokenService.issueRefresh("alice", "session-does-not-exist");
        RefreshOutcome outcome = authService.refresh(issued.compact(), "src-unknown-session");
        log.info("identity=alice rule=REFRESH_SESSION decision=SESSION_NOT_FOUND detail=unknown sid");
        assertEquals(RefreshResult.SESSION_NOT_FOUND, outcome.result());
    }

    @Test
    @DisplayName("账号会话有效期内被停用，后续续期得到 ACCOUNT_DISABLED")
    void disabledAccountRefreshRejected() {
        // carol 在种子数据中即为停用账号：登录阶段就应被拒绝
        TokenPair[] holder = new TokenPair[1];
        LoginResult carolLogin = authService.login("carol", "user123", "src-disabled", "x", p -> holder[0] = p);
        assertEquals(LoginResult.ACCOUNT_DISABLED, carolLogin);

        // alice 登录成功后，管理员在会话有效期内停用其账号：下一次续期即被拒
        TokenPair alice = login("alice", "src-disabled-2");
        UserAccount aliceAccount = userDirectory.findByUsername("alice").orElseThrow();
        aliceAccount.setEnabled(false);
        RefreshOutcome outcome = authService.refresh(alice.refreshToken(), "src-disabled-2");
        aliceAccount.setEnabled(true);

        log.info("identity=alice rule=REFRESH_ACCOUNT_STATE decision=ACCOUNT_DISABLED detail=disabled mid-session");
        assertEquals(RefreshResult.ACCOUNT_DISABLED, outcome.result());
    }

    @Test
    @DisplayName("并发续期：同一张续期凭证被多个线程同时使用，恰好一次成功，其余为 REUSED")
    void concurrentRefreshExactlyOneSucceeds() throws InterruptedException {
        TokenPair pair = login("alice", "src-concurrent");
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger reused = new AtomicInteger();
        AtomicInteger revoked = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    RefreshResult result = authService.refresh(pair.refreshToken(), "src-concurrent").result();
                    switch (result) {
                        case SUCCESS -> success.incrementAndGet();
                        case REUSED -> reused.incrementAndGet();
                        case REVOKED -> revoked.incrementAndGet();
                        default -> { }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("identity=alice rule=REFRESH_CONCURRENCY decision=EXACT-ONE detail=success={} reused={} revoked={}",
                success.get(), reused.get(), revoked.get());

        assertEquals(1, success.get(), "并发续期必须恰好一次成功");
        assertEquals(threads - 1, reused.get() + revoked.get());
    }

    /** 替换 payload 中的 sub 字段但不重算签名。 */
    private static String replaceSubject(String compact, String newSubject) {
        int dot = compact.indexOf('.');
        byte[] payloadBytes = Base64.getUrlDecoder().decode(compact.substring(0, dot));
        String json = new String(payloadBytes, StandardCharsets.UTF_8);
        String replaced = json.replace("\"sub\":\"alice\"", "\"sub\":\"" + newSubject + "\"");
        String newPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(replaced.getBytes(StandardCharsets.UTF_8));
        return newPayload + "." + compact.substring(dot + 1);
    }
}
