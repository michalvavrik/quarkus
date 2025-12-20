package io.quarkus.scheduler.test.security;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.maven.dependency.Dependency;
import io.quarkus.scheduler.Scheduled;
import io.quarkus.security.Authenticated;
import io.quarkus.security.ForbiddenException;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.RunAsUser;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;

class RunAsUserScheduledTest {

    private static final String UNAUTHENTICATED_SCHEDULER = "unauthenticated";
    private static final String AUTHENTICATED_SCHEDULER = "authenticated";
    private static final String FORBIDDEN_SCHEDULER = "forbidden";
    private static final String AUTHORIZED_SCHEDULER = "authorized";

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar.addClasses(Scheduler.class, SecuredBean.class))
            .setForcedDependencies(List.of(Dependency.of("io.quarkus", "quarkus-security")));

    @Inject
    Scheduler scheduler;

    @Test
    void testRunAsUserAnnotation() throws InterruptedException {
        for (var e : scheduler.getLatchMap().entrySet()) {
            var latchKey = e.getKey();
            var latch = e.getValue();
            var result = latch.await(5, TimeUnit.SECONDS);
            assertTrue(result, () -> "Latch " + latchKey + " did not count down in time");
            var failure = scheduler.getLatchKeyToFailure().get(latchKey);
            assertNull(failure, () -> "Test for latch '" + latchKey + "' failed over: " + failure);
        }
    }

    @ApplicationScoped
    static class Scheduler {

        private final Map<String, CountDownLatch> latchMap;
        private final Map<String, Throwable> latchKeyToFailure;
        private final SecuredBean securedBean;

        Scheduler(SecuredBean securedBean) {
            this.latchKeyToFailure = new ConcurrentHashMap<>();
            this.latchMap = Map.of(
                    UNAUTHENTICATED_SCHEDULER, new CountDownLatch(2),
                    FORBIDDEN_SCHEDULER, new CountDownLatch(2),
                    AUTHORIZED_SCHEDULER, new CountDownLatch(2),
                    AUTHENTICATED_SCHEDULER, new CountDownLatch(2));
            this.securedBean = securedBean;
        }

        @Scheduled(every = "1s")
        void noRunAsUserAnnotation() {
            runTest(UNAUTHENTICATED_SCHEDULER, () -> {
                try {
                    securedBean.authenticated();
                } catch (UnauthorizedException ignored) {
                    return;
                }
                throw new AssertionError("Authorization should fail for scheduled method 'noRunAsUserAnnotation'");
            });
        }

        @RunAsUser(user = "Quentin")
        @Scheduled(every = "1s")
        void runAsUserAnnotationWithVoidReturnType() {
            runTest(AUTHENTICATED_SCHEDULER, () -> {
                try {
                    securedBean.authenticated();
                } catch (UnauthorizedException exception) {
                    throw new AssertionError(
                            "Authorization should not fail for scheduled method 'runAsUserAnnotationWithVoidReturnType'",
                            exception);
                }
            });
        }

        @RunAsUser(user = "Julia", roles = "user")
        @Scheduled(every = "1s")
        Uni<Void> runAsUserAnnotationWithUniReturnType() {
            return Uni.createFrom().item(() -> {
                runTest(FORBIDDEN_SCHEDULER, () -> {
                    try {
                        securedBean.rolesAllowedAdmin();
                    } catch (ForbiddenException exception) {
                        return;
                    }
                    throw new AssertionError(
                            "Authorization should fail for scheduled method 'runAsUserAnnotationWithUniReturnType'");
                });
                return null;
            });
        }

        @RunAsUser(user = "Alice", roles = "admin")
        @Scheduled(every = "1s")
        CompletionStage<Void> runAsUserAnnotationWithCompletionStageReturnType() {
            return Uni.createFrom().<Void> item(() -> {
                runTest(AUTHORIZED_SCHEDULER, () -> {
                    try {
                        securedBean.rolesAllowedAdmin();
                    } catch (ForbiddenException exception) {
                        throw new AssertionError(
                                "Authorization should not fail for scheduled method 'runAsUserAnnotationWithCompletionStageReturnType'",
                                exception);
                    }
                });
                return null;
            }).subscribeAsCompletionStage();
        }

        private void runTest(String latchKey, Runnable test) {
            try {
                test.run();
            } catch (Throwable failure) {
                latchKeyToFailure.put(latchKey, failure);
            }
            latchMap.get(latchKey).countDown();
        }

        Map<String, CountDownLatch> getLatchMap() {
            return latchMap;
        }

        Map<String, Throwable> getLatchKeyToFailure() {
            return latchKeyToFailure;
        }
    }

    @ApplicationScoped
    static class SecuredBean {

        @Authenticated
        void authenticated() {

        }

        @RolesAllowed("admin")
        void rolesAllowedAdmin() {

        }

    }

}
