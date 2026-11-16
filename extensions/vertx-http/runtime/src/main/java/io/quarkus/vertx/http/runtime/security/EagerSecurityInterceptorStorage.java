package io.quarkus.vertx.http.runtime.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import io.quarkus.security.spi.runtime.MethodDescription;
import io.vertx.ext.web.RoutingContext;

/**
 * Security interceptors run for desired annotated methods prior to security checks.
 * Interceptors should only be run when proactive security is disabled, because
 * they must be run before request is authenticated.
 * <p>
 * These interceptors are very important when {@link io.quarkus.security.spi.runtime.SecurityCheck}s are not run
 * with CDI interceptors, because they provide only way to link request to invoked method prior to checks.
 */
public class EagerSecurityInterceptorStorage {

    private final Map<MethodDescription, Consumer<RoutingContext>> methodToInterceptor;
    private final Map<String, Consumer<RoutingContext>> classNameToInterceptor;

    EagerSecurityInterceptorStorage(
            Map<MethodDescription, Consumer<RoutingContext>> methodToInterceptor,
            Map<String, Consumer<RoutingContext>> classNameToInterceptor) {
        this.methodToInterceptor = methodToInterceptor.isEmpty() ? Map.of() : Map.copyOf(methodToInterceptor);
        this.classNameToInterceptor = classNameToInterceptor.isEmpty() ? Map.of() : Map.copyOf(classNameToInterceptor);
    }

    public static EagerSecurityInterceptorStorage create(List<InterceptedMethod> interceptedMethods,
            Map<String, Consumer<RoutingContext>> classNameToInterceptor) {
        final Map<MethodDescription, Consumer<RoutingContext>> methodToInterceptor = new HashMap<>();
        for (InterceptedMethod method : interceptedMethods) {
            var methodDescription = new MethodDescription(method.className(), method.methodName(),
                    method.parameterTypes().toArray(new String[0]));
            methodToInterceptor.put(methodDescription, method.interceptor());
        }
        return new EagerSecurityInterceptorStorage(methodToInterceptor, classNameToInterceptor);
    }

    /**
     * This method should be invoked prior to any security check is run if proactive auth is disabled.
     *
     * @param endpoint with security annotation
     * @return return security interceptor
     */
    public Consumer<RoutingContext> getInterceptor(MethodDescription endpoint) {
        return methodToInterceptor.get(endpoint);
    }

    /**
     * This method should be invoked prior to any security check is run if proactive auth is disabled.
     * Class-level security interceptors are applied when security is applied once per class, for example per HTTP upgrade.
     *
     * @param className with security annotation
     * @return return class security interceptor
     */
    public Consumer<RoutingContext> getClassInterceptor(String className) {
        return classNameToInterceptor.get(className);
    }

    public record InterceptedMethod(String className, String methodName, List<String> parameterTypes,
            Consumer<RoutingContext> interceptor) {

        public InterceptedMethod {
            parameterTypes = List.copyOf(parameterTypes);
        }
    }

    public record CompoundInterceptor(Consumer<RoutingContext> interceptor1,
            Consumer<RoutingContext> interceptor2) implements Consumer<RoutingContext> {

        @Override
        public void accept(RoutingContext routingContext) {
            interceptor1.accept(routingContext);
            interceptor2.accept(routingContext);
        }
    }
}
