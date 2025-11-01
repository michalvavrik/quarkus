package io.quarkus.vertx.http.deployment;

import java.util.Collection;
import java.util.Optional;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.MethodInfo;

import io.quarkus.security.spi.SecurityTransformerHelper;
import io.quarkus.security.spi.SecurityTransformerHelperBuildItem;
import io.quarkus.security.spi.SecurityTransformerUtils;
import io.quarkus.vertx.http.security.AuthorizationPolicy;

/**
 * @deprecated this transformer does not reflect annotation transformations, use the {@link SecurityTransformerHelper}
 *             helper produced by the {@link SecurityTransformerHelperBuildItem} build item
 */
@Deprecated(since = "3.30", forRemoval = true)
public final class HttpSecurityUtils {

    static final DotName AUTHORIZATION_POLICY = DotName.createSimple(AuthorizationPolicy.class);

    private HttpSecurityUtils() {
        // deployment module security utility class
    }

    public static boolean hasAuthorizationPolicyAnnotation(MethodInfo methodInfo) {
        return findAuthorizationPolicyAnnotation(methodInfo.annotations()).isPresent();
    }

    public static boolean hasAuthorizationPolicyAnnotation(ClassInfo classInfo) {
        return findAuthorizationPolicyAnnotation(classInfo.declaredAnnotations()).isPresent();
    }

    public static boolean hasSecurityAnnotation(MethodInfo methodInfo) {
        return SecurityTransformerUtils.hasSecurityAnnotation(methodInfo) || hasAuthorizationPolicyAnnotation(methodInfo);
    }

    public static boolean hasSecurityAnnotation(ClassInfo classInfo) {
        return SecurityTransformerUtils.hasSecurityAnnotation(classInfo) || hasAuthorizationPolicyAnnotation(classInfo);
    }

    static Optional<AnnotationInstance> findAuthorizationPolicyAnnotation(Collection<AnnotationInstance> instances) {
        return instances.stream().filter(ai -> ai.name().equals(AUTHORIZATION_POLICY)).findFirst();
    }
}
