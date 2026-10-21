package io.quarkus.security.runtime.interceptor.check;

import java.util.List;

import io.quarkus.security.spi.runtime.MethodDescription;
import io.quarkus.security.spi.runtime.SecurityCheck;

/**
 * Naming scheme of the {@link SecurityCheck} services.
 * <p>
 * A {@link SecurityCheck} registered as a service with a method name (see {@link #forMethod(String, String, List)})
 * is applied to that method by the {@link io.quarkus.security.spi.runtime.SecurityCheckStorage}; this is the way
 * other extensions contribute security checks for methods they secure. Class-level checks are registered with
 * a class name (see {@link #forClass(String)}).
 */
public final class SecurityCheckServiceName {

    private static final String CLASS_PREFIX = "class:";

    private SecurityCheckServiceName() {
    }

    public static String forMethod(String className, String methodName, List<String> parameterTypes) {
        return className + "#" + methodName + "(" + String.join(",", parameterTypes) + ")";
    }

    public static String forClass(String className) {
        return CLASS_PREFIX + className;
    }

    /**
     * @return the method described by a service name created with {@link #forMethod(String, String, List)},
     *         or {@code null} if the service name does not describe a method
     */
    public static MethodDescription parseMethod(String serviceName) {
        int hash = serviceName.indexOf('#');
        if (hash <= 0 || !serviceName.endsWith(")")) {
            return null;
        }
        int paren = serviceName.indexOf('(', hash);
        if (paren < 0) {
            return null;
        }
        String className = serviceName.substring(0, hash);
        String methodName = serviceName.substring(hash + 1, paren);
        String parameters = serviceName.substring(paren + 1, serviceName.length() - 1);
        String[] parameterTypes = parameters.isEmpty() ? new String[0] : parameters.split(",");
        return new MethodDescription(className, methodName, parameterTypes);
    }
}
