package io.quarkus.oidc.client.runtime;

import java.lang.reflect.Method;

public record MethodDescription(String className, String methodName, String[] parameterTypes) {

    public static MethodDescription ofMethod(Method method) {
        return new MethodDescription(method.getDeclaringClass().getName(), method.getName(),
                typesAsStrings(method.getParameterTypes()));
    }

    private static String[] typesAsStrings(Class<?>[] parameterTypes) {
        String[] result = new String[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            result[i] = parameterTypes[i].getName();
        }
        return result;
    }
}
