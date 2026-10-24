package io.quarkus.oidc.runtime;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.EnumSet;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.quarkus.oidc.OidcTenantConfig;

public class OidcTenantConfigTest {

    @Test
    public void testCopyBetweenConfigMappingAndClass() throws Exception {
        var configMappingGroup = new OidcTenantConfigImpl();
        var config = OidcTenantConfig.builder(configMappingGroup).tenantId("tested-later").build();
        // the class delegates to config groups of the interface, so their properties are read through the class
        readProperties(config, io.quarkus.oidc.runtime.OidcTenantConfig.class);
        for (var configMappingMethod : EnumSet.allOf(OidcTenantConfigImpl.ConfigMappingMethods.class)) {
            Boolean invoked = configMappingGroup.invocationsRecorder.get(configMappingMethod);
            assertTrue(invoked != null && invoked,
                    "OidcTenantConfig method '%s' return value is not copied from interface to class"
                            .formatted(configMappingMethod));
        }
    }

    private static void readProperties(Object configGroup, Class<?> configGroupType) throws Exception {
        for (Method method : configGroupType.getMethods()) {
            if (method.isDefault() || Modifier.isStatic(method.getModifiers()) || method.getParameterCount() > 0) {
                continue;
            }
            Object value = method.invoke(configGroup);
            Type type = method.getGenericReturnType();
            if (value instanceof Optional<?> optional && type instanceof ParameterizedType parameterizedType) {
                value = optional.orElse(null);
                type = parameterizedType.getActualTypeArguments()[0];
            }
            if (value != null && type instanceof Class<?> nestedGroupType && nestedGroupType.isInterface()
                    && nestedGroupType.getName().startsWith("io.quarkus.oidc")) {
                readProperties(value, nestedGroupType);
            }
        }
    }
}
