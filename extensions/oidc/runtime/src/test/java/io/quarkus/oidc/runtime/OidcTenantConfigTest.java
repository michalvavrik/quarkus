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
    public void testConfigMappingValuesAreNotLost() throws Exception {
        var configMapping = new OidcTenantConfigImpl();
        // the builder copies the root properties and shares the configuration groups with the config mapping
        OidcTenantConfig config = OidcTenantConfig.builder(configMapping).tenantId("tested-later").build();
        // every value of the built configuration must come from the config mapping
        readEveryValue(config, io.quarkus.oidc.runtime.OidcTenantConfig.class);
        for (var configMappingMethod : EnumSet.allOf(OidcTenantConfigImpl.ConfigMappingMethods.class)) {
            Boolean invoked = configMapping.invocationsRecorder.get(configMappingMethod);
            assertTrue(invoked != null && invoked,
                    "OidcTenantConfig method '%s' return value is not copied from the config mapping to the built config"
                            .formatted(configMappingMethod));
        }
    }

    private static void readEveryValue(Object config, Class<?> configType) throws Exception {
        for (Method method : configType.getMethods()) {
            if (method.getParameterCount() != 0 || Modifier.isStatic(method.getModifiers())) {
                continue;
            }
            Object value = method.invoke(config);
            Type valueType = method.getGenericReturnType();
            if (value instanceof Optional<?> optionalValue) {
                if (optionalValue.isEmpty()) {
                    continue;
                }
                value = optionalValue.get();
                valueType = ((ParameterizedType) valueType).getActualTypeArguments()[0];
            }
            if (value != null && valueType instanceof Class<?> valueClass && isConfigGroup(valueClass)) {
                readEveryValue(value, valueClass);
            }
        }
    }

    private static boolean isConfigGroup(Class<?> type) {
        return type.isInterface() && type.getPackageName().startsWith("io.quarkus.oidc");
    }

}
