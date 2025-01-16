package io.quarkus.test.oidc.client;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import io.quarkus.test.junit.callback.QuarkusTestAfterAllCallback;
import io.quarkus.test.junit.callback.QuarkusTestAfterConstructCallback;
import io.quarkus.test.junit.callback.QuarkusTestContext;

public class OidcTestClientLifecycleCallbacks implements QuarkusTestAfterAllCallback, QuarkusTestAfterConstructCallback {

    // this could be problematic in nested tests
    // but for each callback a new instance of this class is created
    // and 'afterConstruct' can be called several times
    // so it is better to cache the client
    private static volatile OidcTestClient oidcTestClient = null;

    @Override
    public void afterAll(QuarkusTestContext context) {
        System.out.println("////////////// after all");
        if (oidcTestClient != null) {
            System.out.println("................ clsoing");
            oidcTestClient.close();
            oidcTestClient = null;
        }
    }

    @Override
    public void afterConstruct(Object testInstance) {
        System.out.println("after construct ///////////////////");
        Class<?> c = testInstance.getClass();
        while (c != Object.class) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == OidcTestClient.class && isNotPrivate(f) && isNotStatic(f) && isNotFinal(f)) {
                    f.setAccessible(true);
                    System.out.println("............ found a field");
                    if (getFieldValue(testInstance, f) == null) {
                        try {
                            if (oidcTestClient == null) {
                                oidcTestClient = new OidcTestClient();
                            }
                            System.out.println("/////////// setting a vlaue");
                            f.set(testInstance, oidcTestClient);
                            return;
                        } catch (Exception e) {
                            throw new RuntimeException("Unable to set OidcTestClient to field '" + f.getName() + "'", e);
                        }
                    }
                }
            }
            c = c.getSuperclass();
        }
    }

    private static OidcTestClient getFieldValue(Object testInstance, Field f) {
        try {
            return (OidcTestClient) f.get(testInstance);
        } catch (IllegalAccessException e) {
            // we make the field accessible, so the exception should not happen
            return null;
        }
    }

    private static boolean isNotPrivate(Field f) {
        return !Modifier.isPrivate(f.getModifiers());
    }

    private static boolean isNotStatic(Field f) {
        return !Modifier.isStatic(f.getModifiers());
    }

    private static boolean isNotFinal(Field f) {
        return !Modifier.isFinal(f.getModifiers());
    }
}
