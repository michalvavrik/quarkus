package io.quarkus.opentelemetry.runtime.graal;

import java.security.SecureRandom;

import com.oracle.svm.core.annotate.Alias;
import com.oracle.svm.core.annotate.InjectAccessors;
import com.oracle.svm.core.annotate.TargetClass;

@TargetClass(className = "java.rmi.server.ObjID")
final class Target_java_rmi_server_ObjID {

    @Alias
    @InjectAccessors(SecureRandomAccessor.class)
    private static SecureRandom secureRandom;

}

class SecureRandomAccessor {
    private static volatile SecureRandom RANDOM;

    static SecureRandom get() {
        SecureRandom result = RANDOM;
        if (result == null) {
            /* Lazy initialization on first access. */
            result = initializeOnce();
        }
        return result;
    }

    private static synchronized SecureRandom initializeOnce() {
        SecureRandom result = RANDOM;
        if (result != null) {
            /* Double-checked locking is OK because INSTANCE is volatile. */
            return result;
        }

        result = new SecureRandom();
        RANDOM = result;
        return result;
    }
}

class OpenTelemetrySubstitutions {
}
