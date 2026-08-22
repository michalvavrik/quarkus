package io.quarkus.security.spi.runtime;

import java.util.Objects;

public final class PermissionToActionUtil {

    public static final class ParsedPermission {
        private final String name;
        private final String action;

        private ParsedPermission(String name, String action) {
            this.name = name;
            this.action = action;
        }

        public String name() {
            return name;
        }

        public String action() {
            return action;
        }

        public boolean hasAction() {
            return action != null;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (!(o instanceof ParsedPermission that))
                return false;
            return Objects.equals(name, that.name) && Objects.equals(action, that.action);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, action);
        }

        @Override
        public String toString() {
            return "ParsedPermission[name=" + name + ", action=" + action + "]";
        }
    }

    private PermissionToActionUtil() {
    }

    public static ParsedPermission parse(String raw) {
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
