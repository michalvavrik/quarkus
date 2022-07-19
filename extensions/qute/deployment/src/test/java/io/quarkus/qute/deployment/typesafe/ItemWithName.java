package io.quarkus.qute.deployment.typesafe;

public class ItemWithName {
    private final Name name;

    public ItemWithName(Name name) {
        this.name = name;
    }

    public Name getName() {
        return name;
    }

    public static class Name {

        public String toUpperCase() {
            return OrValueResolverValidationTest.ITEM_NAME.toUpperCase();
        }

        public String pleaseMakeMyCaseUpper() {
            return "UPPER CASE";
        }
    }
}
