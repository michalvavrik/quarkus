package io.quarkus.qute.deployment.typesafe;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.qute.TemplateException;
import io.quarkus.test.QuarkusUnitTest;

public class OrValueResolverValidationFailureTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(Item.class, OtherItem.class, ItemWithName.class, ItemWithName.Name.class)
                    .addAsResource(new StringAsset(
                            "{@io.quarkus.qute.deployment.typesafe.Item item}\n" +
                                    "{@io.quarkus.qute.deployment.typesafe.ItemWithName itemWithName}\n" +
                                    "{#for item in item.otherItems}\n" +
                                    "  {data:item.name.or(itemWithName.name).pleaseMakeMyCaseUpper}\n" +
                                    "  {item.getId().or(itemWithName.name).longValue()}\n" +
                                    "  {missing.or(alsoMissing.unknownProperty.or('John')).fictionalMethod()}\n" +
                                    "{/for}\n"),
                            "templates/item.html"))
            .assertException(t -> {
                Throwable e = t;
                TemplateException te = null;
                while (e != null) {
                    if (e instanceof TemplateException) {
                        te = (TemplateException) e;
                        break;
                    }
                    e = e.getCause();
                }
                assertNotNull(te);
                // make sure data:item.name.pleaseMakeMyCaseUpper is validated
                assertTrue(te.getMessage().contains(
                        "{data:item.name.or(itemWithName.name).pleaseMakeMyCaseUpper}: Property/method [pleaseMakeMyCaseUpper] not found on class [java.lang.String]"),
                        te.getMessage());
                // make sure itemWithName.name.longValue() is validated
                assertTrue(te.getMessage().contains(
                        "{itemWithName.name.longValue()}: Property/method [longValue()] not found on class [io.quarkus.qute.deployment.typesafe.ItemWithName$Name]"),
                        te.getMessage());
                // make sure 'John'.fictionalMethod() is validated
                assertTrue(te.getMessage().contains(
                        "'John'.fictionalMethod()}: Property/method [fictionalMethod()] not found on class [java.lang.String]"),
                        te.getMessage());
            });

    @Test
    public void test() {
        Assertions.fail();
    }

}
