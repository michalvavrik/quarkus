package io.quarkus.qute.deployment.typesafe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javax.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.qute.Template;
import io.quarkus.test.QuarkusUnitTest;

public class OrValueResolverValidationTest {

    public static final String ITEM_NAME = "Test Name";

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(Item.class, OtherItem.class, ItemWithName.class, ItemWithName.Name.class)
                    .addAsResource(new StringAsset(
                            "{@io.quarkus.qute.deployment.typesafe.Item item}\n" +
                                    "{@io.quarkus.qute.deployment.typesafe.ItemWithName itemWithName}\n" +
                                    "{#for item in item.otherItems}\n" +
                                    "{missing.or(alsoMissing.or('item id is: ')).toLowerCase}" + // make sure nested validation works
                                    "{data:item.name.or(itemWithName.name).toUpperCase}" + // validate both sides has toUpperCase
                                    "{item.getId().or(itemWithName.name)}\n" + // make sure nothing must follow OR
                                    "{/for}\n"),
                            "templates/item.html"));

    @Inject
    Template item;

    @Test
    public void test() {
        final String expected = "item id is: " + ITEM_NAME.toUpperCase() + new OtherItem().getId();
        assertEquals(expected,
                item.data("item", new Item(ITEM_NAME.toUpperCase(), new OtherItem())).render().trim());
        assertEquals(
                expected,
                item.data("item", new Item(null, new OtherItem()), "itemWithName", new ItemWithName(new ItemWithName.Name()))
                        .render().trim());
    }

}
