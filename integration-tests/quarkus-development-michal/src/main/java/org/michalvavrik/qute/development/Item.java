package org.michalvavrik.qute.development;

import java.util.Set;

public class Item {

    String name;

    Set<Item> derivedItems;

    public Item(String name, Set<Item> derivedItems) {
        this.name = name;
        this.derivedItems = derivedItems;
    }

    public String getName() {
        return name;
    }

    public Set<Item> getDerivedItems() {
        return derivedItems;
    }
}
