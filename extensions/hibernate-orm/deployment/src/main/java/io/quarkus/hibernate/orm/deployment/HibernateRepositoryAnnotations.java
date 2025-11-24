package io.quarkus.hibernate.orm.deployment;

import java.util.Set;

import org.hibernate.annotations.processing.Find;
import org.hibernate.annotations.processing.HQL;
import org.hibernate.annotations.processing.SQL;

/**
 * Collection of Hibernate annotations which, if detected on interface, Hibernate processor generates repository.
 */
public class HibernateRepositoryAnnotations {

    public static final Set<Class<?>> METHOD_ANNOTATIONS = Set.of(Find.class, HQL.class, SQL.class);

}
