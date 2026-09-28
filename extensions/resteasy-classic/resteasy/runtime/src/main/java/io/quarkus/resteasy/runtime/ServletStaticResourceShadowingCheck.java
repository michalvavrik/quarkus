package io.quarkus.resteasy.runtime;

import java.util.Collection;

import jakarta.enterprise.event.Observes;
import jakarta.servlet.ServletContext;

import org.jboss.resteasy.spi.Registry;

import io.quarkus.runtime.StartupEvent;

/**
 * Runs the {@link StaticResourceShadowingCheck} when RESTEasy runs on the servlet container, see
 * {@code ResteasyServletProcessor}.
 */
public class ServletStaticResourceShadowingCheck {

    /**
     * The servlet context attribute holding the request paths the default servlet serves static resources for,
     * relative to the servlet context path.
     */
    public static final String STATIC_RESOURCE_PATHS = ServletStaticResourceShadowingCheck.class.getName() + ".paths";

    void onStart(@Observes StartupEvent event, ServletContext servletContext) {
        // set by ResteasyFilter
        Registry registry = (Registry) servletContext.getAttribute(Registry.class.getName());
        @SuppressWarnings("unchecked")
        Collection<String> paths = (Collection<String>) servletContext.getAttribute(STATIC_RESOURCE_PATHS);
        if (registry != null && paths != null) {
            String contextPath = servletContext.getContextPath();
            new StaticResourceShadowingCheck(registry, contextPath).check(contextPath, paths);
        }
    }
}
