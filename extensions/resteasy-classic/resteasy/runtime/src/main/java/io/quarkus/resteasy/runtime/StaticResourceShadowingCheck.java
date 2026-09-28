package io.quarkus.resteasy.runtime;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.WebApplicationException;

import org.jboss.logging.Logger;
import org.jboss.resteasy.core.ResourceLocatorInvoker;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.spi.Registry;
import org.jboss.resteasy.spi.ResourceInvoker;
import org.jboss.resteasy.util.Encode;

/**
 * Static resources are served for {@code GET} and {@code HEAD} requests before RESTEasy, so an endpoint matching the
 * path of a static resource is never invoked for these requests, and its annotations, security annotations in
 * particular, do not apply to the static resource. This warns about such endpoints when the application starts.
 * <p>
 * The request paths of the static resources are matched by the registry of the RESTEasy deployment, the same way
 * requests are, without invoking the endpoints.
 */
public final class StaticResourceShadowingCheck {

    private static final Logger log = Logger.getLogger(StaticResourceShadowingCheck.class);

    private static final List<String> HTTP_METHODS = List.of(HttpMethod.GET, HttpMethod.HEAD);
    private static final String PROBE_SEGMENT = "quarkus-static-resource-probe";

    private final Registry registry;
    // the path requests are dispatched to RESTEasy under, see ServletUtil#extractUriInfo and VertxUtil#extractUriInfo
    private final String contextPath;
    private final String pathPrefix;

    public StaticResourceShadowingCheck(Registry registry, String contextPath) {
        this.registry = registry;
        this.contextPath = contextPath.startsWith("/") ? contextPath : "/" + contextPath;
        this.pathPrefix = this.contextPath.endsWith("/")
                ? this.contextPath.substring(0, this.contextPath.length() - 1)
                : this.contextPath;
    }

    /**
     * Returns the request paths the static resources are served for: the paths of the files, and the paths of the
     * directories containing the index page or welcome file, ending with a slash.
     */
    public static Set<String> requestPaths(Collection<String> filePaths, String indexPage) {
        String indexFile = indexPage.startsWith("/") ? indexPage : "/" + indexPage;
        Set<String> paths = new TreeSet<>();
        for (String path : filePaths) {
            paths.add(path);
            if (path.endsWith(indexFile)) {
                paths.add(path.substring(0, path.length() - indexFile.length() + 1));
            }
        }
        return paths;
    }

    /**
     * Logs a warning listing the endpoints shadowed by the static resources served for the given paths.
     *
     * @param pathPrefix the path the static resources are served under: the HTTP root path, or the servlet context
     *        path
     * @param paths the request paths of the static resources, relative to the prefix
     */
    public void check(String pathPrefix, Collection<String> paths) {
        // lowering the level of this logger also skips the check
        if (!log.isEnabled(Logger.Level.WARN)) {
            return;
        }
        String prefix = pathPrefix.endsWith("/") ? pathPrefix.substring(0, pathPrefix.length() - 1) : pathPrefix;
        // request path -> endpoint -> HTTP methods
        Map<String, Map<String, Set<String>>> shadowed = new TreeMap<>();
        for (String path : paths) {
            String requestPath = prefix + path;
            for (String httpMethod : HTTP_METHODS) {
                ResourceInvoker endpoint = match(requestPath, httpMethod);
                if (endpoint != null && !acceptsAnyPath(endpoint, requestPath, httpMethod)) {
                    shadowed.computeIfAbsent(requestPath, k -> new LinkedHashMap<>())
                            .computeIfAbsent(describe(endpoint), k -> new LinkedHashSet<>())
                            .add(httpMethod);
                }
            }
        }
        if (shadowed.isEmpty()) {
            return;
        }
        StringBuilder message = new StringBuilder("""
                Static resources shadow Jakarta REST endpoints: requests with the listed HTTP methods to the listed \
                paths are served the static resource and the endpoint is never invoked, so security annotations on \
                the endpoint do not protect the static resource. Move the static resources or change the endpoint \
                paths, or secure the static resources with configuration, see \
                https://quarkus.io/guides/security-authorize-web-endpoints-reference#authorization-using-configuration:""");
        shadowed.forEach((path, endpoints) -> endpoints.forEach((endpoint, httpMethods) -> message
                .append(System.lineSeparator()).append(String.join(", ", httpMethods)).append(' ').append(path)
                .append(" -> ").append(endpoint)));
        log.warn(message);
    }

    /**
     * Returns the endpoint RESTEasy dispatches a request to, or {@code null} if there is none.
     */
    private ResourceInvoker match(String requestPath, String httpMethod) {
        if (!requestPath.equals(pathPrefix) && !requestPath.startsWith(pathPrefix + "/")) {
            // not dispatched to RESTEasy
            return null;
        }
        // static resources are matched with the decoded path, RESTEasy with the encoded one
        MockHttpRequest request = MockHttpRequest.create(httpMethod, "http://localhost" + Encode.encodePath(requestPath),
                null, contextPath);
        try {
            return registry.getResourceInvoker(request);
        } catch (WebApplicationException e) {
            // e.g. NotFoundException
            return null;
        }
    }

    /**
     * An endpoint accepting any path under the directory of a static resource, for example the fallback of a
     * single-page application, is expected to be shadowed by the static resources of the directory. Sub-resource
     * locators accept any path as well, but their sub-resources may not.
     */
    private boolean acceptsAnyPath(ResourceInvoker endpoint, String requestPath, String httpMethod) {
        if (endpoint instanceof ResourceLocatorInvoker) {
            return false;
        }
        String directory = requestPath.endsWith("/")
                ? requestPath.substring(0, requestPath.length() - 1)
                : requestPath.substring(0, requestPath.lastIndexOf('/'));
        return endpoint == match(directory + "/" + PROBE_SEGMENT + "/" + PROBE_SEGMENT, httpMethod);
    }

    private static String describe(ResourceInvoker endpoint) {
        Class<?> resourceClass = endpoint instanceof ResourceMethodInvoker resourceMethod
                ? resourceMethod.getResourceClass()
                : endpoint.getMethod().getDeclaringClass();
        String name = resourceClass.getName() + "#" + endpoint.getMethod().getName();
        return endpoint instanceof ResourceLocatorInvoker ? name + " (sub-resource locator)" : name;
    }
}
