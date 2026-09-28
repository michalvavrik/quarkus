package io.quarkus.resteasy.reactive.server.runtime;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import jakarta.ws.rs.HttpMethod;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.common.util.Encode;
import org.jboss.resteasy.reactive.server.core.Deployment;
import org.jboss.resteasy.reactive.server.mapping.RuntimeResource;

import io.quarkus.resteasy.reactive.server.runtime.RuntimeResourceMatcher.Match;

/**
 * Without the servlet container, static resources are served for {@code GET} and {@code HEAD} requests before Quarkus
 * REST, so an endpoint matching the path of a static resource is never invoked for these requests, and its
 * annotations, security annotations in particular, do not apply to the static resource. This warns about such
 * endpoints when the application starts.
 */
final class StaticResourceShadowingCheck {

    private static final Logger log = Logger.getLogger(StaticResourceShadowingCheck.class);

    private static final List<String> HTTP_METHODS = List.of(HttpMethod.GET, HttpMethod.HEAD);
    private static final String PROBE_SEGMENT = "quarkus-static-resource-probe";

    private final RuntimeResourceMatcher matcher;
    // the HTTP root path and the application path, empty or without a trailing slash
    private final String prefix;
    // the HTTP root path without a trailing slash
    private final String rootPath;

    private StaticResourceShadowingCheck(Deployment deployment, String httpRootPath) {
        this.matcher = new RuntimeResourceMatcher(deployment);
        this.prefix = deployment.getPrefix();
        this.rootPath = httpRootPath.endsWith("/") ? httpRootPath.substring(0, httpRootPath.length() - 1) : httpRootPath;
    }

    /**
     * Logs a warning listing the endpoints shadowed by static resources.
     *
     * @param indexPage the index page served for the directories
     * @param staticFilePaths the paths of the static resources, relative to the HTTP root path
     */
    static void check(Deployment deployment, String httpRootPath, String indexPage, Collection<String> staticFilePaths) {
        // lowering the level of this logger also skips the check
        if (!log.isEnabled(Logger.Level.WARN)) {
            return;
        }
        new StaticResourceShadowingCheck(deployment, httpRootPath).run(requestPaths(staticFilePaths, indexPage));
    }

    /**
     * Returns the request paths the static resources are served for, like {@code StaticResourcesRecorder}: the paths
     * of the files, and the paths of the directories containing the index page, ending with a slash.
     */
    private static Set<String> requestPaths(Collection<String> filePaths, String indexPage) {
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

    private void run(Set<String> paths) {
        // request path -> endpoint -> HTTP methods
        Map<String, Map<String, Set<String>>> shadowed = new TreeMap<>();
        for (String path : paths) {
            String requestPath = rootPath + path;
            for (String httpMethod : HTTP_METHODS) {
                Match match = match(requestPath, httpMethod);
                if (match != null && !acceptsAnyPath(match, requestPath, httpMethod)) {
                    shadowed.computeIfAbsent(requestPath, k -> new LinkedHashMap<>())
                            .computeIfAbsent(describe(match), k -> new LinkedHashSet<>())
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
     * Returns the resource method a request is dispatched to, or {@code null} if there is none.
     */
    private Match match(String requestPath, String httpMethod) {
        String path;
        if (prefix.isEmpty()) {
            path = requestPath;
        } else if (requestPath.equals(prefix)) {
            path = "/";
        } else if (requestPath.startsWith(prefix + "/")) {
            path = requestPath.substring(prefix.length());
        } else {
            // not dispatched to Quarkus REST
            return null;
        }
        // static resources are matched with the decoded path, Quarkus REST with the encoded one
        return matcher.match(Encode.encodePath(path), httpMethod);
    }

    /**
     * A resource method accepting any path under the directory of a static resource, for example the fallback of a
     * single-page application, is expected to be shadowed by the static resources of the directory. Sub-resource
     * locators accept any path as well, but their sub-resources may not.
     */
    private boolean acceptsAnyPath(Match match, String requestPath, String httpMethod) {
        if (isSubResourceLocator(match)) {
            return false;
        }
        String directory = requestPath.endsWith("/")
                ? requestPath.substring(0, requestPath.length() - 1)
                : requestPath.substring(0, requestPath.lastIndexOf('/'));
        Match probe = match(directory + "/" + PROBE_SEGMENT + "/" + PROBE_SEGMENT, httpMethod);
        return probe != null && probe.resource() == match.resource();
    }

    private static boolean isSubResourceLocator(Match match) {
        return match.resource().getHttpMethod() == null;
    }

    private static String describe(Match match) {
        RuntimeResource resource = match.resource();
        if (resource.getResourceClass() == null) {
            // the resource methods with the same path and different media types are dispatched by a MediaTypeMapper
            return "resource methods with the path template " + match.template();
        }
        String name = resource.getResourceClass().getName() + "#" + resource.getJavaMethodName();
        return isSubResourceLocator(match) ? name + " (sub-resource locator)" : name;
    }
}
