package io.quarkus.vertx.http.runtime.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Handler that dispatches to a given handler based of a prefix match of the path.
 * <p>
 * This only matches a single level of a request, e.g. if you have a request that takes the form:
 * <p>
 * /foo/bar
 * <p>
 *
 * @author Stuart Douglas
 */
public class PathMatcher<T> {

    private static final String STRING_PATH_SEPARATOR = "/";

    private volatile T defaultHandler;
    private final SubstringMap<T> paths = new SubstringMap<>();
    private final ConcurrentMap<String, T> exactPathMatches = new ConcurrentHashMap<>();

    public PathMatcher(final T defaultHandler) {
        this.defaultHandler = defaultHandler;
    }

    public PathMatcher() {
    }

    /**
     * Matches a path against the registered handlers.
     *
     * @param path The relative path to match
     * @return The match match. This will never be null, however if none matched its value field will be
     */
    public PathMatch<T> match(String path) {
        if (!exactPathMatches.isEmpty()) {
            T match = getExactPath(path);
            if (match != null) {
                return new PathMatch<>(path, "", match);
            }
        }
        PathMatch<T> prefixMatch = matchPrefixPath(path, paths.getLengths(), path.length(), paths);
        if (prefixMatch != null) {
            return prefixMatch;
        }
        // FIXME this can be problematic when this is nested path?
        // FIXME and what should be default handler? what if it turns out that one/*/three/four doesn't match
        // FIXME one/two/jamaica, and therefore something like */two/* should be used instead??
        // FIXME this can only be avoided by limiting * to exactly one inside path (that is two * in general)
        // FIXME but then, it can still happen than /one/*/jamaica will not match but /*/two/three
        // FIXME this means it can only work when matching will be done in paths."get"
        // FIXME or
        return new PathMatch<>("", path, defaultHandler);
    }

    private static <T> PathMatch<T> matchPrefixPath(String path, int[] lengths, int length, SubstringMap<T> paths) {
        for (int pathLength : lengths) {
            if (pathLength == length) {
                SubstringMap.SubstringMatch<T> next = paths.get(path, length);
                if (next != null) {
                    if (next.hasSubPaths()) {
                        // fixme the path in fact needs to be subpath!!!!! this needs to work differently
                        //   probably substring
                        // FIXME can we really match any subpath if path length already matches????
                        String subPath = path;
                        PathMatch<T> match = matchPrefixPath(subPath, next.getSubPaths().getLengths(), subPath.length(), next.getSubPaths());
                        if (match != null) {
                            return match;
                        }
                    } else {
                        return new PathMatch<>(path, "", next.getValue());
                    }
                }
            } else if (pathLength < length) {
                char c = path.charAt(pathLength);
                // FIXME: this thing about / needs to be extremely well inspected
                if (c == '/') {

                    //String part = path.substring(0, pathLength);
                    SubstringMap.SubstringMatch<T> next = paths.get(path, pathLength);
                    if (next != null) {
                        if (next.hasSubPaths()) {
                            // fixme the path in fact needs to be subpath!!!!! this needs to work differently
                            //   probably substring
                            String subPath = path.substring(pathLength);
                            PathMatch<T> match = matchPrefixPath(subPath, next.getSubPaths().getLengths(), subPath.length(), next.getSubPaths());
                            if (match != null) {
                                return match;
                            }
                        } else {
                            return new PathMatch<>(next.getKey(), path.substring(pathLength), next.getValue());
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Adds a path prefix and a handler for that path. If the path does not start
     * with a / then one will be prepended.
     * <p>
     * The match is done on a prefix bases, so registering /foo will also match /bar. Exact
     * path matches are taken into account first.
     * <p>
     * If / is specified as the path then it will replace the default handler.
     *
     * @param path The path
     * @param handler The handler
     */
    public synchronized PathMatcher addPrefixPath(final String path, final T handler) {
        if (path.isEmpty()) {
            throw new IllegalArgumentException("Path not specified");
        }

        if (PathMatcher.STRING_PATH_SEPARATOR.equals(path)) {
            this.defaultHandler = handler;
            return this;
        }

        paths.put(path, handler);

        return this;
    }

    public synchronized PathMatcher addExactPath(final String path, final T handler) {
        if (path.isEmpty()) {
            throw new IllegalArgumentException("Path not specified");
        }
        exactPathMatches.put(path, handler);
        return this;
    }

    public T getExactPath(final String path) {
        return exactPathMatches.get(path);
    }

    public T getPrefixPath(final String path) {

        // enable the prefix path mechanism to return the default handler
        SubstringMap.SubstringMatch<T> match = paths.get(path);
        if (PathMatcher.STRING_PATH_SEPARATOR.equals(path) && match == null) {
            return this.defaultHandler;
        }
        if (match == null) {
            return null;
        }

        // return the value for the given path
        return match.getValue();
    }

    @Deprecated
    public synchronized PathMatcher removePath(final String path) {
        return removePrefixPath(path);
    }

    public synchronized PathMatcher removePrefixPath(final String path) {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Path not specified");
        }

        if (PathMatcher.STRING_PATH_SEPARATOR.equals(path)) {
            defaultHandler = null;
            return this;
        }

        paths.remove(path);

        return this;
    }

    public synchronized PathMatcher removeExactPath(final String path) {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Path not specified");
        }

        exactPathMatches.remove(path);

        return this;
    }

    public synchronized PathMatcher clearPaths() {
        paths.clear();
        exactPathMatches.clear();
        defaultHandler = null;
        return this;
    }

    public Map<String, T> getPaths() {
        return paths.toMap();
    }

    public static final class PathMatch<T> {
        private final String matched;
        private final String remaining;
        private final T value;

        public PathMatch(String matched, String remaining, T value) {
            this.matched = matched;
            this.remaining = remaining;
            this.value = value;
        }

        public String getRemaining() {
            return remaining;
        }

        public String getMatched() {
            return matched;
        }

        public T getValue() {
            return value;
        }
    }

}
