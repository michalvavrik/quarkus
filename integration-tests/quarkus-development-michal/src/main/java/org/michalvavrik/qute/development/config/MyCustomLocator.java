package org.michalvavrik.qute.development.config;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import org.jboss.logging.Logger;

import io.quarkus.qute.Locate;
import io.quarkus.qute.TemplateLocator;
import io.quarkus.qute.Variant;

@Locate("/home/mvavrik/sources/quarkus/integration-tests/quarkus-development-michal/michal-templates/basic.html")
public class MyCustomLocator implements TemplateLocator {

    private static final Logger LOG = Logger.getLogger(MyCustomLocator.class);

    @Override
    public Optional<TemplateLocation> locate(String s) {

        LOG.info("PRE TRY");
        try {
            Path found = Paths.get(s);
            LOG.info("PATH IS " + found);
            final byte[] content = Files.readAllBytes(found);
            return Optional.of(new TemplateLocation() {
                public Reader read() {
                    LOG.info("CONTENT IS " + content);
                    return new StringReader(new String(content, StandardCharsets.UTF_8));
                }

                public Optional<Variant> getVariant() {
                    return Optional.empty();
                }
            });
        } catch (IOException var4) {
            LOG.warn("123456 Unable to read the template from path: " + s, var4);
            return Optional.empty();
        }
    }

}
