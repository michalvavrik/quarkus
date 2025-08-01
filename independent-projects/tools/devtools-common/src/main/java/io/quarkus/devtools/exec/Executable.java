package io.quarkus.devtools.exec;

import java.io.File;
import java.nio.file.Path;

import io.quarkus.devtools.messagewriter.MessageWriter;
import io.smallrye.common.os.OS;
import io.smallrye.common.process.ProcessUtil;

public class Executable {

    public static File findExecutableFile(String base) {
        String path = null;
        String executable = base;

        if (OS.current() == OS.WINDOWS) {
            executable = base + ".cmd";
            path = findExecutable(executable);
            if (path == null) {
                executable = base + ".bat";
                path = findExecutable(executable);
            }
        } else {
            executable = base;
            path = findExecutable(executable);
        }
        if (path == null)
            return null;
        return new File(path, executable);
    }

    public static String findExecutable(String exec) {
        return ProcessUtil.pathOfCommand(Path.of(exec)).map(Object::toString).orElse(null);
    }

    public static File findExecutable(String name, String errorMessage, MessageWriter output) {
        File command = findExecutableFile(name);
        if (command == null) {
            output.error(errorMessage);
            throw new RuntimeException("Unable to find " + name + " command");
        }
        return command;
    }

    public static File findWrapper(Path projectRoot, String[] windows, String other) {
        if (projectRoot == null) {
            return null;
        }
        if (OS.current() == OS.WINDOWS) {
            for (String name : windows) {
                File wrapper = new File(projectRoot + File.separator + name);
                if (wrapper.isFile())
                    return wrapper;
            }
        } else {
            File wrapper = new File(projectRoot + File.separator + other);
            if (wrapper.isFile())
                return wrapper;
        }

        // look for a wrapper in a parent directory
        Path normalizedPath = projectRoot.normalize();
        if (!normalizedPath.equals(projectRoot.getRoot())) {
            return findWrapper(normalizedPath.getParent(), windows, other);
        } else {
            return null;
        }
    }
}
