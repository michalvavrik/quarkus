# Sandbox environment for quarkusio/quarkus

- /workspace is a shallow clone (1 commit). Work here.
- /opt/project-src has the full git history of quarkusio/quarkus (read-only). Use it for `git log`, `git blame`, `git show`:
  ```
  git -C /opt/project-src log --oneline -20
  git -C /opt/project-src blame path/to/file
  git -C /opt/project-src show <commit>:path/to/file
  ```
- Push to origin (michalvavrik-dev-automation/quarkus), fetch from upstream (quarkusio/quarkus).

## Reference codebases (read-only)
- /opt/project-src — quarkusio/quarkus with full commit history (host mount). Use for `git log`, `git blame`, `git show`.
- /opt/workspace/keycloak — keycloak latest main (shallow, for browsing source)
- /tmp/workspace — additional documents copied in by the user (if any)

## Git branches
You can only push to branches under `dev-auto/quarkus-55916/`. If you need extra branches, name them `dev-auto/quarkus-55916/<name>`.

## Testing
Docker is NOT installed. Podman is the container runtime. Testcontainers works with Podman out of the box (already configured via DOCKER_HOST). Always try running tests before claiming they can't run.

## Task context
- .pr — PR details (`gh pr view` output), present when working on a pull request
- .issue — issue details (`gh issue view` output), present when working on an issue
