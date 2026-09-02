"""Run non-built-in / dynamically-installed tools inside ephemeral Docker containers.

Isolation goals:
- keep the host clean (no polluting installs),
- easy cleanup (container removed after each run),
- network policy governed by mode/config.

If a tool has no dedicated image, a generic base image is used and the install command is
run before the tool command inside the container.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..logging_ import audit, get_logger

log = get_logger(__name__)

DEFAULT_BASE_IMAGE = "kalilinux/kali-rolling"


@dataclass
class ContainerResult:
    exit_code: int
    stdout: str
    stderr: str
    container_id: str | None = None
    timed_out: bool = False
    error: str = ""


class DockerRunner:
    def __init__(self, network: str | None = None):
        self.network = network
        self._client = None

    def _get_client(self):
        if self._client is None:
            import docker  # imported lazily so the package is optional at import time

            self._client = docker.from_env()
            self._client.ping()
        return self._client

    def available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception as e:  # docker not installed / daemon down
            log.warning("Docker unavailable: %s", e)
            return False

    def run(
        self,
        argv: list[str],
        image: str = DEFAULT_BASE_IMAGE,
        install: str = "",
        timeout: int = 600,
    ) -> ContainerResult:
        try:
            client = self._get_client()
        except Exception as e:
            return ContainerResult(1, "", "", error=f"docker init failed: {e}")

        import docker  # type: ignore

        # Build the in-container command: optional install, then the tool argv.
        tool_cmd = " ".join(_shell_quote(a) for a in argv)
        if install:
            full = f"{install} >/dev/null 2>&1 || {install}; {tool_cmd}"
        else:
            full = tool_cmd
        cmd = ["/bin/sh", "-lc", full]

        audit("container.run", image=image, install=bool(install), argv=argv, network=self.network)

        container = None
        try:
            container = client.containers.run(
                image=image,
                command=cmd,
                detach=True,
                network=self.network or "bridge",
                remove=False,
                stdout=True,
                stderr=True,
            )
            try:
                result = container.wait(timeout=timeout)
                exit_code = int(result.get("StatusCode", 1))
                timed_out = False
            except Exception:
                container.kill()
                exit_code = 124
                timed_out = True
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")
            return ContainerResult(exit_code, stdout, stderr, container.id, timed_out)
        except docker.errors.ImageNotFound:
            return self._run_after_pull(client, image, cmd, timeout)
        except Exception as e:
            return ContainerResult(1, "", "", error=str(e))
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _run_after_pull(self, client, image: str, cmd: list[str], timeout: int) -> ContainerResult:
        try:
            log.info("Pulling image %s", image)
            client.images.pull(image)
        except Exception as e:
            return ContainerResult(1, "", "", error=f"image pull failed: {e}")
        container = None
        try:
            container = client.containers.run(
                image=image,
                command=cmd,
                detach=True,
                network=self.network or "bridge",
                stdout=True,
                stderr=True,
            )
            result = container.wait(timeout=timeout)
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")
            return ContainerResult(int(result.get("StatusCode", 1)), stdout, stderr, container.id)
        except Exception as e:
            return ContainerResult(1, "", "", error=str(e))
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass


def _shell_quote(s: str) -> str:
    if not s:
        return "''"
    if all(c.isalnum() or c in "-_./:=@" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"
