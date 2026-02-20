"""LRU cache for Ghidra Program objects.

Keeps at most ``max_size`` programs open simultaneously, evicting the
least-recently-used entry when the cache is full.  Thread-safe via a
reentrant lock so the bridge can be shared across MCP request handlers.

Usage:
    from ghidra_assist.project_cache import ProjectCache
    cache = ProjectCache(max_size=5)
    program = cache.get_program("my_repo", "firmware.bin")
"""

import logging
import threading
import time
from collections import OrderedDict
from pathlib import Path

from .config import settings
from .ghidra_bridge import GhidraBridge

logger = logging.getLogger(__name__)


class _CacheEntry:
    """Internal wrapper around a cached program."""

    __slots__ = ("program", "repo_name", "program_name", "opened_at", "last_used")

    def __init__(self, program, repo_name: str, program_name: str):
        self.program = program
        self.repo_name = repo_name
        self.program_name = program_name
        self.opened_at = time.monotonic()
        self.last_used = time.monotonic()

    def touch(self) -> None:
        self.last_used = time.monotonic()


class ProjectCache:
    """Thread-safe LRU cache for open Ghidra Program objects.

    Programs are keyed by ``(repo_name, program_name)`` tuples.
    When the cache exceeds *max_size*, the least recently used entry
    is evicted and its program is closed.
    """

    def __init__(self, max_size: int | None = None):
        self._max_size = max_size or settings.max_cached_programs
        self._bridge = GhidraBridge()
        self._cache: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def bridge(self) -> GhidraBridge:
        """Expose the underlying bridge for direct operations."""
        return self._bridge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_program(self, repo_name: str, program_name: str):
        """Return a Ghidra Program, from cache or freshly opened.

        Args:
            repo_name: Repository directory name (relative to repos_dir).
            program_name: Program file name inside the repository.

        Returns:
            Ghidra Program Java object.

        Raises:
            FileNotFoundError: If the repo or program cannot be located.
            RuntimeError: If pyghidra fails to open the program.
        """
        key = (repo_name, program_name)

        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                entry.touch()
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                logger.debug("Cache hit: %s/%s", repo_name, program_name)
                return entry.program

        # Open outside the lock to avoid holding it during slow I/O
        repo_path = str(Path(settings.repos_dir) / repo_name)
        program = self._bridge.open_program(repo_path, program_name)

        with self._lock:
            # Another thread may have opened the same program concurrently
            if key in self._cache:
                # Discard the one we just opened, use the cached one
                self._close_program_safe(program)
                entry = self._cache[key]
                entry.touch()
                self._cache.move_to_end(key)
                return entry.program

            # Evict if at capacity
            while len(self._cache) >= self._max_size:
                self._evict_oldest()

            entry = _CacheEntry(program, repo_name, program_name)
            self._cache[key] = entry
            logger.info(
                "Cached program: %s/%s (cache size: %d/%d)",
                repo_name,
                program_name,
                len(self._cache),
                self._max_size,
            )
            return program

    def list_repos(self) -> list[str]:
        """List repository directory names under the configured repos_dir.

        Returns:
            Sorted list of repository directory names.
        """
        repos_path = Path(settings.repos_dir)
        if not repos_path.is_dir():
            logger.warning("Repos directory does not exist: %s", repos_path)
            return []

        return sorted(
            d.name
            for d in repos_path.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )

    def list_programs(self, repo_name: str) -> list[dict]:
        """List program files in a repository.

        Args:
            repo_name: Repository directory name (relative to repos_dir).

        Returns:
            List of dicts with name, size_bytes, modified.

        Raises:
            FileNotFoundError: If the repository directory does not exist.
        """
        repo_path = Path(settings.repos_dir) / repo_name
        if not repo_path.is_dir():
            raise FileNotFoundError(f"Repository not found: {repo_name}")

        programs = []
        for entry in sorted(repo_path.iterdir()):
            # Skip hidden files and Ghidra lock files
            if entry.name.startswith(".") or entry.name.endswith(".lock"):
                continue
            # Include regular files (binaries) and .rep directories (Ghidra projects)
            if entry.is_file() or (entry.is_dir() and entry.suffix == ".rep"):
                stat = entry.stat()
                programs.append(
                    {
                        "name": entry.name,
                        "size_bytes": stat.st_size if entry.is_file() else self._dir_size(entry),
                        "modified": stat.st_mtime,
                        "is_project": entry.suffix == ".rep",
                    }
                )
        return programs

    def evict(self, repo_name: str, program_name: str) -> bool:
        """Manually evict a specific program from the cache.

        Returns True if the entry was found and evicted, False otherwise.
        """
        key = (repo_name, program_name)
        with self._lock:
            entry = self._cache.pop(key, None)
            if entry is None:
                return False
            self._close_program_safe(entry.program)
            logger.info("Evicted program: %s/%s", repo_name, program_name)
            return True

    def clear(self) -> int:
        """Close and evict all cached programs.

        Returns:
            Number of programs evicted.
        """
        with self._lock:
            count = len(self._cache)
            for entry in self._cache.values():
                self._close_program_safe(entry.program)
            self._cache.clear()
            logger.info("Cache cleared: %d programs evicted", count)
            return count

    def stats(self) -> dict:
        """Return cache statistics.

        Returns:
            dict with size, max_size, and entries list.
        """
        with self._lock:
            entries = []
            for key, entry in self._cache.items():
                entries.append(
                    {
                        "repo": entry.repo_name,
                        "program": entry.program_name,
                        "opened_at": entry.opened_at,
                        "last_used": entry.last_used,
                    }
                )
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "entries": entries,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_oldest(self) -> None:
        """Evict the least recently used entry (front of OrderedDict).

        Must be called while holding ``self._lock``.
        """
        if not self._cache:
            return

        key, entry = self._cache.popitem(last=False)
        logger.info(
            "Evicting LRU program: %s/%s", entry.repo_name, entry.program_name
        )
        self._close_program_safe(entry.program)

    @staticmethod
    def _close_program_safe(program) -> None:
        """Close a Ghidra Program, swallowing any exceptions."""
        try:
            if hasattr(program, "release"):
                program.release(None)
            elif hasattr(program, "close"):
                program.close()
        except Exception:
            logger.debug("Error closing program (may already be closed)", exc_info=True)

    @staticmethod
    def _dir_size(path: Path) -> int:
        """Recursively compute the total size of a directory in bytes."""
        total = 0
        try:
            for f in path.rglob("*"):
                if f.is_file():
                    total += f.stat().st_size
        except OSError:
            pass
        return total
