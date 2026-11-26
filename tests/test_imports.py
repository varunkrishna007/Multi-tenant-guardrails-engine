"""AC-M1-4 / AC-P1: vendor, HTTP and storage modules are imported only inside an
``adapters/`` subpackage. Everything else may import only the standard library, pydantic,
and the engine itself.
"""

import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "guardrail_engine"

DENIED = frozenset(
    {
        # vendor SDKs and gateways
        "google", "genai", "vertexai", "litellm", "openai", "anthropic",
        "boto3", "botocore", "azure",
        # HTTP / RPC clients
        "httpx", "requests", "aiohttp", "urllib3", "grpc",
        # storage
        "psycopg", "psycopg2", "asyncpg", "sqlalchemy", "redis",
    }
)  # fmt: skip
THIRD_PARTY_ALLOWED = frozenset({"pydantic", "pydantic_core", "typing_extensions"})
STDLIB_DENIED_OUTSIDE_ADAPTERS = frozenset({"socket", "http", "urllib", "ssl", "sqlite3"})


def top_level_imports(source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def violations(root: Path) -> list[str]:
    found = []
    for path in sorted(root.rglob("*.py")):
        if "adapters" in path.relative_to(root).parts:
            continue
        for name in top_level_imports(path.read_text()):
            if name == "guardrail_engine":
                continue
            if name in DENIED or name in STDLIB_DENIED_OUTSIDE_ADAPTERS:
                found.append(f"{path.relative_to(root)}: denied import {name!r}")
            elif name not in sys.stdlib_module_names and name not in THIRD_PARTY_ALLOWED:
                found.append(f"{path.relative_to(root)}: unlisted third-party import {name!r}")
    return found


def test_no_vendor_imports_outside_adapters():
    assert violations(SRC) == []


@pytest.mark.parametrize(
    "planted",
    [
        "from google import genai\n",
        "import httpx\n",
        "import psycopg.rows\n",
        "import socket\n",
        "import some_new_dependency\n",
    ],
)
def test_detects_planted_import(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "policy").mkdir(parents=True)
    (pkg / "policy" / "compiler.py").write_text("import json\n" + planted)
    assert len(violations(pkg)) == 1


def test_adapters_may_import_vendors(tmp_path):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "decision" / "adapters").mkdir(parents=True)
    (pkg / "decision" / "adapters" / "gemini.py").write_text(
        "import httpx\nfrom google import genai\n"
    )
    assert violations(pkg) == []


# M1-04: the gateway talks to the model only through the port. Beyond the boundary above it
# may import only these modules, and nothing from an ``adapters`` subpackage, so it cannot
# reach a vendor SDK or an HTTP client even indirectly.
GATEWAY_ALLOWED = frozenset(
    {
        "__future__", "asyncio", "collections", "contextvars", "dataclasses", "datetime", "enum",
        "inspect", "logging", "math", "random", "threading", "time", "typing", "zoneinfo",
        "guardrail_engine",
    }
)  # fmt: skip


def imported_modules(source: str) -> set[str]:
    """Full dotted names of every absolute import, including ``from a import b`` as ``a.b``."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def gateway_import_violations(root: Path) -> list[str]:
    found = []
    for path in sorted((root / "gateway").rglob("*.py")):
        source = path.read_text()
        for name in sorted(top_level_imports(source)):
            if name not in GATEWAY_ALLOWED:
                found.append(f"{path.relative_to(root)}: {name!r}")
        for name in sorted(imported_modules(source)):
            if "adapters" in name.split("."):
                found.append(f"{path.relative_to(root)}: adapter import {name!r}")
    return found


def test_gateway_subpackage_exists_and_is_scanned():
    assert (SRC / "gateway" / "gateway.py").is_file()
    assert violations(SRC) == []


def test_gateway_imports_no_vendor_sdk_http_library_or_adapter():
    assert gateway_import_violations(SRC) == []


@pytest.mark.parametrize(
    "planted",
    [
        "import httpx\n",
        "from google import genai\n",
        "import socket\n",
        "import urllib.request\n",
        "import os\n",
        "from guardrail_engine.decision.adapters.gemini import GeminiDecisionModel\n",
        "from guardrail_engine.decision.adapters import gemini\n",
        "from guardrail_engine.decision import adapters\n",
        "import guardrail_engine.decision.adapters.gemini\n",
    ],
)
def test_detects_planted_import_in_gateway(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "gateway").mkdir(parents=True)
    (pkg / "gateway" / "gateway.py").write_text("import asyncio\n" + planted)
    assert gateway_import_violations(pkg)


# AC-P1 for M1-01: the policy compiler is a pure library. Beyond the boundary above, it may
# import only these modules, so no storage, HTTP, filesystem or process module can creep in.
POLICY_ALLOWED = frozenset(
    {
        "__future__", "collections", "dataclasses", "enum", "hashlib", "json", "math", "re",
        "typing", "pydantic", "guardrail_engine",
    }
)  # fmt: skip


def policy_import_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root)}: {name!r}"
        for path in sorted((root / "policy").rglob("*.py"))
        for name in sorted(top_level_imports(path.read_text()))
        if name not in POLICY_ALLOWED
    ]


def test_ac_p1_policy_compiler_imports_only_pure_modules():
    assert policy_import_violations(SRC) == []


# An import check alone misses file I/O that needs no import. The builtin
# ``open`` is always in scope, and ``.read_text()`` works on any path object handed in. So
# inside ``policy/`` these calls are flagged too, whatever object they are made on:
#   open(...), and any method named open (io.open, os.open, Path.open, ...);
#   any method whose name starts with read_ or write_ (read_text, write_bytes, ...).
IO_METHOD_PREFIXES = ("read_", "write_")


def io_calls(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            found.append(f"line {node.lineno}: open()")
        elif isinstance(func, ast.Attribute) and (
            func.attr == "open" or func.attr.startswith(IO_METHOD_PREFIXES)
        ):
            found.append(f"line {node.lineno}: .{func.attr}()")
    return found


def policy_io_call_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root)}: {call}"
        for path in sorted((root / "policy").rglob("*.py"))
        for call in io_calls(path.read_text())
    ]


def test_ac_p1_policy_package_makes_no_file_io_calls():
    assert policy_io_call_violations(SRC) == []


@pytest.mark.parametrize(
    "planted",
    [
        "data = open('floor/rules.json').read()\n",
        "with open(path, 'rb') as f:\n    pass\n",
        "import io\nf = io.open(path)\n",
        "import os\nfd = os.open(path, 0)\n",
        "f = path.open()\n",
        "text = path.read_text()\n",
        "data = Path(path).read_bytes()\n",
        "path.write_text('x')\n",
        "path.write_bytes(b'x')\n",
    ],
)
def test_ac_p1_detects_planted_file_io_call_in_policy(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "policy").mkdir(parents=True)
    (pkg / "policy" / "floor_loader.py").write_text("import json\n" + planted)
    assert len(policy_io_call_violations(pkg)) == 1


def test_ac_p1_pure_json_parsing_in_policy_is_not_flagged(tmp_path):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "policy").mkdir(parents=True)
    (pkg / "policy" / "floor_loader.py").write_text(
        "import json\ndata = json.loads(text)\nopened = is_open(x)\nreader = x.read\n"
    )
    assert policy_io_call_violations(pkg) == []


def test_ac_p1_file_io_outside_policy_is_allowed():
    """``floor_file.py`` is the floor's file reader. It sits outside ``policy/`` on purpose:
    it does make an I/O call, and neither policy check applies to it."""
    assert io_calls((SRC / "floor_file.py").read_text()) != []
    assert not (SRC / "policy" / "floor_file.py").exists()
    assert policy_io_call_violations(SRC) == []
    assert violations(SRC) == []


@pytest.mark.parametrize(
    "planted", ["import os\n", "from pathlib import Path\n", "import sqlite3\n", "import httpx\n"]
)
def test_ac_p1_detects_io_import_in_policy(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "policy").mkdir(parents=True)
    (pkg / "policy" / "compiler.py").write_text("import json\n" + planted)
    assert len(policy_import_violations(pkg)) == 1


# M1-02: the policy store. The Postgres driver is imported in exactly one module, the port
# and the in-memory store import no driver, and the policy compiler imports no storage module.
DRIVERS = frozenset({"asyncpg", "psycopg", "psycopg2", "sqlalchemy", "sqlite3", "redis"})
DRIVER_MODULE = Path("store/adapters/postgres.py")
STORAGE_PACKAGES = ("guardrail_engine.store",)


def driver_import_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root)}: {name!r}"
        for path in sorted(root.rglob("*.py"))
        if path.relative_to(root) != DRIVER_MODULE
        for name in sorted(top_level_imports(path.read_text()) & DRIVERS)
    ]


def store_core_import_violations(root: Path) -> list[str]:
    """Outside ``store/adapters/``, the store may not import a driver or its own adapters."""
    found = []
    for path in sorted((root / "store").rglob("*.py")):
        rel = path.relative_to(root)
        if "adapters" in rel.parts:
            continue
        for name in sorted(imported_modules(path.read_text())):
            if name.split(".")[0] in DRIVERS or name.startswith("guardrail_engine.store.adapters"):
                found.append(f"{rel}: {name!r}")
    return found


def policy_storage_import_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root)}: {name!r}"
        for path in sorted((root / "policy").rglob("*.py"))
        for name in sorted(imported_modules(path.read_text()))
        if name.startswith(STORAGE_PACKAGES)
    ]


def test_m1_02_database_driver_is_imported_only_by_the_postgres_store_module():
    assert (SRC / DRIVER_MODULE).is_file()
    assert "asyncpg" in top_level_imports((SRC / DRIVER_MODULE).read_text())
    assert driver_import_violations(SRC) == []


def test_m1_02_store_port_and_in_memory_store_import_no_driver():
    assert {p.name for p in (SRC / "store").glob("*.py")} >= {"port.py", "memory.py"}
    assert store_core_import_violations(SRC) == []


def test_m1_02_policy_package_imports_no_storage_module():
    assert policy_storage_import_violations(SRC) == []


@pytest.mark.parametrize(
    "where",
    ["store/port.py", "store/memory.py", "store/adapters/other.py", "decision/adapters/gemini.py"],
)
def test_m1_02_detects_driver_import_outside_the_postgres_store_module(tmp_path, where):
    pkg = tmp_path / "guardrail_engine"
    (pkg / where).parent.mkdir(parents=True)
    (pkg / where).write_text("import json\nimport asyncpg\n")
    assert len(driver_import_violations(pkg)) == 1


@pytest.mark.parametrize(
    "planted",
    [
        "import asyncpg\n",
        "from psycopg import rows\n",
        "from guardrail_engine.store.adapters.postgres import PostgresPolicyStore\n",
        "import guardrail_engine.store.adapters.postgres\n",
    ],
)
def test_m1_02_detects_driver_or_adapter_import_in_store_core(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "store").mkdir(parents=True)
    (pkg / "store" / "memory.py").write_text("import json\n" + planted)
    assert len(store_core_import_violations(pkg)) >= 1


@pytest.mark.parametrize(
    "planted",
    [
        "from guardrail_engine.store import InMemoryPolicyStore\n",
        "import guardrail_engine.store.memory\n",
        "from guardrail_engine import store\n",
    ],
)
def test_m1_02_detects_storage_import_in_policy(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "policy").mkdir(parents=True)
    (pkg / "policy" / "compiler.py").write_text("import json\n" + planted)
    assert len(policy_storage_import_violations(pkg)) >= 1


# M1-05: the Guard Service reaches the model only through the gateway and the port, and the
# policy store only through its port. Beyond the boundary above it may import only these
# modules, and nothing from an ``adapters`` subpackage: no vendor SDK, HTTP library, database
# driver or adapter, even indirectly.
GUARD_ALLOWED = frozenset(
    {
        "__future__", "asyncio", "base64", "binascii", "collections", "dataclasses",
        "datetime", "enum", "hashlib", "hmac", "json", "logging", "math", "re", "secrets",
        "time", "types", "typing", "unicodedata", "uuid", "pydantic", "guardrail_engine",
    }
)  # fmt: skip


def guard_import_violations(root: Path) -> list[str]:
    found = []
    for path in sorted((root / "guard").rglob("*.py")):
        source = path.read_text()
        for name in sorted(top_level_imports(source)):
            if name not in GUARD_ALLOWED:
                found.append(f"{path.relative_to(root)}: {name!r}")
        for name in sorted(imported_modules(source)):
            if "adapters" in name.split("."):
                found.append(f"{path.relative_to(root)}: adapter import {name!r}")
    return found


def test_m1_05_guard_subpackage_exists_and_is_scanned():
    assert (SRC / "guard" / "service.py").is_file()
    assert len(list((SRC / "guard").rglob("*.py"))) >= 5
    assert violations(SRC) == []


def test_m1_05_guard_imports_no_vendor_sdk_http_library_driver_or_adapter():
    assert guard_import_violations(SRC) == []


@pytest.mark.parametrize(
    "planted",
    [
        "import httpx\n",
        "from google import genai\n",
        "import asyncpg\n",
        "import redis\n",
        "import socket\n",
        "import urllib.request\n",
        "import os\n",
        "from guardrail_engine.decision.adapters.gemini import GeminiDecisionModel\n",
        "from guardrail_engine.store.adapters.postgres import PostgresPolicyStore\n",
        "from guardrail_engine.store import adapters\n",
        "import guardrail_engine.decision.adapters\n",
    ],
)
def test_m1_05_detects_planted_import_in_guard(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / "guard").mkdir(parents=True)
    (pkg / "guard" / "service.py").write_text("import asyncio\n" + planted)
    assert guard_import_violations(pkg)


# M1-11: the engine composition root. ``engine/`` is the one place outside an ``adapters/``
# subpackage that may import adapters (it builds the Gemini adapter and the Postgres store),
# and it is a leaf: no other engine module imports it, so the guard, gateway, policy, store
# and decision packages never depend on how the engine is wired. It still imports no vendor
# SDK, HTTP library or driver itself (``violations`` above scans it like any other module).
COMPOSITION_ROOT = "engine"


def adapter_import_violations(root: Path) -> list[str]:
    """Outside ``adapters/`` subpackages and the composition root, nothing imports an
    adapters module."""
    found = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if "adapters" in rel.parts or rel.parts[0] == COMPOSITION_ROOT:
            continue
        for name in sorted(imported_modules(path.read_text())):
            if name.startswith("guardrail_engine.") and "adapters" in name.split("."):
                found.append(f"{rel}: {name!r}")
    return found


def composition_root_import_violations(root: Path) -> list[str]:
    """Nothing outside the composition root imports it."""
    found = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if rel.parts[0] == COMPOSITION_ROOT:
            continue
        for name in sorted(imported_modules(path.read_text())):
            if name == f"guardrail_engine.{COMPOSITION_ROOT}" or name.startswith(
                f"guardrail_engine.{COMPOSITION_ROOT}."
            ):
                found.append(f"{rel}: {name!r}")
    return found


def test_m1_11_composition_root_exists_and_is_scanned():
    assert (SRC / COMPOSITION_ROOT / "factory.py").is_file()
    imports = imported_modules((SRC / COMPOSITION_ROOT / "factory.py").read_text())
    assert "guardrail_engine.decision.adapters.gemini" in imports
    assert violations(SRC) == []  # no vendor, HTTP or driver import in engine/ either


def test_m1_11_only_adapters_and_the_composition_root_import_adapters():
    assert adapter_import_violations(SRC) == []


def test_m1_11_nothing_imports_the_composition_root():
    assert composition_root_import_violations(SRC) == []


# M1-06: telemetry. The engine depends on the OpenTelemetry **API** only, and only in the
# telemetry adapter: the Guard Service talks to the telemetry port. The SDK (exporters,
# processors, providers) is the embedding process's choice and a test-only dependency here.
OTEL_MODULE = Path("telemetry/adapters/otel.py")


def otel_import_violations(root: Path) -> list[str]:
    """One finding per offending file."""
    found = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        otel = sorted(
            n for n in imported_modules(path.read_text()) if n.split(".")[0] == "opentelemetry"
        )
        if otel and rel != OTEL_MODULE:
            found.append(f"{rel}: imports {otel} outside the telemetry adapter")
        elif sdk := [n for n in otel if n.startswith("opentelemetry.sdk")]:
            found.append(f"{rel}: imports the SDK {sdk}, not only the API")
    return found


def test_m1_06_opentelemetry_api_only_and_only_in_the_telemetry_adapter():
    assert "opentelemetry" in top_level_imports((SRC / OTEL_MODULE).read_text())
    assert otel_import_violations(SRC) == []


@pytest.mark.parametrize(
    ("where", "planted"),
    [
        ("guard/service.py", "from guardrail_engine.decision.adapters.gemini import CallInfo\n"),
        ("floor_file.py", "import guardrail_engine.store.adapters.postgres\n"),
        ("policy/compiler.py", "from guardrail_engine.decision import adapters\n"),
    ],
)
def test_m1_11_detects_adapter_import_outside_the_composition_root(tmp_path, where, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / where).parent.mkdir(parents=True, exist_ok=True)
    (pkg / where).write_text("import json\n" + planted)
    assert adapter_import_violations(pkg)


def test_m1_11_composition_root_may_import_adapters(tmp_path):
    pkg = tmp_path / "guardrail_engine"
    (pkg / COMPOSITION_ROOT).mkdir(parents=True)
    (pkg / COMPOSITION_ROOT / "factory.py").write_text(
        "from guardrail_engine.decision.adapters.gemini import GeminiDecisionModel\n"
        "from guardrail_engine.store.adapters import postgres\n"
    )
    assert adapter_import_violations(pkg) == []


@pytest.mark.parametrize(
    ("where", "planted"),
    [
        ("guard/service.py", "from guardrail_engine.engine import build_engine\n"),
        ("gateway/gateway.py", "import guardrail_engine.engine.settings\n"),
        ("store/memory.py", "from guardrail_engine import engine\n"),
    ],
)
def test_m1_11_detects_import_of_the_composition_root(tmp_path, where, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / where).parent.mkdir(parents=True, exist_ok=True)
    (pkg / where).write_text("import json\n" + planted)
    assert composition_root_import_violations(pkg)


@pytest.mark.parametrize("planted", ["import httpx\n", "import asyncpg\n"])
def test_m1_11_detects_vendor_import_in_the_composition_root(tmp_path, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / COMPOSITION_ROOT).mkdir(parents=True)
    (pkg / COMPOSITION_ROOT / "factory.py").write_text("import json\n" + planted)
    assert violations(pkg)


@pytest.mark.parametrize(
    ("where", "planted"),
    [
        ("guard/service.py", "from opentelemetry import trace\n"),
        ("telemetry/port.py", "import opentelemetry.trace\n"),
        ("telemetry/adapters/otel.py", "from opentelemetry.sdk.trace import TracerProvider\n"),
    ],
)
def test_m1_06_detects_misplaced_opentelemetry_imports(tmp_path, where, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / where).parent.mkdir(parents=True)
    (pkg / where).write_text("import json\n" + planted)
    assert len(otel_import_violations(pkg)) == 1


# M3-01: the RE2 binding is imported in exactly one module, the regex adapter. Everything else,
# the policy compiler and the Guard Service included, reaches RE2 through the
# ``RegexEngine`` port (``deterministic/regex.py``), so a binding can be replaced in one place.
RE2_MODULE = Path("deterministic/adapters/google_re2.py")


def re2_import_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root)}: imports re2"
        for path in sorted(root.rglob("*.py"))
        if path.relative_to(root) != RE2_MODULE and "re2" in top_level_imports(path.read_text())
    ]


def test_m3_01_re2_is_imported_only_by_the_regex_adapter():
    assert "re2" in top_level_imports((SRC / RE2_MODULE).read_text())
    assert re2_import_violations(SRC) == []
    assert violations(SRC) == []  # and it is flagged anywhere else (see below)


def test_m3_01_policy_compiler_and_guard_use_the_port_not_the_adapter():
    compiler = imported_modules((SRC / "policy" / "compiler.py").read_text())
    assert "guardrail_engine.deterministic.regex" in compiler
    assert adapter_import_violations(SRC) == []


@pytest.mark.parametrize(
    "where", ["policy/compiler.py", "guard/service.py", "deterministic/regex.py", "pii.py"]
)
def test_m3_01_detects_re2_import_outside_the_regex_adapter(tmp_path, where):
    pkg = tmp_path / "guardrail_engine"
    (pkg / where).parent.mkdir(parents=True, exist_ok=True)
    (pkg / where).write_text("import json\nimport re2\n")
    assert len(re2_import_violations(pkg)) == 1
    assert violations(pkg)  # not an allowed third-party import either


def test_m3_01_regex_adapter_may_import_re2(tmp_path):
    pkg = tmp_path / "guardrail_engine"
    (pkg / RE2_MODULE).parent.mkdir(parents=True)
    (pkg / RE2_MODULE).write_text("import re2\n")
    assert re2_import_violations(pkg) == []
    assert violations(pkg) == []  # an adapters/ package may import a vendor library


# ``default_regex_engine`` imports the adapter by name, which the checks above can't
# see. So the name is pinned to the one adapter module, and a string import anywhere else in
# the engine (``importlib.import_module``, ``__import__``) is a finding, except that one call.
ADAPTER_MODULE_NAME = "guardrail_engine.deterministic.adapters.google_re2"
STRING_IMPORT_MODULE = Path("deterministic/regex.py")


def string_import_calls(source: str) -> list[tuple[int, str | None]]:
    """``(line, argument)`` of each ``import_module(...)`` / ``__import__(...)`` call, where
    the argument is a constant string, a bare name (its identifier), or None."""
    found: list[tuple[int, str | None]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name not in {"import_module", "__import__"}:
            continue
        arg = node.args[0] if node.args else None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            found.append((node.lineno, arg.value))
        elif isinstance(arg, ast.Name):
            found.append((node.lineno, arg.id))
        else:
            found.append((node.lineno, None))
    return found


def string_import_violations(root: Path) -> list[str]:
    found = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        for line, arg in string_import_calls(path.read_text()):
            if rel == STRING_IMPORT_MODULE and arg == "ADAPTER_MODULE":
                continue
            found.append(f"{rel}:{line}: string import of {arg!r}")
    return found


def test_m3_01_the_adapter_module_string_is_pinned_to_the_re2_adapter():
    from guardrail_engine.deterministic import regex

    assert regex.ADAPTER_MODULE == ADAPTER_MODULE_NAME
    assert (
        "guardrail_engine." + RE2_MODULE.with_suffix("").as_posix().replace("/", ".")
        == ADAPTER_MODULE_NAME
    )
    assert (SRC / RE2_MODULE).is_file()  # a moved or renamed adapter fails here


def test_m3_01_the_one_string_import_names_the_adapter_constant():
    calls = string_import_calls((SRC / STRING_IMPORT_MODULE).read_text())
    assert [arg for _, arg in calls] == ["ADAPTER_MODULE"]
    assert string_import_violations(SRC) == []


@pytest.mark.parametrize(
    ("where", "planted"),
    [
        ("guard/service.py", "import importlib\nimportlib.import_module('some.module')\n"),
        ("policy/compiler.py", "from importlib import import_module\nimport_module(name)\n"),
        ("pii.py", "__import__('httpx')\n"),
        ("deterministic/regex.py", "import importlib\nimportlib.import_module('other.module')\n"),
        ("deterministic/rules.py", "import importlib\nimportlib.import_module(ADAPTER_MODULE)\n"),
    ],
)
def test_m3_01_detects_an_extra_or_renamed_string_import(tmp_path, where, planted):
    pkg = tmp_path / "guardrail_engine"
    (pkg / where).parent.mkdir(parents=True, exist_ok=True)
    (pkg / where).write_text(planted)
    assert string_import_violations(pkg)


def test_m3_01_the_pinned_string_import_in_the_regex_module_is_allowed(tmp_path):
    pkg = tmp_path / "guardrail_engine"
    (pkg / STRING_IMPORT_MODULE).parent.mkdir(parents=True)
    (pkg / STRING_IMPORT_MODULE).write_text(
        "import importlib\nimportlib.import_module(ADAPTER_MODULE)\n"
    )
    assert string_import_violations(pkg) == []
