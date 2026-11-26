"""M7-10 step 3: the local process runner. It starts the real service (uvicorn) as a subprocess on
loopback or a unix socket, with the fake model, and the remote SDK talks to it for real."""

import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time

import httpx
import pytest

pytest.importorskip("uvicorn")

from service_fixtures import TEXT

from guardrail_engine.engine.serve import (
    LIVE_KEY,
    LIVE_TOKEN,
    check_host,
    check_live_approval,
    load_settings,
    parse_args,
    read_key,
)
from guardrail_engine.guard import HmacContextVerifier
from guardrail_engine.sdk import FailureReason, GuardContext
from guardrail_engine.sdk.adapters.remote import connect

KEY = b"m7-10 runner test key, at least 32 bytes"
TENANT = "t_alpha"


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "key.bin"
    path.write_bytes(KEY)
    path.chmod(0o600)
    return path


def start(key_file, *extra, env=None):
    proc = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-m",
            "guardrail_engine.service",
            "--signing-key-file",
            str(key_file),
            "--tenant",
            TENANT,
            *extra,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**{k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}, **(env or {})},
    )
    return proc


def listening(proc) -> str:
    line = proc.stdout.readline()
    assert line, proc.stderr.read()
    return json.loads(line)["listening"]


def ctx(tenant=TENANT):
    return GuardContext(signed_context=HmacContextVerifier(KEY).issue(tenant))


def stop(proc) -> int:
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()
        raise
    finally:
        proc.stdout.close()
        proc.stderr.close()
    return proc.returncode


async def test_the_service_starts_answers_real_http_and_stops_cleanly_on_sigterm(key_file):
    proc = start(key_file)
    try:
        url = listening(proc)
        async with httpx.AsyncClient() as plain:
            assert (await plain.get(url + "/healthz")).json() == {"status": "ok"}
            assert (await plain.get(url + "/docs")).status_code == 404
        guard = connect(url)
        allowed = await guard.check("input", TEXT, ctx())
        assert allowed.released and allowed.reason == "policy"
        forged = await guard.check(
            "input", TEXT, GuardContext(signed_context=HmacContextVerifier(b"x" * 40).issue(TENANT))
        )
        assert (forged.decision, forged.reason) == ("forbidden", "context_invalid")
        other = await guard.check("input", TEXT, ctx("t_unknown"))
        assert other.released is False  # a tenant the service doesn't have
        await guard.aclose()
    finally:
        code = stop(proc)
    assert code == 0  # it drained the engine and exited, not killed by the signal


async def test_a_service_that_stopped_reads_as_guard_unreachable(key_file):
    proc = start(key_file)
    url = listening(proc)
    assert stop(proc) == 0
    guard = connect(url, margin_s=0.1)
    result = await guard.check("input", TEXT, ctx())
    assert result.failure_reason is FailureReason.GUARD_UNREACHABLE
    assert result.retryable and not result.released
    await guard.aclose()


async def test_it_can_serve_on_a_unix_socket(key_file, tmp_path):
    sock = tmp_path / "guard.sock"
    proc = start(key_file, "--uds", str(sock))
    try:
        assert listening(proc) == f"unix://{sock}"
        client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(sock)), base_url="http://guard"
        )
        guard = connect("http://guard", client=client)
        assert (await guard.check("input", TEXT, ctx())).released
        await client.aclose()
    finally:
        assert stop(proc) == 0


async def test_the_fake_model_latency_is_the_services_not_the_clients(key_file):
    proc = start(key_file, "--fake-latency-s", "0.3")
    try:
        guard = connect(listening(proc))
        started = time.perf_counter()
        assert (await guard.check("input", TEXT, ctx())).released
        assert time.perf_counter() - started >= 0.3
        await guard.aclose()
    finally:
        stop(proc)


# ------------------------------------------------------------------------ what it refuses


def refused(key_file, tmp_path, *extra, settings=None, key=None, env=None):
    args = list(extra)
    if settings is not None:
        path = tmp_path / "settings.json"
        path.write_text(json.dumps(settings))
        args += ["--settings", str(path)]
    proc = start(key if key is not None else key_file, *args, env=env)
    out, err = proc.communicate(timeout=30)
    return proc.returncode, out, err


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_it_refuses_any_environment_but_test(key_file, tmp_path, environment):
    code, out, err = refused(key_file, tmp_path, settings={"environment": environment})
    assert code != 0 and out == "" and "local simulation" in err


def test_it_refuses_a_short_signing_key(tmp_path):
    short = tmp_path / "short.bin"
    short.write_bytes(b"too short")
    short.chmod(0o600)
    code, out, err = refused(None, tmp_path, key=short)
    assert code != 0 and out == "" and "at least 32 bytes" in err


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.20", "10.0.0.5", "::", "example.com", ""])
def test_it_refuses_a_listening_address_that_is_not_loopback_before_binding(
    key_file, tmp_path, host
):
    code, out, err = refused(key_file, tmp_path, "--host", host)
    assert code != 0 and out == "" and "loopback only" in err


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_addresses_are_accepted(host):
    check_host(host)


# ------------------------------------------------------------------------ the unix socket


async def test_the_socket_is_owner_only_when_announced_and_gone_after_sigterm(key_file, tmp_path):
    sock = tmp_path / "guard.sock"
    proc = start(key_file, "--uds", str(sock))
    try:
        assert listening(proc) == f"unix://{sock}"
        assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600  # never 0666
    finally:
        assert stop(proc) == 0
    assert not sock.exists()


def test_the_socket_never_exists_with_wider_permissions(tmp_path):
    from guardrail_engine.service.adapters.uvicorn_server import bind_private_socket

    old = os.umask(0)  # even from a permissive umask
    try:
        listener, _ = bind_private_socket(tmp_path / "s.sock")
    finally:
        os.umask(old)
        listener.close()
    assert stat.S_IMODE(os.stat(tmp_path / "s.sock").st_mode) == 0o600


def test_a_stale_socket_is_replaced_and_anything_else_at_the_path_is_refused(tmp_path):
    from guardrail_engine.service.adapters.uvicorn_server import (
        SocketPathError,
        bind_private_socket,
    )

    path = tmp_path / "s.sock"
    first, _ = bind_private_socket(path)
    first.close()  # leaves the file behind, as a crash would
    second, _ = bind_private_socket(path)
    second.close()
    path.unlink()
    path.write_text("not a socket")
    with pytest.raises(SocketPathError):
        bind_private_socket(path)
    path.unlink()
    target = tmp_path / "elsewhere"
    target.write_text("x")
    path.symlink_to(target)
    with pytest.raises(SocketPathError):
        bind_private_socket(path)
    assert target.read_text() == "x"  # the link's target was not touched


def test_only_the_socket_this_process_made_is_removed(tmp_path):
    from guardrail_engine.service.adapters.uvicorn_server import (
        bind_private_socket,
        remove_socket_if_ours,
    )

    path = tmp_path / "s.sock"
    mine, identity = bind_private_socket(path)  # still open: its inode can't be reused
    other, _ = bind_private_socket(tmp_path / "other.sock")
    os.replace(tmp_path / "other.sock", path)  # another process puts its own socket there
    remove_socket_if_ours(path, identity)
    assert path.exists()  # not ours any more: left alone
    now = os.lstat(path)
    remove_socket_if_ours(path, (now.st_dev, now.st_ino))
    assert not path.exists()
    mine.close()
    other.close()


def test_a_socket_something_is_listening_on_is_not_taken_over(tmp_path):
    from guardrail_engine.service.adapters.uvicorn_server import (
        SocketPathError,
        bind_private_socket,
    )

    path = tmp_path / "s.sock"
    first, identity = bind_private_socket(path)  # listening
    with pytest.raises(SocketPathError, match="in use"):
        bind_private_socket(path)
    assert os.stat(path).st_ino == identity[1]  # untouched
    client = socket.socket(socket.AF_UNIX)
    client.connect(str(path))  # and still answering
    client.close()
    first.close()  # closed but left behind: stale now, and replaced
    second, _ = bind_private_socket(path)
    second.close()


def one_line(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.strip()]


def test_a_second_service_on_the_same_socket_is_refused_and_the_first_keeps_serving(
    key_file, tmp_path
):
    sock = tmp_path / "guard.sock"
    first = start(key_file, "--uds", str(sock))
    try:
        assert listening(first) == f"unix://{sock}"
        code, out, err = refused(key_file, tmp_path, "--uds", str(sock))
        assert code == 1 and out == ""
        assert one_line(err) == [one_line(err)[0]] and one_line(err)[0].startswith("refused: ")
        assert "in use" in err and "Traceback" not in err
        probe = socket.socket(socket.AF_UNIX)
        probe.connect(str(sock))  # the first one still has its socket
        probe.close()
    finally:
        assert stop(first) == 0


@pytest.mark.parametrize("kind", ["file", "symlink", "directory"])
def test_a_socket_path_that_holds_anything_else_is_one_refused_line(key_file, tmp_path, kind):
    path = tmp_path / "guard.sock"
    if kind == "file":
        path.write_text("not a socket")
    elif kind == "symlink":
        (tmp_path / "elsewhere").write_text("x")
        path.symlink_to(tmp_path / "elsewhere")
    else:
        path.mkdir()
    code, out, err = refused(key_file, tmp_path, "--uds", str(path))
    lines = one_line(err)
    assert code == 1 and out == "" and len(lines) == 1 and lines[0].startswith("refused: ")
    assert "Traceback" not in err
    assert path.exists() or path.is_symlink()  # nothing was removed


def test_a_socket_in_a_directory_that_does_not_exist_is_one_refused_line(key_file, tmp_path):
    code, out, err = refused(key_file, tmp_path, "--uds", str(tmp_path / "no" / "such" / "s.sock"))
    lines = one_line(err)
    assert code == 1 and out == "" and "Traceback" not in err
    assert lines[-1].startswith("refused: ")


def test_a_refused_host_is_one_line_and_exit_1(key_file, tmp_path):
    code, out, err = refused(key_file, tmp_path, "--host", "0.0.0.0")
    lines = one_line(err)
    assert code == 1 and out == "" and len(lines) == 1 and lines[0].startswith("refused: ")


def test_a_port_that_is_taken_is_a_refusal_not_a_traceback(key_file, tmp_path):
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    try:
        code, out, err = refused(key_file, tmp_path, "--port", str(taken.getsockname()[1]))
    finally:
        taken.close()
    assert code != 0 and out == "" and "Traceback" not in err


# ------------------------------------------------------------------------ the key file


def key_at(tmp_path, data, mode=0o600, name="k.bin"):
    path = tmp_path / name
    path.write_bytes(data)
    path.chmod(mode)
    return path


def test_the_key_is_the_files_raw_bytes_and_is_not_trimmed(tmp_path):
    raw = b"\n  a key with leading and trailing whitespace, 40+ bytes long  \n"
    assert read_key(key_at(tmp_path, raw)) == raw


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
def test_a_key_file_that_anyone_else_can_read_is_refused(tmp_path, mode):
    with pytest.raises(SystemExit, match="owner-only"):
        read_key(key_at(tmp_path, KEY, mode))


def test_a_key_file_that_is_a_symlink_a_directory_or_too_big_is_refused(tmp_path):
    real = key_at(tmp_path, KEY)
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    with pytest.raises(SystemExit, match="symbolic link"):
        read_key(link)
    with pytest.raises(SystemExit):
        read_key(tmp_path)
    with pytest.raises(SystemExit, match="at most 4096"):
        read_key(key_at(tmp_path, b"k" * 4097, name="big.bin"))
    assert read_key(key_at(tmp_path, b"k" * 4096, name="max.bin")) == b"k" * 4096
    with pytest.raises(SystemExit):
        read_key(tmp_path / "missing.bin")


def test_the_service_refuses_a_world_readable_key_file(tmp_path):
    code, out, err = refused(key_at(tmp_path, KEY, 0o644), tmp_path)
    assert code != 0 and out == "" and "owner-only" in err and KEY.decode() not in err


# ------------------------------------------------------------------------ the live gate


CANARY = "R72_CANARY_KEY"


def settings_with_a_project(tmp_path):
    path = tmp_path / "projects.json"
    path.write_text(json.dumps({"projects": {"dedicated": {"acme": {"key_env": CANARY}}}}))
    return path


def test_fake_mode_refuses_dedicated_projects_and_reads_no_key_variable(
    key_file, tmp_path, monkeypatch
):
    import guardrail_engine.engine.serve as serve_module

    canary_value = "canary-value-that-must-never-be-read"
    monkeypatch.setenv(CANARY, canary_value)
    reads = []

    class Spy(dict):
        def get(self, name, default=None):
            reads.append(name)
            return super().get(name, default)

        def __getitem__(self, name):
            reads.append(name)
            return super().__getitem__(name)

    async def must_not_build(*args, **kwargs):
        raise AssertionError("the engine was built")

    monkeypatch.setattr(serve_module, "build_engine", must_not_build)
    args = parse_args(
        ["--signing-key-file", str(key_file), "--settings", str(settings_with_a_project(tmp_path))]
    )
    with pytest.raises(SystemExit, match="dedicated projects"):
        import asyncio

        asyncio.run(serve_module.serve(args, Spy({CANARY: canary_value})))
    assert CANARY not in reads  # nothing asked for the variable the settings named


def test_the_refusal_of_dedicated_projects_reaches_the_process_without_the_value(
    key_file, tmp_path
):
    code, out, err = refused(
        key_file,
        tmp_path,
        env={CANARY: "canary-value-that-must-never-be-read"},
        settings={"projects": {"dedicated": {"acme": {"key_env": CANARY}}}},
    )
    assert code != 0 and out == "" and "dedicated projects" in err
    assert "canary-value" not in err and "not set" not in err  # the variable was never looked up


def test_live_refusal_does_not_print_the_approval_value(key_file, tmp_path):
    code, out, err = refused(key_file, tmp_path, "--model", "live", "--max-live-calls", "5")
    assert code != 0 and out == "" and LIVE_KEY in err and "written approval" in err
    assert LIVE_TOKEN not in err and "docs/m7-10-guard-service.md" in err


def test_live_needs_a_call_cap_and_fake_refuses_one():
    live = parse_args(["--signing-key-file", "k", "--model", "live"])
    with pytest.raises(SystemExit, match="max-live-calls"):
        check_live_approval(live, {LIVE_KEY: LIVE_TOKEN})
    zero = parse_args(["--signing-key-file", "k", "--model", "live", "--max-live-calls", "0"])
    with pytest.raises(SystemExit, match="max-live-calls"):
        check_live_approval(zero, {LIVE_KEY: LIVE_TOKEN})
    capped = parse_args(["--signing-key-file", "k", "--model", "live", "--max-live-calls", "5"])
    check_live_approval(capped, {LIVE_KEY: LIVE_TOKEN})
    fake = parse_args(["--signing-key-file", "k", "--max-live-calls", "5"])
    with pytest.raises(SystemExit, match="belongs to"):
        check_live_approval(fake, {})


def test_the_cap_is_its_own_counter_and_leaves_the_daily_limit_alone():
    assert load_settings(None, live=True).token_rate == load_settings(None).token_rate


async def test_the_cap_counts_every_send_and_nothing_goes_out_past_it():
    import asyncio

    from guardrail_engine.decision import Failed, FailureKind
    from guardrail_engine.decision.capped import CallCap, CappedDecisionModel

    class Inner:
        model_id = "inner"

        def __init__(self) -> None:
            self.sent = 0

        async def decide(self, input, questions):
            self.sent += 1
            await asyncio.sleep(0)  # others run while this one is "in the provider"
            return Failed(kind=FailureKind.UNAVAILABLE)

    inner = Inner()
    model = CappedDecisionModel(inner, CallCap(10))
    results = await asyncio.gather(*[model.decide("text", {}) for _ in range(50)])
    refused = [r for r in results if r.reason == "live_call_cap"]
    assert inner.sent == 10 and len(refused) == 40  # exactly N, however they interleave
    assert all(r.kind is FailureKind.OTHER for r in refused)
    with pytest.raises(ValueError):
        CallCap(0)


async def test_a_capped_engine_sends_exactly_n_requests_retries_included_then_fails_closed():
    from engine_fixtures import bundle, ctx, directory, settings, verifier

    from guardrail_engine.decision import FailureKind, FakeDecisionModel
    from guardrail_engine.engine import build_engine
    from guardrail_engine.engine.serve import cap_live_calls

    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel()
    )
    try:
        await engine.bootstrap_publish(bundle())
        cap = cap_live_calls(engine, 4)
        engine.model.fail_next(
            FailureKind.UNAVAILABLE, 1
        )  # the first send fails: its retry is a send
        results = [await engine.check(ctx(verifier()), "input", f"text {i}") for i in range(6)]
        assert [r.decision.value for r in results[:3]] == ["allow"] * 3
        assert all(r.decision.value == "block" for r in results[3:])
        assert all(r.reason.value == "model_failure" for r in results[3:])
        assert cap.used == cap.limit == 4
        assert len(engine.model.calls) == 4  # the failed send and its retry, then two allowed
    finally:
        await engine.shutdown()


def test_the_approval_check_is_exact():
    args = parse_args(["--signing-key-file", "k", "--model", "live", "--max-live-calls", "5"])
    with pytest.raises(SystemExit):
        check_live_approval(args, {})
    with pytest.raises(SystemExit):
        check_live_approval(args, {LIVE_KEY: "yes"})
    check_live_approval(args, {LIVE_KEY: LIVE_TOKEN})
    fake = parse_args(["--signing-key-file", "k"])
    check_live_approval(fake, {})  # the fake model needs none


def test_the_settings_reader(tmp_path):
    assert load_settings(None).environment == "test"
    bad = tmp_path / "s.json"
    bad.write_text("[]")
    with pytest.raises(SystemExit):
        load_settings(bad)
