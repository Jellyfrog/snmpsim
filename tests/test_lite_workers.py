import os
import signal
import socket
import subprocess
import sys
import time

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "UPS")
PORT = 1631

p_mod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]


def get_request(request_id, oid):
    pdu = p_mod.GetRequestPDU()
    p_mod.apiPDU.set_defaults(pdu)
    p_mod.apiPDU.set_request_id(pdu, request_id)
    p_mod.apiPDU.set_varbinds(pdu, [(univ.ObjectIdentifier(oid), p_mod.Null(""))])

    msg = p_mod.Message()
    p_mod.apiMessage.set_defaults(msg)
    p_mod.apiMessage.set_community(msg, "public")
    p_mod.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def query(request_id, oid="1.3.6.1.2.1.1.1.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(get_request(request_id, oid), ("127.0.0.1", PORT))
        data, _ = sock.recvfrom(65535)

    msg, _ = decoder.decode(data, asn1Spec=p_mod.Message())
    pdu = p_mod.apiMessage.get_pdu(msg)

    return int(p_mod.apiPDU.get_request_id(pdu)), p_mod.apiPDU.get_varbinds(pdu)


def children_of(pid):
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            return [int(x) for x in f.read().split()]

    except OSError:
        return None


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
def test_workers_answer_and_shut_down(tmp_path):
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "snmpsim.commands.responder_lite",
            "--workers=2",
            f"--data-dir={DATA_DIR}",
            f"--cache-dir={tmp_path}",
            f"--agent-udpv4-endpoint=127.0.0.1:{PORT}",
            "--log-level=error",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        deadline = time.monotonic() + 30

        while True:
            try:
                query(1)
                break

            except (socket.timeout, ConnectionRefusedError):
                if time.monotonic() > deadline or proc.poll() is not None:
                    pytest.fail(proc.stderr.read().decode())

        workers = children_of(proc.pid)

        if workers is not None:
            assert len(workers) == 1

        # every request answered, whichever process picks it up
        for request_id in range(2, 42):
            rid, var_binds = query(request_id)

            assert rid == request_id
            assert str(var_binds[0][0]) == "1.3.6.1.2.1.1.1.0"
            assert str(var_binds[0][1]).startswith("APC Web/SNMP Management Card")

        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 0

        for pid in workers or ():
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)

    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
