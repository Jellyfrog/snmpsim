import os
import sys
import threading
import time
from snmpsim.commands.responder import main as responder_main
import pytest
from pysnmp.hlapi.asyncio import *

import asyncio

TIME_OUT = int(os.getenv("SNMPSIM_TEST_TIMEOUT", "15"))
PORT_NUMBER = 1616


@pytest.fixture(autouse=True)
def setup_args():
    original_argv = sys.argv
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data", "short-oid")
    test_args = [
        "responder.py",
        f"--data-dir={data_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{PORT_NUMBER}",
        f"--timeout={TIME_OUT}",
    ]
    sys.argv = test_args
    yield
    sys.argv = original_argv


@pytest.fixture
def run_app_in_background():
    def target():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            responder_main()
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()

    app_thread = threading.Thread(target=target)
    app_thread.start()
    time.sleep(1)
    yield
    app_thread.join(timeout=TIME_OUT)


@pytest.mark.asyncio
async def test_short_oid_bulkwalk(run_app_in_background):
    """GETBULK walk over records containing short OID values must not crash.

    The snmprec data contains OID-typed values "0" (single component) which
    cannot be BER-encoded.  These records should be dropped gracefully so
    the walk completes and valid records before them are still returned.
    """
    snmpEngine = SnmpEngine()
    try:
        authData = UsmUserData(
            "simulator",
            "auctoritas",
            "privatus",
            authProtocol=usmHMACMD5AuthProtocol,
            privProtocol=usmDESPrivProtocol,
        )

        all_results = []
        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            snmpEngine,
            authData,
            await UdpTransportTarget.create(("localhost", PORT_NUMBER), retries=0),
            ContextData(contextName=OctetString("public").asOctets()),
            0,
            10,
            ObjectType(ObjectIdentity("1.3.6.1.2.1")),
            lexicographicMode=False,
        ):
            assert errorIndication is None, f"Error: {errorIndication}"
            assert errorStatus == 0, f"Error status: {errorStatus}"
            all_results.extend(varBinds)

        # Valid records (sysDescr, sysObjectID, sysUpTime, ifSpecific.1=0.0)
        # are returned.  The two short-OID records (ifSpecific.2=0,
        # ifSpecific.3=0) are dropped via endOfMib.
        assert len(all_results) >= 4, (
            f"Expected at least 4 valid varbinds, got {len(all_results)}"
        )

    finally:
        if snmpEngine.transport_dispatcher:
            snmpEngine.transport_dispatcher.close_dispatcher()

        await asyncio.sleep(TIME_OUT)
