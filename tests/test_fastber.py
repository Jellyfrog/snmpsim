import glob
import os

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905

from snmpsim import fastber
from snmpsim.record.snmprec import SnmprecRecord

V1, V2C = api.SNMP_VERSION_1, api.SNMP_VERSION_2C

OIDS = [
    (1, 3, 6, 1, 2, 1, 1, 1, 0),
    (1, 3, 6, 1, 4, 1, 20408, 999, 1, 1, 1),
    (1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 168, 255, 255),
    (1, 3, 6, 1, 4, 1, 2**32 - 1, 2**40),
    (0, 0),
    (2, 999, 3),
]


def build_request(version, kind, oids, request_id=1234, community=b"public", **extra):
    p_mod = api.PROTOCOL_MODULES[version]

    pdu = {
        fastber.GET_REQUEST: p_mod.GetRequestPDU,
        fastber.GET_NEXT_REQUEST: p_mod.GetNextRequestPDU,
        fastber.GET_BULK_REQUEST: getattr(p_mod, "GetBulkRequestPDU", None),
        0xA3: p_mod.SetRequestPDU,
    }[kind]()

    p_mod.apiPDU.set_defaults(pdu)
    p_mod.apiPDU.set_request_id(pdu, request_id)

    if kind == fastber.GET_BULK_REQUEST:
        p_mod.apiBulkPDU.set_non_repeaters(pdu, extra.get("non_repeaters", 0))
        p_mod.apiBulkPDU.set_max_repetitions(pdu, extra.get("max_repetitions", 25))

    value = extra.get("value", p_mod.Null(""))
    p_mod.apiPDU.set_varbinds(pdu, [(univ.ObjectIdentifier(o), value) for o in oids])

    msg = p_mod.Message()
    p_mod.apiMessage.set_defaults(msg)
    p_mod.apiMessage.set_version(msg, version)
    p_mod.apiMessage.set_community(msg, community)
    p_mod.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


def reference_response(version, community, request_id, es, ei, var_binds):
    p_mod = api.PROTOCOL_MODULES[version]

    pdu = p_mod.GetResponsePDU()
    p_mod.apiPDU.set_defaults(pdu)
    p_mod.apiPDU.set_request_id(pdu, request_id)
    p_mod.apiPDU.set_error_status(pdu, es)
    p_mod.apiPDU.set_error_index(pdu, ei)
    p_mod.apiPDU.set_varbinds(pdu, var_binds)

    msg = p_mod.Message()
    p_mod.apiMessage.set_defaults(msg)
    p_mod.apiMessage.set_version(msg, version)
    p_mod.apiMessage.set_community(msg, community)
    p_mod.apiMessage.set_pdu(msg, pdu)

    return encoder.encode(msg)


@pytest.mark.parametrize("version", [V1, V2C])
@pytest.mark.parametrize("kind", [fastber.GET_REQUEST, fastber.GET_NEXT_REQUEST])
@pytest.mark.parametrize("request_id", [0, 1, 127, 128, -1, 2**31 - 1, -(2**31)])
def test_decode_get(version, kind, request_id):
    data = build_request(version, kind, OIDS, request_id)

    assert fastber.decode_request(data) == (
        version,
        b"public",
        kind,
        request_id,
        0,
        0,
        OIDS,
    )


def test_decode_bulk_and_long_lengths():
    oids = OIDS * 30  # var-bind list well over 255 octets
    community = b"c" * 300

    data = build_request(
        V2C,
        fastber.GET_BULK_REQUEST,
        oids,
        community=community,
        non_repeaters=2,
        max_repetitions=50,
    )

    assert fastber.decode_request(data) == (
        V2C,
        community,
        fastber.GET_BULK_REQUEST,
        1234,
        2,
        50,
        oids,
    )


def test_decode_empty_var_binds():
    data = build_request(V2C, fastber.GET_REQUEST, [])
    assert fastber.decode_request(data)[-1] == []


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(
            build_request(V2C, 0xA3, OIDS, value=rfc1902.Integer32(1)), id="set"
        ),
        pytest.param(
            build_request(V2C, fastber.GET_REQUEST, OIDS, value=rfc1902.Integer32(1)),
            id="non-null-value",
        ),
        pytest.param(
            build_request(V2C, fastber.GET_REQUEST, OIDS) * 2, id="two-messages"
        ),
        pytest.param(build_request(V2C, fastber.GET_REQUEST, OIDS)[:-3], id="truncated"),
        pytest.param(
            build_request(V2C, fastber.GET_REQUEST, OIDS).replace(
                b"\x02\x01\x01", b"\x02\x01\x03", 1
            ),
            id="snmpv3",
        ),
        pytest.param(
            bytes.fromhex("3080020101040670756274696300a000020100000000"), id="indefinite"
        ),
    ],
)
def test_decode_unsupported(data):
    with pytest.raises(fastber.Unsupported):
        fastber.decode_request(data)


def test_decode_unsupported_field_values():
    # values the pysnmp schema would reject or that are unusual in requests
    def request(pdu_type, request_id, field1, field2):
        def integer(v):
            return fastber._encode_tlv(0x02, fastber._encode_integer(v))

        pdu = fastber._encode_tlv(
            pdu_type,
            integer(request_id)
            + integer(field1)
            + integer(field2)
            + fastber._encode_tlv(0x30, b""),
        )
        return fastber._encode_tlv(
            0x30, integer(1) + fastber._encode_tlv(0x04, b"public") + pdu
        )

    assert fastber.decode_request(request(fastber.GET_BULK_REQUEST, 1, 0, 10))

    for data in (
        request(fastber.GET_BULK_REQUEST, 1, 0, -1),
        request(fastber.GET_BULK_REQUEST, 1, -1, 10),
        request(fastber.GET_BULK_REQUEST, 2**31, 0, 10),
        request(fastber.GET_REQUEST, 1, 5, 0),
        request(fastber.GET_NEXT_REQUEST, 1, 0, 1),
    ):
        with pytest.raises(fastber.Unsupported):
            fastber.decode_request(data)

    # GETBULK over SNMPv1
    data = request(fastber.GET_BULK_REQUEST, 1, 0, 10).replace(
        b"\x02\x01\x01", b"\x02\x01\x00", 1
    )
    with pytest.raises(fastber.Unsupported):
        fastber.decode_request(data)


VALUES = [
    rfc1902.Integer32(0),
    rfc1902.Integer32(-1),
    rfc1902.Integer32(127),
    rfc1902.Integer32(128),
    rfc1902.Integer32(-128),
    rfc1902.Integer32(-129),
    rfc1902.Integer32(2**31 - 1),
    rfc1902.Integer32(-(2**31)),
    univ.Integer(12345678),
    rfc1902.Counter32(0),
    rfc1902.Counter32(2**32 - 1),
    rfc1902.Gauge32(2**31),
    rfc1902.TimeTicks(398079840),
    rfc1902.Counter64(2**64 - 1),
    rfc1902.Counter64(0),
    rfc1902.OctetString(b""),
    rfc1902.OctetString(b"GigaEthernet0/1"),
    rfc1902.OctetString(bytes(range(256)) * 2),
    rfc1902.IpAddress("192.168.1.1"),
    rfc1902.Opaque(b"\x9f\x78\x04\x3f\x80\x00\x00"),
    rfc1902.ObjectIdentifier("1.3.6.1.4.1.20408"),
    rfc1902.ObjectIdentifier("2.999.3"),
    rfc1902.ObjectIdentifier("1.3.6.1.4.1.4294967295.1099511627776"),
    rfc1902.Bits(b"\x80"),
    univ.Null(""),
    rfc1905.noSuchObject,
    rfc1905.noSuchInstance,
    rfc1905.endOfMibView,
]


@pytest.mark.parametrize("value", VALUES, ids=lambda v: v.__class__.__name__)
def test_encode_value(value):
    assert fastber.encode_value(value) == encoder.encode(value)


@pytest.mark.parametrize("version", [V1, V2C])
@pytest.mark.parametrize("request_id", [0, 300, -5, 2**31 - 1])
def test_encode_response(version, request_id):
    values = [v for v in VALUES if version == V2C or v.tagSet[0].tagClass != 0x80]
    values = [v for v in values if version == V2C or not isinstance(v, rfc1902.Counter64)]
    var_binds = [
        (univ.ObjectIdentifier(OIDS[i % len(OIDS)]), v) for i, v in enumerate(values)
    ]

    assert fastber.encode_response(
        version, b"public", request_id, 0, 0, var_binds
    ) == reference_response(version, b"public", request_id, 0, 0, var_binds)


def test_encode_response_error_and_plain_oids():
    # SNMPv1 error response, and OIDs given as tuples (index context)
    var_binds = [((1, 3, 6, 1, 4, 1, 20408, 999, 1, 1, 1), univ.Null(""))]

    assert fastber.encode_response(
        V1, b"x" * 200, 7, 2, 1, var_binds
    ) == reference_response(V1, b"x" * 200, 7, 2, 1, var_binds)


def test_encode_response_unusual_oid():
    with pytest.raises(fastber.Unsupported):
        fastber.encode_response(V2C, b"public", 1, 0, 0, [((1,), univ.Null(""))])


def test_encode_all_bundled_record_values():
    data_dir = os.path.join(os.path.dirname(fastber.__file__), "data")
    parser = SnmprecRecord()
    count = 0

    for path in glob.glob(os.path.join(data_dir, "**", "*.snmprec"), recursive=True):
        with open(path, "rb") as f:
            for line in f:
                if not line.strip() or line.startswith(b"#"):
                    continue

                oid, tag, value = parser.grammar.parse(line)

                if ":" in tag:  # variation module records
                    continue

                _, _, value = parser.evaluate_value(oid, tag, value)

                assert fastber.encode_value(value) == encoder.encode(value), line
                count += 1

    assert count > 1000


def test_decoded_request_matches_pysnmp():
    data = build_request(V2C, fastber.GET_BULK_REQUEST, OIDS, 42, max_repetitions=3)
    p_mod = api.PROTOCOL_MODULES[V2C]
    msg, rest = decoder.decode(data, asn1Spec=p_mod.Message())
    pdu = p_mod.apiMessage.get_pdu(msg)

    version, community, pdu_type, request_id, nr, mr, oids = fastber.decode_request(
        data
    )

    assert not rest
    assert version == int(msg[0])
    assert community == msg[1].asOctets()
    assert request_id == int(p_mod.apiPDU.get_request_id(pdu))
    assert (nr, mr) == (
        int(p_mod.apiBulkPDU.get_non_repeaters(pdu)),
        int(p_mod.apiBulkPDU.get_max_repetitions(pdu)),
    )
    assert oids == [tuple(vb[0]) for vb in p_mod.apiPDU.get_varbinds(pdu)]
