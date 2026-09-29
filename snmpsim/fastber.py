#
# This file is part of snmpsim software.
#
# License: https://www.pysnmp.com/snmpsim/license.html
#
# Minimal BER codec for SNMP v1/v2c GET, GETNEXT and GETBULK messages
#
# Decoding and encoding whole messages with pyasn1 dominates request
# handling time. This codec only handles the plain, most common request
# layout and raises Unsupported for anything else, so callers can fall
# back to the full pyasn1/pysnmp machinery.
#
from pyasn1.codec.ber import encoder
from pyasn1.type import univ

GET_REQUEST = 0xA0
GET_NEXT_REQUEST = 0xA1
GET_RESPONSE = 0xA2
GET_BULK_REQUEST = 0xA5

REQUEST_PDUS = (GET_REQUEST, GET_NEXT_REQUEST, GET_BULK_REQUEST)

_SEQUENCE = 0x30
_INTEGER = 0x02
_OCTET_STRING = 0x04
_NULL = 0x05
_OBJECT_IDENTIFIER = 0x06

# Integer, Counter32, Gauge32, TimeTicks, Counter64
_INTEGER_TAGS = frozenset((0x02, 0x41, 0x42, 0x43, 0x46))
# OctetString, IpAddress, Opaque
_OCTET_TAGS = frozenset((0x04, 0x40, 0x44))
# Null, noSuchObject, noSuchInstance, endOfMibView
_EMPTY_TAGS = frozenset((0x05, 0x80, 0x81, 0x82))


# snmprec tag -> (BER tag, min value, max value + 1)
_RECORD_INTEGERS = {
    "2": (0x02, -(2**31), 2**31),  # Integer32
    "65": (0x41, 0, 2**32),  # Counter32
    "66": (0x42, 0, 2**32),  # Gauge32
    "67": (0x43, 0, 2**32),  # TimeTicks
    "70": (0x46, 0, 2**64),  # Counter64
}

# snmprec tag -> (BER tag, max size, whether hex encoded)
_RECORD_OCTETS = {
    "4": (0x04, 65535, False),  # OctetString
    "4x": (0x04, 65535, True),
    "68": (0x44, None, False),  # Opaque
    "68x": (0x44, None, True),
}


class Unsupported(Exception):
    """Message is not handled by this codec, use pyasn1 instead"""


class EncodedVarBind:
    """Var-bind BER-encoded straight from a data file record.

    Unpacks as an (oid, value) pair of pyasn1 objects, built on first
    use by calling `evaluate`, so it can stand in for a plain var-bind.
    """

    __slots__ = ("key", "encoded", "_evaluate", "_var_bind")

    def __init__(self, key, encoded, evaluate):
        self.key = key  # OID as text, as in the data file index
        self.encoded = encoded
        self._evaluate = evaluate
        self._var_bind = None

    def _get(self):
        if self._var_bind is None:
            self._var_bind = self._evaluate()

        return self._var_bind

    def __iter__(self):
        return iter(self._get())

    def __getitem__(self, idx):
        return self._get()[idx]

    def __len__(self):
        return 2


def _header(data, idx, expected_tag=None):
    """Parse a TLV header, returns (tag, value start, value end)"""
    try:
        tag = data[idx]
        length = data[idx + 1]
        idx += 2

        if length & 0x80:
            count = length & 0x7F

            # indefinite length or unreasonably long
            if not count or count > 4:
                raise Unsupported("unsupported length encoding")

            length = int.from_bytes(data[idx : idx + count], "big")
            idx += count

    except IndexError:
        raise Unsupported("truncated message")

    end = idx + length

    if end > len(data):
        raise Unsupported("truncated message")

    if expected_tag is not None and tag != expected_tag:
        raise Unsupported(f"unexpected tag {tag:#x}")

    return tag, idx, end


def _decode_integer(data, start, end):
    if start == end:
        raise Unsupported("empty integer")

    return int.from_bytes(data[start:end], "big", signed=True)


def _decode_oid(data, start, end):
    arcs = []
    arc = 0

    for octet in data[start:end]:
        arc = (arc << 7) | (octet & 0x7F)

        if not octet & 0x80:
            arcs.append(arc)
            arc = 0

    if not arcs or data[end - 1] & 0x80:
        raise Unsupported("malformed object identifier")

    first = arcs[0]

    if first < 40:
        return (0, first, *arcs[1:])

    if first < 80:
        return (1, first - 40, *arcs[1:])

    return (2, first - 80, *arcs[1:])


def decode_request(data):
    """Decode SNMP v1/v2c GET, GETNEXT or GETBULK request message.

    Returns (version, community, pdu_type, request_id, non_repeaters,
    max_repetitions, oids) where non_repeaters and max_repetitions are
    the error-status and error-index fields for non-bulk PDUs and oids is
    a list of OID tuples.

    Raises Unsupported for anything else, including multiple messages
    and var-binds with non-NULL values.
    """
    _, idx, end = _header(data, 0, _SEQUENCE)

    if end != len(data):
        raise Unsupported("trailing data")

    _, start, idx = _header(data, idx, _INTEGER)
    version = _decode_integer(data, start, idx)

    if version not in (0, 1):
        raise Unsupported(f"SNMP version {version}")

    _, start, idx = _header(data, idx, _OCTET_STRING)
    community = bytes(data[start:idx])

    pdu_type, idx, pdu_end = _header(data, idx)

    if pdu_type not in REQUEST_PDUS or pdu_end != end:
        raise Unsupported(f"PDU type {pdu_type:#x}")

    if pdu_type == GET_BULK_REQUEST and not version:
        raise Unsupported("GETBULK over SNMPv1")

    fields = []

    for _ in range(3):
        _, start, idx = _header(data, idx, _INTEGER)
        fields.append(_decode_integer(data, start, idx))

    request_id, field1, field2 = fields

    # values the pysnmp schema would reject or that are unusual in requests
    if not -(2**31) <= request_id < 2**31:
        raise Unsupported("request-id out of range")

    if pdu_type == GET_BULK_REQUEST:
        if not (0 <= field1 < 2**31 and 0 <= field2 < 2**31):
            raise Unsupported("non-repeaters/max-repetitions out of range")

    elif field1 or field2:
        raise Unsupported("error-status/error-index set in request")

    _, idx, list_end = _header(data, idx, _SEQUENCE)

    if list_end != end:
        raise Unsupported("trailing PDU data")

    oids = []

    while idx < list_end:
        _, start, idx = _header(data, idx, _SEQUENCE)
        _, oid_start, oid_end = _header(data, start, _OBJECT_IDENTIFIER)
        _, value_start, value_end = _header(data, oid_end, _NULL)

        if value_start != value_end or value_end != idx:
            raise Unsupported("unexpected var-bind value")

        oids.append(_decode_oid(data, oid_start, oid_end))

    return (version, community, pdu_type, *fields, oids)


def _encode_tlv(tag, value):
    length = len(value)

    if length < 0x80:
        return bytes((tag, length)) + value

    length = length.to_bytes((length.bit_length() + 7) // 8, "big")

    return bytes((tag, 0x80 | len(length))) + length + value


def _encode_integer(value):
    return value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True)


def _encode_arc(arc):
    if arc < 0x80:
        return bytes((arc,))

    chunk = [arc & 0x7F]
    arc >>= 7

    while arc:
        chunk.append(0x80 | (arc & 0x7F))
        arc >>= 7

    return bytes(reversed(chunk))


# encoded sub-identifiers, by value and by text, most OIDs only have small ones
_ARCS = {arc: _encode_arc(arc) for arc in range(0x4000)}
_TEXT_ARCS = {str(arc): octets for arc, octets in _ARCS.items()}
# the first two sub-identifiers are encoded as one
_TEXT_HEADS = {
    (str(arc // 40), str(arc % 40)) if arc < 80 else ("2", str(arc - 80)): octets
    for arc, octets in _ARCS.items()
}


def _encode_oid(arcs):
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
        raise Unsupported("unusual object identifier")

    arcs = (arcs[0] * 40 + arcs[1], *arcs[2:])

    try:
        return b"".join(map(_ARCS.__getitem__, arcs))

    except KeyError:
        return b"".join(map(_encode_arc, arcs))


def _encode_text_oid(oid):
    """Encode OID given in the dotted form pyasn1 prints, e.g. "1.3.6.1".

    Raises Unsupported for other forms, like leading zeros or dots.
    """
    arcs = oid.split(".")

    try:
        return _TEXT_HEADS[arcs[0], arcs[1]] + b"".join(
            map(_TEXT_ARCS.__getitem__, arcs[2:])
        )

    except (KeyError, IndexError):
        pass

    for arc in arcs:
        if not (arc.isascii() and arc.isdigit()) or (arc[0] == "0" and arc != "0"):
            raise Unsupported("unusual object identifier")

    return _encode_oid(tuple(map(int, arcs)))


def encode_value(value):
    """BER-encode an SNMP value, falling back to pyasn1 for rare types"""
    tag_set = value.tagSet

    if len(tag_set) == 1:
        tag = tag_set[0]
        tag = tag.tagClass | tag.tagFormat | tag.tagId

        if tag in _INTEGER_TAGS:
            return _encode_tlv(tag, _encode_integer(int(value)))

        if tag in _OCTET_TAGS:
            return _encode_tlv(tag, value.asOctets())

        if tag in _EMPTY_TAGS:
            return bytes((tag, 0))

        if tag == _OBJECT_IDENTIFIER:
            try:
                return _encode_tlv(tag, _encode_oid(tuple(value)))

            except Unsupported:
                pass

    return encoder.encode(value)


def _encode_record_value(tag, value):
    spec = _RECORD_INTEGERS.get(tag)

    if spec:
        ber_tag, low, high = spec
        number = int(value)

        if not low <= number < high:
            return

        return _encode_tlv(ber_tag, _encode_integer(number))

    spec = _RECORD_OCTETS.get(tag)

    if spec:
        ber_tag, max_size, hex_encoded = spec
        octets = bytes.fromhex(value) if hex_encoded else value.encode("iso-8859-1")

        if max_size is not None and len(octets) > max_size:
            return

        return _encode_tlv(ber_tag, octets)

    if tag == "64":  # IpAddress
        # four characters are taken as raw octets by pysnmp
        if len(value) == 4:
            return

        octets = bytes(int(x) for x in value.split("."))

    elif tag == "64x":
        octets = bytes.fromhex(value)

    elif tag == "6":  # ObjectIdentifier
        if "-" in value:
            return

        try:
            return _encode_tlv(_OBJECT_IDENTIFIER, _encode_text_oid(value))

        except Unsupported:
            # pyasn1 also takes e.g. empty sub-identifiers
            arcs = tuple(int(x) for x in value.split(".") if x)

            return _encode_tlv(_OBJECT_IDENTIFIER, _encode_oid(arcs))

    elif tag == "5" and not value:  # Null
        return bytes((_NULL, 0))

    else:
        return

    if len(octets) == 4:
        return _encode_tlv(0x40, octets)


def encode_record(oid, tag, value):
    """BER-encode a var-bind from the fields of a plain snmprec record.

    Returns None for records needing the full pyasn1 based evaluation,
    e.g. variation module references, rare types or invalid values.
    """
    # only OIDs in canonical form, those are the index keys pyasn1 OIDs map to
    try:
        encoded_value = _encode_record_value(tag, value)

        if encoded_value is None:
            return

        return _encode_tlv(
            _SEQUENCE,
            _encode_tlv(_OBJECT_IDENTIFIER, _encode_text_oid(oid)) + encoded_value,
        )

    except (Unsupported, ValueError):
        return


def encode_response(
    version, community, request_id, error_status, error_index, var_binds
):
    """Encode SNMP v1/v2c GetResponse message"""
    encoded_var_binds = []

    for var_bind in var_binds:
        if type(var_bind) is EncodedVarBind:
            encoded_var_binds.append(var_bind.encoded)
            continue

        oid, value = var_bind

        if not isinstance(oid, univ.ObjectIdentifier):
            oid = univ.ObjectIdentifier(oid)

        encoded_var_binds.append(
            _encode_tlv(
                _SEQUENCE,
                _encode_tlv(_OBJECT_IDENTIFIER, _encode_oid(tuple(oid)))
                + encode_value(value),
            )
        )

    pdu = _encode_tlv(
        GET_RESPONSE,
        _encode_tlv(_INTEGER, _encode_integer(request_id))
        + _encode_tlv(_INTEGER, _encode_integer(error_status))
        + _encode_tlv(_INTEGER, _encode_integer(error_index))
        + _encode_tlv(_SEQUENCE, b"".join(encoded_var_binds)),
    )

    return _encode_tlv(
        _SEQUENCE,
        _encode_tlv(_INTEGER, _encode_integer(version))
        + _encode_tlv(_OCTET_STRING, community)
        + pdu,
    )
