#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
import asyncio
import importlib
import math
import os
import sys
import threading

import pysnmp
import pyasn1

try:
    import pysmi

except ImportError:  # optional, only needed for MIB compilation
    pysmi = None

import snmpsim

TITLE = """\
SNMP Simulator version {}, written by Ilya Etingof <etingof@gmail.com>
Using foundation libraries: pysmi {}, pysnmp {}, pyasn1 {}.
Python interpreter: {}
Documentation and support at https://www.pysnmp.com/snmpsim
""".format(
    snmpsim.__version__,
    pysmi.__version__ if pysmi else "n/a",
    pysnmp.__version__,
    pyasn1.__version__,
    sys.version,
)


def _cgroup_cpu_limit(root="/sys/fs/cgroup"):
    """CPU quota of this process's cgroup as a number of CPUs or None"""
    limits = []

    # cgroup v2: "<quota> <period>" or "max <period>" in cpu.max of the
    # process's cgroup and of its ancestors
    try:
        with open("/proc/self/cgroup") as f:
            path = next(
                (line[3:].strip() for line in f if line.startswith("0::")), None
            )

    except OSError:
        path = None

    if path is not None:
        path = path.strip("/")

        while True:
            try:
                with open(os.path.join(root, path, "cpu.max")) as f:
                    quota, period = f.read().split()

                if quota != "max":
                    limits.append(int(quota) / int(period))

            except (OSError, ValueError):
                pass

            if not path:
                break

            path = os.path.dirname(path)

    # cgroup v1, as mounted inside a container
    try:
        with open(os.path.join(root, "cpu", "cpu.cfs_quota_us")) as f:
            quota = int(f.read())

        with open(os.path.join(root, "cpu", "cpu.cfs_period_us")) as f:
            period = int(f.read())

        if quota > 0 and period > 0:
            limits.append(quota / period)

    except (OSError, ValueError):
        pass

    return min(limits) if limits else None


def available_cpus():
    """Number of CPUs this process can use, honouring container CPU limits"""
    try:
        cpus = len(os.sched_getaffinity(0))

    except AttributeError:  # not available on all platforms
        cpus = os.cpu_count() or 1

    limit = _cgroup_cpu_limit()

    if limit is not None:
        cpus = min(cpus, max(1, math.ceil(limit)))

    return cpus


def try_load(module, package=None):
    """Try to load given module, return `None` on failure"""
    try:
        return importlib.import_module(module, package)

    except ImportError:
        return


def split(val, sep):
    """Split a string into a list based on a separator"""
    for x in (3, 2, 1):
        if val.find(sep * x) != -1:
            return val.split(sep * x)

    return [val]


def run_in_new_loop(coroutine):
    """Run a coroutine in a new event loop and return its result"""
    result = None

    def run():
        nonlocal result
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            result = new_loop.run_until_complete(coroutine)
        finally:
            new_loop.close()

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()

    return result



def _tlv_size(length):
    """Size of a BER TLV with a one-octet tag and `length` octets of value"""
    return 2 + length if length < 0x80 else 2 + (length.bit_length() + 7) // 8 + length


def _oid_size_bound(oid):
    arcs = len(oid)

    # sub-identifiers below 2**35 take at most 5 octets
    if not arcs or max(oid) < 0x800000000:
        return 5 * arcs

    return sum((arc.bit_length() + 6) // 7 or 1 for arc in oid)


def _varbind_size_bound(var_bind):
    """Cheap upper bound of the BER-encoded size of a var-bind"""
    encoded = getattr(var_bind, "encoded", None)

    if encoded is not None:
        return len(encoded)

    from pyasn1.type import univ

    oid, value = var_bind

    if not value.isValue:
        value_size = 0  # e.g. an exception value such as endOfMibView

    elif isinstance(value, univ.ObjectIdentifier):
        value_size = _oid_size_bound(value)

    elif isinstance(value, univ.OctetString):
        value_size = len(value)

    else:
        # INTEGER-based SNMP types take at most 9 octets, NULL-likes none
        value_size = 9

    return _tlv_size(_tlv_size(_oid_size_bound(oid)) + _tlv_size(value_size))


def _varbind_size(var_bind):
    """BER-encoded size of a single var-bind"""
    encoded = getattr(var_bind, "encoded", None)

    if encoded is not None:
        return len(encoded)

    from pyasn1.codec.ber import encoder
    from pysnmp.proto import rfc1902

    oid, value = var_bind

    return _tlv_size(
        len(encoder.encode(rfc1902.ObjectName(oid))) + len(encoder.encode(value))
    )


def fit_var_binds(var_binds, max_size, min_count=0):
    """Drop trailing var-binds so their total encoded size fits `max_size`.

    RFC 3416, 4.2.3: if the GETBULK response would not fit in a message,
    the response is generated with a lesser number of variable bindings.
    At least `min_count` var-binds are always kept.
    """
    # the common case: cheap estimate shows it fits, nothing is encoded
    if sum(map(_varbind_size_bound, var_binds)) <= max_size:
        return var_binds

    total = 0

    for idx, var_bind in enumerate(var_binds):
        total += _varbind_size(var_bind)

        if total > max_size and idx >= min_count:
            return var_binds[:idx]

    return var_binds
