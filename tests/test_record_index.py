import marshal
import os

import pytest
from pyasn1.type import univ

from snmpsim import confdir
from snmpsim import datafile
from snmpsim import error
from snmpsim import log
from snmpsim import variation
from snmpsim.record.search import database
from snmpsim.record.search.database import RecordIndex

RECORDS = (
    b"# comment\n"
    b"1.3.6.1.2.1.1.1.0|4|test device\n"
    b"\n"
    b"1.3.6.1.2.1.1.3.0|67|12345\n"
    b"1.3.6.1.2.1.2|:foo|bar\n"
    b"1.3.6.1.2.1.2.1.0|2|7\n"
)

PARSER = variation.RECORD_TYPES["snmprec"]


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    log.set_logger("test", "null", force=True)
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(confdir, "cache", str(cache))


@pytest.fixture
def data_file(tmp_path):
    path = tmp_path / "public.snmprec"
    path.write_bytes(RECORDS)
    return str(path)


def offset_of(oid):
    return RECORDS.index(oid.encode() + b"|")


def bump_mtime(path, delta):
    st = os.stat(path)
    os.utime(path, (st.st_atime + delta, st.st_mtime + delta))


def test_build_and_lookup(data_file):
    index = RecordIndex(data_file, PARSER).create()
    index.open()

    assert index.lookup("1.3.6.1.2.1.1.1.0") == (
        offset_of("1.3.6.1.2.1.1.1.0"),
        False,
        -1,
    )
    assert index.lookup("1.3.6.1.2.1.1.3.0") == (
        offset_of("1.3.6.1.2.1.1.3.0"),
        False,
        -1,
    )
    # subtree record, and the record following it references it back
    assert index.lookup("1.3.6.1.2.1.2") == (offset_of("1.3.6.1.2.1.2"), True, -1)
    assert index.lookup("1.3.6.1.2.1.2.1.0") == (
        offset_of("1.3.6.1.2.1.2.1.0"),
        False,
        offset_of("1.3.6.1.2.1.2"),
    )
    assert index.lookup("last") == (len(RECORDS), False, -1)

    with pytest.raises(KeyError):
        index.lookup("1.3.6.1.2.1.1.2.0")

    index.close()
    assert not index.is_open()


def test_index_reused_when_up_to_date(data_file):
    index = RecordIndex(data_file, PARSER)
    index.create()

    # make the index clearly newer than the data file
    bump_mtime(index._db_file, 10)
    mtime = os.stat(index._db_file).st_mtime_ns

    RecordIndex(data_file, PARSER).create()
    assert os.stat(index._db_file).st_mtime_ns == mtime


def test_index_rebuilt_when_data_file_changes(data_file):
    index = RecordIndex(data_file, PARSER).create()

    with open(data_file, "ab") as f:
        f.write(b"1.3.6.1.2.1.3.0|2|1\n")
    bump_mtime(data_file, 10)

    index = RecordIndex(data_file, PARSER).create()
    index.open()
    assert index.lookup("1.3.6.1.2.1.3.0")[0] == len(RECORDS)
    index.close()


def test_forced_rebuild(data_file):
    index = RecordIndex(data_file, PARSER).create()
    bump_mtime(index._db_file, 10)
    mtime = os.stat(index._db_file).st_mtime_ns

    RecordIndex(data_file, PARSER).create(force_index_build=True)
    assert os.stat(index._db_file).st_mtime_ns != mtime


@pytest.mark.parametrize(
    "content",
    [
        b"garbage",
        b"",
        marshal.dumps((database.INDEX_VERSION + 1, {})),
    ],
    ids=["corrupt", "empty", "other-version"],
)
def test_unusable_index_is_rebuilt_on_open(data_file, content):
    index = RecordIndex(data_file, PARSER).create()

    with open(index._db_file, "wb") as f:
        f.write(content)

    index.open()
    assert index.lookup("1.3.6.1.2.1.1.3.0")[0] == offset_of("1.3.6.1.2.1.1.3.0")
    index.close()


def test_broken_record_raises(tmp_path):
    path = tmp_path / "broken.snmprec"
    path.write_bytes(b"1.3.6.1.2.1.1.1.0|4|ok\nnot a record\n")

    index = RecordIndex(str(path), PARSER)

    with pytest.raises(error.SnmpsimError, match=r"broken\.snmprec:2"):
        index.create()

    assert not os.listdir(confdir.cache)


def test_data_file_get_and_next(data_file):
    data = datafile.DataFile(data_file, PARSER, {}).index_text()
    ctx = {"nextFlag": False, "setFlag": False}

    ((oid, val),) = data.process_var_binds(
        [(univ.ObjectIdentifier("1.3.6.1.2.1.1.1.0"), univ.Null(""))], **ctx
    )
    assert str(oid) == "1.3.6.1.2.1.1.1.0"
    assert str(val) == "test device"

    ctx["nextFlag"] = True
    ((oid, val),) = data.process_var_binds(
        [(univ.ObjectIdentifier("1.3.6.1.2.1.1.1.0"), univ.Null(""))], **ctx
    )
    assert str(oid) == "1.3.6.1.2.1.1.3.0"
    assert int(val) == 12345

    ((oid, val),) = data.process_var_binds(
        [(univ.ObjectIdentifier("1.3.6.1.2.1.2.1.0"), univ.Null(""))], **ctx
    )
    assert val.__class__.__name__ == "EndOfMibView"

    data.close()
