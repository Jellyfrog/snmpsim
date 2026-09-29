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


def test_search_matches_file_search(data_file):
    from snmpsim.record.search.file import get_record
    from snmpsim.record.search.file import search_record_by_oid

    index = RecordIndex(data_file, PARSER).create()
    index.open()

    for oid in (
        "0.0",
        "1.3",
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.2",
        "1.3.6.1.2.1.1.3.0.1",
        "1.3.6.1.2.1.2.0",
        "1.3.6.1.2.1.2.1.0",
        "1.3.6.1.2.1.3",
        "2.1",
    ):
        oid = univ.ObjectIdentifier(oid)
        offset = index.search(oid)

        assert offset is not None

        index._text.seek(offset)
        found = get_record(index._text)[0]

        index._text.seek(search_record_by_oid(oid, index._text, PARSER))
        assert found == get_record(index._text)[0], oid

    assert index.search(univ.ObjectIdentifier("2.1")) == len(RECORDS)

    index.close()


@pytest.mark.parametrize(
    "records",
    [
        b"1.3.6.1.2.1.1.3.0|2|1\n1.3.6.1.2.1.1.1.0|2|1\n",
        b"1.3.6.1.2.1.1.1.0|2|1\n1.3.6.1.2.1.1.1.0|2|2\n",
    ],
    ids=["out-of-order", "duplicate"],
)
def test_search_unavailable_for_unsorted_data(tmp_path, records):
    path = tmp_path / "unsorted.snmprec"
    path.write_bytes(records)

    index = RecordIndex(str(path), PARSER).create()
    index.open()

    assert index.search(univ.ObjectIdentifier("1.3.6.1.2.1.1.2.0")) is None

    index.close()


def test_search(data_file):
    index = RecordIndex(data_file, PARSER).create()
    index.open()

    def search(oid):
        return index.search(univ.ObjectIdentifier(oid))

    assert search("1.3.6.1.2.1.1.1.0") == offset_of("1.3.6.1.2.1.1.1.0")
    assert search("1.3") == offset_of("1.3.6.1.2.1.1.1.0")
    assert search("1.3.6.1.2.1.1.2") == offset_of("1.3.6.1.2.1.1.3.0")
    assert search("1.3.6.1.2.1.2.0") == offset_of("1.3.6.1.2.1.2.1.0")
    assert search("1.3.6.1.2.1.3") == len(RECORDS)

    index.close()


def test_search_falls_back_on_unordered_data(tmp_path):
    path = tmp_path / "unordered.snmprec"
    path.write_bytes(b"1.3.6.1.2.1.1.3.0|2|1\n1.3.6.1.2.1.1.1.0|2|1\n")

    index = RecordIndex(str(path), PARSER).create()
    index.open()
    assert index.search(univ.ObjectIdentifier("1.3.6.1.2.1.1.2.0")) is None
    index.close()


def test_data_file_missing_oids(data_file):
    data = datafile.DataFile(data_file, PARSER, {}).index_text()

    ((oid, val),) = data.process_var_binds(
        [(univ.ObjectIdentifier("1.3.6.1.2.1.1.2.0"), univ.Null(""))],
        nextFlag=False,
        setFlag=False,
    )
    assert val.__class__.__name__ == "NoSuchInstance"

    ((oid, val),) = data.process_var_binds(
        [(univ.ObjectIdentifier("1.3.6.1.2.1.1.2.0"), univ.Null(""))],
        nextFlag=True,
        setFlag=False,
    )
    assert str(oid) == "1.3.6.1.2.1.1.3.0"
    assert int(val) == 12345

    data.close()


def test_modified_data_file_is_reopened(data_file, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(database.time, "monotonic", lambda: clock[0])

    index = RecordIndex(data_file, PARSER).create()
    index.get_handles()

    with open(data_file, "ab") as f:
        f.write(b"1.3.6.1.2.1.3.0|2|1\n")
    bump_mtime(data_file, 10)

    # modification checks are rate limited
    clock[0] += 0.5
    _, db = index.get_handles()
    assert "1.3.6.1.2.1.3.0" not in db

    clock[0] += 1
    _, db = index.get_handles()
    assert "1.3.6.1.2.1.3.0" in db

    index.close()


def test_build_indices(tmp_path, monkeypatch):
    # use the process pool even on single CPU machines
    monkeypatch.setattr(datafile, "_available_cpus", lambda: 2)

    paths = []

    for name in ("a", "b", "c"):
        path = tmp_path / f"{name}.snmprec"
        path.write_bytes(RECORDS)
        # indices must be newer than data files, at one second resolution
        bump_mtime(path, -10)
        paths.append(str(path))

    data_files = [(path, PARSER, "x") for path in paths]

    assert datafile.build_indices(data_files) == set(paths)
    assert len(os.listdir(confdir.cache)) == 3

    for path in paths:
        assert not RecordIndex(path, PARSER).index_needed()

    # all up to date, nothing to do
    assert datafile.build_indices(data_files) == set()

    assert datafile.build_indices(data_files, force_index_build=True) == set(paths)

    index = RecordIndex(paths[0], PARSER)
    index.open()
    assert index.lookup("1.3.6.1.2.1.1.3.0")[0] == offset_of("1.3.6.1.2.1.1.3.0")
    index.close()


def test_build_indices_reports_broken_data(tmp_path, monkeypatch):
    monkeypatch.setattr(datafile, "_available_cpus", lambda: 2)

    good = tmp_path / "good.snmprec"
    good.write_bytes(RECORDS)
    broken = tmp_path / "broken.snmprec"
    broken.write_bytes(b"1.3.6.1.2.1.1.1.0|4|ok\nnot a record\n")

    with pytest.raises(error.SnmpsimError, match=r"broken\.snmprec:2"):
        datafile.build_indices([(str(good), PARSER, "g"), (str(broken), PARSER, "b")])


@pytest.mark.parametrize("log_level", ["error", "info"])
@pytest.mark.parametrize(
    "start",
    ["1.3", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2", "1.3.6.1.2.1.2", "1.3.6.1.2.1.3"],
)
def test_read_next_run_matches_chained_getnext(data_file, start, log_level):
    log.set_level(log_level)

    try:
        data = datafile.DataFile(data_file, PARSER, {}).index_text()
        ctx = {"nextFlag": True, "setFlag": False}

        def render(var_binds):
            return [(str(oid), val.prettyPrint()) for oid, val in var_binds]

        expected = []
        var_bind = (univ.ObjectIdentifier(start), univ.Null(""))

        for _ in range(8):
            (var_bind,) = data.process_var_binds([var_bind], **ctx)
            expected.append(var_bind)

        run = data.read_next_run(univ.ObjectIdentifier(start), univ.Null(""), 8, **ctx)

        assert render(run) == render(expected)

        data.close()

    finally:
        log.set_level("info")
