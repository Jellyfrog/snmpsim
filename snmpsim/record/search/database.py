#
# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#

import bisect
import marshal
import os
import time

from snmpsim import confdir
from snmpsim import error
from snmpsim import log

# Bump whenever the on-disk index layout changes
INDEX_VERSION = 2


class RecordIndex:
    """OID -> (offset, subtree_flag, prev_offset) index of a data file.

    The index is a plain dict persisted with `marshal` in the cache
    directory. It is loaded into memory as a whole when the data file
    is opened.
    """

    def __init__(self, text_file, text_parser):
        self._text_file = text_file
        self._text_parser = text_parser

        try:
            self._db_file = text_file[: text_file.rindex(os.path.extsep)]

        except ValueError:
            self._db_file = text_file

        self._db_file += os.path.extsep + "idx"

        self._db_file = os.path.join(
            confdir.cache,
            os.path.splitdrive(self._db_file)[1].replace(os.path.sep, "_"),
        )

        self._db = self._text = None
        self._unique_oids = False
        self._search_table = None

        self._text_file_time = 0
        self._text_file_checked = 0

    def __str__(self):
        return "Data file {}, {}".format(
            self._text_file,
            self._db is not None and "opened" or "closed",
        )

    def is_open(self):
        return self._db is not None

    def get_handles(self):
        if self.is_open():
            now = time.monotonic()

            # checking for modifications on every request is costly
            if now - self._text_file_checked >= 1:
                self._text_file_checked = now

                if self._text_file_time != os.stat(self._text_file)[8]:
                    log.info("Text file %s modified, closing" % self._text_file)
                    self.close()

        if not self.is_open():
            self.create()
            self.open()

        return self._text, self._db

    def index_needed(self, force_index_build=False):
        """Whether the index has to be (re)built"""
        try:
            db_file_time = os.stat(self._db_file)[8]

        except OSError:
            log.info(
                "Index %s does not exist for data file "
                "%s" % (self._db_file, self._text_file)
            )
            return True

        if os.stat(self._text_file)[8] >= db_file_time:
            log.info("Index %s out of date" % self._db_file)
            return True

        if force_index_build:
            log.info("Forced index rebuild %s" % self._db_file)
            return True

        return False

    def create(self, force_index_build=False, validate_data=False):
        text_file_time = os.stat(self._text_file)[8]

        if self.index_needed(force_index_build):
            self._build(validate_data)

        self._text_file_time = text_file_time

        return self

    def _build(self, validate_data):
        try:
            text = self._text_parser.open(self._text_file)

        except Exception as exc:
            raise error.SnmpsimError(
                f"Failed to open data file {self._text_file}: {exc}"
            )

        log.info(
            "Building index %s for data file %s..." % (self._db_file, self._text_file)
        )

        parse = self._text_parser.grammar.parse

        db = {}
        unique_oids = True
        line_no = 0
        offset = 0
        prev_offset = -1

        with text:
            for line_no, line in enumerate(text, 1):
                tline = line.strip()

                # skip comment or blank line
                if not tline or tline.startswith(b"#"):
                    offset += len(line)
                    continue

                try:
                    oid, tag, val = parse(line)

                except Exception as exc:
                    raise error.SnmpsimError(
                        "Data error at %s:%d: %s" % (self._text_file, line_no, exc)
                    )

                if validate_data:
                    try:
                        self._text_parser.evaluate_oid(oid)

                    except Exception as exc:
                        raise error.SnmpsimError(
                            "OID error at %s:%d: %s" % (self._text_file, line_no, exc)
                        )

                    try:
                        self._text_parser.evaluate_value(
                            oid, tag, val, dataValidation=True
                        )

                    except Exception as exc:
                        log.info("ERROR at line %s, value %r: %s" % (line_no, val, exc))

                # for lines serving subtrees, type is empty in tag field
                subtree_flag = tag[0] == ":"

                if oid in db:
                    unique_oids = False

                db[oid] = (offset, subtree_flag, prev_offset)

                # not a subtree - no back reference
                prev_offset = offset if subtree_flag else -1

                offset += len(line)

        # reference to last OID in data file
        db["last"] = (offset, False, prev_offset)

        # write atomically so concurrent readers never see a partial index
        tmp_file = "%s.%d.tmp" % (self._db_file, os.getpid())

        try:
            with open(tmp_file, "wb") as f:
                marshal.dump((INDEX_VERSION, db, unique_oids), f)

            os.replace(tmp_file, self._db_file)

        except OSError as exc:
            try:
                os.remove(tmp_file)

            except OSError:
                pass

            raise error.SnmpsimError(f"Failed to write index {self._db_file}: {exc}")

        log.info("...%d entries indexed" % line_no)

    def lookup(self, oid):
        return self._db[oid]

    def _build_search_table(self):
        # duplicate OIDs share one index entry, the file search may differ
        if not self._unique_oids:
            return False

        oids = []
        offsets = []

        for key, (offset, _, _) in self._db.items():
            if key == "last":
                continue

            try:
                oids.append(tuple(int(arc) for arc in key.split(".")))

            except ValueError:
                return False

            offsets.append(offset)

        # binary search needs strictly increasing OIDs
        if any(a >= b for a, b in zip(oids, oids[1:])):
            return False

        offsets.append(self._db["last"][0])

        return oids, offsets

    def search(self, oid):
        """Offset of the first record with OID not less than `oid`.

        Returns None if the data file can not be searched in memory
        (non-numeric, duplicate or out of order OIDs).
        """
        if self._search_table is None:
            self._search_table = self._build_search_table()

        if not self._search_table:
            return None

        oids, offsets = self._search_table

        return offsets[bisect.bisect_left(oids, tuple(oid))]

    def _load(self):
        """Returns (db, unique_oids) or None if the index is unusable"""
        try:
            with open(self._db_file, "rb") as f:
                payload = marshal.load(f)

        except (OSError, EOFError, ValueError, TypeError):
            return None

        if (
            not isinstance(payload, tuple)
            or len(payload) != 3
            or payload[0] != INDEX_VERSION
        ):
            return None

        return payload[1:]

    def open(self):
        index = self._load()

        if index is None:
            log.info("Index %s unreadable, rebuilding" % self._db_file)
            self._build(validate_data=False)
            index = self._load()

            if index is None:
                raise error.SnmpsimError(f"Failed to load index {self._db_file}")

        self._text = self._text_parser.open(self._text_file)
        self._db, self._unique_oids = index
        self._search_table = None
        self._text_file_checked = time.monotonic()

    def close(self):
        self._text.close()
        self._db = self._text = None
        self._search_table = None
