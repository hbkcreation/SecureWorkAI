"""Read the real application icon stored inside a Windows .exe/.dll (PE file).

Pure Python and read-only: the file is memory-mapped and only its resource table is parsed,
nothing is executed. Works on any OS, so it can be tested off-Windows. Every offset is
bounds-checked and any malformed file simply returns None.
"""
from __future__ import annotations

import mmap
import os
import struct

RT_ICON, RT_GROUP_ICON = 3, 14
_MAX_ENTRIES = 512


class _Bad(Exception):
    pass


class _PE:
    def __init__(self, buf) -> None:
        self.b = buf
        if self.u16(0) != 0x5A4D:
            raise _Bad("not MZ")
        pe = self.u32(0x3C)
        if self.u32(pe) != 0x00004550:
            raise _Bad("not PE")
        n_sections = self.u16(pe + 6)
        opt_size = self.u16(pe + 20)
        opt = pe + 24
        magic = self.u16(opt)
        dd = opt + (96 if magic == 0x10B else 112)  # data directories start
        if magic not in (0x10B, 0x20B):
            raise _Bad("bad optional header")
        self.res_rva = self.u32(dd + 2 * 8)
        self.res_size = self.u32(dd + 2 * 8 + 4)
        if not self.res_rva:
            raise _Bad("no resources")
        sec = opt + opt_size
        self.sections = []
        for i in range(min(n_sections, 96)):
            o = sec + i * 40
            vsize, va, rawsize, rawptr = self.u32(o + 8), self.u32(o + 12), self.u32(o + 16), self.u32(o + 20)
            self.sections.append((va, max(vsize, rawsize), rawptr))
        self.res_off = self.rva_to_off(self.res_rva)

    def u16(self, o: int) -> int:
        if o < 0 or o + 2 > len(self.b):
            raise _Bad("oob")
        return struct.unpack_from("<H", self.b, o)[0]

    def u32(self, o: int) -> int:
        if o < 0 or o + 4 > len(self.b):
            raise _Bad("oob")
        return struct.unpack_from("<I", self.b, o)[0]

    def rva_to_off(self, rva: int) -> int:
        for va, size, raw in self.sections:
            if va <= rva < va + size:
                return raw + (rva - va)
        raise _Bad("rva")

    def entries(self, dir_off: int) -> list[tuple[int, int]]:
        """(name_or_id, target) pairs of a resource directory; named entries first (as Windows lists them)."""
        named, ids = self.u16(dir_off + 12), self.u16(dir_off + 14)
        out = []
        for i in range(min(named + ids, _MAX_ENTRIES)):
            o = dir_off + 16 + i * 8
            out.append((self.u32(o), self.u32(o + 4)))
        return out

    def child_dir(self, target: int) -> int:
        if not target & 0x80000000:
            raise _Bad("expected directory")
        return self.res_off + (target & 0x7FFFFFFF)

    def first_leaf_data(self, target: int) -> bytes:
        """Follow directories to the first data entry and return its bytes."""
        for _ in range(4):
            if not target & 0x80000000:
                break
            entries = self.entries(self.res_off + (target & 0x7FFFFFFF))
            if not entries:
                raise _Bad("empty")
            target = entries[0][1]
        o = self.res_off + target
        rva, size = self.u32(o), self.u32(o + 4)
        start = self.rva_to_off(rva)
        if size > 8 * 1024 * 1024 or start + size > len(self.b):
            raise _Bad("data size")
        return bytes(self.b[start:start + size])

    def type_dir(self, rtype: int) -> int | None:
        for name, target in self.entries(self.res_off):
            if name == rtype:
                return self.child_dir(target)
        return None


def extract_icon_ico(path: str) -> bytes | None:
    """Return a single-image .ico (the best/largest image of the app's main icon group), or None."""
    try:
        if os.path.getsize(path) < 1024:
            return None
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            pe = _PE(buf)
            groups, icons = pe.type_dir(RT_GROUP_ICON), pe.type_dir(RT_ICON)
            if groups is None or icons is None:
                return None
            group_entries = pe.entries(groups)
            if not group_entries:
                return None
            grp = pe.first_leaf_data(group_entries[0][1])  # first group = the app's main icon
            count = struct.unpack_from("<H", grp, 4)[0]
            icon_by_id = {name: target for name, target in pe.entries(icons)}
            best = None
            for i in range(min(count, 32)):
                w, h, _cc, _r, _pl, bits, _size, icon_id = struct.unpack_from("<BBBBHHIH", grp, 6 + i * 14)
                px = (w or 256) * (h or 256)
                if icon_id not in icon_by_id:
                    continue
                score = (min(px, 256 * 256), bits)
                if best is None or score > best[0]:
                    best = (score, w, h, bits, icon_id)
            if best is None:
                return None
            _s, w, h, bits, icon_id = best
            data = pe.first_leaf_data(icon_by_id[icon_id])
            header = struct.pack("<HHH", 0, 1, 1)
            entry = struct.pack("<BBBBHHII", w, h, 0, 0, 1, bits, len(data), 22)
            return header + entry + data
    except (_Bad, OSError, ValueError, struct.error):
        return None
