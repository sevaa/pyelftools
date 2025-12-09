#-------------------------------------------------------------------------------
# elftools: common/utils.py
#
# Miscellaneous utilities for elftools
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from contextlib import contextmanager
from .exceptions import ELFParseError, ELFError, DWARFError
from ..construct import ConstructError, ULInt8
import os


def merge_dicts(*dicts):
    "Given any number of dicts, merges them into a new one."""
    result = {}
    for d in dicts:
        result.update(d)
    return result

def bytes2str(b):
    """Decode a bytes object into a string."""
    return b.decode('latin-1')

def bytelist2string(bytelist):
    """ Convert a list of byte values (e.g. [0x10 0x20 0x00]) to a bytes object
        (e.g. b'\x10\x20\x00').
    """
    return b''.join(bytes((b,)) for b in bytelist)


def struct_parse(struct, stream, stream_pos=None):
    """ Convenience function for using the given struct to parse a stream.
        If stream_pos is provided, the stream is seeked to this position before
        the parsing is done. Otherwise, the current position of the stream is
        used.
        Wraps the error thrown by construct with ELFParseError.
    """
    try:
        if stream_pos is not None:
            stream.seek(stream_pos)
        return struct.parse_stream(stream)
    except ConstructError as e:
        raise ELFParseError(str(e))


def parse_cstring_from_stream(stream, stream_pos=None):
    """ Parse a C-string from the given stream. The string is returned without
        the terminating \x00 byte. If the terminating byte wasn't found, None
        is returned (the stream is exhausted).
        If stream_pos is provided, the stream is seeked to this position before
        the parsing is done. Otherwise, the current position of the stream is
        used.
        Note: a bytes object is returned here, because this is what's read from
        the binary file.
    """
    if isinstance(stream, DebugSectionStream):
        return stream.parse_cstring(stream_pos)
    
    if stream_pos is not None:
        stream.seek(stream_pos)
    CHUNKSIZE = 64
    chunks = []
    found = False
    while True:
        chunk = stream.read(CHUNKSIZE)
        end_index = chunk.find(b'\x00')
        if end_index >= 0:
            chunks.append(chunk[:end_index])
            found = True
            break
        else:
            chunks.append(chunk)
        if len(chunk) < CHUNKSIZE:
            break
    return b''.join(chunks) if found else None


def elf_assert(cond, msg=''):
    """ Assert that cond is True, otherwise raise ELFError(msg)
    """
    _assert_with_exception(cond, msg, ELFError)


def dwarf_assert(cond, msg=''):
    """ Assert that cond is True, otherwise raise DWARFError(msg)
    """
    _assert_with_exception(cond, msg, DWARFError)


@contextmanager
def preserve_stream_pos(stream):
    """ Usage:
        # stream has some position FOO (return value of stream.tell())
        with preserve_stream_pos(stream):
            # do stuff that manipulates the stream
        # stream still has position FOO
    """
    saved_pos = stream.tell()
    yield
    stream.seek(saved_pos)


def roundup(num, bits):
    """ Round up a number to nearest multiple of 2^bits. The result is a number
        where the least significant bits passed in bits are 0.
    """
    return (num - 1 | (1 << bits) - 1) + 1

def read_blob(stream, length):
    """Read length bytes from stream, return a list of ints
    """
    return [struct_parse(ULInt8(''), stream) for i in range(length)]

def save_dwarf_section(section, filename):
    """Debug helper: dump section contents into a file
    Section is expected to be one of the debug_xxx_sec elements of DWARFInfo
    """
    stream = section.stream
    pos = stream.tell()
    stream.seek(0, os.SEEK_SET)
    section.stream.seek(0)
    with open(filename, 'wb') as file:
        data = stream.read(section.size)
        file.write(data)
    stream.seek(pos, os.SEEK_SET)

def iterbytes(b):
    """Return an iterator over the elements of a bytes object.

    For example, for b'abc' yields b'a', b'b' and then b'c'.
    """
    for i in range(len(b)):
        yield b[i:i+1]

def bytes2hex(b, sep=''):
    if not sep:
        return b.hex()
    return sep.join(map('{:02x}'.format, b))

class DebugSectionStream:
    """A drop-in replacement for a read only BytesIO with access
    to the underlying buffer, with the least amount of memory copying.
    read() on this returns slices of the underlying buffer; if that's a memoryview,
    the slices will be memoryviews also.
    """
    __slots__ = ('buffer', 'pos', 'section_name')
    def __init__(self, buf, name = None):
        self.buffer = buf
        self.pos = 0
        self.section_name = name

    def tell(self):
        return self.pos
    
    def seek(self, offset, whence = os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.pos = offset
        elif whence == os.SEEK_CUR:
            self.pos += offset
        elif whence == os.SEEK_END:
            self.pos = len(self.buffer) + offset
        else:
            raise ValueError()
        
    def read(self, length):
        n = len(self.buffer)
        pos = self.pos
        if pos >= n:
            r = b''
            length = 0
        else:
            if pos + length > n:
                length = n - pos
            r = self.buffer[pos:pos + length]
        self.pos = pos + length
        return r
    
    def getbuffer(self):
        """For compatibility with BytesIO
        """
        return self.buffer
    
    def getvalue(self):
        """For compatibility with BytesIO
        """
        return self.buffer
    
    def parse_cstring(self, stream_pos=None):
        """Helper for parse_cstring_from_stream
        """
        if stream_pos is not None:
            self.pos = stream_pos
        n = len(self.buffer)
        if self.pos >= n:
            return None
        # No find() in memoryview
        end_pos = next((i for i in range(self.pos, n) if self.buffer[i] == 0), None)
        if end_pos is not None:
            r = bytes(self.buffer[self.pos:end_pos])
            self.pos = end_pos + 1
        else:
            r = None
            self.pos = len(self.buffer)
        return r
    
def to_bytes(b):
    """Takes a buffer, wraps in bytes if it isn't one already
    """
    return b if isinstance(b, bytes) else bytes(b)

#------------------------- PRIVATE -------------------------

def _assert_with_exception(cond, msg, exception_type):
    if not cond:
        raise exception_type(msg)
