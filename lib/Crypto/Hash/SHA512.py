# -*- coding: utf-8 -*-
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

from Crypto.Util.py3compat import bord

from Crypto.Util._raw_api import (load_pycryptodome_raw_lib,
                                  VoidPointer, SmartPointer,
                                  create_string_buffer,
                                  get_raw_buffer, c_size_t,
                                  c_ulong, c_uint8_ptr)

_raw_sha512_lib = load_pycryptodome_raw_lib("Crypto.Hash._SHA512",
                        """
                        int SHA512_init(void **shaState,
                                        size_t digest_size);
                        int SHA512_destroy(void *shaState);
                        int SHA512_update(void *hs,
                                          const uint8_t *buf,
                                          size_t len);
                        int SHA512_digest(const void *shaState,
                                          uint8_t *digest,
                                          size_t digest_size);
                        int SHA512_undigest(const void *shaState,
                                            const uint8_t *buf,
                                            long tb0,
                                            long tb1,
                                            long tb2,
                                            long tb3);
                        int SHA512_copy(const void *src, void *dst);

                        int SHA512_pbkdf2_hmac_assist(const void *inner,
                                            const void *outer,
                                            const uint8_t *first_digest,
                                            uint8_t *final_digest,
                                            size_t iterations,
                                            size_t digest_size);
                        """)

class SHA512Hash(object):
    """A SHA-512 hash object (possibly in its truncated version SHA-512/224 or
    SHA-512/256.
    Do not instantiate directly. Use the :func:`new` function.

    :ivar oid: ASN.1 Object ID
    :vartype oid: string

    :ivar block_size: the size in bytes of the internal message block,
                      input to the compression function
    :vartype block_size: integer

    :ivar digest_size: the size in bytes of the resulting hash
    :vartype digest_size: integer
    """

    # The internal block size of the hash algorithm in bytes.
    block_size = 128

    def __init__(self, data, truncate):
        self._truncate = truncate

        if truncate is None:
            self.oid = "2.16.840.1.101.3.4.2.3"
            self.digest_size = 64
        elif truncate == "224":
            self.oid = "2.16.840.1.101.3.4.2.5"
            self.digest_size = 28
        elif truncate == "256":
            self.oid = "2.16.840.1.101.3.4.2.6"
            self.digest_size = 32
        else:
            raise ValueError("Incorrect truncation length. It must be '224' or '256'.")

        state = VoidPointer()
        result = _raw_sha512_lib.SHA512_init(state.address_of(),
                                             c_size_t(self.digest_size))
        if result:
            raise ValueError("Error %d while instantiating SHA-512"
                             % result)
        self._state = SmartPointer(state.get(),
                                   _raw_sha512_lib.SHA512_destroy)
        if data:
            self.update(data)

    def update(self, data):
        """Continue hashing of a message by consuming the next chunk of data.

        Args:
            data (byte string/byte array/memoryview): The next chunk of the message being hashed.
        """

        result = _raw_sha512_lib.SHA512_update(self._state.get(),
                                               c_uint8_ptr(data),
                                               c_size_t(len(data)))
        if result:
            raise ValueError("Error %d while hashing data with SHA512"
                             % result)

    def digest(self):
        """Return the **binary** (non-printable) digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        bfr = create_string_buffer(self.digest_size)
        result = _raw_sha512_lib.SHA512_digest(self._state.get(),
                                               bfr,
                                               c_size_t(self.digest_size))
        if result:
            raise ValueError("Error %d while making SHA512 digest"
                             % result)

        return get_raw_buffer(bfr)

    def hexdigest(self):
        """Return the **printable** digest of the message that has been hashed so far.

        :return: The hash digest, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return "".join(["%02x" % bord(x) for x in self.digest()])

    def copy(self):
        """Return a copy ("clone") of the hash object.

        The copy will have the same internal state as the original hash
        object.
        This can be used to efficiently compute the digests of strings that
        share a common initial substring.

        :return: A hash object of the same type
        """

        clone = SHA512Hash(None, self._truncate)
        result = _raw_sha512_lib.SHA512_copy(self._state.get(),
                                             clone._state.get())
        if result:
            raise ValueError("Error %d while copying SHA512" % result)
        return clone

    def new(self, data=None):
        """Create a fresh SHA-512 hash object."""

        return SHA512Hash(data, self._truncate)


def new(data=None, truncate=None,
        undigest=None, length=None):
    """Create a new hash object.

    Args:
      data (bytes/bytearray/memoryview):
        Optional. The very first chunk of the message to hash.
        It is equivalent to an early call to :meth:`SHA512Hash.update`.
      truncate (string):
        Optional. The desired length of the digest. It can be either "224" or
        "256". If not present, the digest is 512 bits long.
        Passing this parameter is **not** equivalent to simply truncating
        the output digest.
      undigest (bytes):
        A hashed output state to 'restart' the hash from. If an argument is 
        passed, the hash object's internal state is initialised to the value
        inferred from the hash that is passed in.
      length (int):
        the length of message, in bytes, of the message that was previously hashed.

    :Return: A :class:`SHA512Hash` hash object
    """

    if undigest is None:
        return SHA512Hash(data, truncate)

    hasher = SHA512Hash(None, None)
    assert len(undigest) == 64,\
        f"Expected a 512-bit hash, got {len(undigest) * 8} bits."
    
    if length is None:
        raise TypeError("You must also provide a length for the undigest to be meaningful.")
    totbits = (length // 128) * 8
    curlen = (length % 128)
    totbits += 128 * 8 if curlen <= 119 else 128 * 8 * 2

    result = _raw_sha512_lib.SHA512_undigest(hasher._state.get(),
                                               c_uint8_ptr(undigest),
                                               c_ulong(totbits >> 0),
                                               c_ulong(totbits >> 16),
                                               c_ulong(totbits >> 32),
                                               c_ulong(totbits >> 48))

    if result:
        raise ValueError("Error %d while undigesting to SHA-512"
                         % result)
    
    return hasher


# The size of the full SHA-512 hash in bytes.
digest_size = 64

# The internal block size of the hash algorithm in bytes.
block_size = 128


def _pbkdf2_hmac_assist(inner, outer, first_digest, iterations):
    """Compute the expensive inner loop in PBKDF-HMAC."""

    assert iterations > 0

    bfr = create_string_buffer(len(first_digest));
    result = _raw_sha512_lib.SHA512_pbkdf2_hmac_assist(
                    inner._state.get(),
                    outer._state.get(),
                    first_digest,
                    bfr,
                    c_size_t(iterations),
                    c_size_t(len(first_digest)))

    if result:
        raise ValueError("Error %d with PBKDF2-HMAC assist for SHA512" % result)

    return get_raw_buffer(bfr)
