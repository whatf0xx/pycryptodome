from typing import Union, Optional

Buffer = Union[bytes, bytearray, memoryview]

class SHA512Hash(object):
    digest_size: int
    block_size: int
    oid: str

    def __init__(self,
                 data: Optional[Buffer],
		 truncate: Optional[str]) -> None: ...
    def update(self, data: Buffer) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def copy(self) -> SHA512Hash: ...
    def new(self, data: Optional[Buffer] = ...) -> SHA512Hash: ...

def new(data: Optional[Buffer] = ...,
        truncate: Optional[str] = ...,
        undigest: Optional[Buffer] = ...,
        length: Optional[int] = ...) -> SHA512Hash: ...
digest_size: int
block_size: int
