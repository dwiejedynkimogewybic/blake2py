import struct
from dataclasses import dataclass
# CONSTANT DEFINITIONS

# Config dataclass
@dataclass(frozen=True)
class Config:
    r: int; w: int; bb: int
    R1: int; R2: int; R3: int; R4: int
    MASK: int; IV: tuple

# Permutation array
SIGMA = (
    ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
    (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3),
    (11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4),
    ( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8),
    ( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13),
    ( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9),
    (12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11),
    (13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10),
    ( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5),
    (10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0)
)

CFG_BLAKE2B = Config(
    r = 12,
    w = 64,
    bb = 128,
    R1 = 32,
    R2 = 24,
    R3 = 16,
    R4 = 63,
    MASK = 0xFFFFFFFFFFFFFFFF,
    IV = (
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    )
)

CFG_BLAKE2S = Config(
    r = 10,
    w = 32,
    bb = 64,
    R1 = 16,
    R2 = 12,
    R3 = 8,
    R4 = 7,
    MASK = 0xFFFFFFFF,
    IV = (
        0x6A09E667, 0xBB67AE85,
        0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C,
        0x1F83D9AB, 0x5BE0CD19
    )
)

# HELPER FUNCTIONS & CLASSES

class HashFormatter(bytes):
    def __str__(self):
        return self.hex()
    def __repr__(self):
        return self.hex()

# FUNCTION DEFINITIONS

# Compress function (F)
def compress(h, m, t, f, cfg):
    MASK, w, r = cfg.MASK, cfg.w, cfg.r
    R1, R2, R3, R4 = cfg.R1, cfg.R2, cfg.R3, cfg.R4

    v = list(h) + list(cfg.IV)
    v[12] = v[12] ^ (t & MASK)
    v[13] = v[13] ^ ((t >> w) & MASK)

    if f:
        v[14] = v[14] ^ MASK

    # NESTED FUNCTIONS


    # Binary rotation function
    def rot(x, y):
        return ((x >> y) | (x << (w - y))) & MASK

    # Mixing function (G)
    def mix(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & MASK
        v[d] = rot(v[d] ^ v[a], R1)

        v[c] = (v[c] + v[d]) & MASK
        v[b] = rot(v[b] ^ v[c], R2)

        v[a] = (v[a] + v[b] + y) & MASK
        v[d] = rot(v[d] ^ v[a], R3)

        v[c] = (v[c] + v[d]) & MASK
        v[b] = rot(v[b] ^ v[c], R4)

    for i in range(r):
        s = SIGMA[i % 10]

        mix(0, 4, 8, 12, m[s[0]], m[s[1]])
        mix(1, 5, 9, 13, m[s[2]], m[s[3]])
        mix(2, 6, 10, 14, m[s[4]], m[s[5]])
        mix(3, 7, 11, 15, m[s[6]], m[s[7]])

        mix(0, 5, 10, 15, m[s[8]], m[s[9]])
        mix(1, 6, 11, 12, m[s[10]], m[s[11]])
        mix(2, 7, 8, 13, m[s[12]], m[s[13]])
        mix(3, 4, 9, 14, m[s[14]], m[s[15]])

    for i in range(8):
        h[i] = h[i] ^ v[i] ^ v[i + 8]

    return h

def blake2(data, m='b', k=b'', l=None):

    # Data typecasting
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data has to be either str, bytes or bytearray")

    # Key typecasting
    if isinstance(k, str):
        k = k.encode('utf-8')
    elif not isinstance(k, (bytes, bytearray)):
        raise TypeError("Key has to be either str, bytes or bytearray")

    # Mode selection
    if m in ('b', 64):
        cfg = CFG_BLAKE2B
        if l is None:
            l = 64
    elif m in ('s', 32):
        cfg = CFG_BLAKE2S
        if l is None:
            l = 32
    else:
        raise ValueError("Invalid mode")
    max_l = cfg.bb // 2
    if not (1 <= l <= max_l):
        raise ValueError(f"Output length must be between 1 and {max_l}")

    buf = bytearray()
    kk = len(k)
    bb = cfg.bb
    max_key = max_l
    if kk > max_key:
        raise ValueError(f"Key too long: max {max_key} bytes for this variant")
    if kk>0:
        key_block = k.ljust(bb, b'\x00')
        buf.extend(key_block)

    #Adding proper message at the end of buf
    buf.extend(data)
    h = list(cfg.IV)
    h[0] = h[0] ^ 0x01010000 ^ (kk<<8) ^ l
    
    if cfg.w==64:
        word_char ='Q'
    else:
        word_char ='I'

    # If the message and key are null
    byte_counter = 0
    if len(buf) == 0:
        chunk = b'\x00' * bb
        msg_words = list(struct.unpack('<16' + word_char, chunk))
        h = compress(h, msg_words, 0, True, cfg)

    # Cuts buffer into blocks
    else:
        for i in range(0, len(buf), bb):
            chunk = buf[i : i + bb]
            f = (i + bb >= len(buf))
            if f:
                byte_counter += len(buf) - i
            else:
                byte_counter += bb

            # Padding
            if len(chunk) < bb:
                chunk = chunk.ljust(bb, b'\x00')

            # Processing
            msg_words = list(struct.unpack('<16' + word_char, chunk))
            h = compress(h, msg_words, byte_counter, f, cfg)

    # Finalization
    final_bytes=bytearray()
    for word in h:
        final_bytes.extend(struct.pack('<'+word_char, word))

    # Returning l bytes
    return HashFormatter(final_bytes[:l])