# --- Constants --------------------------------------------------------
rate = 8               # bytes (64-bit rate)
init_rounds = 12       # initialization/finalization rounds
inter_rounds = 6       # intermediate rounds

key_bits = 128         # bits
nonce_bits = 128       # bits
ad_bits = 40           # associated data length in bits
ct_bits = 32           # ciphertext length in bits

ad_bytes = ad_bits // 8  # 5 bytes
ct_bytes = ct_bits // 8  # 4 bytes

# --- Utility Functions -----------------------------------------------


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def bytes_to_int(b):
    return int.from_bytes(b, 'big')


def int_to_bytes(val, length):
    return val.to_bytes(length, 'big')


def reverse_bytes(data: bytes) -> bytes:
    return data[::-1]


# --- ASCON Permutation Layers ----------------------------------------
def constant_layer(x2, rounds, counter):
    """Apply round constant to x2."""
    if rounds == inter_rounds:
        return x2 ^ (0x96 - (counter - 1) * 15)
    elif rounds == 8:
        return x2 ^ (0xb4 - (counter - 1) * 15)
    else:
        return x2 ^ (0xf0 - (counter - 1) * 15)


def substitution_layer(state):
    """Non-linear S-box layer, in-place."""
    x0, x1, x2, x3, x4 = state
    x0 ^= x4; x4 ^= x3; x2 ^= x1
    t0 = (~x0) & x1
    t1 = (~x1) & x2
    t2 = (~x2) & x3
    t3 = (~x3) & x4
    t4 = (~x4) & x0
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2 & 0xFFFFFFFFFFFFFFFF
    state[:] = [x0, x1, x2, x3, x4]


def linear_layer(state):
    state[0] ^= rotr(state[0], 19) ^ rotr(state[0], 28)
    state[1] ^= rotr(state[1], 61) ^ rotr(state[1], 39)
    state[2] ^= rotr(state[2], 1) ^ rotr(state[2], 6)
    state[3] ^= rotr(state[3], 10) ^ rotr(state[3], 17)
    state[4] ^= rotr(state[4], 7) ^ rotr(state[4], 41)
    for i in range(5):
        state[i] &= 0xFFFFFFFFFFFFFFFF


def ascon_permutation(state, rounds):
    for r in range(1, rounds + 1):
        state[2] = constant_layer(state[2], rounds, r)
        substitution_layer(state)
        linear_layer(state)


# --- ASCON-128 Decryption -------------------------------------
def ascon_decrypt(key, nonce, ad, ciphertext):
    assert len(key)*8 == key_bits
    assert len(nonce)*8 == nonce_bits
    assert len(ad) == ad_bytes
    assert len(ciphertext) == ct_bytes

    # 1) Initialization
    iv = (key_bits << 56) | (rate*8 << 48) | (init_rounds << 40) | (inter_rounds << 32)
    state = [
        iv,
        bytes_to_int(key[:8]),
        bytes_to_int(key[8:]),
        bytes_to_int(nonce[:8]),
        bytes_to_int(nonce[8:])
    ]
    ascon_permutation(state, init_rounds)
    state[3] ^= bytes_to_int(key[:8])
    state[4] ^= bytes_to_int(key[8:])

    # 2) Associated Data
    if ad:
        pad_ad = ad + b"\x80" + b"\x00" * ((rate - len(ad) - 1) % rate)
        for i in range(0, len(pad_ad), rate):
            state[0] ^= bytes_to_int(pad_ad[i:i+rate])
            ascon_permutation(state, inter_rounds)
    state[4] ^= 1

    # 3) Ciphertext Processing
    pt = bytearray()
    pad_ct = ciphertext + b"\x80" + b"\x00" * ((rate - len(ciphertext) - 1) % rate)
    blocks = [pad_ct[i:i+rate] for i in range(0, len(pad_ct), rate)]
    for idx, blk in enumerate(blocks):
        c = bytes_to_int(blk)
        m = state[0] ^ c
        m_bytes = int_to_bytes(m, rate)
        last = (idx == len(blocks) - 1)
        if last and ct_bytes % rate != 0:
            ln = ct_bytes % rate
            pt += m_bytes[:ln]
            pad_last = m_bytes[:ln] + b"\x80" + b"\x00" * (rate - ln - 1)
            state[0] ^= bytes_to_int(pad_last)
        else:
            pt += m_bytes
            state[0] = c
            if not last:
                ascon_permutation(state, inter_rounds)

    # 4) Finalization
    state[3] ^= bytes_to_int(key[:8])
    state[4] ^= bytes_to_int(key[8:])
    ascon_permutation(state, init_rounds)
    state[3] ^= bytes_to_int(key[:8])
    state[4] ^= bytes_to_int(key[8:])

    return bytes(pt)


# --- Example Testbench -----------------------------------------------
if __name__ == "__main__":
    key = bytes.fromhex("2db083053e848cefa30007336c47a5a1")
    nonce = bytes.fromhex("3f3607dbce3503ba84f5843d623de056")
    ad = bytes.fromhex("4153434f4e")
    ct = bytes.fromhex("8b86d932")
    pt = ascon_decrypt(key, nonce, ad, ct)
    pt = reverse_bytes(pt)
    print("Decrypted plaintext:", pt.decode("utf-8"))

