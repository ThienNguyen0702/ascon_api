# parameter
ASCON_AEAD_128  = 0
ASCON_AEAD_128A = 1

# --- Utility functions ---
def rotr(x: int, n: int) -> int:
    return ((x >> n) | ((x << (64 - n)) & 0xFFFFFFFFFFFFFFFF)) 

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b[:8], byteorder='big')

# permutation layers
def constant_layer(x2, rounds, counter):
    if rounds == 6:
        return x2 ^ (0x96 - (counter - 1) * 15)
    elif rounds == 8:
        return x2 ^ (0xb4 - (counter - 1) * 15)
    else:
        return x2 ^ (0xf0 - (counter - 1) * 15)

def substitution_layer(state):
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

# --- AEAD encrypt
def  ascon_encrypt(variant: int, key: bytes, nonce: bytes, adata: bytes, adlen: int,
    plaintext: bytes, ptlen: int, ciphertext: bytearray, tag: bytearray):
    if variant == ASCON_AEAD_128:
        IV = 0x80400c0600000000
        round_a = 12
        round_b = 6
        rate = 8   # bytes (64-bit)
    elif variant == ASCON_AEAD_128A:
        IV = 0x80800c0800000000
        round_a = 12
        round_b = 8
        rate = 16  # bytes (128-bit)

    # Khởi tạo state
    state = [0]*5
    state[0] = IV
    state[1] = bytes_to_int(key[0:8])
    state[2] = bytes_to_int(key[8:16])
    state[3] = bytes_to_int(nonce[0:8])
    state[4] = bytes_to_int(nonce[8:16])

    ascon_permutation(state, round_a)

    state[3] ^= bytes_to_int(key[0:8])
    state[4] ^= bytes_to_int(key[8:16])

    # Tinh so khoi va padding
    s = (adlen + rate - 1) // rate
    t = (ptlen + rate - 1) // rate
    l = ptlen % rate

    pad_ad = bytearray(s * rate)
    pad_pt = bytearray(t * rate)

    # Padding associated data
    pad_ad[:adlen] = adata[:adlen]
    pad_ad[adlen] = 0x80

    # Padding plaintext
    pad_pt[:ptlen] = plaintext[:ptlen]
    pad_pt[ptlen] = 0x80

    # Absorb associated data
    for i in range(s):
        block = pad_ad[i*rate:(i+1)*rate]
        state[0] ^= bytes_to_int(block[0:8])
        if variant == ASCON_AEAD_128A:
            state[1] ^= bytes_to_int(block[8:16])
        ascon_permutation(state, round_b)

    state[4] ^= 1

    # Absorb plaintext
    for i in range(t - 1):
        block = pad_pt[i*rate:(i+1)*rate]
        state[0] ^= bytes_to_int(block[0:8])
        if variant == ASCON_AEAD_128A:
            state[1] ^= bytes_to_int(block[8:16])

        #  ciphertext 
        for j in range(rate):
            ciphertext[i*rate + j] = ((state[0] >> (8 * (rate - 1 - j))) & 0xFF)
            if variant == ASCON_AEAD_128A:
                ciphertext[i*rate + 8 + j] = ((state[1] >> (8 * (rate - 1 - j))) & 0xFF)

        ascon_permutation(state, round_b)

    # Xử lý khối cuối
    last_block = pad_pt[(t-1)*rate : t*rate]
    state[0] ^= bytes_to_int(last_block[0:8])
    if variant == ASCON_AEAD_128A:
        state[1] ^= bytes_to_int(last_block[8:16])

    for j in range(l):
        if j < rate:
            ciphertext[(t-1)*rate + j] = (state[0] >> (56 - 8*j)) & 0xFF
        else:
            ciphertext[(t-1)*rate + j] = (state[1] >> (56 - 8*(j - 8))) & 0xFF


    # Finalization
    if variant == ASCON_AEAD_128:
        state[1] ^= bytes_to_int(key[0:8])
        state[2] ^= bytes_to_int(key[8:16])
    else:  # ASCON_AEAD_128A
        state[2] ^= bytes_to_int(key[0:8])
        state[3] ^= bytes_to_int(key[8:16])

    ascon_permutation(state, round_a)

    # Tag 
    for i in range(8):
        tag[i]     = ((state[3] >> (56 - 8*i)) & 0xFF) ^ key[i]
        tag[i + 8] = ((state[4] >> (56 - 8*i)) & 0xFF) ^ key[i + 8]
        
    return ciphertext, tag

# --- AEAD decryption
# def ascon_decrypt(variant: int, key: bytes, nonce: bytes, adata: bytes, adlen: int,
#     ciphertext: bytes, ctlen: int, plaintext: bytearray, tag: bytearray):
#     if variant == ASCON_AEAD_128:
#         IV = 0x80400c0600000000
#         round_a = 12
#         round_b = 6
#         rate = 8   # bytes (64-bit)
#     elif variant == ASCON_AEAD_128A:
#         IV = 0x80800c0800000000
#         round_a = 12
#         round_b = 8
#         rate = 16  # bytes (128-bit)

#     # Khởi tạo state
#     state = [0]*5
#     state[0] = IV
#     state[1] = bytes_to_int(key[0:8])
#     state[2] = bytes_to_int(key[8:16])
#     state[3] = bytes_to_int(nonce[0:8])
#     state[4] = bytes_to_int(nonce[8:16])

#     ascon_permutation(state, round_a)

#     state[3] ^= bytes_to_int(key[0:8])
#     state[4] ^= bytes_to_int(key[8:16])

#     # Tinh so khoi va padding
#     s = (adlen + rate - 1) // rate
#     t = (ctlen + rate - 1) // rate
#     l = ctlen % rate

#     pad_ad = bytearray(s * rate)
#     pad_ct = bytearray(t * rate)

#     # Padding associated data
#     pad_ad[:adlen] = adata[:adlen]
#     pad_ad[adlen] = 0x80

#     # Padding plaintext
#     pad_ct[:ctlen] = ciphertext[:ctlen]
#     pad_ct[ctlen] = 0x80

#     # Absorb associated data
#     for i in range(s):
#         block = pad_ad[i*rate:(i+1)*rate]
#         state[0] ^= bytes_to_int(block[0:8])
#         if variant == ASCON_AEAD_128A:
#             state[1] ^= bytes_to_int(block[8:16])
#         ascon_permutation(state, round_b)

#     state[4] ^= 1

#     # Absorb plaintext
#     for i in range(t - 1):
#         block = pad_ct[i*rate:(i+1)*rate]
#         C0 = bytes_to_int(block[0:8])
#         P0 = state[0] ^ C0
#         for j in range(8):
#             plaintext[i*rate + j] = (P0 >> (56 - 8*j)) & 0xFF

#         if variant == ASCON_AEAD_128A:
#             C1 = bytes_to_int(block[8:16])
#             P1 = state[1] ^ C1
#             for j in range(8):
#                 plaintext[i*rate + 8 + j] = (P1 >> (56 - 8*j)) & 0xFF

#         state[0] = C0
#         if variant == ASCON_AEAD_128A:
#             state[1] = C1

#         ascon_permutation(state, round_b)

#     # Xử lý khối cuối
#     last_block = pad_ct[(t-1)*rate : t*rate]
#     C0 = bytes_to_int(last_block[0:8])
#     P0 = state[0] ^ C0
#     if variant == ASCON_AEAD_128A:
#         C1 = bytes_to_int(last_block[8:16])
#         P1 = state[1] ^ C1

#     for j in range(l):
#         if j < rate:
#             plaintext[(t-1)*rate + j] = (P0 >> (56 - 8*j)) & 0xFF
#         else:
#             plaintext[(t-1)*rate + j] = (P1 >> (56 - 8*(j - 8))) & 0xFF

#     state[0] = C0
#     if variant == ASCON_AEAD_128A:
#         state[1] = C1  

#     # Finalization
#     if variant == ASCON_AEAD_128:
#         state[1] ^= bytes_to_int(key[0:8])
#         state[2] ^= bytes_to_int(key[8:16])
#     else:  # ASCON_AEAD_128A
#         state[2] ^= bytes_to_int(key[0:8])
#         state[3] ^= bytes_to_int(key[8:16])

#     ascon_permutation(state, round_a)

#     # Tag 
#     for i in range(8):
#         tag[i]     = ((state[3] >> (56 - 8*i)) & 0xFF) ^ key[i]
#         tag[i + 8] = ((state[4] >> (56 - 8*i)) & 0xFF) ^ key[i + 8]
        
#     return plaintext, tag
def ascon_decrypt(variant: int, key: bytes, nonce: bytes, adata: bytes, adlen: int,
                  ciphertext: bytes, ctlen: int, plaintext: bytearray, tag: bytearray):
    if variant == ASCON_AEAD_128:
        IV = 0x80400c0600000000
        round_a = 12
        round_b = 6
        rate = 8   # bytes (64-bit)
    elif variant == ASCON_AEAD_128A:
        IV = 0x80800c0800000000
        round_a = 12
        round_b = 8
        rate = 16  # bytes (128-bit)

    # Initialize state
    state = [0] * 5
    state[0] = IV
    state[1] = bytes_to_int(key[0:8])
    state[2] = bytes_to_int(key[8:16])
    state[3] = bytes_to_int(nonce[0:8])
    state[4] = bytes_to_int(nonce[8:16])

    ascon_permutation(state, round_a)

    state[3] ^= bytes_to_int(key[0:8])
    state[4] ^= bytes_to_int(key[8:16])

    # Calculate number of blocks
    s = (adlen + rate - 1) // rate
    t = (ctlen + rate - 1) // rate
    l = ctlen % rate

    # Padding associated data
    pad_ad = bytearray(s * rate)
    pad_ad[:adlen] = adata[:adlen]
    pad_ad[adlen] = 0x80

    # Absorb associated data
    for i in range(s):
        block = pad_ad[i * rate:(i + 1) * rate]
        state[0] ^= bytes_to_int(block[0:8])
        if variant == ASCON_AEAD_128A:
            state[1] ^= bytes_to_int(block[8:16])
        ascon_permutation(state, round_b)

    state[4] ^= 1

    # Absorb ciphertext 
    for i in range(t - 1):
        block = ciphertext[i * rate:(i + 1) * rate]
        C0 = bytes_to_int(block[0:8])
        P0 = state[0] ^ C0
        for j in range(8):
            plaintext[i * rate + j] = (P0 >> (56 - 8 * j)) & 0xFF

        if variant == ASCON_AEAD_128A:
            C1 = bytes_to_int(block[8:16])
            P1 = state[1] ^ C1
            for j in range(8):
                plaintext[i * rate + 8 + j] = (P1 >> (56 - 8 * j)) & 0xFF

        state[0] = C0
        if variant == ASCON_AEAD_128A:
            state[1] = C1

        ascon_permutation(state, round_b)

    # Process last block
    last_block = ciphertext[(t - 1) * rate: t * rate]
    C0 = bytes_to_int(last_block[0:8])
    P0 = state[0] ^ C0
    if variant == ASCON_AEAD_128A:
        C1 = bytes_to_int(last_block[8:16])
        P1 = state[1] ^ C1

    for j in range(l):
        if j < 8:
            plaintext[(t - 1) * rate + j] = (P0 >> (56 - 8 * j)) & 0xFF
        elif variant == ASCON_AEAD_128A:
            plaintext[(t - 1) * rate + j] = (P1 >> (56 - 8 * (j - 8))) & 0xFF

    pad_last = bytearray(rate)
    pad_last[:l] = plaintext[(t - 1) * rate:(t - 1) * rate + l]
    pad_last[l] = 0x80
    state[0] ^= bytes_to_int(pad_last[0:8])
    if variant == ASCON_AEAD_128A:
        state[1] ^= bytes_to_int(pad_last[8:16])

    # Finalization
    if variant == ASCON_AEAD_128:
        state[1] ^= bytes_to_int(key[0:8])
        state[2] ^= bytes_to_int(key[8:16])
    else:  # ASCON_AEAD_128A
        state[2] ^= bytes_to_int(key[0:8])
        state[3] ^= bytes_to_int(key[8:16])

    ascon_permutation(state, round_a)

    # Generate tag
    for i in range(8):
        tag[i] = ((state[3] >> (56 - 8 * i)) & 0xFF) ^ key[i]
        tag[i + 8] = ((state[4] >> (56 - 8 * i)) & 0xFF) ^ key[i + 8]

    return plaintext, tag
def main():
    key   = bytes([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f])
    nonce = bytes([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f])
    ad    = bytes([0x41,0x53,0x43,0x4f,0x4e])
    pt    = bytes([0x8b,0x86,0xd9,0x32,0x8b,0x86,0xd9,0x32])
    ct    = bytearray(len(pt))
    tag   = bytearray(16)

    ascon_encrypt(ASCON_AEAD_128A, key, nonce, ad, len(ad), pt, len(pt), ct, tag)

    print("Ciphertext:", " ".join(f"{b:02X}" for b in ct))
    print("Tag:", " ".join(f"{b:02X}" for b in tag))

    pt_dec  = bytearray(len(ct))
    tag_dec = bytearray(16)
  
    ascon_decrypt(ASCON_AEAD_128A, key, nonce, ad, len(ad), ct, len(ct), pt_dec, tag_dec)
    print("Plaintext:", " ".join(f"{b:02X}" for b in pt_dec))
    print("Tag:", " ".join(f"{b:02X}" for b in tag_dec))

if __name__ == "__main__":
    main()
