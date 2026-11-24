#!/usr/bin/env python3
"""W1seGuy solver: recover the 5-char XOR key via a known-plaintext attack.

Run it, paste the hex string sent by the server, and it prints the key
and the decrypted flag 1.
"""

KEY_LEN = 5
PREFIX = b"THM{"   # known start of the flag
SUFFIX = b"}"      # known end of the flag


def recover_key(ct: bytes) -> bytes:
    key = [None] * KEY_LEN
    # known plaintext at the start: positions 0..3
    for i, p in enumerate(PREFIX):
        key[i % KEY_LEN] = ct[i] ^ p
    # known plaintext at the end: last byte, index len-1
    idx = len(ct) - 1
    key[idx % KEY_LEN] = ct[idx] ^ SUFFIX[0]
    if None in key:
        raise ValueError("not enough known plaintext to recover the full key")
    return bytes(key)


def decrypt(ct: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))


def main() -> None:
    hex_ct = input("Paste the hex string sent by the server: ").strip()
    try:
        ct = bytes.fromhex(hex_ct)
    except ValueError:
        raise SystemExit("Invalid hex string.")
    if len(ct) < len(PREFIX) + len(SUFFIX):
        raise SystemExit("Ciphertext too short.")

    key = recover_key(ct)
    print(f"Key : {key.decode()}")
    print(f"Flag: {decrypt(ct, key).decode()}")


if __name__ == "__main__":
    main()
