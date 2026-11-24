# W1seGuy – TryHackMe Write-up

![Difficulty](https://img.shields.io/badge/difficulty-easy-green)
![Category](https://img.shields.io/badge/category-crypto-blue)

- **Room:** https://tryhackme.com/room/w1seguy
- **Author:** petesta9
- **Date:** 2026-11-22

> I redacted the flags on purpose, in line with TryHackMe's rules on publishing solutions.

## Objective

My goal was to reverse engineer the Python source code of a network service and use the weakness I found there to recover two flags from the live server (TCP port 1337).

## Tools

- `nmap` (port scan)
- `netcat`
- Python 3 (`solve.py`)

## 1. Source code analysis

The room provides the source of the service. For every incoming connection, the server:

1. Generates a **random key of 5 characters** taken from `string.ascii_letters + string.digits`, using Python's `random.choices`.
2. **XOR-encrypts the flag** with that key and sends the result, hex-encoded, to the client ("flag 1").
3. Asks the client for the encryption key. If the answer is correct, it sends the second flag ("flag 2").

### Key generation and encoding

```python
res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
key = str(res)
```

The first thing I noticed is that the key is only 5 characters long, drawn from a 62-symbol alphabet. On top of that, `random` is not a cryptographically secure generator (`secrets` should be used instead).

The encryption routine is a **repeating-key XOR**:

```python
for i in range(0, len(flag)):
    xored += chr(ord(flag[i]) ^ ord(key[i % len(key)]))

hex_encoded = xored.encode().hex()
```

Each byte of the flag is XORed with one character of the key. When the key ends, it wraps around thanks to the modulo operator (`i % len(key)`). Finally the result is converted to hexadecimal.

It's worth stressing that this is **not a hash**: XOR is reversible, and nothing is irreversibly derived from the key. What the server sends is simply the ciphertext in hex form, two hex digits per byte (a 20-character flag gives 40 hex digits, i.e. 20 bytes).

## 2. Interaction with the service

I port-scanned the target host and found one open port (1337) exposing the Python service from the source code. I connected with netcat:

```bash
nc <TARGET_IP> 1337
```

The server answers with the hex-encoded ciphertext and then waits for the key:

```
This XOR encoded text has flag 1: <40 hex digits>
What is the encryption key?
```

## 3. Exploitation: known-plaintext attack

Let:

- `F` = the flag (plaintext)
- `C` = the 5-character key
- `K` = the ciphertext received from the server (20 bytes)

From the source code I know that:

```
K[i] = F[i] XOR C[i mod 5]
```

XOR is its own inverse, so:

```
C[i mod 5] = K[i] XOR F[i]
```

I don't know `F`, but I do know the TryHackMe flag format `THM{...}`:

- `F[0..3] = "THM{"` gives me `C[0]`, `C[1]`, `C[2]`, `C[3]`.
- The last character is `}`, at index 19 for a 20-byte flag. Since `19 mod 5 == 4`, it gives me `C[4]`.

That's the whole key: the modulo makes different positions of the flag share the same key character (e.g. `4 mod 5 == 19 mod 5`), so knowing a few characters at the right positions is enough.

I first did this by hand with online hex/ASCII XOR tools, then automated it in [`solve.py`](solve.py). The script asks for the hex string sent by the server and prints the recovered key and flag 1:

```bash
$ python3 solve.py
Paste the hex string sent by the server: <hex_from_server>
Key : *****
Flag: THM{********************}
```

Sending the recovered key back to the server prints flag 2.

> The key is regenerated at every connection, so I had to recover it and submit it **within the same connection**.

## 4. Flags

| # | Flag |
|---|------|
| 1 | `THM{********************}` |
| 2 | `THM{********************}` |

## Lessons learned

- A repeating-key XOR with a short key is trivially broken as soon as part of the plaintext is known (known-plaintext attack). Flag formats like `THM{...}` give that away for free.
- Encoding, encryption and hashing are different things: hex is an encoding, XOR with a short key is a weak cipher, and a hash is one-way.
- Keys must come from a cryptographically secure source (`secrets`, `os.urandom`), be long enough, and be used with proper algorithms (e.g. AES-GCM) rather than home-made schemes.
