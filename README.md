# cipher

Encrypt text documents with a keyphrase. AES-256-GCM, scrypt key derivation,
one file in and one file out.

```bash
pip3 install cryptography      # the only dependency
chmod +x cipher.py
```

## Use

```bash
./cipher.py encrypt journal.txt -k "sunset-ladder-quiet-anchor-42"
# journal.txt -> journal.txt.cipher

./cipher.py decrypt journal.txt.cipher -k "sunset-ladder-quiet-anchor-42"
# journal.txt.cipher -> journal.txt
```

The same keyphrase does both directions. Several files at once is fine — they
all take the same keyphrase:

```bash
./cipher.py encrypt notes/*.txt -k "my keyphrase"
```

### Where the keyphrase comes from

| Option | When to use it |
|---|---|
| `-k "phrase"` | Quick and scriptable. **Lands in your shell history** and is visible in `ps`. |
| *(nothing)* | Prompts without echoing, and asks twice on encrypt. Safest for real documents. |
| `--keyphrase-env VAR` | Automation. Keeps it off the command line. |
| `--keyphrase-file PATH` | Reads the first line of a file. Good with a `chmod 600` file. |

A leading space hides a command from history in most shells (`HISTCONTROL=ignorespace`
in bash, `setopt histignorespace` in zsh), which is a decent middle ground with `-k`.

### Other flags

```
-o PATH          output path (single input only)
-f, --force      overwrite an existing output file
--remove-source  delete the plaintext after encrypting
--log-n N        scrypt cost exponent, default 17
info             print a file's header without decrypting it
```

## Things worth knowing

**Lose the keyphrase and the document is gone.** There is no recovery, no reset,
no master key. That is the point of the design, and it means a typo in a
keyphrase you only typed once is a permanent problem. The interactive prompt
asks twice for exactly this reason; `-k` cannot, so check it.

**`--remove-source` unlinks the file, it does not scrub the disk.** The old
bytes may survive in free space or in an SSD's spare blocks. On an encrypted
volume (FileVault) that mostly stops mattering; if it matters a lot, the
plaintext should never have been written to that disk.

**Tampering fails loudly.** GCM authenticates both the ciphertext and the
header, so a flipped bit, a truncated file, or an edited header gives you an
error — never quietly wrong plaintext. A wrong keyphrase is indistinguishable
from a corrupted file, which is why both produce the same message.

**What a `.cipher` file still reveals**: its size (within 59 bytes of the
plaintext), its modification time, and its name. Encryption hides contents, not
the fact that a document exists or roughly how long it is.

**Not streaming.** Files are encrypted in one pass, so peak memory is a few
times the file size. Fine for documents, wrong for disk images.

## File format

Version 1. The header is plaintext but authenticated, so editing it breaks
decryption rather than changing the result.

```
offset  size      field
0       7 bytes   magic  b"CIPHER\x01"   (tag + format version)
7       1 byte    kdf id, 1 = scrypt
8       1 byte    log_n, scrypt N = 2**log_n
9       2 bytes   r   (big endian)
11      2 bytes   p   (big endian)
13      1 byte    salt length
14      16 bytes  salt   -- fresh random per file
30      12 bytes  nonce  -- fresh random per file
42      ...       AES-256-GCM ciphertext, then its 16-byte tag
```

Overhead is 59 bytes. Both the salt and the nonce are regenerated on every
encrypt, so encrypting the same document twice with the same keyphrase produces
different bytes.

The parameters live in the header rather than in the code, so files encrypted
today still open after the defaults get slower.

## Tests

```bash
python3 -m unittest -v test_cipher
```

34 tests: round trips, unicode keyphrases, bit-flip and truncation detection,
scrypt-cost downgrade rejection, every keyphrase source, overwrite refusal, and
a check that a failed decrypt leaves no output file behind.

## Why not a cipher I invented myself?

A homemade algorithm is the one component you cannot test your way into
trusting — it round-trips perfectly right up until someone who breaks ciphers
for a living reads it. Everything here that *is* a design choice is yours: the
format, the CLI, the scrypt cost, the defaults. The primitive is AES-256-GCM
because that part should be boring.
