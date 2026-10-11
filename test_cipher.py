#!/usr/bin/env python3
"""Tests for cipher. Run with: python3 -m unittest -v test_cipher"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import cipher

HERE = Path(__file__).parent
CLI = [sys.executable, str(HERE / "cipher.py")]

PHRASE = "correct horse battery staple"

# Cheap scrypt params so the tests finish in a sane amount of time. Real use
# gets the much slower defaults, which DefaultParameters exercises once.
FAST = dict(log_n=10, r=8, p=1)


class RoundTrip(unittest.TestCase):
    def test_roundtrip(self):
        for text in [
            b"",
            b"hello",
            b"a" * 100_000,
            "unicode: é中文 \U0001f510".encode("utf-8"),
            bytes(range(256)),
        ]:
            with self.subTest(size=len(text)):
                blob = cipher.encrypt_bytes(text, PHRASE, **FAST)
                self.assertEqual(cipher.decrypt_bytes(blob, PHRASE), text)

    def test_unicode_keyphrase(self):
        phrase = "paßwort-ключ-密码-🔐"
        blob = cipher.encrypt_bytes(b"data", phrase, **FAST)
        self.assertEqual(cipher.decrypt_bytes(blob, phrase), b"data")

    def test_wrong_keyphrase_fails(self):
        blob = cipher.encrypt_bytes(b"secret", PHRASE, **FAST)
        for wrong in ["wrong phrase entirely", PHRASE + " ", PHRASE.upper(), ""]:
            with self.subTest(wrong=wrong):
                with self.assertRaises(cipher.CipherError):
                    cipher.decrypt_bytes(blob, wrong)

    def test_ciphertext_differs_each_time(self):
        """Same plaintext, same keyphrase -> different bytes, thanks to the
        per-file salt and nonce. Otherwise identical files would be visibly
        identical to anyone looking at the directory."""
        a = cipher.encrypt_bytes(b"same text", PHRASE, **FAST)
        b = cipher.encrypt_bytes(b"same text", PHRASE, **FAST)
        self.assertNotEqual(a, b)

    def test_plaintext_not_present_in_output(self):
        needle = b"SUPER-SECRET-MARKER"
        blob = cipher.encrypt_bytes(needle * 20, PHRASE, **FAST)
        self.assertNotIn(needle, blob)

    def test_keyphrase_not_present_in_output(self):
        blob = cipher.encrypt_bytes(b"x" * 100, PHRASE, **FAST)
        self.assertNotIn(PHRASE.encode(), blob)


class Tampering(unittest.TestCase):
    def setUp(self):
        self.blob = cipher.encrypt_bytes(b"x" * 500, PHRASE, **FAST)

    def _expect_failure(self, mutated):
        with self.assertRaises(cipher.CipherError):
            cipher.decrypt_bytes(mutated, PHRASE)

    def test_flipped_ciphertext_bit(self):
        mutated = bytearray(self.blob)
        mutated[cipher.HEADER_LEN + 10] ^= 0x01
        self._expect_failure(bytes(mutated))

    def test_flipped_header_bit(self):
        """The header is associated data, so touching it must also fail."""
        mutated = bytearray(self.blob)
        mutated[cipher.HEADER_LEN - 1] ^= 0x01  # last byte of the nonce
        self._expect_failure(bytes(mutated))

    def test_downgraded_kdf_cost_is_rejected(self):
        mutated = bytearray(self.blob)
        mutated[8] = 1  # log_n byte -> trivially cheap to brute-force
        self._expect_failure(bytes(mutated))

    def test_truncation(self):
        self._expect_failure(self.blob[:-1])
        self._expect_failure(self.blob[: cipher.HEADER_LEN])

    def test_not_a_cipher_file(self):
        self._expect_failure(b"just some plain text sitting in a file, no magic")

    def test_empty_file(self):
        self._expect_failure(b"")

    def test_future_version_is_named_clearly(self):
        mutated = bytearray(self.blob)
        mutated[6] = 99  # version byte
        with self.assertRaises(cipher.CipherError) as ctx:
            cipher.decrypt_bytes(bytes(mutated), PHRASE)
        self.assertIn("version 99", str(ctx.exception))


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name)
        self.env = {**os.environ, "CIPHER_PHRASE": PHRASE}
        self.addCleanup(self.dir.cleanup)

    def run_cli(self, *args, expect_ok=True):
        proc = subprocess.run(
            CLI + list(args), capture_output=True, text=True,
            env=self.env, cwd=self.path,
        )
        if expect_ok:
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        else:
            self.assertNotEqual(proc.returncode, 0, f"expected failure: {proc.stdout}")
        return proc

    # -- keyphrase sources ------------------------------------------------

    def test_keyphrase_flag_roundtrip(self):
        """-k on both sides, the main thing the flag exists for."""
        doc = self.path / "notes.txt"
        doc.write_text("my private notes\nline two\n")
        original = doc.read_bytes()

        self.run_cli("encrypt", "notes.txt", "-k", PHRASE, "--log-n", "10")
        enc = self.path / "notes.txt.cipher"
        self.assertTrue(enc.exists())
        self.assertNotIn(b"private", enc.read_bytes())

        doc.unlink()
        self.run_cli("decrypt", "notes.txt.cipher", "-k", PHRASE)
        self.assertEqual(doc.read_bytes(), original)

    def test_keyphrase_flag_warns_about_shell_history(self):
        (self.path / "a.txt").write_text("x")
        proc = self.run_cli("encrypt", "a.txt", "-k", PHRASE, "--log-n", "10")
        self.assertIn("shell history", proc.stderr)

    def test_keyphrase_with_spaces_and_quotes(self):
        phrase = "a phrase with spaces, 'quotes' and $dollar signs"
        (self.path / "a.txt").write_text("content")
        self.run_cli("encrypt", "a.txt", "-k", phrase, "--log-n", "10")
        (self.path / "a.txt").unlink()
        self.run_cli("decrypt", "a.txt.cipher", "-k", phrase)
        self.assertEqual((self.path / "a.txt").read_text(), "content")

    def test_short_keyphrase_warns_but_proceeds(self):
        (self.path / "a.txt").write_text("x")
        proc = self.run_cli("encrypt", "a.txt", "-k", "short", "--log-n", "10")
        self.assertIn("characters", proc.stderr)
        self.assertTrue((self.path / "a.txt.cipher").exists())

    def test_keyphrase_env(self):
        (self.path / "a.txt").write_text("env content")
        self.run_cli("encrypt", "a.txt", "--keyphrase-env", "CIPHER_PHRASE", "--log-n", "10")
        (self.path / "a.txt").unlink()
        self.run_cli("decrypt", "a.txt.cipher", "--keyphrase-env", "CIPHER_PHRASE")
        self.assertEqual((self.path / "a.txt").read_text(), "env content")

    def test_keyphrase_file_ignores_trailing_newline(self):
        """A keyphrase file written by an editor has a trailing newline; it must
        not become part of the key, or -k and --keyphrase-file would disagree."""
        (self.path / "phrase.txt").write_text(PHRASE + "\n")
        (self.path / "a.txt").write_text("file content")
        self.run_cli("encrypt", "a.txt", "--keyphrase-file", "phrase.txt", "--log-n", "10")
        (self.path / "a.txt").unlink()
        self.run_cli("decrypt", "a.txt.cipher", "-k", PHRASE)
        self.assertEqual((self.path / "a.txt").read_text(), "file content")

    def test_missing_env_var_is_a_clean_error(self):
        (self.path / "a.txt").write_text("x")
        proc = self.run_cli(
            "encrypt", "a.txt", "--keyphrase-env", "NOT_SET_ANYWHERE", expect_ok=False
        )
        self.assertIn("unset or empty", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_conflicting_keyphrase_sources_rejected(self):
        (self.path / "a.txt").write_text("x")
        proc = self.run_cli(
            "encrypt", "a.txt", "-k", PHRASE,
            "--keyphrase-env", "CIPHER_PHRASE", expect_ok=False,
        )
        self.assertIn("not allowed with", proc.stderr)

    def test_no_keyphrase_without_a_tty_is_a_clean_error(self):
        """stdin is a pipe under subprocess, so prompting is impossible."""
        (self.path / "a.txt").write_text("x")
        proc = self.run_cli("encrypt", "a.txt", expect_ok=False)
        self.assertIn("no terminal", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    # -- file handling ----------------------------------------------------

    def test_encrypted_file_is_owner_only(self):
        (self.path / "a.txt").write_text("x")
        self.run_cli("encrypt", "a.txt", "-k", PHRASE, "--log-n", "10")
        mode = (self.path / "a.txt.cipher").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, f"got {oct(mode)}")

    def test_multiple_files_one_keyphrase(self):
        names = ["one.txt", "two.txt", "three.txt"]
        for name in names:
            (self.path / name).write_text(f"contents of {name}")
        self.run_cli("encrypt", *names, "-k", PHRASE, "--log-n", "10")
        for name in names:
            self.assertTrue((self.path / f"{name}.cipher").exists(), name)
        self.run_cli("decrypt", *[f"{n}.cipher" for n in names], "-k", PHRASE, "--force")
        for name in names:
            self.assertEqual((self.path / name).read_text(), f"contents of {name}")

    def test_refuses_to_clobber_without_force(self):
        (self.path / "a.txt").write_text("new")
        (self.path / "a.txt.cipher").write_text("precious existing file")
        self.run_cli("encrypt", "a.txt", "-k", PHRASE, "--log-n", "10", expect_ok=False)
        self.assertEqual(
            (self.path / "a.txt.cipher").read_text(), "precious existing file"
        )

    def test_force_allows_clobber(self):
        (self.path / "a.txt").write_text("new")
        (self.path / "a.txt.cipher").write_text("stale")
        self.run_cli("encrypt", "a.txt", "-f", "-k", PHRASE, "--log-n", "10")
        self.assertNotEqual(
            (self.path / "a.txt.cipher").read_text(errors="replace"), "stale"
        )

    def test_custom_output_path(self):
        (self.path / "a.txt").write_text("content")
        self.run_cli("encrypt", "a.txt", "-o", "vault.bin", "-k", PHRASE, "--log-n", "10")
        self.assertTrue((self.path / "vault.bin").exists())
        self.run_cli("decrypt", "vault.bin", "-o", "back.txt", "-k", PHRASE)
        self.assertEqual((self.path / "back.txt").read_text(), "content")

    def test_wrong_keyphrase_leaves_no_output(self):
        (self.path / "a.txt").write_text("secret stuff")
        self.run_cli("encrypt", "a.txt", "-k", PHRASE, "--log-n", "10")
        (self.path / "a.txt").unlink()

        proc = self.run_cli(
            "decrypt", "a.txt.cipher", "-k", "the wrong keyphrase", expect_ok=False
        )
        self.assertIn("wrong keyphrase", proc.stderr)
        self.assertFalse((self.path / "a.txt").exists(), "wrote output despite failing")

    def test_remove_source(self):
        doc = self.path / "gone.txt"
        doc.write_text("bye")
        self.run_cli(
            "encrypt", "gone.txt", "--remove-source", "-k", PHRASE, "--log-n", "10"
        )
        self.assertFalse(doc.exists())
        self.assertTrue((self.path / "gone.txt.cipher").exists())

    def test_missing_file_is_a_clean_error(self):
        proc = self.run_cli("encrypt", "nope.txt", "-k", PHRASE, expect_ok=False)
        self.assertIn("does not exist", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    # -- the empty-input trap ---------------------------------------------

    def test_refuses_to_encrypt_an_empty_file(self):
        """Encrypting an empty file "succeeds" and produces a vault with
        nothing in it. That reads as success until you need the contents back,
        so it has to be an error."""
        (self.path / "ww.txt").touch()
        proc = self.run_cli("encrypt", "ww.txt", "-k", PHRASE, expect_ok=False)
        self.assertIn("empty", proc.stderr)
        self.assertFalse((self.path / "ww.txt.cipher").exists())

    def test_empty_file_refused_before_removing_source(self):
        """The dangerous combination: a typo'd name plus --remove-source."""
        (self.path / "ww.txt").touch()
        self.run_cli(
            "encrypt", "ww.txt", "--remove-source", "-k", PHRASE, expect_ok=False
        )
        self.assertTrue((self.path / "ww.txt").exists(), "deleted the source anyway")

    def test_one_empty_file_blocks_the_whole_batch(self):
        (self.path / "good.txt").write_text("real content")
        (self.path / "empty.txt").touch()
        proc = self.run_cli(
            "encrypt", "good.txt", "empty.txt", "-k", PHRASE, expect_ok=False
        )
        self.assertIn("empty.txt", proc.stderr)
        self.assertNotIn("good.txt", proc.stderr.split("empty")[0])

    def test_allow_empty_opts_back_in(self):
        (self.path / "ww.txt").touch()
        self.run_cli("encrypt", "ww.txt", "--allow-empty", "-k", PHRASE, "--log-n", "10")
        self.assertTrue((self.path / "ww.txt.cipher").exists())

    def test_no_temp_file_left_behind(self):
        (self.path / "a.txt").write_text("x")
        self.run_cli("encrypt", "a.txt", "-k", PHRASE, "--log-n", "10")
        leftovers = [p.name for p in self.path.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_info_shows_metadata_only(self):
        (self.path / "a.txt").write_text("hello there")
        self.run_cli("encrypt", "a.txt", "-k", PHRASE, "--log-n", "10")
        proc = self.run_cli("info", "a.txt.cipher")
        self.assertIn("AES-256-GCM", proc.stdout)
        self.assertIn("scrypt N=2^10", proc.stdout)
        self.assertIn("11 bytes", proc.stdout)  # plaintext length
        self.assertNotIn("hello", proc.stdout)


class DefaultParameters(unittest.TestCase):
    def test_real_defaults_work_end_to_end(self):
        """Every other test overrides log_n for speed; make sure the shipped
        default actually runs (it needs 128 MiB of scrypt memory, which fails
        outright if maxmem is left at OpenSSL's 32 MiB default)."""
        blob = cipher.encrypt_bytes(b"real params", PHRASE)
        self.assertEqual(cipher.decrypt_bytes(blob, PHRASE), b"real params")

    def test_header_size_matches_layout(self):
        blob = cipher.encrypt_bytes(b"", PHRASE, **FAST)
        self.assertEqual(len(blob), cipher.HEADER_LEN + cipher.TAG_LEN)

    def test_overhead_is_58_bytes(self):
        """Pinned because it is a diagnostic: a .cipher file of exactly 58
        bytes encrypts nothing at all, whatever the keyphrase. That is how an
        "empty decrypt" gets traced back to an empty input."""
        self.assertEqual(cipher.HEADER_LEN + cipher.TAG_LEN, 58)
        self.assertEqual(len(cipher.encrypt_bytes(b"", PHRASE, **FAST)), 58)
        self.assertEqual(len(cipher.encrypt_bytes(b"x" * 100, PHRASE, **FAST)), 158)


if __name__ == "__main__":
    unittest.main()
