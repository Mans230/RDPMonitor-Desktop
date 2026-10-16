"""Behavioral invitation security checks; no Windows services or network changes."""
import base64
import unittest

from relay.protocol import (ProtocolError, create_pairing_envelope, decode_secret,
                            decrypt_pairing, encode_secret, make_invitation,
                            normalize_origin, parse_invitation)


class RelayInvitationTests(unittest.TestCase):
    now = 1800000000
    origin = "https://relay.example"
    secret = bytes(range(32))  # Public deterministic test material, never a credential.

    def payload(self):
        return {
            "v": 1,
            "agent_id": "a7d8442c-116b-4f2d-9152-23f394194b7b",
            "route_id": "fa8f97a9-3ee4-4dd5-80d6-c62827187c44",
            "fingerprint": "ab" * 32,
            "pairing_code": "public_test_pairing_capability",
            "route_token": encode_secret(bytes(range(32, 64))),
            "expires": self.now + 300,
            "name": "Windows test VM",
        }

    def envelope(self):
        return create_pairing_envelope(self.origin, self.payload(), secret=self.secret, now=self.now)

    def test_wrong_secret_and_other_relay_cannot_authenticate_connection_code(self):
        envelope = self.envelope()
        for origin, secret in ((self.origin, bytes(reversed(self.secret))),
                               ("https://another-relay.example", self.secret)):
            with self.subTest(origin=origin), self.assertRaises(ProtocolError):
                decrypt_pairing(origin, secret, envelope["ciphertext"], now=self.now)
        self.assertEqual(decrypt_pairing(self.origin, self.secret, envelope["ciphertext"], now=self.now), self.payload())

    def test_nonce_ciphertext_and_tag_changes_are_rejected(self):
        encoded = self.envelope()["ciphertext"]
        original = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        for offset in (0, 12, len(original) - 1):
            modified = bytearray(original)
            modified[offset] ^= 1
            tampered = base64.urlsafe_b64encode(modified).decode("ascii").rstrip("=")
            with self.subTest(offset=offset), self.assertRaises(ProtocolError):
                decrypt_pairing(self.origin, self.secret, tampered, now=self.now)

    def test_code_expiry_applies_after_authenticated_decryption(self):
        envelope = self.envelope()
        with self.assertRaises(ProtocolError):
            decrypt_pairing(self.origin, self.secret, envelope["ciphertext"], now=self.now + 300)
        for expiry in (self.now, self.now + 601, True, float(self.now + 300)):
            payload = self.payload()
            payload["expires"] = expiry
            with self.subTest(expiry=expiry), self.assertRaises(ProtocolError):
                create_pairing_envelope(self.origin, payload, now=self.now)

    def test_unrecognized_or_malformed_payload_never_becomes_routing_authority(self):
        for field, value in (("v", True), ("v", 2), ("agent_id", "not-a-machine"),
                             ("fingerprint", "ab" * 31), ("route_token", "plaintext"),
                             ("pairing_code", "newline\ncapability")):
            payload = self.payload()
            payload[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ProtocolError):
                create_pairing_envelope(self.origin, payload, now=self.now)
        payload = self.payload()
        payload["endpoint"] = "https://unapproved.example"
        with self.assertRaises(ProtocolError):
            create_pairing_envelope(self.origin, payload, now=self.now)

    def test_pair_code_cannot_be_used_as_installation_invitation(self):
        code = self.envelope()["code"]
        with self.assertRaises(ProtocolError):
            parse_invitation(code, kind="install")
        for malformed in (code.replace("v=1", "v=2"), code.replace("v=1", "v=1&v=1"),
                          code.replace("v=1", "v=1&relay=https%3A%2F%2Fother.example"),
                          code + "="):
            with self.subTest(code=malformed), self.assertRaises(ProtocolError):
                parse_invitation(malformed, kind="pair")

    def test_numeric_loopback_development_exception_does_not_admit_remote_http(self):
        self.assertEqual(normalize_origin("http://127.0.0.1:8765", allow_loopback=True), "http://127.0.0.1:8765")
        for origin in ("http://127.0.0.1:8765", "http://localhost:8765", "http://127.0.0.1.evil", "http://192.0.2.1"):
            with self.subTest(origin=origin), self.assertRaises(ProtocolError):
                normalize_origin(origin)
        for origin in ("http://localhost:8765", "http://127.0.0.1.evil", "http://192.0.2.1"):
            with self.subTest(development_origin=origin), self.assertRaises(ProtocolError):
                normalize_origin(origin, allow_loopback=True)

    def test_origin_canonicalization_and_credential_alias_rejection(self):
        code = make_invitation("install", "https://RELAY.example:443/", encode_secret(self.secret))
        parsed = parse_invitation(code, kind="install")
        self.assertEqual(parsed.origin, self.origin)
        for origin in ("https://user@relay.example", "https://relay.example/path", "https://relay.example?key=x", "https://relay.example/#secret"):
            with self.subTest(origin=origin), self.assertRaises(ProtocolError):
                normalize_origin(origin)
        for token in ("A" * 42 + "B", "A" * 43 + "=", "A" * 42, "A" * 44):
            with self.subTest(token=token), self.assertRaises(ProtocolError):
                decode_secret(token)


if __name__ == "__main__":
    unittest.main()
