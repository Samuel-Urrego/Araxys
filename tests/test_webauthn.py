"""Tests for the WebAuthn / Passkeys module."""
# ruff: noqa: D100, D101, D102, D103

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256

from araxys.core.exceptions import AraxysError
from araxys.webauthn.exceptions import COSEAlgorithmError, WebAuthnError
from araxys.webauthn.models import CredentialRecord, RelyingPartyConfig

if TYPE_CHECKING:
    from araxys.webauthn.challenges import ChallengeStore
    from araxys.webauthn.manager import WebAuthnManager
    from araxys.webauthn.storage import CredentialStore


class TestExceptions:
    def test_webauthn_error_is_araxys_error(self) -> None:
        """WebAuthnError must be a subclass of AraxysError."""
        assert issubclass(WebAuthnError, AraxysError)

    def test_webauthn_error_default_message(self) -> None:
        """Default message should be descriptive."""
        err = WebAuthnError()
        assert "WebAuthn" in str(err)

    def test_webauthn_error_custom_message(self) -> None:
        """Custom message should be preserved."""
        err = WebAuthnError("Origin mismatch")
        assert str(err) == "Origin mismatch"

    def test_cose_algorithm_error_is_webauthn_error(self) -> None:
        """COSEAlgorithmError must be a subclass of WebAuthnError."""
        assert issubclass(COSEAlgorithmError, WebAuthnError)

    def test_cose_algorithm_error_message(self) -> None:
        """COSEAlgorithmError should include the algorithm code."""
        err = COSEAlgorithmError(-999)
        assert "-999" in str(err)

    def test_cose_algorithm_error_default(self) -> None:
        """COSEAlgorithmError with unknown_alg should produce sensible message."""
        err = COSEAlgorithmError(42)
        assert "42" in str(err)


class TestModels:
    def test_relying_party_config_defaults(self) -> None:
        """RelyingPartyConfig must store rp_id, rp_name, expected_origin."""
        rp = RelyingPartyConfig(
            rp_id="example.com",
            rp_name="Example",
            expected_origin="https://example.com",
        )
        assert rp.rp_id == "example.com"
        assert rp.rp_name == "Example"
        assert rp.expected_origin == "https://example.com"

    def test_credential_record_minimal(self) -> None:
        """CredentialRecord must store all required fields."""
        now = datetime.now(UTC)
        record = CredentialRecord(
            credential_id=b"\x01\x02\x03",
            user_id="user-123",
            public_key_cbor=b"\xa3\x01\x02\x03",
            sign_count=0,
            alg=-7,
            created_at=now,
        )
        assert record.credential_id == b"\x01\x02\x03"
        assert record.user_id == "user-123"
        assert record.sign_count == 0
        assert record.alg == -7
        assert record.created_at == now

    def test_credential_record_defaults(self) -> None:
        """Defaults for credential_type and attestation_type should be set."""
        record = CredentialRecord(
            credential_id=b"\x01",
            user_id="user-1",
            public_key_cbor=b"\x02",
            sign_count=1,
            alg=-7,
            created_at=datetime.now(UTC),
        )
        assert record.credential_type == "public-key"
        assert record.attestation_type == "none"


class TestCredentialStore:
    """Tests for CredentialStore backends."""

    @pytest.fixture
    def record(self) -> CredentialRecord:
        return CredentialRecord(
            credential_id=b"\x01\x02\x03",
            user_id="user-1",
            public_key_cbor=b"\xa5\x01\x02\x03\x04\x05",
            sign_count=0,
            alg=-7,
            created_at=datetime.now(UTC),
        )

    @pytest.fixture
    def store(self) -> CredentialStore:
        from araxys.webauthn.storage import InMemoryCredentialStore
        return InMemoryCredentialStore()

    async def test_save_and_get(
        self, store: CredentialStore, record: CredentialRecord
    ) -> None:
        """Saved credential should be retrievable by ID."""
        await store.save(record)
        retrieved = await store.get(record.credential_id)
        assert retrieved is not None
        assert retrieved.credential_id == record.credential_id
        assert retrieved.user_id == record.user_id

    async def test_get_unknown(self, store: CredentialStore) -> None:
        """Unknown credential ID should return None."""
        result = await store.get(b"\x99\x99\x99")
        assert result is None

    async def test_list_by_user(
        self, store: CredentialStore, record: CredentialRecord
    ) -> None:
        """List by user should return only that user's credentials."""
        record2 = CredentialRecord(
            credential_id=b"\x04\x05\x06",
            user_id="user-2",
            public_key_cbor=b"\x05",
            sign_count=0,
            alg=-7,
            created_at=datetime.now(UTC),
        )
        await store.save(record)
        await store.save(record2)
        user1_creds = await store.list_by_user("user-1")
        assert len(user1_creds) == 1
        assert user1_creds[0].credential_id == record.credential_id

    async def test_update_sign_count(
        self, store: CredentialStore, record: CredentialRecord
    ) -> None:
        """Update sign count should persist the new value."""
        await store.save(record)
        await store.update_sign_count(record.credential_id, 42)
        updated = await store.get(record.credential_id)
        assert updated is not None
        assert updated.sign_count == 42


class TestRedisCredentialStore:
    """Tests for RedisCredentialStore using fakeredis."""

    @pytest.fixture
    def store(self) -> CredentialStore:
        from fakeredis.aioredis import FakeRedis

        from araxys.webauthn.storage import RedisCredentialStore
        return RedisCredentialStore(FakeRedis())

    async def test_redis_persistence(self, store: CredentialStore) -> None:
        """Credential stored in Redis should persist as a HASH."""
        record = CredentialRecord(
            credential_id=b"\xaa\xbb",
            user_id="user-r1",
            public_key_cbor=b"\xcc\xdd",
            sign_count=5,
            alg=-7,
            created_at=datetime.now(UTC),
        )
        await store.save(record)
        retrieved = await store.get(record.credential_id)
        assert retrieved is not None
        assert retrieved.sign_count == 5
        assert retrieved.user_id == "user-r1"

    async def test_redis_list_by_user(self, store: CredentialStore) -> None:
        """Multiple credentials for same user should be listed."""
        r1 = CredentialRecord(
            credential_id=b"\x01", user_id="u1", public_key_cbor=b"\x01",
            sign_count=0, alg=-7, created_at=datetime.now(UTC),
        )
        r2 = CredentialRecord(
            credential_id=b"\x02", user_id="u1", public_key_cbor=b"\x02",
            sign_count=0, alg=-7, created_at=datetime.now(UTC),
        )
        await store.save(r1)
        await store.save(r2)
        creds = await store.list_by_user("u1")
        assert len(creds) == 2


class TestChallengeStore:
    """Tests for ChallengeStore backends."""

    @pytest.fixture
    def store(self) -> ChallengeStore:
        from araxys.webauthn.challenges import InMemoryChallengeStore
        return InMemoryChallengeStore()

    async def test_set_and_get(self, store: ChallengeStore) -> None:
        """A challenge should be retrievable by key after set."""
        challenge = b"\x01\x02\x03" * 11  # 33 bytes
        await store.set("challenge-1", challenge)
        retrieved = await store.get("challenge-1")
        assert retrieved == challenge

    async def test_get_unknown(self, store: ChallengeStore) -> None:
        """Unknown key should return None."""
        result = await store.get("unknown-key")
        assert result is None

    async def test_delete(self, store: ChallengeStore) -> None:
        """Deleted challenge should not be retrievable."""
        await store.set("to-delete", b"\xde\xad")
        await store.delete("to-delete")
        assert await store.get("to-delete") is None

    async def test_set_and_get_after_ttl_expiry(self, store: ChallengeStore) -> None:
        """Challenge past TTL should return None."""
        await store.set("expire-me", b"\xee\xff", ttl_seconds=0)  # immediate expiry
        import asyncio
        await asyncio.sleep(0.01)
        assert await store.get("expire-me") is None

    async def test_set_and_get_with_custom_ttl(self, store: ChallengeStore) -> None:
        """Challenge should be retrievable within TTL window."""
        await store.set("valid", b"\xca\xfe", ttl_seconds=60)
        assert await store.get("valid") == b"\xca\xfe"


class TestRedisChallengeStore:
    """Tests for RedisChallengeStore using fakeredis."""

    @pytest.fixture
    def store(self) -> ChallengeStore:
        from fakeredis.aioredis import FakeRedis

        from araxys.webauthn.challenges import RedisChallengeStore
        return RedisChallengeStore(FakeRedis())

    async def test_redis_set_and_get(self, store: ChallengeStore) -> None:
        """Challenge stored in Redis should be retrievable."""
        await store.set("rc-key", b"\xca\xfe", ttl_seconds=60)
        retrieved = await store.get("rc-key")
        assert retrieved == b"\xca\xfe"

    async def test_redis_ttl_expiry(self, store: ChallengeStore) -> None:
        """Challenge with TTL=0 should expire immediately in Redis."""
        await store.set("rc-expire", b"\xde\xad", ttl_seconds=0)
        retrieved = await store.get("rc-expire")
        assert retrieved is None


class TestCOSE:
    """Tests for COSE key parsing."""

    def test_parse_ec2_p256(self) -> None:
        """EC2 P-256 COSE key should yield an EllipticCurvePublicKey."""
        from araxys.webauthn.cose import parse_cose_key

        # Build a valid P-256 COSE_Key in CBOR
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        nums = public_key.public_numbers()
        x_bytes = nums.x.to_bytes(32, "big")
        y_bytes = nums.y.to_bytes(32, "big")

        import cbor2
        cose_key = cbor2.dumps({
            1: 2,    # kty: EC2
            3: -7,   # alg: ES256
            -1: 1,   # crv: P-256
            -2: x_bytes,
            -3: y_bytes,
        })
        key = parse_cose_key(cose_key)
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert key.key_size == 256

    def test_parse_rsa(self) -> None:
        """RSA COSE key should yield an RSAPublicKey."""
        from araxys.webauthn.cose import parse_cose_key

        private_key = rsa.generate_private_key(65537, 2048)
        nums = private_key.public_key().public_numbers()
        n_bytes = nums.n.to_bytes(256, "big")
        e_bytes = nums.e.to_bytes(3, "big")

        import cbor2
        cose_key = cbor2.dumps({
            1: 3,     # kty: RSA
            3: -257,  # alg: RS256
            -1: n_bytes,
            -2: e_bytes,
        })
        key = parse_cose_key(cose_key)
        assert isinstance(key, RSAPublicKey)

    def test_unknown_algorithm_rejected(self) -> None:
        """Unknown COSE algorithm should raise COSEAlgorithmError."""
        import cbor2

        from araxys.webauthn.cose import parse_cose_key

        cose_key = cbor2.dumps({
            1: 2,     # kty: EC2
            3: -8,    # alg: EdDSA (unsupported)
            -1: 1,    # crv: P-256
            -2: b"\x00" * 32,
            -3: b"\x00" * 32,
        })
        with pytest.raises(COSEAlgorithmError):
            parse_cose_key(cose_key)

    def test_cose_alg_to_hash_es256(self) -> None:
        """COSE alg -7 (ES256) should map to SHA256."""
        from cryptography.hazmat.primitives.hashes import SHA256

        from araxys.webauthn.cose import cose_alg_to_hash
        assert isinstance(cose_alg_to_hash(-7)(), SHA256)

    def test_cose_alg_to_hash_rs256(self) -> None:
        """COSE alg -257 (RS256) should map to SHA256."""
        from cryptography.hazmat.primitives.hashes import SHA256

        from araxys.webauthn.cose import cose_alg_to_hash
        assert isinstance(cose_alg_to_hash(-257)(), SHA256)

    def test_malformed_ec2_key_missing_x(self) -> None:
        """EC2 COSE key missing 'x' coordinate should raise KeyError/etc."""
        import cbor2

        from araxys.webauthn.cose import parse_cose_key

        cose_key = cbor2.dumps({
            1: 2,   # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            # missing -2 (x) and -3 (y)
        })
        with pytest.raises((KeyError, COSEAlgorithmError, WebAuthnError)):
            parse_cose_key(cose_key)

    def test_malformed_rsa_key_missing_n(self) -> None:
        """RSA COSE key missing 'n' modulus should raise KeyError or WebAuthnError."""
        import cbor2

        from araxys.webauthn.cose import parse_cose_key

        cose_key = cbor2.dumps({
            1: 3,    # kty: RSA
            3: -257, # alg: RS256
            -2: b"\x01\x00\x01",  # e exponent present but no n
        })
        with pytest.raises((KeyError, COSEAlgorithmError, WebAuthnError)):
            parse_cose_key(cose_key)


class TestAttestation:
    """Tests for attestation verification."""

    def _make_auth_data(
        self,
        rp_id: str = "example.com",
        credential_id: bytes = b"\x01\x02\x03\x04",
        cred_pubkey_cbor: bytes | None = None,
        sign_count: int = 1,
    ) -> bytes:
        """Build a minimal authenticator data blob for testing."""
        import hashlib
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
        # Flags: UP=1, UV=1, AT=1, ED=0
        flags = bytes([0x45])  # bit0=UP, bit2=UV, bit6=AT
        sc = sign_count.to_bytes(4, "big")
        if cred_pubkey_cbor is None:
            # Default: generate a P-256 key and use its COSE encoding
            key = ec.generate_private_key(ec.SECP256R1()).public_key()
            nums = key.public_numbers()
            x_bytes = nums.x.to_bytes(32, "big")
            y_bytes = nums.y.to_bytes(32, "big")
            import cbor2
            cred_pubkey_cbor = cbor2.dumps({
                1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes,
            })
        # Attested credential data
        aaguid = b"\x00" * 16
        cred_id_len = len(credential_id).to_bytes(2, "big")
        attested_cred = aaguid + cred_id_len + credential_id + cred_pubkey_cbor
        return rp_id_hash + flags + sc + attested_cred

    def _make_client_data_json(
        self, challenge: bytes, origin: str = "https://example.com"
    ) -> bytes:
        """Build clientDataJSON bytes."""
        import base64
        import json
        return json.dumps({
            "type": "webauthn.create",
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
            "origin": origin,
            "crossOrigin": False,
        }).encode()

    def test_none_attestation_returns_credential_data(self) -> None:
        """"none" attestation should extract credential data from authData."""
        import cbor2

        from araxys.webauthn.attestation import verify_none

        credential_id = b"\xaa\xbb\xcc\xdd"
        auth_data = self._make_auth_data(credential_id=credential_id)
        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        })
        result = verify_none(cbor2.loads(att_obj))
        assert result["credential_id"] == credential_id
        assert isinstance(result["public_key_cbor"], bytes)

    def test_none_attestation_extracts_sign_count(self) -> None:
        """"none" attestation should extract the sign count from authData."""
        import cbor2

        from araxys.webauthn.attestation import verify_none

        auth_data = self._make_auth_data(sign_count=42)
        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        })
        result = verify_none(cbor2.loads(att_obj))
        assert result["sign_count"] == 42
        assert result["credential_id"] is not None

    def test_packed_attestation_valid_signature(self) -> None:
        """"packed" attestation with valid ECDSA sig should verify."""
        import hashlib

        import cbor2

        from araxys.webauthn.attestation import verify_packed

        # Generate a key pair — this serves as BOTH the credential key
        # (embedded in authData) and the self-attestation signing key.
        att_private_key = ec.generate_private_key(ec.SECP256R1())
        att_public_key = att_private_key.public_key()

        # Build the COSE key CBOR for this public key
        nums = att_public_key.public_numbers()
        x_bytes = nums.x.to_bytes(32, "big")
        y_bytes = nums.y.to_bytes(32, "big")
        pubkey_cbor = cbor2.dumps({
            1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes,
        })

        credential_id = b"\x11\x22\x33\x44"
        # Pass the same pubkey into auth_data so credential matches signer
        auth_data = self._make_auth_data(
            credential_id=credential_id, cred_pubkey_cbor=pubkey_cbor
        )

        # Sign authData + clientDataHash with the attestation private key
        client_data = self._make_client_data_json(b"\xca" * 32)
        client_data_hash = hashlib.sha256(client_data).digest()
        sig_input = auth_data + client_data_hash
        signature = att_private_key.sign(sig_input, ec.ECDSA(SHA256()))

        att_obj = cbor2.dumps({
            "fmt": "packed",
            "attStmt": {
                "alg": -7,
                "sig": signature,
            },
            "authData": auth_data,
        })
        # packed verification without x5c uses the credential pubkey
        result = verify_packed(
            cbor2.loads(att_obj),
            rp_id_hash=hashlib.sha256(b"example.com").digest(),
            client_data_hash=client_data_hash,
        )
        assert result["credential_id"] == credential_id

    def test_packed_forged_signature_rejected(self) -> None:
        """"packed" with forged sig should raise WebAuthnError."""
        import hashlib

        import cbor2

        from araxys.webauthn.attestation import verify_packed
        from araxys.webauthn.exceptions import WebAuthnError

        auth_data = self._make_auth_data()
        client_data_hash = hashlib.sha256(b"fake-client-data").digest()

        # Forged signature
        bad_sig = b"\x00" * 64
        att_obj = cbor2.dumps({
            "fmt": "packed",
            "attStmt": {"alg": -7, "sig": bad_sig},
            "authData": auth_data,
        })
        with pytest.raises(WebAuthnError):
            verify_packed(
                cbor2.loads(att_obj),
                rp_id_hash=hashlib.sha256(b"example.com").digest(),
                client_data_hash=client_data_hash,
            )

    def test_authenticator_data_too_short(self) -> None:
        """Auth data shorter than 37 bytes should raise WebAuthnError."""
        import cbor2

        from araxys.webauthn.attestation import verify_none

        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": b"\x00" * 20,  # too short
        })
        with pytest.raises(WebAuthnError, match="(?i)authenticator data too short"):
            verify_none(cbor2.loads(att_obj))

    def test_auth_data_missing_at_flag(self) -> None:
        """Auth data without AT flag should raise WebAuthnError."""
        import hashlib

        import cbor2

        from araxys.webauthn.attestation import verify_none

        # Build auth_data with flags=0x01 (UP only, no AT flag)
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        flags = bytes([0x01])  # UP only, AT bit NOT set
        sign_count = (1).to_bytes(4, "big")
        auth_data = rp_id_hash + flags + sign_count
        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        })
        with pytest.raises(WebAuthnError, match="(?i)at flag"):
            verify_none(cbor2.loads(att_obj))


class TestWebAuthnManager:
    """Tests for the WebAuthnManager ceremony orchestrator."""

    @pytest.fixture
    def rp_config(self) -> RelyingPartyConfig:
        return RelyingPartyConfig(
            rp_id="example.com",
            rp_name="Example Corp",
            expected_origin="https://example.com",
        )

    @pytest.fixture
    def cred_store(self) -> CredentialStore:
        from araxys.webauthn.storage import InMemoryCredentialStore
        return InMemoryCredentialStore()

    @pytest.fixture
    def manager(
        self,
        rp_config: RelyingPartyConfig,
        cred_store: CredentialStore,
    ) -> WebAuthnManager:
        from araxys.webauthn.manager import WebAuthnManager
        return WebAuthnManager(rp_config, cred_store)

    async def test_create_registration_challenge_returns_dict(
        self, manager: WebAuthnManager
    ) -> None:
        """Challenge response must include rp, user, challenge, pubKeyCredParams."""
        result = await manager.create_registration_challenge("user-1", "Alice")
        assert "rp" in result
        assert result["rp"]["id"] == "example.com"
        assert result["rp"]["name"] == "Example Corp"
        assert "user" in result
        assert result["user"]["id"] == "user-1"
        assert result["user"]["name"] == "Alice"
        assert "challenge" in result
        assert len(result["challenge"]) == 32
        assert "pubKeyCredParams" in result
        algs = [p["alg"] for p in result["pubKeyCredParams"]]
        assert -7 in algs
        assert -257 in algs

    async def test_create_authentication_challenge_with_credentials(
        self, manager: WebAuthnManager, cred_store: CredentialStore
    ) -> None:
        """Auth challenge should include allowCredentials for stored creds."""
        # Store a credential first
        record = CredentialRecord(
            credential_id=b"\xab\xcd",
            user_id="user-1",
            public_key_cbor=b"\xa5\x01\x02\x03\x04\x05",
            sign_count=0,
            alg=-7,
            created_at=datetime.now(UTC),
        )
        await cred_store.save(record)
        result = await manager.create_authentication_challenge("user-1")
        assert "challenge" in result
        assert len(result["challenge"]) == 32
        assert "allowCredentials" in result
        cred_ids = [c["id"] for c in result["allowCredentials"]]
        assert b"\xab\xcd" in cred_ids

    async def test_create_authentication_challenge_no_credentials(
        self, manager: WebAuthnManager
    ) -> None:
        """Auth challenge without stored creds should have empty allowCredentials."""
        result = await manager.create_authentication_challenge("no-creds-user")
        assert result["allowCredentials"] == []

    async def test_registration_auth_round_trip(
        self, manager: WebAuthnManager, cred_store: CredentialStore
    ) -> None:
        """Full registration round-trip should store credential and verify."""
        import base64
        import hashlib
        import json

        import cbor2

        # 1. Create challenge
        challenge_result = await manager.create_registration_challenge("user-r1", "Bob")
        challenge = challenge_result["challenge"]

        # 2. Build a valid registration response
        # Generate credential key pair
        cred_private = ec.generate_private_key(ec.SECP256R1())
        cred_public = cred_private.public_key()

        # Build auth data
        nums = cred_public.public_numbers()
        x_bytes = nums.x.to_bytes(32, "big")
        y_bytes = nums.y.to_bytes(32, "big")
        pubkey_cbor = cbor2.dumps({
            1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes,
        })

        credential_id = b"\xaa" * 16
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        flags = bytes([0x45])  # UP + UV + AT
        sign_count = (0).to_bytes(4, "big")
        aaguid = b"\x00" * 16
        cred_id_len = len(credential_id).to_bytes(2, "big")
        attested_cred = aaguid + cred_id_len + credential_id + pubkey_cbor
        auth_data = rp_id_hash + flags + sign_count + attested_cred

        # Build clientDataJSON
        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()

        client_data_b64 = base64.urlsafe_b64encode(client_data).rstrip(b"=").decode()

        # For "none" attestation, attStmt is empty
        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        })
        att_obj_b64 = base64.urlsafe_b64encode(att_obj).rstrip(b"=").decode()

        response = {
            "id": base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": att_obj_b64,
            },
        }

        # 3. Verify registration
        record = await manager.verify_registration(
            response, challenge, "https://example.com", user_id="user-r1"
        )
        assert record.credential_id == credential_id
        assert record.user_id == "user-r1"
        assert record.sign_count == 0

        # 4. Create authentication challenge
        auth_result = await manager.create_authentication_challenge("user-r1")
        auth_challenge = auth_result["challenge"]

        # 5. Build assertion response
        auth_client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(auth_challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        auth_client_data_b64 = (
            base64.urlsafe_b64encode(auth_client_data).rstrip(b"=").decode()
        )

        client_data_hash = hashlib.sha256(auth_client_data).digest()

        # Build assertion auth data (no AT flag, just UP+UV)
        auth_flags = bytes([0x05])  # UP + UV
        auth_sign_count = (1).to_bytes(4, "big")
        assertion_auth_data = rp_id_hash + auth_flags + auth_sign_count

        # Sign
        sig_input = assertion_auth_data + client_data_hash
        assertion_sig = cred_private.sign(sig_input, ec.ECDSA(SHA256()))

        def _b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        assertion = {
            "id": _b64(credential_id),
            "response": {
                "clientDataJSON": auth_client_data_b64,
                "authenticatorData": _b64(assertion_auth_data),
                "signature": _b64(assertion_sig),
            },
        }

        # 6. Verify authentication
        updated = await manager.verify_authentication(
            assertion, auth_challenge, "https://example.com"
        )
        assert updated.credential_id == credential_id
        assert updated.sign_count == 1

    async def test_sign_count_monotonic(
        self, manager: WebAuthnManager, cred_store: CredentialStore
    ) -> None:
        """Assertion with sign_count <= stored count should raise WebAuthnError."""
        import base64
        import hashlib
        import json

        import cbor2

        # Generate a real credential key pair
        cred_private = ec.generate_private_key(ec.SECP256R1())
        cred_public = cred_private.public_key()
        nums = cred_public.public_numbers()
        x_bytes = nums.x.to_bytes(32, "big")
        y_bytes = nums.y.to_bytes(32, "big")
        pubkey_cbor = cbor2.dumps({
            1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes,
        })

        credential_id = b"\xbc" * 16

        # Store credential with sign_count=5
        record = CredentialRecord(
            credential_id=credential_id,
            user_id="user-sc",
            public_key_cbor=pubkey_cbor,
            sign_count=5,
            alg=-7,
            created_at=datetime.now(UTC),
        )
        await cred_store.save(record)

        # Build an assertion with sign_count=5 (not greater)
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        auth_challenge = b"\xca" * 32
        auth_flags = bytes([0x05])
        auth_sign_count = (5).to_bytes(4, "big")  # same as stored
        assertion_auth_data = rp_id_hash + auth_flags + auth_sign_count

        auth_client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(auth_challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        auth_client_data_b64 = (
            base64.urlsafe_b64encode(auth_client_data).rstrip(b"=").decode()
        )

        def _b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

        client_data_hash = hashlib.sha256(auth_client_data).digest()
        sig_input = assertion_auth_data + client_data_hash
        assertion_sig = cred_private.sign(sig_input, ec.ECDSA(SHA256()))

        assertion = {
            "id": _b64(credential_id),
            "response": {
                "clientDataJSON": auth_client_data_b64,
                "authenticatorData": _b64(assertion_auth_data),
                "signature": _b64(assertion_sig),
            },
        }

        from araxys.webauthn.exceptions import WebAuthnError

        with pytest.raises(WebAuthnError, match="(?i)sign count"):
            await manager.verify_authentication(
                assertion, auth_challenge, "https://example.com"
            )

    async def test_origin_mismatch_rejected(
        self, manager: WebAuthnManager
    ) -> None:
        """Origin mismatch in clientDataJSON should raise WebAuthnError."""
        import base64
        import json

        import cbor2

        from araxys.webauthn.exceptions import WebAuthnError

        challenge = b"\xca" * 32

        # clientDataJSON with wrong origin
        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
            "origin": "https://evil.com",
            "crossOrigin": False,
        }).encode()
        client_data_b64 = base64.urlsafe_b64encode(client_data).rstrip(b"=").decode()

        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": b"\x00" * 37,  # minimal auth data
        })
        att_obj_b64 = base64.urlsafe_b64encode(att_obj).rstrip(b"=").decode()

        response = {
            "id": "dGVzdC1pZA",
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": att_obj_b64,
            },
        }
        with pytest.raises(WebAuthnError, match="(?i)origin"):
            await manager.verify_registration(response, challenge, "https://example.com")

    async def test_challenge_mismatch_rejected(
        self, manager: WebAuthnManager
    ) -> None:
        """Challenge mismatch in clientDataJSON should raise WebAuthnError."""
        import base64
        import json

        import cbor2

        from araxys.webauthn.exceptions import WebAuthnError

        stored_challenge = b"\xca" * 32
        wrong_challenge = b"\xfe" * 32

        # clientDataJSON with wrong challenge
        def _b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": _b64(wrong_challenge),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        client_data_b64 = base64.urlsafe_b64encode(client_data).rstrip(b"=").decode()

        att_obj = cbor2.dumps({
            "fmt": "none",
            "attStmt": {},
            "authData": b"\x00" * 37,
        })
        att_obj_b64 = _b64(att_obj)

        response = {
            "id": "dGVzdC1pZA",
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": att_obj_b64,
            },
        }
        with pytest.raises(WebAuthnError, match="(?i)challenge"):
            await manager.verify_registration(response, stored_challenge, "https://example.com")

    async def test_tampered_assertion_signature_rejected(
        self, manager: WebAuthnManager, cred_store: CredentialStore
    ) -> None:
        """Forged assertion signature should raise WebAuthnError (REQ-07)."""
        import base64
        import hashlib
        import json

        import cbor2

        from araxys.webauthn.exceptions import WebAuthnError

        # Register a credential
        cred_private = ec.generate_private_key(ec.SECP256R1())
        cred_public = cred_private.public_key()
        nums = cred_public.public_numbers()
        x_bytes = nums.x.to_bytes(32, "big")
        y_bytes = nums.y.to_bytes(32, "big")
        pubkey_cbor = cbor2.dumps({
            1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes,
        })
        credential_id = b"\xdd" * 16
        record = CredentialRecord(
            credential_id=credential_id, user_id="user-tamper",
            public_key_cbor=pubkey_cbor, sign_count=0, alg=-7,
            created_at=datetime.now(UTC),
        )
        await cred_store.save(record)

        # Build a valid assertion
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        auth_challenge = b"\xab" * 32
        auth_flags = bytes([0x05])
        auth_sign_count = (1).to_bytes(4, "big")
        assertion_auth_data = rp_id_hash + auth_flags + auth_sign_count
        auth_client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(auth_challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        client_data_hash = hashlib.sha256(auth_client_data).digest()
        sig_input = assertion_auth_data + client_data_hash
        assertion_sig = cred_private.sign(sig_input, ec.ECDSA(SHA256()))

        # Tamper with the signature
        forged_sig = b"\xde" * len(assertion_sig)

        def _b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        assertion = {
            "id": _b64(credential_id),
            "response": {
                "clientDataJSON": _b64(auth_client_data),
                "authenticatorData": _b64(assertion_auth_data),
                "signature": _b64(forged_sig),
            },
        }
        with pytest.raises(WebAuthnError, match="(?i)(invalid|signature)"):
            await manager.verify_authentication(
                assertion, auth_challenge, "https://example.com"
            )

    async def test_tampered_authenticator_data_rejected(
        self, manager: WebAuthnManager, cred_store: CredentialStore
    ) -> None:
        """Tampered authenticatorData should raise WebAuthnError (REQ-07)."""
        import base64
        import hashlib
        import json

        import cbor2

        from araxys.webauthn.exceptions import WebAuthnError

        # Register a credential
        cred_private = ec.generate_private_key(ec.SECP256R1())
        cred_public = cred_private.public_key()
        nums = cred_public.public_numbers()
        x_bytes = nums.x.to_bytes(32, "big")
        y_bytes = nums.y.to_bytes(32, "big")
        pubkey_cbor = cbor2.dumps({
            1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes,
        })
        credential_id = b"\xee" * 16
        record = CredentialRecord(
            credential_id=credential_id, user_id="user-tamper",
            public_key_cbor=pubkey_cbor, sign_count=0, alg=-7,
            created_at=datetime.now(UTC),
        )
        await cred_store.save(record)

        # Build a valid assertion but tamper auth_data after signing
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        auth_challenge = b"\xbc" * 32
        auth_flags = bytes([0x05])
        auth_sign_count = (1).to_bytes(4, "big")
        good_auth_data = rp_id_hash + auth_flags + auth_sign_count
        auth_client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(auth_challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        client_data_hash = hashlib.sha256(auth_client_data).digest()
        sig_input = good_auth_data + client_data_hash
        assertion_sig = cred_private.sign(sig_input, ec.ECDSA(SHA256()))

        # Tamper the auth data (change the RP ID hash portion)
        tampered_auth_data = b"\x00" * 32 + auth_flags + auth_sign_count

        def _b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        assertion = {
            "id": _b64(credential_id),
            "response": {
                "clientDataJSON": _b64(auth_client_data),
                "authenticatorData": _b64(tampered_auth_data),
                "signature": _b64(assertion_sig),
            },
        }
        with pytest.raises(WebAuthnError, match="(?i)(rp.?id|invalid|signature)"):
            await manager.verify_authentication(
                assertion, auth_challenge, "https://example.com"
            )

    async def test_malformed_cbor_rejected(
        self, manager: WebAuthnManager
    ) -> None:
        """Malformed CBOR in attestationObject should raise an error (REQ-17)."""
        import base64
        import json

        import cbor2

        from araxys.webauthn.exceptions import WebAuthnError

        challenge = b"\xcf" * 32

        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        client_data_b64 = base64.urlsafe_b64encode(client_data).rstrip(b"=").decode()

        # Pass invalid (non-CBOR) bytes as attestationObject
        garbage = b"this is not cbor data!!!"
        invalid_cbor_b64 = base64.urlsafe_b64encode(garbage).rstrip(b"=").decode()

        response = {
            "id": "dGVzdC1pZA",
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": invalid_cbor_b64,
            },
        }
        with pytest.raises((WebAuthnError, cbor2.CBORDecodeError)):
            await manager.verify_registration(response, challenge, "https://example.com")

    async def test_unsupported_attestation_format(
        self, manager: WebAuthnManager
    ) -> None:
        """Unsupported attestation format should raise WebAuthnError."""
        import base64
        import hashlib
        import json

        import cbor2

        from araxys.webauthn.exceptions import WebAuthnError

        challenge = b"\xfa" * 32
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        auth_data = rp_id_hash + bytes([0x45]) + (0).to_bytes(4, "big")
        auth_data += b"\x00" * 16 + (4).to_bytes(2, "big") + b"\xaa" * 4 + b"\x00" * 10
        client_data = json.dumps({
            "type": "webauthn.create",
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()
        client_data_b64 = base64.urlsafe_b64encode(client_data).rstrip(b"=").decode()

        att_obj = cbor2.dumps({
            "fmt": "fido-u2f",
            "attStmt": {"sig": b"\x00" * 64, "alg": -7},
            "authData": auth_data,
        })
        att_obj_b64 = base64.urlsafe_b64encode(att_obj).rstrip(b"=").decode()

        response = {
            "id": "dGVzdC1pZA",
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": att_obj_b64,
            },
        }
        with pytest.raises(WebAuthnError, match="(?i)unsupported.*format"):
            await manager.verify_registration(response, challenge, "https://example.com")

    async def test_verify_authentication_credential_not_found(
        self, manager: WebAuthnManager
    ) -> None:
        """Assertion for unknown credential should raise WebAuthnError."""
        import base64
        import hashlib
        import json

        from araxys.webauthn.exceptions import WebAuthnError

        challenge = b"\xfb" * 32
        rp_id_hash = hashlib.sha256(b"example.com").digest()
        auth_data = rp_id_hash + bytes([0x05]) + (1).to_bytes(4, "big")
        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
            "origin": "https://example.com",
            "crossOrigin": False,
        }).encode()

        def _b64(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

        assertion = {
            "id": _b64(b"\x00" * 16),  # credential that was never stored
            "response": {
                "clientDataJSON": _b64(client_data),
                "authenticatorData": _b64(auth_data),
                "signature": _b64(b"\x00" * 64),
            },
        }
        with pytest.raises(WebAuthnError, match="(?i)not found"):
            await manager.verify_authentication(assertion, challenge, "https://example.com")


class TestWebAuthnDependency:
    """Tests for FastAPI dependency injection (REQ-20 / Task 6.7)."""

    @pytest.fixture
    def app_and_manager(self) -> tuple[object, object]:
        """Create a FastAPI app with WebAuthnManager wired on app.state."""
        from fastapi import FastAPI

        from araxys.webauthn.manager import WebAuthnManager
        from araxys.webauthn.models import RelyingPartyConfig
        from araxys.webauthn.storage import InMemoryCredentialStore

        app = FastAPI()
        rp_config = RelyingPartyConfig(
            rp_id="example.com",
            rp_name="Test",
            expected_origin="https://example.com",
        )
        cred_store = InMemoryCredentialStore()
        manager = WebAuthnManager(rp_config, cred_store)
        app.state.webauthn_manager = manager
        return app, manager

    def test_dependency_injects_manager(
        self, app_and_manager: tuple[object, object]
    ) -> None:
        """WebAuthnDependency should return the configured WebAuthnManager."""
        from fastapi import Depends
        from fastapi.testclient import TestClient

        from araxys.webauthn.dependencies import WebAuthnDependency

        app, expected_manager = app_and_manager

        # Register a test route that uses the dependency via Depends()
        @app.get("/test-inject")
        async def test_inject(  # type: ignore[misc]
            webauthn: object = Depends(WebAuthnDependency()),
        ) -> dict[str, object]:
            return {"injected": webauthn is expected_manager}

        client = TestClient(app)
        response = client.get("/test-inject")
        assert response.status_code == 200
        data = response.json()
        assert data["injected"] is True

    def test_dependency_no_manager_raises_error(self) -> None:
        """WebAuthnDependency should raise Error when no manager configured."""
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from araxys.webauthn.dependencies import WebAuthnDependency

        app = FastAPI()

        @app.get("/test-no-manager")
        async def test_no_manager(  # type: ignore[misc]
            webauthn: object = Depends(WebAuthnDependency()),
        ) -> dict[str, object]:
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/test-no-manager")
        # FastAPI catches the WebAuthnError and returns generic 500
        assert response.status_code == 500
