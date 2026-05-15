"""Tests for the audit logging and encryption module."""

import pytest

from araxys.audit.encryption import AuditEncryption
from araxys.audit.logger import AuditLogger
from araxys.core.config import AuditConfig
from araxys.core.exceptions import EncryptionError
from araxys.core.types import AuditEntry, AuditEventType


class TestAuditEncryption:
    @pytest.fixture
    def encryption(self) -> AuditEncryption:
        return AuditEncryption(master_key="test-secret-key-must-be-32-chars!!")

    def test_encrypt_decrypt_roundtrip(self, encryption: AuditEncryption) -> None:
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="1.2.3.4",
            user_id="user-123",
            detail="Login via JWT",
        )
        encrypted = encryption.encrypt_entry(entry)
        decrypted = encryption.decrypt_entry(encrypted)

        assert decrypted["event_type"] == "login_success"
        assert decrypted["ip_address"] == "1.2.3.4"
        assert decrypted["user_id"] == "user-123"

    def test_different_entries_different_ciphertext(
        self, encryption: AuditEncryption
    ) -> None:
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="1.2.3.4",
        )
        # Same entry encrypted twice should produce different ciphertext
        # (because of random salt and nonce)
        c1 = encryption.encrypt_entry(entry)
        c2 = encryption.encrypt_entry(entry)
        assert c1 != c2

    def test_wrong_key_fails_decryption(self, encryption: AuditEncryption) -> None:
        entry = AuditEntry(event_type=AuditEventType.RATE_LIMITED)
        encrypted = encryption.encrypt_entry(entry)

        wrong_key_encryption = AuditEncryption(
            master_key="wrong-key-that-is-also-32-chars!!"
        )
        with pytest.raises(EncryptionError):
            wrong_key_encryption.decrypt_entry(encrypted)

    def test_tampered_ciphertext_fails(self, encryption: AuditEncryption) -> None:
        entry = AuditEntry(event_type=AuditEventType.HONEYPOT_TRIGGERED)
        encrypted = encryption.encrypt_entry(entry)

        # Tamper with the base64 content
        tampered = encrypted[:-4] + "XXXX"
        with pytest.raises(EncryptionError):
            encryption.decrypt_entry(tampered)


class TestAuditLogger:
    async def test_logger_logs_without_file(self) -> None:
        logger = AuditLogger(
            config=AuditConfig(enabled=True, encrypt=False, log_file=None),
        )
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="1.2.3.4",
        )
        # Should not raise
        await logger.log(entry)

    async def test_logger_writes_to_file(self, tmp_path) -> None:  # type: ignore
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            config=AuditConfig(enabled=True, encrypt=False, log_file=str(log_file)),
        )
        entry = AuditEntry(
            event_type=AuditEventType.API_KEY_CREATED,
            detail="Test key created",
        )
        await logger.log(entry)

        assert log_file.exists()
        entries = logger.read_entries()
        assert len(entries) == 1
        assert entries[0]["event_type"] == "api_key_created"

    async def test_encrypted_file_roundtrip(self, tmp_path) -> None:  # type: ignore
        log_file = tmp_path / "audit_encrypted.log"
        secret = "test-secret-key-must-be-32-chars!!"
        logger = AuditLogger(
            config=AuditConfig(enabled=True, encrypt=True, log_file=str(log_file)),
            secret_key=secret,
        )

        entry = AuditEntry(
            event_type=AuditEventType.HONEYPOT_TRIGGERED,
            ip_address="10.0.0.1",
            detail="Bot trapped on /admin/config",
        )
        await logger.log(entry)

        entries = logger.read_entries()
        assert len(entries) == 1
        assert entries[0]["ip_address"] == "10.0.0.1"

        # Raw file content should be encrypted (not readable JSON)
        raw = log_file.read_text()
        assert "10.0.0.1" not in raw  # IP should be encrypted
