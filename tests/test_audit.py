"""Tests for the audit logging and encryption module."""

from typing import Any

import pytest

from araxys.audit.encryption import AuditEncryption
from araxys.audit.logger import AuditLogger
from araxys.audit.masking import mask_pii
from araxys.audit.shipping import LogShipper
from araxys.audit.writer import LogWriter
from araxys.core.config import AuditConfig, LogShippingConfig
from araxys.core.exceptions import EncryptionError
from araxys.core.types import AuditEntry, AuditEventType


class TestPIIDetection:
    """Tests for PII masking utility (task 4.3)."""

    def test_mask_simple_fields(self) -> None:
        data = {"email": "user@example.com", "name": "John"}
        result = mask_pii(data, pii_fields=["email"])
        assert result["email"] == "***"
        assert result["name"] == "John"

    def test_original_not_mutated(self) -> None:
        data = {"email": "user@example.com"}
        original_copy = dict(data)
        mask_pii(data, pii_fields=["email"])
        assert data == original_copy  # original unchanged

    def test_nested_dict_masking(self) -> None:
        data = {"user": {"email": "a@b.com", "name": "Alice"}, "role": "admin"}
        result = mask_pii(data, pii_fields=["email"])
        assert result["user"]["email"] == "***"
        assert result["user"]["name"] == "Alice"
        assert result["role"] == "admin"

    def test_list_of_dicts_masking(self) -> None:
        data = {
            "users": [
                {"email": "a@b.com", "name": "A"},
                {"email": "c@d.com", "name": "C"},
            ]
        }
        result = mask_pii(data, pii_fields=["email"])
        for user in result["users"]:
            assert user["email"] == "***"
        assert result["users"][0]["name"] == "A"

    def test_multiple_pii_fields(self) -> None:
        data = {"email": "e@e.com", "password": "s3cret", "name": "Bob"}
        result = mask_pii(data, pii_fields=["email", "password"])
        assert result["email"] == "***"
        assert result["password"] == "***"
        assert result["name"] == "Bob"

    def test_no_pii_fields_no_change(self) -> None:
        data = {"name": "Alice", "role": "user"}
        result = mask_pii(data, pii_fields=[])
        assert result == data

    def test_custom_mask_char(self) -> None:
        data = {"email": "user@example.com"}
        result = mask_pii(data, pii_fields=["email"], mask_char="#")
        assert result["email"] == "###"

    def test_deeply_nested_masking(self) -> None:
        data = {"level1": {"level2": {"level3": {"email": "deep@x.com"}}}}
        result = mask_pii(data, pii_fields=["email"])
        assert result["level1"]["level2"]["level3"]["email"] == "***"

    def test_non_dict_data_passes_through(self) -> None:
        result = mask_pii("just a string", pii_fields=["email"])
        assert result == "just a string"


class TestLogWriter:
    """Tests for the LogWriter file I/O and rotation (tasks 4.1, 4.2)."""

    async def test_writes_line_to_file(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.log"
        writer = LogWriter(log_file=str(log_file), async_write=False)
        await writer.write('{"event":"test"}\n')
        await writer.flush()
        content = log_file.read_text(encoding="utf-8")
        assert '{"event":"test"}' in content

    async def test_async_write_uses_aiofiles(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.log"
        writer = LogWriter(log_file=str(log_file), async_write=True)
        await writer.write('{"event":"async_test"}\n')
        await writer.flush()
        content = log_file.read_text(encoding="utf-8")
        assert '{"event":"async_test"}' in content

    async def test_rotation_creates_backup(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.log"
        writer = LogWriter(
            log_file=str(log_file),
            log_rotation_bytes=10,
            log_backup_count=2,
            async_write=False,
        )
        # First write creates the file
        await writer.write("x" * 20 + "\n")
        await writer.flush()
        # Second write triggers rotation (file size > threshold)
        await writer.write("y" * 20 + "\n")
        await writer.flush()
        # The original content should now be in audit.log.1
        backup = tmp_path / "audit.log.1"
        assert backup.exists()
        content = backup.read_text()
        assert "x" in content
        assert backup.stat().st_size > 0

    async def test_rotation_limits_backup_count(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.log"
        writer = LogWriter(
            log_file=str(log_file),
            log_rotation_bytes=10,
            log_backup_count=2,
            async_write=False,
        )
        # Write enough to trigger multiple rotations
        for _ in range(5):
            await writer.write("x" * 50 + "\n")
        await writer.flush()
        # Only 2 backups should exist
        assert (tmp_path / "audit.log.1").exists()
        assert (tmp_path / "audit.log.2").exists()
        assert not (tmp_path / "audit.log.3").exists()

    async def test_no_rotation_when_disabled(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.log"
        writer = LogWriter(
            log_file=str(log_file),
            log_rotation_bytes=0,  # disabled
            async_write=False,
        )
        await writer.write("x" * 1000 + "\n")
        await writer.flush()
        assert not (tmp_path / "audit.log.1").exists()
        assert log_file.exists()

    async def test_flush_buffer_on_shutdown(self, tmp_path: Any) -> None:
        """Verify buffered writes are flushed before writer is closed."""
        log_file = tmp_path / "audit.log"
        writer = LogWriter(log_file=str(log_file), async_write=True)
        await writer.write("line1\n")
        await writer.write("line2\n")
        # Without explicit flush, close should flush
        writer.close()
        content = log_file.read_text(encoding="utf-8")
        assert "line1" in content
        assert "line2" in content


class TestLogShipper:
    """Tests for the LogShipper that ships audit events via webhook (task 4.4)."""

    async def test_ship_sends_json_post(self, tmp_path: Any) -> None:
        """Verify the shipper sends a JSON POST to the configured endpoint."""
        import httpx

        captured: list[dict[str, Any]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append({
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": request.content.decode(),
            })
            return httpx.Response(200, json={"status": "ok"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        shipper = LogShipper(
            config=LogShippingConfig(
                type="http",
                endpoint="https://logs.example.com/ingest",
                headers={"X-API-Key": "test-key"},
                tls_enabled=True,
            ),
            client=client,
        )

        await shipper.ship({"event_type": "login_success", "user_id": "u-1"})

        assert len(captured) == 1
        assert captured[0]["method"] == "POST"
        assert captured[0]["url"] == "https://logs.example.com/ingest"
        # httpx lowercases header names in MockTransport
        assert captured[0]["headers"].get("x-api-key") == "test-key"
        assert '"event_type": "login_success"' in captured[0]["body"]

    async def test_tls_disabled_uses_http(self, tmp_path: Any) -> None:
        """When tls_enabled is False, the endpoint should use http://."""
        import httpx

        captured: list[dict[str, Any]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append({"url": str(request.url)})
            return httpx.Response(200)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        shipper = LogShipper(
            config=LogShippingConfig(
                type="http",
                endpoint="https://logs.example.com/ingest",
                tls_enabled=False,
            ),
            client=client,
        )

        await shipper.ship({"event": "test"})
        assert captured[0]["url"].startswith("http://")

    async def test_shipping_failure_does_not_raise(self) -> None:
        """Shipping failures must NOT raise — they log a warning and continue."""
        import httpx

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        shipper = LogShipper(
            config=LogShippingConfig(
                type="http",
                endpoint="https://logs.example.com/ingest",
            ),
            client=client,
        )

        # Should not raise any exception
        await shipper.ship({"event": "test"})

    async def test_shipping_connection_error_does_not_raise(self) -> None:
        """Connection errors must NOT raise — they log a warning and continue."""
        import httpx

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.RequestError("Connection refused")

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        shipper = LogShipper(
            config=LogShippingConfig(
                type="http",
                endpoint="https://logs.example.com/ingest",
            ),
            client=client,
        )

        # Should not raise any exception
        await shipper.ship({"event": "test"})


class TestAuditLoggerIntegration:
    """Integration tests for the updated AuditLogger with PII, writer, shipping."""

    async def test_logger_masks_pii_before_write(self, tmp_path: Any) -> None:
        """Fields listed in pii_fields should be masked in the written log."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            config=AuditConfig(
                enabled=True,
                encrypt=False,
                log_file=str(log_file),
                pii_fields=["user_id"],
            ),
        )
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="1.2.3.4",
            user_id="u-1",
        )
        await logger.log(entry)
        entries = logger.read_entries()
        assert entries[0]["user_id"] == "***"
        assert entries[0]["ip_address"] == "1.2.3.4"  # non-PII preserved

    async def test_logger_masks_pii_fields_in_entry_dict(self, tmp_path: Any) -> None:
        """Verify that fields listed in pii_fields are masked in the written log."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            config=AuditConfig(
                enabled=True,
                encrypt=False,
                log_file=str(log_file),
                pii_fields=["user_id", "api_key_prefix"],
            ),
        )
        entry = AuditEntry(
            event_type=AuditEventType.API_KEY_CREATED,
            ip_address="1.2.3.4",
            user_id="user-456",
            api_key_prefix="sk-abc",
        )
        await logger.log(entry)
        entries = logger.read_entries()
        assert entries[0]["user_id"] == "***"
        assert entries[0]["api_key_prefix"] == "***"

    async def test_logger_async_write_flag(self, tmp_path: Any) -> None:
        """async_write=True should produce a valid log file."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            config=AuditConfig(
                enabled=True,
                encrypt=False,
                log_file=str(log_file),
                async_write=True,
            ),
        )
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="5.6.7.8",
        )
        await logger.log(entry)
        entries = logger.read_entries()
        assert len(entries) == 1
        assert entries[0]["ip_address"] == "5.6.7.8"

    async def test_logger_with_rotation(self, tmp_path: Any) -> None:
        """Logger with rotation should rotate files correctly."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            config=AuditConfig(
                enabled=True,
                encrypt=False,
                log_file=str(log_file),
                log_rotation_bytes=10,
                log_backup_count=2,
            ),
        )
        for i in range(3):
            entry = AuditEntry(
                event_type=AuditEventType.LOGIN_SUCCESS,
                ip_address=f"10.0.0.{i}",
                detail="x" * 50,  # force rotation
            )
            await logger.log(entry)

        # After rotations, at least one backup should exist
        assert (tmp_path / "audit.log.1").exists()

    async def test_logger_with_encryption_and_masking(self, tmp_path: Any) -> None:
        """Encrypted logs mask PII field values before encrypting."""
        log_file = tmp_path / "audit_encrypted.log"
        secret = "test-secret-key-must-be-32-chars!!"
        logger = AuditLogger(
            config=AuditConfig(
                enabled=True,
                encrypt=True,
                log_file=str(log_file),
                pii_fields=["user_id"],
            ),
            secret_key=secret,
        )
        entry = AuditEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="1.2.3.4",
            user_id="sensitive-user",
        )
        await logger.log(entry)
        entries = logger.read_entries()
        # Masking should be applied before encryption, so the decrypted data is masked
        assert entries[0]["user_id"] == "***"
        assert entries[0]["ip_address"] == "1.2.3.4"

    async def test_backward_compatibility(self, tmp_path: Any) -> None:
        """Original tests should still work — no PII, no rotation, no async."""
        log_file = tmp_path / "audit_bc.log"
        logger = AuditLogger(
            config=AuditConfig(enabled=True, encrypt=False, log_file=str(log_file)),
        )
        entry = AuditEntry(
            event_type=AuditEventType.API_KEY_CREATED,
            detail="Backward compat test",
        )
        await logger.log(entry)
        assert log_file.exists()
        entries = logger.read_entries()
        assert len(entries) == 1
        assert entries[0]["event_type"] == "api_key_created"


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
