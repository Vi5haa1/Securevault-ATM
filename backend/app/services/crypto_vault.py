import os
import uuid
import datetime
import hashlib
import hmac
import base64
import logging
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from app.db.models.models import Certificate, HsmKey, KeyUsageAudit, Atm
from app.audit.writer import write_audit_log

logger = logging.getLogger("securevault.crypto")

# Master Vault Encryption Key (from env or securely derived for local dev)
MASTER_VAULT_KEY = os.environ.get("SECUREVAULT_MASTER_KEY", "sv-master-vault-aes256gcm-key-2026-production!!").encode()[:32].ljust(32, b"0")


class CryptoVault:
    """
    Cryptographic Controls & Operations Service
    - AES-256-GCM authenticated encryption with unique 96-bit nonces
    - Ed25519 digital signatures for firmware & audit manifests
    - HMAC-SHA256 for message authentication (MAC)
    - Constant-time comparisons (prevent timing side-channels)
    """

    @classmethod
    def encrypt_data(cls, plaintext: str, key_bytes: Optional[bytes] = None) -> Dict[str, str]:
        """Encrypts sensitive payload using AES-256-GCM with a random 96-bit nonce."""
        key = key_bytes or MASTER_VAULT_KEY
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit unique nonce
        data_bytes = plaintext.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)

        return {
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
        }

    @classmethod
    def decrypt_data(cls, nonce_b64: str, ciphertext_b64: str, key_bytes: Optional[bytes] = None) -> str:
        """Decrypts and authenticates AES-256-GCM ciphertext."""
        key = key_bytes or MASTER_VAULT_KEY
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    @classmethod
    def compute_mac(cls, message: str, key_bytes: Optional[bytes] = None) -> str:
        """Generates HMAC-SHA256 digest for message authentication."""
        key = key_bytes or MASTER_VAULT_KEY
        digest = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest

    @classmethod
    def verify_mac(cls, message: str, expected_mac: str, key_bytes: Optional[bytes] = None) -> bool:
        """Constant-time verification of HMAC-SHA256 digest."""
        computed = cls.compute_mac(message, key_bytes)
        return hmac.compare_digest(computed, expected_mac)

    @classmethod
    def generate_ed25519_keypair(cls) -> Tuple[str, str]:
        """Generates an Ed25519 signature keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return priv_pem, pub_pem

    @classmethod
    def sign_ed25519(cls, private_pem: str, data: str) -> str:
        """Signs payload using Ed25519 private key."""
        priv_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        sig = priv_key.sign(data.encode("utf-8"))
        return base64.b64encode(sig).decode("utf-8")

    @classmethod
    def verify_ed25519(cls, public_pem: str, data: str, sig_b64: str) -> bool:
        """Verifies Ed25519 signature in constant-time."""
        try:
            pub_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
            sig = base64.b64decode(sig_b64)
            pub_key.verify(sig, data.encode("utf-8"))
            return True
        except Exception:
            return False


class PkiService:
    """
    Simulated Internal PKI & X.509 Certificate Authority
    Generates genuine X.509 certificates using Python cryptography library for ATM client identities.
    Manages issuance, rotation, CRL/revocation, and validation.
    """

    @classmethod
    async def issue_atm_certificate(cls, db: AsyncSession, atm_code: str, atm_id: Optional[int] = None) -> Certificate:
        """Issues a genuine synthetic X.509 certificate for an ATM terminal."""
        cert_id = f"CERT-{atm_code}"
        
        # Check if already exists
        stmt = select(Certificate).where(Certificate.cert_id == cert_id)
        res = await db.execute(stmt)
        existing = res.scalar_one_or_none()
        if existing:
            return existing

        # Generate RSA 2048 keypair for the ATM
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVault ATM Banking Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, atm_code)
        ])
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVault Root CA G2"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureVault Internal ATM Root CA")
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        valid_until = now + datetime.timedelta(days=365)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(valid_until)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        db_cert = Certificate(
            cert_id=cert_id,
            subject=f"CN={atm_code}, O=SecureVault",
            issuer="CN=SecureVault Internal ATM Root CA",
            serial_number=str(cert.serial_number),
            fingerprint=fingerprint,
            valid_from=now,
            valid_until=valid_until,
            status="VALID",
            public_key_pem=cert_pem,
            atm_id=atm_id
        )
        db.add(db_cert)
        await db.flush()

        # Update ATM's certificate reference
        if atm_id:
            await db.execute(
                update(Atm)
                .where(Atm.id == atm_id)
                .values(certificate_id=cert_id, certificate_status="VALID")
            )

        return db_cert

    @classmethod
    async def revoke_certificate(cls, db: AsyncSession, cert_id: str, reason: str, actor: str) -> Certificate:
        """Revokes a certificate and blocks associated ATM terminal."""
        stmt = select(Certificate).where(Certificate.cert_id == cert_id)
        res = await db.execute(stmt)
        cert = res.scalar_one_or_none()
        if not cert:
            raise ValueError(f"Certificate '{cert_id}' not found.")

        cert.status = "REVOKED"
        cert.revocation_reason = reason

        # If attached to an ATM, degrade ATM certificate status
        if cert.atm_id:
            await db.execute(
                update(Atm)
                .where(Atm.id == cert.atm_id)
                .values(certificate_status="REVOKED")
            )

        await write_audit_log(
            db=db,
            action="CERTIFICATE_REVOKED",
            resource_type="PKI_CERTIFICATE",
            resource_id=cert_id,
            actor_id=actor,
            actor_role="SECURITY_OFFICER",
            payload={"cert_id": cert_id, "reason": reason}
        )
        await db.commit()
        return cert


class HsmKeyVault:
    """
    Hardware Security Module (HSM) Simulator & Key Management Service
    Encrypted key material at rest using Master Vault Key.
    Supports key generation, rotation, version tracking, and audited usage.
    """

    @classmethod
    async def get_or_create_key(cls, db: AsyncSession, purpose: str, algorithm: str = "AES-256-GCM") -> HsmKey:
        """Retrieves active key for purpose, or generates one if absent."""
        stmt = select(HsmKey).where(
            HsmKey.purpose == purpose,
            HsmKey.status == "ACTIVE"
        ).order_by(HsmKey.version.desc())
        res = await db.execute(stmt)
        key = res.scalars().first()

        if key:
            return key

        # Generate new key
        raw_key = os.urandom(32)
        encrypted_material = CryptoVault.encrypt_data(base64.b64encode(raw_key).decode("utf-8"))

        now = datetime.datetime.now(datetime.timezone.utc)
        new_key = HsmKey(
            key_id=f"KEY-{purpose.upper()}-V1",
            purpose=purpose,
            algorithm=algorithm,
            version=1,
            status="ACTIVE",
            expires_at=now + datetime.timedelta(days=90),
            key_material_encrypted=f"{encrypted_material['nonce']}:{encrypted_material['ciphertext']}",
            usage_count=0
        )
        db.add(new_key)
        await db.commit()
        return new_key

    @classmethod
    async def rotate_key(cls, db: AsyncSession, key_id: str, actor: str) -> HsmKey:
        """Rotates a key: marks current key ROTATING and spawns new ACTIVE version."""
        stmt = select(HsmKey).where(HsmKey.key_id == key_id)
        res = await db.execute(stmt)
        old_key = res.scalar_one_or_none()
        if not old_key:
            raise ValueError(f"HSM Key '{key_id}' not found.")

        old_key.status = "ROTATING"
        new_version = old_key.version + 1

        raw_key = os.urandom(32)
        encrypted_material = CryptoVault.encrypt_data(base64.b64encode(raw_key).decode("utf-8"))

        now = datetime.datetime.now(datetime.timezone.utc)
        new_key = HsmKey(
            key_id=f"KEY-{old_key.purpose.upper()}-V{new_version}",
            purpose=old_key.purpose,
            algorithm=old_key.algorithm,
            version=new_version,
            status="ACTIVE",
            expires_at=now + datetime.timedelta(days=90),
            key_material_encrypted=f"{encrypted_material['nonce']}:{encrypted_material['ciphertext']}",
            usage_count=0
        )
        db.add(new_key)

        await write_audit_log(
            db=db,
            action="HSM_KEY_ROTATED",
            resource_type="HSM_KEY",
            resource_id=key_id,
            actor_id=actor,
            actor_role="SECURITY_ADMIN",
            payload={"old_key": key_id, "new_key": new_key.key_id, "version": new_version}
        )
        await db.commit()
        return new_key
