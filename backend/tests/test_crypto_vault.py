import pytest
from app.services.crypto_vault import CryptoVault, PkiService, HsmKeyVault
from app.db.models.models import Certificate, HsmKey

def test_aes_gcm_encryption_roundtrip():
    plaintext = "Confidential Banking Payload - Account Balance INR 2,50,000"
    encrypted = CryptoVault.encrypt_data(plaintext)
    
    assert "nonce" in encrypted
    assert "ciphertext" in encrypted
    assert encrypted["algorithm"] == "AES-256-GCM"
    
    # Decrypt and verify
    decrypted = CryptoVault.decrypt_data(
        encrypted["nonce"],
        encrypted["ciphertext"]
    )
    assert decrypted == plaintext

def test_aes_gcm_tamper_detection():
    plaintext = "Integrity critical ledger entry"
    encrypted = CryptoVault.encrypt_data(plaintext)
    
    # Tamper with the ciphertext by altering the base64 string
    tampered_ct = "A" + encrypted["ciphertext"][1:]
    
    with pytest.raises(Exception):
        CryptoVault.decrypt_data(
            encrypted["nonce"],
            tampered_ct
        )

def test_ed25519_signatures():
    priv_pem, pub_pem = CryptoVault.generate_ed25519_keypair()
    manifest_data = "Firmware-Version-3.4.1-Signed-Build"
    
    sig = CryptoVault.sign_ed25519(priv_pem, manifest_data)
    assert isinstance(sig, str) and len(sig) > 10
    
    # Verify signature
    is_valid = CryptoVault.verify_ed25519(pub_pem, manifest_data, sig)
    assert is_valid is True
    
    # Tampered manifest should fail verification
    is_tampered_valid = CryptoVault.verify_ed25519(pub_pem, manifest_data + "_TAMPERED", sig)
    assert is_tampered_valid is False

@pytest.mark.asyncio
async def test_pki_x509_certificate_generation(db_session):
    cert = await PkiService.issue_atm_certificate(db_session, "SV-ATM-CHE-101")
    assert isinstance(cert, Certificate)
    assert "SV-ATM-CHE-101" in cert.subject
    assert "BEGIN" in cert.public_key_pem
    assert cert.fingerprint is not None
    assert len(cert.fingerprint) == 64
    assert cert.status == "VALID"

@pytest.mark.asyncio
async def test_hsm_key_lifecycle_and_rotation(db_session):
    key = await HsmKeyVault.get_or_create_key(db_session, "TRANSACTION_ENCRYPTION")
    assert isinstance(key, HsmKey)
    assert key.status == "ACTIVE"
    assert key.version == 1

    # Rotate key
    rotated_key = await HsmKeyVault.rotate_key(db_session, key.key_id, "SECURITY_ADMIN")
    assert rotated_key.version == 2
    assert rotated_key.status == "ACTIVE"
