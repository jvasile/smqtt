"""
SMQTT Python client library.

Handles registration, challenge-response auth, DH key exchange,
and relationship management against the SMQTT REST API.
"""

import hashlib
import hmac as _hmac
import base64
import json
import os
from dataclasses import dataclass
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64u_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


@dataclass
class SharedSecret:
    """
    Keying material for one Relationship, derived from X25519 DH via HKDF.

    Derives:
      topic_seed  — used to compute unguessable MQTT topic names
      enc_key     — ChaCha20-Poly1305 key for payload encryption
      auth_key    — reserved for future MAC use

    Both parties derive identical material independently from the same
    X25519 exchange — the server never sees the shared secret.
    """
    peer_id: str
    topic_seed: bytes
    enc_key: bytes
    auth_key: bytes

    @classmethod
    def derive(cls, raw_secret: bytes, my_pub: bytes, peer_pub: bytes, peer_id: str) -> 'SharedSecret':
        # Sort public keys so both parties compute the same salt regardless of
        # who initiated the exchange.
        keys = sorted([my_pub, peer_pub])
        salt = keys[0] + keys[1]

        okm = HKDF(
            algorithm=hashes.SHA256(),
            length=96,
            salt=salt,
            info=b"smqtt-v1",
        ).derive(raw_secret)

        return cls(
            peer_id=peer_id,
            topic_seed=okm[0:32],
            enc_key=okm[32:64],
            auth_key=okm[64:96],
        )

    def outbound_topic(self, my_id: str) -> str:
        """Topic this user publishes to — peer subscribes to this."""
        msg = f"{my_id}>{self.peer_id}".encode()
        digest = _hmac.new(self.topic_seed, msg, hashlib.sha256).digest()
        return b64u_encode(digest)

    def inbound_topic(self, my_id: str) -> str:
        """Topic peer publishes to — this user subscribes to this."""
        msg = f"{self.peer_id}>{my_id}".encode()
        digest = _hmac.new(self.topic_seed, msg, hashlib.sha256).digest()
        return b64u_encode(digest)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with ChaCha20-Poly1305. Nonce is prepended to ciphertext."""
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(self.enc_key).encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt. Raises exception if authentication fails."""
        nonce, ct = data[:12], data[12:]
        return ChaCha20Poly1305(self.enc_key).decrypt(nonce, ct, None)


class SmqttClient:
    """
    Client for the SMQTT REST API.

    Typical flow:
        client = SmqttClient("http://localhost:8765")
        client.register()
        client.authenticate()

        # Server-mediated key exchange
        exchange_id, eph_priv = client.initiate_exchange(peer_id)
        # ... peer calls respond_to_exchange(exchange_id) ...
        secret, peer_id = client.complete_exchange(exchange_id, eph_priv)
    """

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
        self.user_id: Optional[str] = None
        self.device_id: Optional[str] = None
        self.jwt: Optional[str] = None
        self._ed_private: Optional[Ed25519PrivateKey] = None

    @property
    def _auth_headers(self) -> dict:
        return {'Authorization': f'Bearer {self.jwt}'}

    def register(self, registration_token: str = None) -> str:
        """
        Generate an Ed25519 keypair and register the public key with SMQTT.
        Returns the assigned user_id.
        """
        self._ed_private = Ed25519PrivateKey.generate()
        pub_raw = self._ed_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        body = {'pubkey': b64u_encode(pub_raw)}
        if registration_token:
            body['registration_token'] = registration_token

        r = requests.post(f"{self.server_url}/register", json=body)
        r.raise_for_status()
        data = r.json()
        self.user_id  = data['user_id']
        self.device_id = data['device_id']
        return self.user_id

    def authenticate(self) -> str:
        """
        Challenge-response auth: SMQTT issues a nonce, we sign it with our
        Ed25519 private key, SMQTT verifies and returns a JWT.
        """
        r = requests.get(f"{self.server_url}/auth/challenge",
                         params={'user_id': self.user_id})
        r.raise_for_status()
        nonce = b64u_decode(r.json()['nonce'])

        sig = self._ed_private.sign(nonce)
        r = requests.post(f"{self.server_url}/auth/verify", json={
            'user_id':   self.user_id,
            'device_id': self.device_id,
            'signature': b64u_encode(sig),
        })
        r.raise_for_status()
        self.jwt = r.json()['token']
        return self.jwt

    def initiate_exchange(self, peer_id: str) -> tuple[str, X25519PrivateKey]:
        """
        Start a DH key exchange with peer_id. Returns (exchange_id, ephemeral_private_key).
        Hold onto the ephemeral private key — you need it to complete the exchange.
        """
        eph_priv = X25519PrivateKey.generate()
        pub_raw = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        r = requests.post(
            f"{self.server_url}/exchange",
            json={'peer_id': peer_id, 'ephemeral_pubkey': b64u_encode(pub_raw)},
            headers=self._auth_headers,
        )
        r.raise_for_status()
        return r.json()['exchange_id'], eph_priv

    def respond_to_exchange(self, exchange_id: str) -> tuple[SharedSecret, str]:
        """
        Respond to an exchange initiated by a peer. Derives the shared secret
        and registers the Relationship. Returns (shared_secret, peer_id).
        """
        r = requests.get(f"{self.server_url}/exchange/{exchange_id}",
                         headers=self._auth_headers)
        r.raise_for_status()
        data = r.json()

        initiator_pub_raw = b64u_decode(data['initiator_pubkey'])
        peer_id = data['initiator_id']

        eph_priv = X25519PrivateKey.generate()
        our_pub_raw = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        raw_secret = eph_priv.exchange(X25519PublicKey.from_public_bytes(initiator_pub_raw))

        r = requests.post(
            f"{self.server_url}/exchange/{exchange_id}/respond",
            json={'ephemeral_pubkey': b64u_encode(our_pub_raw)},
            headers=self._auth_headers,
        )
        r.raise_for_status()

        secret = SharedSecret.derive(raw_secret, our_pub_raw, initiator_pub_raw, peer_id)
        self._create_relationship(peer_id, secret)
        return secret, peer_id

    def complete_exchange(self, exchange_id: str, eph_priv: X25519PrivateKey) -> Optional[tuple[SharedSecret, str]]:
        """
        Complete an exchange after the peer has responded. Returns
        (shared_secret, peer_id) or None if the peer hasn't responded yet.
        """
        r = requests.get(f"{self.server_url}/exchange/{exchange_id}",
                         headers=self._auth_headers)
        r.raise_for_status()
        data = r.json()

        if not data.get('responder_pubkey'):
            return None

        our_pub_raw = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        responder_pub_raw = b64u_decode(data['responder_pubkey'])
        raw_secret = eph_priv.exchange(X25519PublicKey.from_public_bytes(responder_pub_raw))
        peer_id = data['responder_id']

        secret = SharedSecret.derive(raw_secret, our_pub_raw, responder_pub_raw, peer_id)
        self._create_relationship(peer_id, secret)
        return secret, peer_id

    def _create_relationship(self, peer_id: str, secret: SharedSecret) -> str:
        r = requests.post(
            f"{self.server_url}/relationships",
            json={
                'peer_id': peer_id,
                'publish_topics': [secret.outbound_topic(self.user_id)],
                'subscribe_topics': [secret.inbound_topic(self.user_id)],
            },
            headers=self._auth_headers,
        )
        r.raise_for_status()
        return r.json()['relationship_id']
