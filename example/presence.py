"""
Multi-user presence demo for SMQTT.

Three users (Alice, Bob, Carol) share mocked GPS location with each other.
Each pair has a separate Relationship with independent encryption keys derived
from a pairwise X25519 DH exchange. Location data is encrypted on-device
before publishing; the MQTT broker sees only ciphertext.

This demo includes an in-process mock SMQTT REST server. When the real SMQTT
is built, replace SMQTT_URL with its address and remove the mock server.

Requirements:
    pip install -r requirements.txt
    mosquitto &          # local MQTT broker on localhost:1883

Usage:
    python presence.py
"""

import json
import math
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import jwt as pyjwt
import paho.mqtt.client as mqtt
import requests
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from smqtt_client import SmqttClient, SharedSecret, b64u_encode, b64u_decode

SMQTT_URL  = "http://localhost:8765"
MQTT_HOST  = "localhost"
MQTT_PORT  = 1883
TICK_SECS  = 2      # location publish interval
PRINT_SECS = 4      # display refresh interval


# ─────────────────────────────────────────────────────────────
# Mock SMQTT REST server
#
# Implements just enough of the SMQTT API to run the demo.
# Note: uses HS256 JWTs for simplicity; real SMQTT uses Ed25519.
# ─────────────────────────────────────────────────────────────

_mock_app   = Flask(__name__)
_users      = {}      # user_id -> {pubkey_raw}
_challenges = {}      # user_id -> nonce
_exchanges  = {}      # exchange_id -> {initiator_id, initiator_pubkey, responder_id, responder_pubkey}
_rels       = {}      # rel_id -> {user_id, peer_id, publish_topics, subscribe_topics}
_JWT_SECRET = os.urandom(32)


@_mock_app.route('/register', methods=['POST'])
def _register():
    data = request.json
    user_id   = str(uuid.uuid4())[:8]
    device_id = str(uuid.uuid4())[:8]
    _users[user_id] = {'pubkey_raw': b64u_decode(data['pubkey'])}
    return jsonify({'user_id': user_id, 'device_id': device_id})


@_mock_app.route('/auth/challenge')
def _challenge():
    user_id = request.args['user_id']
    nonce = os.urandom(32)
    _challenges[user_id] = nonce
    return jsonify({'nonce': b64u_encode(nonce)})


@_mock_app.route('/auth/verify', methods=['POST'])
def _verify():
    data = request.json
    user_id = data['user_id']
    nonce = _challenges.pop(user_id, None)
    if not nonce:
        return jsonify({'error': 'no challenge'}), 400
    pub_key = Ed25519PublicKey.from_public_bytes(_users[user_id]['pubkey_raw'])
    try:
        pub_key.verify(b64u_decode(data['signature']), nonce)
    except Exception:
        return jsonify({'error': 'invalid signature'}), 401
    token = pyjwt.encode(
        {'sub': user_id, 'exp': int(time.time()) + 3600},
        _JWT_SECRET, algorithm='HS256'
    )
    return jsonify({'token': token})


def _jwt_user_id(req) -> Optional[str]:
    auth = req.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    try:
        return pyjwt.decode(auth[7:], _JWT_SECRET, algorithms=['HS256'])['sub']
    except Exception:
        return None


@_mock_app.route('/exchange', methods=['POST'])
def _initiate_exchange():
    data = request.json
    exchange_id = str(uuid.uuid4())
    _exchanges[exchange_id] = {
        'initiator_id':     _jwt_user_id(request),
        'initiator_pubkey': data['ephemeral_pubkey'],
        'responder_id':     data['peer_id'],
        'responder_pubkey': None,
    }
    return jsonify({'exchange_id': exchange_id})


@_mock_app.route('/exchange/<exchange_id>')
def _get_exchange(exchange_id):
    return jsonify(_exchanges[exchange_id])


@_mock_app.route('/exchange/<exchange_id>/respond', methods=['POST'])
def _respond_exchange(exchange_id):
    _exchanges[exchange_id]['responder_pubkey'] = request.json['ephemeral_pubkey']
    return jsonify(_exchanges[exchange_id])


@_mock_app.route('/relationships', methods=['POST'])
def _create_rel():
    data = request.json
    rel_id = str(uuid.uuid4())
    _rels[rel_id] = {'user_id': _jwt_user_id(request), **data}
    return jsonify({'relationship_id': rel_id})


def _run_mock_server():
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    _mock_app.run(port=8765, threaded=True)


# ─────────────────────────────────────────────────────────────
# Location simulation
# ─────────────────────────────────────────────────────────────

@dataclass
class Location:
    name: str
    lat: float
    lon: float

    def move(self):
        """Small random walk each tick."""
        self.lat += random.gauss(0, 0.0005)
        self.lon += random.gauss(0, 0.0005)

    def distance_km(self, other: 'Location') -> float:
        R = 6371
        dlat = math.radians(other.lat - self.lat)
        dlon = math.radians(other.lon - self.lon)
        a = (math.sin(dlat / 2) ** 2
             + math.cos(math.radians(self.lat))
             * math.cos(math.radians(other.lat))
             * math.sin(dlon / 2) ** 2)
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def to_payload(self) -> bytes:
        return json.dumps({
            'lat': round(self.lat, 6),
            'lon': round(self.lon, 6),
            'ts':  round(time.time(), 2),
        }).encode()

    @classmethod
    def from_payload(cls, name: str, raw: bytes) -> 'Location':
        d = json.loads(raw)
        return cls(name=name, lat=d['lat'], lon=d['lon'])


# ─────────────────────────────────────────────────────────────
# User agent
# ─────────────────────────────────────────────────────────────

@dataclass
class User:
    name: str
    start_lat: float
    start_lon: float

    client:          SmqttClient   = field(init=False)
    location:        Location      = field(init=False)
    secrets:         dict          = field(default_factory=dict)  # peer_id -> SharedSecret
    peer_names:      dict          = field(default_factory=dict)  # peer_id -> name
    known_locations: dict          = field(default_factory=dict)  # peer_name -> Location
    _lock:           threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self.client   = SmqttClient(SMQTT_URL)
        self.location = Location(self.name, self.start_lat, self.start_lon)

    def setup(self):
        """Register and authenticate with SMQTT."""
        self.client.register()
        self.client.authenticate()

    def add_relationship(self, secret: SharedSecret, peer_name: str):
        self.secrets[secret.peer_id]    = secret
        self.peer_names[secret.peer_id] = peer_name

    def run(self):
        """Connect to MQTT, subscribe to peer topics, and publish location in a loop."""
        mqc = mqtt.Client(client_id=f"{self.name}-{self.client.user_id}")

        def on_connect(client, userdata, flags, rc):
            if rc != 0:
                print(f"  {self.name}: MQTT connect failed (rc={rc})")
                return
            for peer_id, secret in self.secrets.items():
                topic = secret.inbound_topic(self.client.user_id)
                client.subscribe(topic, qos=1)

        def on_message(client, userdata, msg):
            for peer_id, secret in self.secrets.items():
                if msg.topic == secret.inbound_topic(self.client.user_id):
                    try:
                        plaintext = secret.decrypt(bytes(msg.payload))
                        loc = Location.from_payload(self.peer_names[peer_id], plaintext)
                        with self._lock:
                            self.known_locations[self.peer_names[peer_id]] = loc
                    except Exception as e:
                        print(f"  {self.name}: decrypt error from {self.peer_names[peer_id]}: {e}")
                    break

        mqc.on_connect = on_connect
        mqc.on_message = on_message
        mqc.username_pw_set(self.client.user_id, self.client.jwt)
        mqc.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        mqc.loop_start()

        while True:
            self.location.move()
            for peer_id, secret in self.secrets.items():
                topic   = secret.outbound_topic(self.client.user_id)
                payload = secret.encrypt(self.location.to_payload())
                # Each peer gets a separately-encrypted copy — different enc_key per Relationship
                mqc.publish(topic, payload, qos=1, retain=True)
            time.sleep(TICK_SECS)

    def status_lines(self) -> list[str]:
        with self._lock:
            lines = [f"  {self.name:<8} {self.location.lat:+.4f}, {self.location.lon:+.4f}  (self)"]
            for peer_name, loc in sorted(self.known_locations.items()):
                dist = self.location.distance_km(loc)
                age  = time.time() - json.loads(
                    # re-derive age from the stored loc — approximate
                    json.dumps({'lat': loc.lat, 'lon': loc.lon})
                ).get('ts', time.time())
                lines.append(
                    f"    {peer_name:<8} {loc.lat:+.4f}, {loc.lon:+.4f}  "
                    f"({dist:,.0f} km away)"
                )
            return lines


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def exchange_pair(a: User, b: User, label: str):
    """Perform a server-mediated DH key exchange between two users."""
    ex_id, eph = a.client.initiate_exchange(b.client.user_id)
    secret_b, _ = b.client.respond_to_exchange(ex_id)
    secret_a, _ = a.client.complete_exchange(ex_id, eph)
    a.add_relationship(secret_a, b.name)
    b.add_relationship(secret_b, a.name)
    print(f"  {label}: independent enc_key derived  "
          f"(A→B topic: {secret_a.outbound_topic(a.client.user_id)[:12]}…)")


def main():
    # Start mock server in background
    threading.Thread(target=_run_mock_server, daemon=True).start()
    time.sleep(0.5)

    print("=== SMQTT Multi-User Presence Demo ===\n")

    alice = User("Alice", start_lat=40.7128, start_lon=-74.0060)  # New York
    bob   = User("Bob",   start_lat=51.5074, start_lon= -0.1278)  # London
    carol = User("Carol", start_lat=48.8566, start_lon=  2.3522)  # Paris

    print("Registering users...")
    for user in [alice, bob, carol]:
        user.setup()
        print(f"  {user.name}: user_id={user.client.user_id}")

    print("\nKey exchange — each pair derives independent keys...")
    exchange_pair(alice, bob,   "Alice <-> Bob  ")
    exchange_pair(alice, carol, "Alice <-> Carol")
    exchange_pair(bob,   carol, "Bob   <-> Carol")

    print(f"\n  Each user maintains {len(alice.secrets)} relationships")
    print(f"  Each user publishes {len(alice.secrets)} encrypted topics per tick")
    print(f"  Broker sees {len(alice.secrets) * 3} opaque topic streams total\n")

    print("Connecting to MQTT and publishing location...\n")
    for user in [alice, bob, carol]:
        threading.Thread(target=user.run, daemon=True).start()

    # Let some messages arrive before printing
    time.sleep(TICK_SECS * 2)

    try:
        while True:
            print(f"{'─' * 56}  {time.strftime('%H:%M:%S')}")
            for user in [alice, bob, carol]:
                for line in user.status_lines():
                    print(line)
            print()
            time.sleep(PRINT_SECS)
    except KeyboardInterrupt:
        print("\nDone.")


if __name__ == '__main__':
    main()
