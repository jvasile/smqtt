"""
SMQTT end-to-end smoke test.

Starts a real SMQTT process, exercises the full stack:
  - registration and challenge-response auth
  - DH key exchange between two users
  - MQTT connect with JWT password
  - pub/sub on permitted topics
  - rejection on unpermitted topics
  - relationship revocation kicks connected client

Usage:
    python smoke_test.py [path/to/smqtt/binary]
"""

import base64
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import threading

import paho.mqtt.client as mqtt
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

sys.path.insert(0, os.path.dirname(__file__))
from smqtt_client import SmqttClient, SharedSecret, b64u_encode


# ── Helpers ───────────────────────────────────────────────────────────────────

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open within {timeout}s")


PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = []

def check(label: str, ok: bool):
    print(f"  {'[' + PASS + ']' if ok else '[' + FAIL + ']'}  {label}")
    if not ok:
        failures.append(label)


# ── SMQTT process ─────────────────────────────────────────────────────────────

class SmqttProcess:
    def __init__(self, binary: str):
        self.http_port = find_free_port()
        self.mqtt_port = find_free_port()
        self.tmpdir    = tempfile.mkdtemp(prefix="smqtt-smoke-")
        self.db_path   = os.path.join(self.tmpdir, "test.db")
        self.url       = f"http://127.0.0.1:{self.http_port}"

        env = os.environ.copy()
        env.update({
            "SMQTT__HTTP__BIND":                f"127.0.0.1:{self.http_port}",
            "SMQTT__MQTT__BIND":                f"127.0.0.1:{self.mqtt_port}",
            "SMQTT__DATABASE__PATH":            self.db_path,
            "SMQTT__REGISTRATION__MODE":        "open",
            "SMQTT__ADMIN__API_KEY":            "smoke-test-key",
            "SMQTT__JWT__SIGNING_KEY":          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SMQTT__JWT__TTL_SECONDS":          "3600",
            "SMQTT__NOTIFICATIONS__NOTIFY_SECRET": "smoke-notify-secret",
            "SMQTT__SUSPENSION__TYPE":          "push",
            "DATABASE_URL":                     f"sqlite:{self.db_path}",
            "RUST_LOG":                         "error",
        })
        self._proc = subprocess.Popen(
            [binary],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_port("127.0.0.1", self.http_port)
        wait_for_port("127.0.0.1", self.mqtt_port)

    def stop(self):
        self._proc.send_signal(signal.SIGTERM)
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── MQTT helpers ──────────────────────────────────────────────────────────────

class MqttClient:
    def __init__(self, host: str, port: int, user_id: str, jwt: str):
        self.received: list[tuple[str, bytes]] = []
        self._connected = threading.Event()
        self._disconnected = threading.Event()

        self._client = mqtt.Client(client_id=user_id)
        self._client.username_pw_set(user_id, jwt)
        self._client.on_connect    = self._on_connect
        self._client.on_message    = self._on_message
        self._client.on_disconnect = self._on_disconnect
        self._client.connect(host, port, keepalive=60)
        self._client.loop_start()
        self._connected.wait(timeout=5)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected.set()

    def _on_message(self, client, userdata, msg):
        self.received.append((msg.topic, bytes(msg.payload)))

    def _on_disconnect(self, client, userdata, rc):
        self._disconnected.set()

    def subscribe(self, topic: str):
        self._client.subscribe(topic, qos=1)

    def publish(self, topic: str, payload: bytes):
        self._client.publish(topic, payload, qos=1)

    def wait_for_message(self, timeout: float = 3.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.received:
                return True
            time.sleep(0.05)
        return False

    def wait_for_disconnect(self, timeout: float = 5.0) -> bool:
        return self._disconnected.wait(timeout=timeout)

    def is_connected(self) -> bool:
        return self._connected.is_set() and not self._disconnected.is_set()

    def stop(self):
        self._client.loop_stop()
        self._client.disconnect()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_registration_and_auth(server: SmqttProcess):
    print("\nRegistration and auth")
    alice = SmqttClient(server.url)
    alice.register()
    check("register returns user_id",  bool(alice.user_id))
    check("register returns device_id", bool(alice.device_id))

    alice.authenticate()
    check("authenticate returns JWT", bool(alice.jwt))
    return alice


def test_key_exchange(server: SmqttProcess, alice: SmqttClient):
    print("\nKey exchange")
    bob = SmqttClient(server.url)
    bob.register()
    bob.authenticate()

    ex_id, eph = alice.initiate_exchange(bob.user_id)
    check("initiate_exchange returns exchange_id", bool(ex_id))

    secret_b, peer_id_b = bob.respond_to_exchange(ex_id)
    check("bob responds and gets peer_id", peer_id_b == alice.user_id)

    result = alice.complete_exchange(ex_id, eph)
    check("alice completes exchange", result is not None)
    secret_a, peer_id_a = result
    check("alice gets bob's peer_id", peer_id_a == bob.user_id)

    check("topics match across both sides",
          secret_a.outbound_topic(alice.user_id) == secret_b.inbound_topic(bob.user_id))

    return bob, secret_a, secret_b


def test_mqtt_pubsub(server: SmqttProcess, alice: SmqttClient, bob: SmqttClient,
                     secret_a: SharedSecret, secret_b: SharedSecret):
    print("\nMQTT pub/sub")
    mqc_a = MqttClient("127.0.0.1", server.mqtt_port, alice.user_id, alice.jwt)
    mqc_b = MqttClient("127.0.0.1", server.mqtt_port, bob.user_id,   bob.jwt)

    check("alice connects to broker", mqc_a.is_connected())
    check("bob connects to broker",   mqc_b.is_connected())

    bob_inbound = secret_b.inbound_topic(bob.user_id)
    mqc_b.subscribe(bob_inbound)
    time.sleep(0.2)

    payload = secret_a.encrypt(b"hello from alice")
    mqc_a.publish(secret_a.outbound_topic(alice.user_id), payload)

    got_message = mqc_b.wait_for_message()
    check("bob receives alice's message", got_message)
    if got_message:
        _, raw = mqc_b.received[-1]
        check("bob decrypts correctly", secret_b.decrypt(raw) == b"hello from alice")

    return mqc_a, mqc_b


def test_unpermitted_topic(server: SmqttProcess, alice: SmqttClient):
    print("\nUnpermitted topic rejection")
    mqc = MqttClient("127.0.0.1", server.mqtt_port, alice.user_id, alice.jwt)

    # Subscribe to a random topic alice has no claim to
    mqc.subscribe("not-alices-topic")
    time.sleep(0.2)

    # Publish from a throwaway client; alice should not receive it
    eve = SmqttClient(server.url)
    eve.register()
    eve.authenticate()
    mqc_eve = MqttClient("127.0.0.1", server.mqtt_port, eve.user_id, eve.jwt)
    mqc_eve.publish("not-alices-topic", b"eve snoops")
    got = mqc.wait_for_message(timeout=1.0)
    check("alice does not receive message on unpermitted topic", not got)

    mqc.stop()
    mqc_eve.stop()


def test_revocation_kick(server: SmqttProcess, alice: SmqttClient, bob: SmqttClient,
                         mqc_a: mqtt.Client, mqc_b: mqtt.Client):
    print("\nRevocation kick")
    rels = requests.get(f"{server.url}/relationships",
                        headers={'Authorization': f'Bearer {alice.jwt}'})
    rel_id = rels.json()[0]['relationship_id']

    requests.delete(f"{server.url}/relationships/{rel_id}",
                    headers={'Authorization': f'Bearer {alice.jwt}'})

    kicked = mqc_a.wait_for_disconnect(timeout=5.0)
    check("alice is kicked after revoking relationship", kicked)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), '..', 'target', 'debug', 'smqtt'
    )
    binary = os.path.realpath(binary)
    if not os.path.exists(binary):
        print(f"binary not found: {binary}")
        sys.exit(1)

    print(f"Starting SMQTT ({binary})...")
    server = SmqttProcess(binary)
    print(f"  HTTP: {server.url}")
    print(f"  MQTT: 127.0.0.1:{server.mqtt_port}")

    try:
        alice                       = test_registration_and_auth(server)
        bob, secret_a, secret_b     = test_key_exchange(server, alice)
        mqc_a, mqc_b                = test_mqtt_pubsub(server, alice, bob, secret_a, secret_b)
        test_unpermitted_topic(server, alice)
        test_revocation_kick(server, alice, bob, mqc_a, mqc_b)
    finally:
        server.stop()

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All checks passed.")


if __name__ == '__main__':
    main()
