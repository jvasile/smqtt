# SMQTT Examples

## Setup

```
pip install -r requirements.txt
```

## smoke_test.py

End-to-end test against a real SMQTT binary. Covers registration, auth, DH key
exchange, MQTT pub/sub with JWT authentication, unpermitted topic rejection, and
relationship revocation kick.

```
python smoke_test.py [path/to/smqtt]
```

Defaults to `../target/debug/smqtt`. From the repo root:

```
bin/dosh test-example
```

## presence.py

Multi-user location sharing demo. Three users (Alice, Bob, Carol) exchange
encrypted GPS coordinates over MQTT. Each pair derives independent encryption
keys from a pairwise X25519 DH exchange — the broker sees only ciphertext.

Runs with an in-process mock SMQTT REST server and a local MQTT broker:

```
mosquitto &
python presence.py
```

To run against a real SMQTT instance, set `SMQTT_URL` and `MQTT_HOST`/`MQTT_PORT`
at the top of the file and remove the mock server setup.

## smqtt_client.py

Python client library for the SMQTT REST API. Import it in your own scripts:

```python
from smqtt_client import SmqttClient

client = SmqttClient("http://localhost:8765")
client.register()
client.authenticate()

exchange_id, eph_priv = client.initiate_exchange(peer_id)
# ... peer calls respond_to_exchange(exchange_id) ...
secret, peer_id = client.complete_exchange(exchange_id, eph_priv)
```
