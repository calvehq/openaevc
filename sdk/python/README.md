# openaevc (Python)

Client SDK for OpenAEVC protocol 0.1.0 using only the standard library (Python ≥ 3.10).
Ed25519 is implemented in pure Python (RFC 8032, not constant-time); set
`OPENAEVC_CRYPTO=cryptography` with `pip install openaevc[fast]` for the native backend.

```python
from openaevc import Client, Session, SigningKey

c = Client("127.0.0.1:7878", Session(SigningKey.from_hex(seed), principal, namespace))
c.negotiate()
pack = c.create_change_pack()
candidate = c.seal(pack, 1)
for event in c.events(kinds=["changepack.sealed"]):
    print(event["sequence"], event["kind"])
    break
```

Unix sockets: `Client("unix:/var/lib/openaevc/openaevcd.sock", session)`.

`openaevc.extension` lets you write extensions in Python (see
`examples/custom-extension-python`).

Tests: `python3 -m unittest discover -s tests -p 'test_*.py'` (golden fixtures).
