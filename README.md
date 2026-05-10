# blindrsa_rust

Implements blind signatures used in anonymous ecash/evotes implementations.

Python wrapper for [rust-blind-rsa-signatures](https://github.com/jedisct1/rust-blind-rsa-signatures).

```python
from pathlib import Path
import secrets
import subprocess

import blindrsa

# Generate PEM formatted public/secret keys
pk_path = Path("./.key.pub.pem")
sk_path = Path("./.key.pem")
if not sk_path.exists():
    subprocess.check_call(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(sk_path)])
    subprocess.check_call(["openssl", "rsa", "-pubout", "-in", str(sk_path), "-out", str(pk_path)])

# Initialize
public_key = blindrsa.PublicKey(pk_path.read_text())
secret_key = blindrsa.SecretKey(sk_path.read_text())

# CLIENT: Create and blind message
msg = secrets.token_bytes(32)
blind_msg, secret, msg_randomizer = public_key.blind(msg, True)

# SERVER: Sign the blinded message
blind_sig = secret_key.sign(blind_msg)

# CLIENT: Unblind to arrive at valid msg + msg_randomizer + signature
sig = public_key.finalize(blind_sig, secret, msg_randomizer, msg)

# SERVER: Verify that signature is correct
is_valid = public_key.verify(sig, msg, msg_randomizer)
print("Signature valid:", is_valid)
```
