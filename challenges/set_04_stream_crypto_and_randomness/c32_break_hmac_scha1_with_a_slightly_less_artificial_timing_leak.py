"""
Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)

Now break it again.
"""

import time
import requests
import statistics
import hmac
import hashlib
import threading
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = b"yellow_submarine"

# -- Server Logic --

def insecure_compare(a: bytes, b: bytes):
    if len(a) != len(b):
        return False

    for x, y in zip(a, b):
        if x != y:
            return False
        # Vul: For each matching byte, the latency increases by 50ms
        time.sleep(0.005)
    return True


@app.route('/test')
def verify():
    filename = request.args.get('file', '')
    signature = request.args.get('signature', '')

    try:
        provided = bytes.fromhex(signature)
    except:
        return "Bad signature", 500

    correct = hmac.new(
        SECRET_KEY,
        filename.encode(),
        hashlib.sha1
    ).digest()

    # use insecure comparison to verify
    if insecure_compare(provided, correct):
        return "OK", 200
    else:
        return "Mismatch", 500


# -- Attack Logic --

TARGET = "http://localhost:9000/test"
FILENAME = "foo"

SAMPLES = 30
session = requests.Session()


def measure(sig_hex):
    samples = []
    for _ in range(SAMPLES):
        start = time.perf_counter()
        try:
            session.get(TARGET, params={"file": FILENAME, "signature": sig_hex})
        except:
            continue
        samples.append(time.perf_counter() - start)

    return statistics.median(samples)


def exploit():
    known = b""
    print(f"[*] Start breaking C32 (Reduced latency attack)...")

    for pos in range(20):
        results = []
        for b in range(256):
            test = known + bytes([b]) + b'\x00' * (19 - pos)
            t = measure(test.hex())
            results.append((t, b))

        results.sort(key=lambda x: x[0], reverse=True)

        best_byte = results[0][1]
        best_time = results[0][0]

        diff = best_time - results[1][0]

        known += bytes([best_byte])
        print(f"[+] Byte {pos + 1}: {best_byte:02x} | gap: {diff:.6f}s | current: {known.hex()}")

    print("\n[!!!] C32 DONE:", known.hex())


# -- main logic --

if __name__ == '__main__':
    server_thread = threading.Thread(
        target=lambda: app.run(port=9000, debug=False, use_reloader=False)
    )
    server_thread.daemon = True
    server_thread.start()

    # execute attack!
    time.sleep(1)
    exploit()