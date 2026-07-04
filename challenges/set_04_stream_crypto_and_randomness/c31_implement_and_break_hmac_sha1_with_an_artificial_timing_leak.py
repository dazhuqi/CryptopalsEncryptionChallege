"""
The psuedocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application that has a URL that takes a "file" argument and a "signature" argument, like so:

http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file", using the "==" operator to compare the valid MAC for a file with the "signature" parameter (in other words, verify the HMAC the way any normal programmer would verify it).

Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).

In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).

Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the valid MAC for any file.

Why artificial delays?
Early-exit string compares are probably the most common source of cryptographic timing leaks, but they aren't especially easy to exploit. In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. To play with attacking real-world timing leaks, you have to start writing low-level timing code. We're keeping things cryptographic in these challenges.
"""
import time
import hmac
import hashlib
import requests
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
        time.sleep(0.05)
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

SAMPLES = 8
SLEEP_BETWEEN = 0.01

def measure(sig_hex):
    samples = []

    for _ in range(SAMPLES):
        start = time.perf_counter()
        try:
            requests.get(TARGET, params={
                "file": FILENAME,
                "signature": sig_hex
            }, timeout=5)
        except:
            continue
        samples.append(time.perf_counter() - start)

    samples.sort()

    # trim mean（去掉最大最小）
    trimmed = samples[2:-2]
    return sum(trimmed) / len(trimmed)

def exploit():
    known = b""

    print("[*] Start timing attack...")
    try:
        # sha1 20 bytes
        for pos in range(20):
            best_byte = None
            best_time = float("inf")

            for b in range(256):
                test = known + bytes([b]) + b'\x00' * (19 - pos)
                t = measure(test.hex())

                if t > best_time:
                    best_time = t
                    best_byte = b

            known += bytes([best_byte])

            print(f"[+] byte {pos + 1:02d}: {best_byte:02x} | time={best_time:.4f}s | current={known.hex()}")

        print("\n[!!!] DONE:", known.hex())

    except KeyboardInterrupt:
        print("\n[!] Interrupted!")
        print("[!] Current progress:", known.hex())

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