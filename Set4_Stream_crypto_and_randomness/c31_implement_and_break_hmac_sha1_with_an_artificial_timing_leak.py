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
from flask import Flask, request, Response

app = Flask(__name__)
SECRET_KEY = b"yellow_submarine"

# -- Server logic --

def insecure_compare(actual, expected):
    if len(actual) != len(expected):
        return False

    for a, b in zip(actual, expected):
        if a != b:
            return False
        # Vul: For each matching byte, the latency increases by 50ms
        time.sleep(0.05)
    return True

@app.route('/test')
def verify():
    filename = request.args.get('file', '')
    signature = request.args.get('signature', '')

    # calc correct HMAC (SHA1)
    mac = hmac.new(SECRET_KEY, filename.encode(), hashlib.sha1)
    correct_signature = mac.hexdigest()

    # use insecure comparison to verify
    if insecure_compare(signature, correct_signature):
        return "OK", 200
    else:
        return "Signature Mismatch", 500

# -- attack logic --

def exploit():
    # wait server to start
    time.sleep(2)

    target_url = "http://localhost:9000/test"
    filename = "foo"
    # SHA1 hex length is 40 char
    known_signature = ""

    print(f"[*] Start breaking file  '{filename}'  HMAC...")

    for position in range(40):
        best_char = ""
        max_time = 0

        # attempt all hex range
        for char in "0123456789abcdef":
            test_signature = known_signature + char + ("0" * (39 - position))

            # To compensate for network jitter, multiple measurements can be taken and the average value calculated
            start = time.time()
            try:
                requests.get(target_url, params={"file": filename, "signature": test_signature})
            except:
                continue
            duration = time.time() - start

            if duration > max_time:
                max_time = duration
                best_char = char

        known_signature += best_char
        print(f"[!] Find the {position+1} th: {best_char} | time consuming: {max_time:.3f}s | current signature: {known_signature}")

    print(f"\n[!] Broke completed! Effective signature is: {known_signature}")

if __name__ == '__main__':
    server_thread = threading.Thread(target=lambda: app.run(port=9000, debug=False, use_reloader=False))
    server_thread.daemon = True
    server_thread.start()

    # execute attack!
    exploit()