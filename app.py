from rsa.rsa_cipher import GenerateKeys, Encrypt, Decrypt
from rsa.rsa_cipher_demo import RSADemo
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import os

app = Flask(__name__)
UPLOAD = "uploads"
OUTPUT = "output"
CURRENT_PUBLIC_KEY = None
CURRENT_PRIVATE_KEY = None
rsacipherdemo = RSADemo

os.makedirs(OUTPUT, exist_ok=True)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/enterprimes")
def enter_primes():
    return render_template("/RSA_templates/enterprimes.html")

@app.route("/generate_keys_manual", methods=["POST"])
def generate_keys_manual():
    global CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY
    p = int(request.form["p"])
    q = int(request.form["q"])

    CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY = rsacipherdemo.GenerateKeys(p, q)
    return render_template(
        "/RSA_templates/keys.html",
        public_key=CURRENT_PUBLIC_KEY,
        private_key=CURRENT_PRIVATE_KEY
    )
    

# @app.route("/generate_keys", methods=["POST"])
# def generate_keys():
#     global CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY

#     CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY = GenerateKeys()
#     return render_template(
#         "/RSAKeys/keys.html",
#         public_key=CURRENT_PUBLIC_KEY,
#         private_key=CURRENT_PRIVATE_KEY
#     )

@app.route("/encryptRSA", methods=["POST"])
def encrypt():
    global CURRENT_PUBLIC_KEY
    if CURRENT_PUBLIC_KEY is None:
        return {"error": "No public key"}
    
    file  = request.files["input_file"]
    plaintext = file.read().decode("utf-8")

    cipher_block = rsacipherdemo.Encrypt(plaintext, CURRENT_PUBLIC_KEY)

    out_path = os.path.join(OUTPUT, "encrypted.txt")

    with open(out_path,"w") as f:
        f.write(" ".join(str(x) for x in cipher_block))

    return send_file(out_path, as_attachment=True)

@app.route("/decryptRSA", methods=["POST"])
def decrypt():
    global CURRENT_PRIVATE_KEY
    if CURRENT_PRIVATE_KEY is None:
        return {"error": "No private key"}
    
    file  = request.files["input_file"]
    cipher_text = file.read().decode("utf-8")

    cipher_blocks = [int(x) for x in cipher_text.split(" ")]
    plaintext = rsacipherdemo.Decrypt(cipher_blocks, CURRENT_PRIVATE_KEY)

    out_path = os.path.join(OUTPUT, "decrypted.txt")

    with open(out_path,"w") as f:
        f.write(str(plaintext))

    return send_file(out_path, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)