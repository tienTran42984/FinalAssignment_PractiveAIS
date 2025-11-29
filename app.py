from rsa.rsa_cipher import GenerateKeys, Encrypt, Decrypt
from rsa.rsa_cipher_demo import RSADemo
from flask import Flask, redirect, render_template, request, send_file, session
import os

app = Flask(__name__)
app.secret_key = "1343"

CURRENT_PUBLIC_KEY = None 
CURRENT_PRIVATE_KEY = None
OUTPUT = "output"

rsacipherdemo = RSADemo

os.makedirs(OUTPUT, exist_ok=True)

###### MAIN HOMEPAGE #######
@app.route("/")
def home():
    return render_template("index.html")

##### RSA ONLY - LET USERS CHOOSE 2 PRIME NUMBERS #####
@app.route("/enterprimes")
def enter_primes():
    return render_template("/RSA_templates/enterprimes.html")

#### RSA ONLY - GENERATE PUBLIC AND PRIVATE KEY FOR RSA #####
@app.route("/generate_keys_manual", methods=["POST"])
def generate_keys_manual():
    global CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY
    p = int(request.form["p"])
    q = int(request.form["q"])

    CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY, p_val, q_val, phi_val = rsacipherdemo.GenerateKeys(p, q)
    e_val,n_val = CURRENT_PUBLIC_KEY
    d_val,n_val = CURRENT_PRIVATE_KEY

    return render_template(
        "/RSA_templates/keys.html",
        public_key=CURRENT_PUBLIC_KEY,
        private_key=CURRENT_PRIVATE_KEY,
        q = q_val,
        p = p_val,
        phi = phi_val,
        e = e_val,
        n = n_val,
        d = d_val
    )

##### LET USER CHOOSE ALGORITHMS / STORE SELECTED ALGORITHM IN SESSION ######
@app.route("/set_algorithm", methods=["POST"])
def set_algorithms():
    algo = request.form.get("algo", "RSA")
    session["algorithm"] = algo
    return render_template("index.html", selected_algo=algo)
    
###### ENCRYPT USING KEY PROVIDED #######
@app.route("/encrypt_with_key", methods=["POST"])
def encrypt_with_key():
    algo = session.get("algorithm", "RSA")
    file  = request.files["input_file"]
    plaintext = file.read().decode("utf-8")
    out_path = os.path.join(OUTPUT, "encrypted.txt")

    if algo == "RSA":
        global CURRENT_PUBLIC_KEY 
        if CURRENT_PUBLIC_KEY is None: 
            return {"error": "No public key"}
        cipher_block = rsacipherdemo.Encrypt(plaintext, CURRENT_PUBLIC_KEY)
        with open(out_path,"w") as f:
            f.write(" ".join(str(x) for x in cipher_block))
        return send_file(out_path, as_attachment=True)
    
    # elif algo == "AES": #

    else:
        return {"error": "Algorithm not supported"}
    
    return send_file(out_path, as_attachment=True)

###### DECRYPT USING KEY PROVIDED #######
@app.route("/decrypt_with_key", methods=["POST"])
def decrypt_with_key():
    algo = session.get("algorithm", "RSA")
    file = request.files["input_file"]
    cipher_text = file.read().decode("utf-8")
    out_path = os.path.join(OUTPUT, "decrypted.txt")

    if algo == "RSA":
        global CURRENT_PRIVATE_KEY 
        if CURRENT_PRIVATE_KEY is None: 
            return {"error": "No private key"}

        cipher_blocks = [int(x) for x in cipher_text.split(" ")]
        plaintext = rsacipherdemo.Decrypt(cipher_blocks, CURRENT_PRIVATE_KEY)

        with open(out_path,"w") as f:
            f.write(str(plaintext))

        return send_file(out_path, as_attachment=True)
    
    # elif algo == "AES": #

    else:
        return {"error": "Algorithm not supported"}
    
    return send_file(out_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)