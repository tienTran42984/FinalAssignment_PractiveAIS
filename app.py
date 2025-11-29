from routing_table import ALGO_UI_REQUIREMENTS
from rsa.rsa_cipher import GenerateKeys, Encrypt, Decrypt
from rsa.rsa_cipher_demo import RSADemo
from flask import Flask, redirect, render_template, request, jsonify, send_file, session
import os

app = Flask(__name__)
app.secret_key = "1343"

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

##### IF USER CHOOSE TO ENCRYPT USING THE SELECTED ALGORITHM ######
@app.route("/choose_encrypt", methods=["POST"])
def choose_encrypt():
    algo = session.get("algorithm", "RSA")
    ui_page = ALGO_UI_REQUIREMENTS.get(algo, {}).get("encrypt")
    
    if(ui_page):
        return render_template(ui_page)
    
    return redirect("/encrypt_now")

##### IF USER CHOOSE TO DECRYPT USING THE SELECTED ALGORITHM ######
@app.route("/choose_decrypt", methods=["POST"])
def choose_decrypt():
    algo = session.get("algorithm", "RSA")
    ui_page = ALGO_UI_REQUIREMENTS.get(algo, {}).get("decrypt")
    
    if(ui_page):
        return render_template(ui_page)
    
    return redirect("/decrypt_now")

##### GOI CAC THUAT TOAN KHAC TAI DAY ######
@app.route("/encrypt_now", methods=["POST"])
def encrypt_now():
    algo = session.get("algorithm")

    if algo == "AES":
        #### TO DO ENCRYPT AES ####
        return "AES"
    elif algo == "DES":
        #### TO DO ENCRYPT DES ####
        return "DES"
    elif algo == "TripleDES":
        #### TO DO ENCRYPT TRIPLE DES ####
        return "TRIPLE"
    else:
        return "Algorithm not supported"

##### GOI CAC THUAT TOAN KHAC TAI DAY ######
@app.route("/decrypt_now", methods=["POST"])
def decrypt_now():
    algo = session.get("algorithm")

    if algo == "AES":
        #### TO DO DECRYPT AES ####
        return "AES"
    elif algo == "DES":
        #### TO DO DECRYPT DES ####
        return "DES"
    elif algo == "TripleDES":
        #### TO DO DECRYPT TRIPLE DES ####
        return "TRIPLE"
    else:
        return "Algorithm not supported"
    
###### RSA ONLY - ENCRYPT USING KEY PROVIDED #######
@app.route("/encrypt_with_key", methods=["POST"])
def encrypt_with_key():
    e = int(request.form["e"])
    n = int(request.form["n"])
    public_key = (e, n)
    
    file  = request.files["input_file"]
    plaintext = file.read().decode("utf-8")

    cipher_block = rsacipherdemo.Encrypt(plaintext, public_key)

    out_path = os.path.join(OUTPUT, "encrypted.txt")

    with open(out_path,"w") as f:
        f.write(" ".join(str(x) for x in cipher_block))

    return send_file(out_path, as_attachment=True)

###### RSA ONLY - DECRYPT USING KEY PROVIDED #######
@app.route("/decrypt_with_key", methods=["POST"])
def decrypt_with_key():
    d = int(request.form["d"])
    n = int(request.form["n"])
    private_key = (d, n)
    
    file  = request.files["input_file"]
    cipher_text = file.read().decode("utf-8")

    cipher_blocks = [int(x) for x in cipher_text.split(" ")]
    plaintext = rsacipherdemo.Decrypt(cipher_blocks, private_key)

    out_path = os.path.join(OUTPUT, "decrypted.txt")

    with open(out_path,"w") as f:
        f.write(str(plaintext))

    return send_file(out_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)