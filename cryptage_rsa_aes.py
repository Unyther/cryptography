import os
import hashlib
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# === Générateur de flux aléatoire à partir du mot-clé ===
class DeterministicRandom:
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0

    def __call__(self, n):
        result = b""
        while len(result) < n:
            data = self.seed + self.counter.to_bytes(4, 'big')
            result += hashlib.sha256(data).digest()
            self.counter += 1
        return result[:n]

# === Génération RSA depuis mot-clé ===
def generer_cle_RSA_depuis_mot_cle(mot_cle):
    seed = hashlib.sha256(mot_cle.encode()).digest()
    randfunc = DeterministicRandom(seed)
    key = RSA.generate(2048, e=65537, randfunc=randfunc)
    return key

# === Générer une clé RSA aléatoire ===
def generer_cle_RSA_aleatoire():
    key = RSA.generate(2048)
    return key

# === Crypter fichier avec AES + RSA ===
def crypter_fichier():
    fichier_source = filedialog.askopenfilename(title="Choisir le fichier à crypter")
    if not fichier_source:
        return

    mot_cle = entry_cle.get().strip()
    if not mot_cle and var_mot_cle.get():
        messagebox.showwarning("Attention", "Entrez un mot-clé pour la clé RSA.")
        return

    cle_RSA = generer_cle_RSA_depuis_mot_cle(mot_cle) if var_mot_cle.get() else generer_cle_RSA_aleatoire()
    public_key = cle_RSA.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)

    cle_AES = get_random_bytes(32)  # Utilisation d'une clé AES de 256 bits
    cipher_aes = AES.new(cle_AES, AES.MODE_EAX)

    try:
        with open(fichier_source, 'rb') as f:
            donnees = f.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(donnees)

        nom_fichier_original = os.path.basename(fichier_source)
        fichier_crypte = filedialog.asksaveasfilename(defaultextension=".enc", title="Enregistrer le fichier crypté", initialfile=f"{nom_fichier_original} - crypter.enc")
        if fichier_crypte:
            with open(fichier_crypte, 'wb') as f:
                f.write(len(nom_fichier_original.encode('utf-8')).to_bytes(2, 'big'))
                f.write(nom_fichier_original.encode('utf-8'))
                f.write(cipher_aes.nonce + tag + ciphertext)

        cle_AES_cryptee = cipher_rsa.encrypt(cle_AES)
        fichier_cle_aes = filedialog.asksaveasfilename(defaultextension=".bin", title="Enregistrer la clé AES cryptée", initialfile=f"aes-crypter-{nom_fichier_original}.bin")
        if fichier_cle_aes:
            with open(fichier_cle_aes, 'wb') as f:
                f.write(cle_AES_cryptee)

        fichier_RSA = filedialog.asksaveasfilename(defaultextension=".pem", title="Enregistrer la clé privée RSA", initialfile=f"rsa-crypter-{nom_fichier_original}.pem")
        if fichier_RSA:
            with open(fichier_RSA, 'wb') as f:
                f.write(cle_RSA.export_key('PEM'))

        messagebox.showinfo("Succès", "Fichier et clés cryptés avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur pendant le cryptage : {e}")

# === Décrypter fichier ou dossier ===
def decrypter_fichier():
    fichier_crypte = filedialog.askopenfilename(title="Choisir le fichier crypté", filetypes=[("Fichiers cryptés", "*.enc")])
    if not fichier_crypte:
        return

    fichier_cle_AES = filedialog.askopenfilename(title="Choisir la clé AES cryptée", filetypes=[("Clé AES cryptée", "*.bin")])
    if not fichier_cle_AES:
        return

    fichier_cle_RSA = filedialog.askopenfilename(title="Choisir la clé privée RSA", filetypes=[("Clé privée RSA", "*.pem")])
    if not fichier_cle_RSA:
        return

    try:
        with open(fichier_cle_RSA, 'rb') as f:
            cle_data = f.read()
            cle_RSA = RSA.import_key(cle_data)
            cipher_rsa = PKCS1_OAEP.new(cle_RSA)

        with open(fichier_cle_AES, 'rb') as f:
            cle_AES_cryptee = f.read()
            cle_AES = cipher_rsa.decrypt(cle_AES_cryptee)

        with open(fichier_crypte, 'rb') as f:
            longueur_nom_fichier = int.from_bytes(f.read(2), 'big')
            nom_fichier = f.read(longueur_nom_fichier).decode('utf-8')
            contenu = f.read()

        nonce, tag, ciphertext = contenu[:16], contenu[16:32], contenu[32:]

        cipher_aes = AES.new(cle_AES, AES.MODE_EAX, nonce)
        donnees = cipher_aes.decrypt_and_verify(ciphertext, tag)

        fichier_decrypte = filedialog.asksaveasfilename(initialfile=nom_fichier, title="Enregistrer le fichier décrypté")
        if fichier_decrypte:
            with open(fichier_decrypte, 'wb') as f:
                f.write(donnees)

        messagebox.showinfo("Succès", "Fichier décrypté avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur de décryptage : {e}")

# === Crypter dossier ===
def crypter_dossier():
    dossier_source = filedialog.askdirectory(title="Choisir le dossier à crypter")
    if not dossier_source:
        return

    mot_cle = entry_cle.get().strip()
    if not mot_cle and var_mot_cle.get():
        messagebox.showwarning("Attention", "Entrez un mot-clé pour la clé RSA.")
        return

    cle_RSA = generer_cle_RSA_depuis_mot_cle(mot_cle) if var_mot_cle.get() else generer_cle_RSA_aleatoire()
    public_key = cle_RSA.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)

    cle_AES = get_random_bytes(32)  # Utilisation d'une clé AES de 256 bits
    cipher_aes = AES.new(cle_AES, AES.MODE_EAX)

    try:
        # Créer un fichier ZIP à partir du dossier
        zip_filename = f"{os.path.basename(dossier_source)}.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for root, dirs, files in os.walk(dossier_source):
                for file in files:
                    zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), dossier_source))

        with open(zip_filename, 'rb') as f:
            donnees = f.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(donnees)

        fichier_crypte = filedialog.asksaveasfilename(defaultextension=".enc", title="Enregistrer le fichier crypté", initialfile=f"{os.path.basename(dossier_source)} - crypter.enc")
        if fichier_crypte:
            with open(fichier_crypte, 'wb') as f:
                nom_fichier_original = os.path.basename(zip_filename)
                nom_fichier_original_encode = nom_fichier_original.encode('utf-8')
                f.write(len(nom_fichier_original_encode).to_bytes(2, 'big'))
                f.write(nom_fichier_original_encode)
                f.write(cipher_aes.nonce + tag + ciphertext)

        cle_AES_cryptee = cipher_rsa.encrypt(cle_AES)
        fichier_cle_aes = filedialog.asksaveasfilename(defaultextension=".bin", title="Enregistrer la clé AES cryptée", initialfile=f"aes-crypter-{os.path.basename(dossier_source)}.bin")
        if fichier_cle_aes:
            with open(fichier_cle_aes, 'wb') as f:
                f.write(cle_AES_cryptee)

        fichier_RSA = filedialog.asksaveasfilename(defaultextension=".pem", title="Enregistrer la clé privée RSA", initialfile=f"rsa-crypter-{os.path.basename(dossier_source)}.pem")
        if fichier_RSA:
            with open(fichier_RSA, 'wb') as f:
                f.write(cle_RSA.export_key('PEM'))

        # Supprimer le fichier ZIP temporaire
        os.remove(zip_filename)

        messagebox.showinfo("Succès", "Dossier crypté et clés sauvegardés avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur pendant le cryptage : {e}")

# === Interface Graphique ===
root = tk.Tk()
root.title("RSA & AES Cryptage 🔐")
root.geometry("600x700")
root.resizable(False, False)

label_titre = tk.Label(root, text="Cryptage Fichier & Dossier", font=("Arial", 18, "bold"))
label_titre.pack(pady=10)

label_cle = tk.Label(root, text="Mot-clé (pour RSA) :")
label_cle.pack()
entry_cle = tk.Entry(root, width=40, show='*')
entry_cle.pack(pady=5)

var_mot_cle = tk.BooleanVar(value=False)
check_mot_cle = tk.Checkbutton(root, text="Utiliser un mot-clé pour générer la clé RSA", variable=var_mot_cle)
check_mot_cle.pack(pady=5)

frame_boutons = tk.Frame(root)
frame_boutons.pack(pady=15)

btn_crypter_fichier = tk.Button(frame_boutons, text="Crypter Fichier", command=crypter_fichier, width=20, bg="#FFD700")
btn_crypter_fichier.grid(row=0, column=0, padx=10, pady=5)

btn_decrypter_fichier = tk.Button(frame_boutons, text="Décrypter Fichier ou Dossier", command=decrypter_fichier, width=20, bg="#FFA07A")
btn_decrypter_fichier.grid(row=0, column=1, padx=10, pady=5)

btn_crypter_dossier = tk.Button(frame_boutons, text="Crypter Dossier", command=crypter_dossier, width=20, bg="#DA70D6")
btn_crypter_dossier.grid(row=1, column=0, padx=10, pady=5)

root.mainloop()