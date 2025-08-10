import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import argparse

MAGIC = b'CTENCv1\x00'   
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200_000     
KEY_LEN = 32            


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a AES key (32 bytes) from password & salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt plaintext bytes with password, return packaged bytes: MAGIC|salt|nonce|ciphertext."""
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Decrypt bytes produced by encrypt_bytes. Raises Exception on failure."""
    if len(blob) < len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Encrypted data too short or corrupted.")
    if not blob.startswith(MAGIC):
        raise ValueError("File format not recognized (bad magic header).")

    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_SIZE]; offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
    ciphertext = blob[offset:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


def encrypt_file(path: str, password: str, out_path: str = None, overwrite=False) -> str:
    """Encrypt a single file. Returns output path."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, 'rb') as f:
        data = f.read()

    encrypted = encrypt_bytes(data, password)
    if out_path is None:
        out_path = path + '.enc'

    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(out_path)

    with open(out_path, 'wb') as f:
        f.write(encrypted)
    return out_path


def decrypt_file(path: str, password: str, out_path: str = None, overwrite=False) -> str:
    """Decrypt a single .enc file. Returns output path."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, 'rb') as f:
        blob = f.read()

    plaintext = decrypt_bytes(blob, password)
    if out_path is None:
        if path.endswith('.enc'):
            out_path = path[:-4] + '.dec'
        else:
            out_path = path + '.dec'

    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(out_path)

    with open(out_path, 'wb') as f:
        f.write(plaintext)
    return out_path


def process_folder_encrypt(folder: str, password: str, out_folder: str = None, overwrite=False):
    """Encrypt all files inside folder (non-recursive)."""
    if out_folder is None:
        out_folder = folder
    os.makedirs(out_folder, exist_ok=True)
    results = []
    for entry in os.scandir(folder):
        if entry.is_file():
            src = entry.path
            dst = os.path.join(out_folder, entry.name + '.enc')
            try:
                outp = encrypt_file(src, password, dst, overwrite=overwrite)
                results.append(outp)
            except Exception as e:
                results.append(f"ERROR {src}: {e}")
    return results


def process_folder_decrypt(folder: str, password: str, out_folder: str = None, overwrite=False):
    """Decrypt all .enc files inside folder (non-recursive)."""
    if out_folder is None:
        out_folder = folder
    os.makedirs(out_folder, exist_ok=True)
    results = []
    for entry in os.scandir(folder):
        if entry.is_file() and entry.name.endswith('.enc'):
            src = entry.path
            # produce name with .dec removal of .enc
            base = entry.name[:-4]
            dst = os.path.join(out_folder, base + '.dec')
            try:
                outp = decrypt_file(src, password, dst, overwrite=overwrite)
                results.append(outp)
            except Exception as e:
                results.append(f"ERROR {src}: {e}")
    return results



# Simple Tkinter GUI

class App(tk.Tk):
    def _init_(self):
        super()._init_()
        self.title("Advanced AES-256 Encryption Tool (Task-4)")
        self.geometry("520x320")
        self.resizable(False, False)

        tk.Label(self, text="Advanced Encryption Tool", font=("Helvetica", 16, "bold")).pack(pady=8)
        tk.Label(self, text="Enter a strong password (used to derive AES-256 key):").pack()
        self.pw_entry = tk.Entry(self, show='*', width=50)
        self.pw_entry.pack(pady=4)

        frame = tk.Frame(self)
        frame.pack(pady=6)

        tk.Button(frame, text="Select File to Encrypt", width=22, command=self.gui_encrypt_file).grid(row=0, column=0, padx=6, pady=6)
        tk.Button(frame, text="Select File to Decrypt", width=22, command=self.gui_decrypt_file).grid(row=0, column=1, padx=6, pady=6)

        tk.Button(frame, text="Select Folder to Encrypt", width=22, command=self.gui_encrypt_folder).grid(row=1, column=0, padx=6, pady=6)
        tk.Button(frame, text="Select Folder to Decrypt (.enc files)", width=22, command=self.gui_decrypt_folder).grid(row=1, column=1, padx=6, pady=6)

        tk.Button(self, text="Exit", width=12, command=self.quit, fg='white', bg='firebrick').pack(pady=14)

        self.status = tk.Label(self, text="", fg="blue")
        self.status.pack()

    def get_password(self):
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showerror("Missing password", "Please enter a password first.")
            raise ValueError("No password provided")
        return pw

    def gui_encrypt_file(self):
        try:
            password = self.get_password()
        except ValueError:
            return
        path = filedialog.askopenfilename(title="Choose file to encrypt")
        if not path:
            return
        out = path + '.enc'
        try:
            encrypt_file(path, password, out_path=out, overwrite=False)
            messagebox.showinfo("Success", f"Encrypted file saved:\n{out}")
            self.status.config(text=f"Encrypted: {os.path.basename(path)}")
        except FileExistsError:
            if messagebox.askyesno("File exists", f"{out} exists. Overwrite?"):
                encrypt_file(path, password, out_path=out, overwrite=True)
                messagebox.showinfo("Success", f"Encrypted file saved:\n{out}")
                self.status.config(text=f"Encrypted: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text=f"Error: {e}")

    def gui_decrypt_file(self):
        try:
            password = self.get_password()
        except ValueError:
            return
        path = filedialog.askopenfilename(title="Choose .enc file to decrypt", filetypes=[("Encrypted files", ".enc"), ("All files", ".*")])
        if not path:
            return
        if not path.endswith('.enc'):
            if not messagebox.askyesno("Continue?", "Selected file does not end with .enc. Continue decryption?"):
                return
        out = path[:-4] + '.dec' if path.endswith('.enc') else path + '.dec'
        try:
            decrypt_file(path, password, out_path=out, overwrite=False)
            messagebox.showinfo("Success", f"Decrypted file saved:\n{out}")
            self.status.config(text=f"Decrypted: {os.path.basename(path)}")
        except FileExistsError:
            if messagebox.askyesno("File exists", f"{out} exists. Overwrite?"):
                decrypt_file(path, password, out_path=out, overwrite=True)
                messagebox.showinfo("Success", f"Decrypted file saved:\n{out}")
                self.status.config(text=f"Decrypted: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text=f"Error: {e}")

    def gui_encrypt_folder(self):
        try:
            password = self.get_password()
        except ValueError:
            return
        folder = filedialog.askdirectory(title="Choose folder to encrypt (non-recursive)")
        if not folder:
            return
        out_folder = folder  # encrypt files in place (write .enc next to each file)
        results = process_folder_encrypt(folder, password, out_folder=out_folder, overwrite=False)
        messagebox.showinfo("Folder encryption complete", "Results:\n" + "\n".join(results[:20]) + ("\n..." if len(results) > 20 else ""))
        self.status.config(text=f"Encrypted contents of folder: {os.path.basename(folder)}")

    def gui_decrypt_folder(self):
        try:
            password = self.get_password()
        except ValueError:
            return
        folder = filedialog.askdirectory(title="Choose folder to decrypt (.enc files)")
        if not folder:
            return
        out_folder = folder
        results = process_folder_decrypt(folder, password, out_folder=out_folder, overwrite=False)
        messagebox.showinfo("Folder decryption complete", "Results:\n" + "\n".join(results[:20]) + ("\n..." if len(results) > 20 else ""))
        self.status.config(text=f"Decrypted .enc files in folder: {os.path.basename(folder)}")


# CLI functionality

def build_cli():
    parser = argparse.ArgumentParser(description="Advanced AES-256 file encryption tool (Task-4).")
    sub = parser.add_subparsers(dest='cmd', required=False)

    p_enc = sub.add_parser('encrypt', help='Encrypt a file or folder')
    p_enc.add_argument('-f', '--file', help='File to encrypt')
    p_enc.add_argument('-d', '--dir', help='Directory to encrypt (non-recursive)')
    p_enc.add_argument('-o', '--out', help='Output file or folder')
    p_enc.add_argument('--overwrite', action='store_true')
    p_enc.add_argument('-p', '--password', help='Password (if omitted, prompt)')

    p_dec = sub.add_parser('decrypt', help='Decrypt a file or folder')
    p_dec.add_argument('-f', '--file', help='File to decrypt')
    p_dec.add_argument('-d', '--dir', help='Directory to decrypt (.enc files) (non-recursive)')
    p_dec.add_argument('-o', '--out', help='Output file or folder')
    p_dec.add_argument('--overwrite', action='store_true')
    p_dec.add_argument('-p', '--password', help='Password (if omitted, prompt)')

    return parser


def run_cli(args):
    if args.cmd == 'encrypt':
        password = args.password or (input("Password: ") if sys.stdin.isatty() else None)
        if not password:
            print("Password required.")
            return
        if args.file:
            outp = args.out or (args.file + '.enc')
            print("Encrypting file:", args.file, "->", outp)
            encrypt_file(args.file, password, out_path=outp, overwrite=args.overwrite)
            print("Done.")
        elif args.dir:
            out_folder = args.out or args.dir
            results = process_folder_encrypt(args.dir, password, out_folder=out_folder, overwrite=args.overwrite)
            for r in results:
                print(r)
        else:
            print("Specify --file or --dir.")
    elif args.cmd == 'decrypt':
        password = args.password or (input("Password: ") if sys.stdin.isatty() else None)
        if not password:
            print("Password required.")
            return
        if args.file:
            outp = args.out or (args.file[:-4] + '.dec' if args.file.endswith('.enc') else args.file + '.dec')
            print("Decrypting file:", args.file, "->", outp)
            decrypt_file(args.file, password, out_path=outp, overwrite=args.overwrite)
            print("Done.")
        elif args.dir:
            out_folder = args.out or args.dir
            results = process_folder_decrypt(args.dir, password, out_folder=out_folder, overwrite=args.overwrite)
            for r in results:
                print(r)
        else:
            print("Specify --file or --dir.")
    else:
        print("No command specified. Launching GUI.")
        App().mainloop()


if _name_ == '_main_':

    parser = build_cli()
    # parse_known_args so plain python file.py doesn't error (no args -> GUI)
    ns, unknown = parser.parse_known_args()
    if len(sys.argv) > 1:
        # run CLI
        run_cli(ns)
    else:
        # launch GUI
        App().mainloop()