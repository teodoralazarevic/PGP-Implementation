import customtkinter as ctk
from tkinter import messagebox
from PgpService import PGP_Service
from Confidentiality import EncryptionAlgorithm
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class SendMessageDialog(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)

        self.result = None

        self.title("Send Message")
        self.geometry("700x650")
        self.resizable(False, False)

        # main frame
        main_frame = ctk.CTkScrollableFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # field for message
        ctk.CTkLabel(
            main_frame,
            text="Message:",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 5))

        self.message_text = ctk.CTkTextbox(
            main_frame,
            height=150,
            font=("Arial", 12)
        )
        self.message_text.pack(fill="x", pady=(0, 20))

        # field for filename
        ctk.CTkLabel(
            main_frame,
            text="Filename:",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 5))

        self.filename = ctk.CTkTextbox(
            main_frame,
            height=80,
            font=("Arial", 12)
        )
        self.filename.pack(fill="x", pady=(0, 20))

        # options available
        options_frame = ctk.CTkFrame(main_frame)
        options_frame.pack(fill="x", pady=10)

        # 1. encryption
        self.encrypt_var = ctk.BooleanVar(value=False)
        encrypt_check = ctk.CTkCheckBox(
            options_frame,
            text="Encrypt message (Privacy)",
            variable=self.encrypt_var,
            command=self.toggle_encryption_options
        )
        encrypt_check.pack(anchor="w", pady=5)

        # frame for encryption options, hidden by default
        self.encrypt_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        self.encrypt_frame.pack(anchor="w", padx=30, pady=5)
        self.encrypt_frame.pack_forget()  # hidden by default

        # choose public key from public key ring
        ctk.CTkLabel(
            self.encrypt_frame,
            text="Select Recipient's Public Key:"
        ).pack(anchor="w")

        self.public_key_menu = ctk.CTkOptionMenu(
            self.encrypt_frame,
            values=self.get_public_keys(),
            width=400
        )
        self.public_key_menu.pack(anchor="w", pady=(0, 10))

        # choose symmetric algorithm
        ctk.CTkLabel(
            self.encrypt_frame,
            text="Select Symmetric Algorithm:"
        ).pack(anchor="w")

        self.symmetric_algo = ctk.CTkOptionMenu(
            self.encrypt_frame,
            values=["AES-128", "Triple DES"],
            width=400
        )
        self.symmetric_algo.pack(anchor="w", pady=(0, 10))

        # 2. Digital signature
        self.sign_var = ctk.BooleanVar(value=False)
        sign_check = ctk.CTkCheckBox(
            options_frame,
            text="Sign message (Authenticity)",
            variable=self.sign_var,
            command=self.toggle_sign_options
        )
        sign_check.pack(anchor="w", pady=5)

        # frame for signing options
        self.sign_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        self.sign_frame.pack(anchor="w", padx=30, pady=5)
        self.sign_frame.pack_forget()  # hidden by default

        # choose private key for signature
        ctk.CTkLabel(
            self.sign_frame,
            text="Select Your Private Key for Signing:"
        ).pack(anchor="w")

        self.private_key_menu = ctk.CTkOptionMenu(
            self.sign_frame,
            values=self.get_private_keys(),
            width=400
        )
        self.private_key_menu.pack(anchor="w", pady=(0, 10))

        # 3. compression
        self.compress_var = ctk.BooleanVar(value=False)
        compress_check = ctk.CTkCheckBox(
            options_frame,
            text="Compress message",
            variable=self.compress_var
        )
        compress_check.pack(anchor="w", pady=5)

        # 4. radix conversion
        self.radix64_var = ctk.BooleanVar(value=False)
        radix64_check = ctk.CTkCheckBox(
            options_frame,
            text="Convert to Radix-64 format",
            variable=self.radix64_var
        )
        radix64_check.pack(anchor="w", pady=5)

        # buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        ctk.CTkButton(
            button_frame,
            text="Send",
            command=self.send_message,
            width=150,
            height=40
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            button_frame,
            text="Close",
            command=self.close,
            width=150,
            height=40
        ).pack(side="left", padx=10)

        # window settings
        self.transient(parent)
        self.wait_visibility()
        self.grab_set()

    """Get list of public keys from public key ring"""
    def get_public_keys(self):
        try:
            keys = PGP_Service().public_key_ring.public_key_ring
            return [f"{hex(key_id)} - {record.name} <{record.email}>"
                    for key_id, record in keys.items()]
        except:
            return ["No public keys available"]

    """Get list of private keys from private key ring"""
    def get_private_keys(self):
        try:
            keys = PGP_Service().private_key_ring.private_key_ring
            return [f"{hex(key_id)} - {record.name} <{record.email}>"
                    for key_id, record in keys.items()]
        except:
            return ["No private keys available"]

    """Show/hide encryption options"""
    def toggle_encryption_options(self):
        if self.encrypt_var.get():
            self.encrypt_frame.pack(anchor="w", padx=30, pady=5)
        else:
            self.encrypt_frame.pack_forget()

    """Show/hide signing options"""
    def toggle_sign_options(self):
        if self.sign_var.get():
            self.sign_frame.pack(anchor="w", padx=30, pady=5)
        else:
            self.sign_frame.pack_forget()

    """Extract key id from selected text"""
    def extract_key_id_from_selection(self, selection_text):
        match = re.match(r'0x([0-9a-fA-F]+)', selection_text)
        if match:
            return int(match.group(1), 16)
        return None

    """Get encrypted private key from selected text"""
    def get_private_key_from_selection(self, selection_text):
        key_id = self.extract_key_id_from_selection(selection_text)
        if key_id is None:
            return None

        try:
            record = PGP_Service().private_key_ring.private_key_ring.get(key_id)
            if record:
                return record.enc_private_key
        except:
            pass
        return None

    """Get public key from selected text"""
    def get_public_key_from_selection(self, selection_text):
        key_id = self.extract_key_id_from_selection(selection_text)
        if key_id is None:
            return None

        try:
            record = PGP_Service().public_key_ring.public_key_ring.get(key_id)
            if record:
                return record.public_key
        except:
            pass
        return None

    def ask_password_dialog(self, key_info: str) -> str:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Enter Private Key Password")
        dialog.geometry("450x250")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.wait_visibility()
        dialog.grab_set()

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 450) // 2
        y = self.winfo_y() + (self.winfo_height() - 250) // 2
        dialog.geometry(f"+{x}+{y}")

        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text="Enter password for private key:",
            font=("Arial", 14, "bold")
        ).pack(pady=(0, 10))

        key_frame = ctk.CTkFrame(main_frame, fg_color=("gray85", "gray20"))
        key_frame.pack(fill="x", pady=(0, 15), padx=10)

        ctk.CTkLabel(
            key_frame,
            text=key_info,
            font=("Arial", 11),
            wraplength=380,
            justify="center"
        ).pack(pady=10, padx=10)

        password_entry = ctk.CTkEntry(
            main_frame,
            placeholder_text="Enter password...",
            show="•",
            width=350,
            height=40
        )
        password_entry.pack(pady=(0, 15))
        password_entry.focus()

        show_password_var = ctk.BooleanVar(value=False)

        def toggle_password_visibility():
            if show_password_var.get():
                password_entry.configure(show="")
            else:
                password_entry.configure(show="•")

        show_check = ctk.CTkCheckBox(
            main_frame,
            text="Show password",
            variable=show_password_var,
            command=toggle_password_visibility
        )
        show_check.pack(pady=(0, 15))

        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=10)

        password_result = [None]

        def on_confirm():
            password = password_entry.get().strip()
            if password:
                password_result[0] = password
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Password cannot be empty!")

        def on_cancel():
            password_result[0] = None
            dialog.destroy()

        ctk.CTkButton(
            button_frame,
            text="Confirm",
            command=on_confirm,
            width=120,
            height=35,
            fg_color="#2e7d32",
            hover_color="#1b5e20"
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=on_cancel,
            width=120,
            height=35,
            fg_color="#c62828",
            hover_color="#b71c1c"
        ).pack(side="left", padx=5)

        dialog.bind('<Return>', lambda e: on_confirm())
        dialog.bind('<Escape>', lambda e: on_cancel())

        self.wait_window(dialog)

        return password_result[0]

    def decrypt_private_key(self, encrypted_private_key: bytes, password: str) -> RSAPrivateKey | None:
        try:
            private_key_bytes = PGP_Service().private_key_ring.decrypt_private_key(
                encrypted_private_key,
                password
            )

            if private_key_bytes is None:
                messagebox.showerror("Error", "Wrong password! Please try again.")
                return None

            private_key = serialization.load_der_private_key(
                private_key_bytes,
                password=None
            )

            return private_key

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt private key: {str(e)}")
            return None

    def send_message(self):
        message = self.message_text.get("1.0", "end-1c").strip()

        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        filename = self.filename.get("1.0", "end-1c").strip()
        if not filename:
            messagebox.showerror("Error", "File name cannot be empty!")
            return

        self.result = {
            "message": message,
            "filename": filename,
            "encrypt": self.encrypt_var.get(),
            "algorithm": EncryptionAlgorithm.TDES if self.symmetric_algo.get() == "Triple DES" else EncryptionAlgorithm.AES128,
            "sign": self.sign_var.get(),
            "compress": self.compress_var.get(),
            "radix64": self.radix64_var.get()
        }

        public_key = None
        private_key = None

        if self.encrypt_var.get():
            selected_key = self.public_key_menu.get()
            if "No public keys" in selected_key:
                messagebox.showerror("Error", "No public keys available for encryption!")
                return

            public_key = self.get_public_key_from_selection(selected_key)
            if public_key is None:
                messagebox.showerror("Error", "Selected public key not found!")
                return

        if self.sign_var.get():
            selected_key = self.private_key_menu.get()
            if "No private keys" in selected_key:
                messagebox.showerror("Error", "No private keys available for signing!")
                return

            encrypted_private_key = self.get_private_key_from_selection(selected_key)
            if encrypted_private_key is None:
                messagebox.showerror("Error", "Selected private key not found!")
                return

            max_attempts = 3
            attempts = 0
            private_key = None

            while attempts < max_attempts and private_key is None:
                attempts += 1

                password = self.ask_password_dialog(selected_key)
                if password is None:
                    # Korisnik je otkazao
                    return

                private_key = self.decrypt_private_key(encrypted_private_key, password)

                if private_key is None and attempts < max_attempts:
                    retry = messagebox.askyesno(
                        "Wrong Password",
                        f"Invalid password. You have {max_attempts - attempts} attempts remaining.\n\nDo you want to try again?"
                    )
                    if not retry:
                        return

            if private_key is None:
                messagebox.showerror("Error", "Maximum attempts exceeded. Operation cancelled.")
                return

        try:
            PGP_Service().send_message(
                self.result["message"],
                self.result["filename"],
                self.result["sign"],
                private_key,  # RSAPrivateKey (decrypted)
                self.result["encrypt"],
                public_key,  # RSAPublicKey
                self.result["algorithm"],
                self.result["compress"],
                self.result["radix64"]
            )
            messagebox.showinfo("Success", "Message sent successfully!")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")

    def close(self):
        self.result = None
        self.destroy()