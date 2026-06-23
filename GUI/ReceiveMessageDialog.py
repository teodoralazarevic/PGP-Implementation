import customtkinter as ctk
from tkinter import messagebox, filedialog

from Files import sent_messages_folder
from PgpService import PGP_Service
import re
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

class ReceiveMessageDialog(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)

        self.result = None
        self.received_data = None
        self.original_message = None
        self.signature_valid = None
        self.sender_info = None
        self.file_path = None

        self.title("Receive Message")
        self.geometry("800x650")
        self.resizable(False, False)

        # main frame
        main_frame = ctk.CTkScrollableFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            main_frame,
            text="Receive PGP Message",
            font=("Arial", 20, "bold")
        ).pack(pady=(0, 20))

        # Frame for file selection
        file_frame = ctk.CTkFrame(main_frame)
        file_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            file_frame,
            text="Select message file:",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 10))

        # File selection row
        file_select_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_select_frame.pack(fill="x")

        self.file_path_var = ctk.StringVar(value="No file selected")
        self.file_path_label = ctk.CTkLabel(
            file_select_frame,
            textvariable=self.file_path_var,
            font=("Arial", 11),
            fg_color=("gray85", "gray20"),
            corner_radius=5,
            height=35,
            width=400
        )
        self.file_path_label.pack(side="left", padx=(0, 10), fill="x", expand=True)

        ctk.CTkButton(
            file_select_frame,
            text="Browse...",
            command=self.select_file,
            width=100,
            height=35
        ).pack(side="right")

        # Frame for message info (displayed after loading)
        self.info_frame = ctk.CTkFrame(main_frame)
        self.info_frame.pack(fill="x", pady=(0, 20))
        self.info_frame.pack_forget()

        # Message info labels
        self.services_label = ctk.CTkLabel(
            self.info_frame,
            text="",
            font=("Arial", 16),
            justify="left"
        )
        self.services_label.pack(anchor="w", pady=5, padx=20)

        self.message_preview_label = ctk.CTkLabel(
            self.info_frame,
            text="",
            font=("Arial", 16),
            justify="left",
            wraplength=700
        )
        self.message_preview_label.pack(anchor="w", pady=5, padx=20)

        # Signature status frame
        self.signature_frame = ctk.CTkFrame(main_frame)
        self.signature_frame.pack(fill="x", pady=(0, 20))
        self.signature_frame.pack_forget()

        self.signature_status_label = ctk.CTkLabel(
            self.signature_frame,
            text="",
            font=("Arial", 13, "bold")
        )
        self.signature_status_label.pack(anchor="w", pady=5)

        self.signature_author_label = ctk.CTkLabel(
            self.signature_frame,
            text="",
            font=("Arial", 12)
        )
        self.signature_author_label.pack(anchor="w", pady=5)

        # Frame for decryption options
        self.decrypt_frame = ctk.CTkFrame(main_frame)
        self.decrypt_frame.pack(fill="x", pady=(0, 20))
        self.decrypt_frame.pack_forget()

        ctk.CTkLabel(
            self.decrypt_frame,
            text="Decryption Options:",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 10))

        # Select private key for decryption
        ctk.CTkLabel(
            self.decrypt_frame,
            text="Select Your Private Key:"
        ).pack(anchor="w")

        self.private_key_menu = ctk.CTkOptionMenu(
            self.decrypt_frame,
            values=self.get_private_keys(),
            width=500
        )
        self.private_key_menu.pack(anchor="w", pady=(0, 10))

        # Select sender's public key for verification
        ctk.CTkLabel(
            self.decrypt_frame,
            text="Select Sender's Public Key (for verification):"
        ).pack(anchor="w")

        self.sender_public_key_menu = ctk.CTkOptionMenu(
            self.decrypt_frame,
            values=self.get_public_keys(),
            width=500
        )
        self.sender_public_key_menu.pack(anchor="w", pady=(0, 10))

        # Decrypt button
        self.decrypt_action_btn = ctk.CTkButton(
            self.decrypt_frame,
            text="Decrypt Message",
            command=self.decrypt_with_private_key,
            width=200,
            height=40
        )
        self.decrypt_action_btn.pack(pady=10)

        # Buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        self.load_btn = ctk.CTkButton(
            button_frame,
            text="Load Message Info",
            command=self.load_and_decrypt,
            width=180,
            height=40
        )
        self.load_btn.pack(side="left", padx=10)

        self.save_btn = ctk.CTkButton(
            button_frame,
            text="Save Original Message",
            command=self.save_original_message,
            width=180,
            height=40,
            state="disabled"
        )
        self.save_btn.pack(side="left", padx=10)

        ctk.CTkButton(
            button_frame,
            text="Close",
            command=self.cancel,
            width=120,
            height=40
        ).pack(side="left", padx=10)

        # window settings
        self.transient(parent)
        self.wait_visibility()
        self.grab_set()

    """Get list of private keys from private key ring"""
    def get_private_keys(self):
        try:
            keys = PGP_Service().private_key_ring.private_key_ring
            return [f"{hex(key_id)} - {record.name} <{record.email}>"
                    for key_id, record in keys.items()]
        except:
            return ["No private keys available"]

    """Get list of public keys from public key ring"""
    def get_public_keys(self):
        try:
            keys = PGP_Service().public_key_ring.public_key_ring
            return [f"{hex(key_id)} - {record.name} <{record.email}>"
                    for key_id, record in keys.items()]
        except:
            return ["No public keys available"]

    """Open file selection dialog"""
    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select PGP Message File",
            initialdir=sent_messages_folder,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path = file_path
            self.file_path_var.set(file_path)
            self.load_btn.configure(state="normal")
            # Reset display
            self.info_frame.pack_forget()
            self.signature_frame.pack_forget()
            self.decrypt_frame.pack_forget()
            self.save_btn.configure(state="disabled")
            self.original_message = None

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

    """Show password dialog for private key decryption"""
    def ask_password_dialog(self, key_info: str) -> str | None:
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
            height=35
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=on_cancel,
            width=120,
            height=35
        ).pack(side="left", padx=5)

        dialog.bind('<Return>', lambda e: on_confirm())
        dialog.bind('<Escape>', lambda e: on_cancel())

        self.wait_window(dialog)

        return password_result[0]

    """Decrypt private key using password"""
    def decrypt_private_key(self, encrypted_private_key: bytes, password: str) -> RSAPrivateKey | None:
        try:
            private_key_bytes = PGP_Service().private_key_ring.decrypt_private_key(
                encrypted_private_key,
                password
            )

            if private_key_bytes is None:
                return None

            private_key = serialization.load_der_private_key(
                private_key_bytes,
                password=None
            )
            return private_key

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt private key: {str(e)}")
            return None

    """Load message info and display services used"""
    def load_and_decrypt(self):
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Error", "Please select a valid file first!")
            return

        try:
            with open(self.file_path, 'rb') as f:
                full_message = json.loads(f.read().decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")
            return

        services = full_message.get("services", {})
        needs_decryption = services.get("confidentiality", False)
        needs_verification = services.get("authentication", False)

        # Display services information
        self.info_frame.pack(fill="x", pady=(0, 20))
        services_text = "Services used in this message:\n"
        services_text += f"  - Encryption: {'Yes' if needs_decryption else 'No'}"
        if needs_decryption:
            services_text += f" (Algorithm: {services.get('encryption_algorithm', 'N/A')})\n"
        else:
            services_text += "\n"
        services_text += f"  - Authentication: {'Yes' if needs_verification else 'No'}\n"
        services_text += f"  - Compression: {'Yes' if services.get('compression', False) else 'No'}\n"
        services_text += f"  - Radix-64: {'Yes' if services.get('conversion', False) else 'No'}"
        self.services_label.configure(text=services_text)

        # Show decryption options if encryption was used
        if needs_decryption:
            self.decrypt_frame.pack(fill="x", pady=(0, 20))
            self.signature_frame.pack_forget()
            self.message_preview_label.configure(
                text="Message is encrypted. Please select your private key and click 'Decrypt Message'.")
        else:
            self.decrypt_frame.pack_forget()
            if needs_verification:
                self.decrypt_frame.pack(fill="x", pady=(0, 20))
                self.message_preview_label.configure(
                    text="Message is signed but not encrypted. Please select sender's public key for verification.")
            else:
                # No encryption or signature, display directly
                self.decrypt_and_display(self.file_path, None, None)

    """Decrypt and display message content"""
    def decrypt_and_display(self, file_path, private_key, sender_public_key):
        try:
            result = PGP_Service().receive_message(file_path, private_key, sender_public_key)

            self.received_data = result
            self.original_message = result.get("data", "")

            # Display message info
            self.info_frame.pack(fill="x", pady=(0, 20))

            with open(file_path, 'rb') as f:
                full_message = json.loads(f.read().decode('utf-8'))
            services = full_message.get("services", {})

            services_text = "Services used:\n"
            services_text += f"  - Encryption: {'Yes' if services.get('confidentiality', False) else 'No'}\n"
            if services.get('confidentiality', False):
                services_text += f"    - Algorithm: {services.get('encryption_algorithm', 'N/A')}\n"
            services_text += f"  - Authentication: {'Yes' if services.get('authentication', False) else 'No'}\n"
            services_text += f"  - Compression: {'Yes' if services.get('compression', False) else 'No'}\n"
            services_text += f"  - Radix-64: {'Yes' if services.get('conversion', False) else 'No'}"
            self.services_label.configure(text=services_text)

            # Display message preview
            message_preview = result.get("data", "")
            if len(message_preview) > 500:
                message_preview = message_preview[:500] + "..."
            self.message_preview_label.configure(
                text=f"Message content:\n{message_preview}"
            )

            # Display signature status if authentication was used
            if services.get('authentication', False):
                self.signature_frame.pack(fill="x", pady=(0, 20))
                sender_info = "Unknown"
                if sender_public_key:
                    for key_id, record in PGP_Service().public_key_ring.public_key_ring.items():
                        if record.public_key.public_numbers().n == sender_public_key.public_numbers().n:
                            sender_info = f"{record.name} <{record.email}>"
                            break

                self.signature_status_label.configure(
                    text="Signature verification: SUCCESSFUL",
                    text_color="#2e7d32"
                )
                self.signature_author_label.configure(
                    text=f"Message signed by: {sender_info}"
                )
                self.signature_valid = True
                self.sender_info = sender_info
            else:
                self.signature_frame.pack_forget()

            # Enable save button
            self.save_btn.configure(state="normal")

            # Hide decrypt frame if shown
            self.decrypt_frame.pack_forget()

            messagebox.showinfo("Success", "Message received successfully!")

        except Exception as e:
            error_msg = str(e)
            if "Signature verification failed" in error_msg:
                self.signature_frame.pack(fill="x", pady=(0, 20))
                self.signature_status_label.configure(
                    text="Signature verification: FAILED",
                    text_color="#c62828"
                )
                self.signature_author_label.configure(
                    text="The message signature could not be verified!\nThe message may have been tampered with or the sender's public key is incorrect."
                )
                self.signature_valid = False

                messagebox.showerror(
                    "Verification Failed",
                    "Message signature verification failed!\n\nThe message may have been tampered with or the sender's public key is incorrect."
                )
            else:
                messagebox.showerror("Error", f"Failed to decrypt message: {error_msg}")

    """Decrypt message with selected private key"""
    def decrypt_with_private_key(self):
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Error", "Please select a valid file first!")
            return

        selected_private_key = self.private_key_menu.get()
        if "No private keys" in selected_private_key:
            messagebox.showerror("Error", "Please select a valid private key!")
            return

        encrypted_private_key = self.get_private_key_from_selection(selected_private_key)
        if encrypted_private_key is None:
            messagebox.showerror("Error", "Selected private key not found!")
            return

        # Get sender's public key if needed for verification
        sender_public_key = None
        selected_sender_key = self.sender_public_key_menu.get()
        if "No public keys" not in selected_sender_key:
            sender_public_key = self.get_public_key_from_selection(selected_sender_key)

        # Ask for password with retry attempts
        max_attempts = 3
        attempts = 0
        private_key = None

        while attempts < max_attempts and private_key is None:
            attempts += 1
            password = self.ask_password_dialog(selected_private_key)
            if password is None:
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

        # Decrypt and display message
        self.decrypt_and_display(self.file_path, private_key, sender_public_key)

    """Save original message to desired location"""
    def save_original_message(self):
        if self.original_message is None:
            messagebox.showerror("Error", "No message to save!")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Original Message",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.original_message)
                messagebox.showinfo("Success", f"Message saved successfully to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save message: {str(e)}")

    """Cancel and close dialog"""
    def cancel(self):
        self.result = None
        self.destroy()