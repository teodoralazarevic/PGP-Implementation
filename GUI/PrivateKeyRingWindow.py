import base64
from tkinter import ttk, font, messagebox
import customtkinter as ctk
from cryptography.hazmat.primitives import serialization

from PgpService import PGP_Service
from GUI.GenerateKeyDialog import GenerateKeyDialog


class PrivateKeyRingWindow(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)

        self.title("Private Key Ring")
        self.geometry("1000x800")

        # self.grab_set()

        title = ctk.CTkLabel(
            self,
            text="Private Key Ring",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=10)

        content_frame = ctk.CTkFrame(self)
        content_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)

        columns = (
            "timestamp",
            "key_id",
            "name",
            "email"
        )

        self.tree = ttk.Treeview(
            content_frame,
            columns=columns,
            show="headings"
        )

        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("key_id", text="Key ID")
        self.tree.heading("name", text="Name")
        self.tree.heading("email", text="Email")

        self.tree.column("timestamp", width=45)
        self.tree.column("key_id", width=100)
        self.tree.column("name", width=90)
        self.tree.column("email", width=110)

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 5)
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.on_row_selected
        )

        self.row_data = {}

        self.refresh_table()

        self.details_frame = ctk.CTkFrame(content_frame)
        self.details_frame.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(5, 0)
        )

        details_title = ctk.CTkLabel(
            self.details_frame,
            text="Key Details",
            font=("Arial", 16, "bold")
        )
        details_title.pack(pady=(10, 5))

        ctk.CTkLabel(
            self.details_frame,
            text="Public Key",
            anchor="w"
        ).pack(fill="x", padx=10)

        self.public_key_box = ctk.CTkTextbox(
            self.details_frame,
            height=120,
            state="disabled"
        )
        self.public_key_box.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        ctk.CTkLabel(
            self.details_frame,
            text="Encrypted Private Key",
            anchor="w"
        ).pack(fill="x", padx=10)

        self.private_key_box = ctk.CTkTextbox(
            self.details_frame,
            height=120,
            state="disabled"
        )
        self.private_key_box.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        self.selected_item_id = None

        password_label = ctk.CTkLabel(
            self.details_frame,
            text="Password"
        )
        password_label.pack(fill="x", padx=10)

        self.password_entry = ctk.CTkEntry(
            self.details_frame,
            show="*"
        )
        self.password_entry.pack(
            fill="x",
            padx=10,
            pady=(0, 10)
        )

        decrypt_btn = ctk.CTkButton(
            self.details_frame,
            text="Show Private Key",
            command=self.show_private_key
        )
        decrypt_btn.pack(
            padx=10,
            pady=(0, 10)
        )

        ctk.CTkLabel(
            self.details_frame,
            text="Decrypted Private Key"
        ).pack(fill="x", padx=10)

        self.decrypted_key_box = ctk.CTkTextbox(
            self.details_frame,
            height=120,
            state="disabled"
        )
        self.decrypted_key_box.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=10)

        generate_btn = ctk.CTkButton(
            button_frame,
            text="Generate Key Pair",
            command=self.generate_key_dialog
        )
        generate_btn.pack(side="left", padx=5)

        close_btn = ctk.CTkButton(
            button_frame,
            text="Close",
            command=self.destroy
        )
        close_btn.pack(side="left", padx=5)


        self.transient(parent)
        self.wait_visibility()
        self.grab_set()

        self.resizable(False, False)

    def generate_key_dialog(self):
        dialog = GenerateKeyDialog(self)

        self.wait_window(dialog)

        if dialog.result is None:
            return

        PGP_Service().generate_private_key_pair(
            dialog.result["name"],
            dialog.result["email"],
            int(dialog.result["key_size"]),
            dialog.result["password"]
        )

        self.refresh_table()

    def refresh_table(self):

        self.row_data.clear()

        self.selected_item_id = None

        for item in self.tree.get_children():
            self.tree.delete(item)


        for key_id, record in PGP_Service().private_key_ring.private_key_ring.items():
            item_id = self.tree.insert(
                "",
                "end",
                values=(
                    int(record.timestamp),
                    hex(record.public_key.public_numbers().n % (2 ** 64)),
                    record.name,
                    record.email
                )
            )

            self.row_data[item_id] = {
                "public_key": base64.b64encode(record.public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8'),
                "encrypted_private_key": base64.b64encode(
                    record.enc_private_key
                ).decode("utf-8")
            }

    def on_row_selected(self, event):
        selection = self.tree.selection()

        if not selection:
            return

        self.selected_item_id = item_id = selection[0]
        data = self.row_data[item_id]

        self.public_key_box.configure(state="normal")
        self.public_key_box.delete("1.0", "end")
        self.public_key_box.insert(
            "1.0",
            data["public_key"]
        )
        self.public_key_box.configure(state="disabled")

        self.private_key_box.configure(state="normal")
        self.private_key_box.delete("1.0", "end")
        self.private_key_box.insert(
            "1.0",
            data["encrypted_private_key"]
        )
        self.private_key_box.configure(state="disabled")

        self.decrypted_key_box.configure(state="normal")
        self.decrypted_key_box.delete("1.0", "end")
        self.decrypted_key_box.insert(
            "1.0",
            ""
        )
        self.decrypted_key_box.configure(state="disabled")

    def show_private_key(self):

        if self.selected_item_id is None:
            messagebox.showwarning(
                "No Selection",
                "Please select a key."
            )
            return

        password = self.password_entry.get()

        try:
            private_key = PGP_Service().private_key_ring.decrypt_private_key(
                base64.b64decode(self.row_data[self.selected_item_id]["encrypted_private_key"]),
                password
            )

            if private_key is None:
                raise ValueError

            self.decrypted_key_box.configure(state="normal")
            self.decrypted_key_box.delete("1.0", "end")
            self.decrypted_key_box.insert(
                "1.0",
                base64.b64encode(
                    private_key
                ).decode("utf-8")
            )
            self.decrypted_key_box.configure(state="disabled")

        except ValueError:
            messagebox.showerror(
                "Invalid Password",
                "The supplied password is incorrect."
            )