import base64
from tkinter import ttk
import customtkinter as ctk

import PgpService
from cryptography.hazmat.primitives import serialization


class PublicKeyRingWindow(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)

        self.title("Public Key Ring")
        self.geometry("1000x500")

        # self.grab_set()

        title = ctk.CTkLabel(
            self,
            text="Public Key Ring",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=10)

        columns = (
            "timestamp",
            "key_id",
            "public_key",
            "name",
            "email"
        )

        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings"
        )

        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("key_id", text="Key ID")
        self.tree.heading("public_key", text="Public Key")
        self.tree.heading("name", text="Name")
        self.tree.heading("email", text="Email")

        self.tree.column("timestamp", width=100)
        self.tree.column("key_id", width=40)
        self.tree.column("public_key", width=240)
        self.tree.column("name", width=100)
        self.tree.column("email", width=160)

        self.tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        self.refresh_table()

        close_btn = ctk.CTkButton(
            self,
            text="Close",
            command=self.destroy
        )
        close_btn.pack(pady=10)

        self.transient(parent)
        self.wait_visibility()
        self.grab_set()

        self.resizable(False, False)


    # loads data from public key ring
    def refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        public_key_ring = PgpService.PublicKeyRing()

        for key_id, record in public_key_ring.public_key_ring.items():
            timestamp = record.timestamp
            key_id_hex = hex(key_id)


            public_key_bytes = record.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')[:50] + "..."

            name = record.name
            email = record.email

            self.tree.insert(
                "",
                "end",
                values=(
                    timestamp,
                    key_id_hex,
                    public_key_b64,
                    name,
                    email
                )
            )