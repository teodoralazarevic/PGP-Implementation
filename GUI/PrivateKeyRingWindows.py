from tkinter import ttk
import customtkinter as ctk

import PgpService
from GUI.GenerateKeyDialog import GenerateKeyDialog


class PrivateKeyRingWindow(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)

        self.title("Private Key Ring")
        self.geometry("1000x500")

        # self.grab_set()

        title = ctk.CTkLabel(
            self,
            text="Private Key Ring",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=10)

        columns = (
            "timestamp",
            "key_id",
            "public_key",
            "encrypted_private_key",
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
        self.tree.heading("encrypted_private_key", text="Encrypted Private Key")
        self.tree.heading("name", text="Name")
        self.tree.heading("email", text="Email")

        self.tree.column("timestamp", width=100)
        self.tree.column("key_id", width=40)
        self.tree.column("public_key", width=240)
        self.tree.column("encrypted_private_key", width=240)
        self.tree.column("name", width=100)
        self.tree.column("email", width=160)

        self.tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # Dummy data
        # self.tree.insert(
        #     "",
        #     "end",
        #     values=(
        #         "2026-06-20",
        #         "AB12CD34",
        #         "PUBLIC_KEY_DATA",
        #         "PRIVATE_KEY_DATA",
        #         "Alice",
        #         "alice@test.com"
        #     )
        # )
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

        generate_btn = ctk.CTkButton(
            self,
            text="Generate Key Pair",
            command=self.generate_key_dialog
        )
        generate_btn.pack(pady=10)

    def generate_key_dialog(self):
        dialog = GenerateKeyDialog(self)

        self.wait_window(dialog)

        if dialog.result is None:
            return

        PgpService.PGP_Service().generate_private_key_pair(
            dialog.result["name"],
            dialog.result["email"],
            int(dialog.result["key_size"]),
            dialog.result["password"]
        )

        self.refresh_table()

    def refresh_table(self):

        for item in self.tree.get_children():
            self.tree.delete(item)

        for key_id, record in PgpService.PrivateKeyRing().private_key_ring.items():
            self.tree.insert(
                "",
                "end",
                values=(
                    record.timestamp,
                    hex(record.public_key.public_numbers().n % (2 ** 64)),
                    hex(record.public_key.public_numbers().n),
                    record.name,
                    record.email
                )
            )