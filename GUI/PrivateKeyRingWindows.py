import base64
from tkinter import ttk
import customtkinter as ctk

from PgpService import PGP_Service
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

        self.refresh_table()

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

        for item in self.tree.get_children():
            self.tree.delete(item)

        for key_id, record in PGP_Service().private_key_ring.private_key_ring.items():
            self.tree.insert(
                "",
                "end",
                values=(
                    record.timestamp,
                    hex(record.public_key.public_numbers().n % (2 ** 64)),
                    hex(record.public_key.public_numbers().n),
                    base64.b64encode(record.enc_private_key).decode("utf-8"),
                    record.name,
                    record.email
                )
            )