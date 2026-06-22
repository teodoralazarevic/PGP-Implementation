from tkinter import ttk
import customtkinter as ctk


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

        # Dummy data
        self.tree.insert(
            "",
            "end",
            values=(
                "2026-06-20",
                "AB12CD34",
                "PUBLIC_KEY_DATA",
                "Alice",
                "alice@test.com"
            )
        )

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