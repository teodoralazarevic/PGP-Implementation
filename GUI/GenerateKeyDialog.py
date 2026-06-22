import customtkinter as ctk
from tkinter import messagebox


class GenerateKeyDialog(ctk.CTkToplevel):

    def __init__(self, master):
        super().__init__(master)

        self.result = None

        self.title("Generate Key Pair")
        self.geometry("400x250")
        self.resizable(False, False)

        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self,
            text="Key Size"
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.key_size = ctk.CTkOptionMenu(
            self,
            values=["1024", "2048"]
        )
        self.key_size.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(
            self,
            text="Name"
        ).grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.name_entry = ctk.CTkEntry(self)
        self.name_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(
            self,
            text="Email"
        ).grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.email_entry = ctk.CTkEntry(self)
        self.email_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(
            self,
            text="Password"
        ).grid(row=3, column=0, padx=10, pady=10, sticky="w")

        self.password_entry = ctk.CTkEntry(
            self,
            show="*"
        )
        self.password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(
            row=4,
            column=0,
            columnspan=2,
            pady=20
        )

        ctk.CTkButton(
            button_frame,
            text="Generate",
            command=self.generate
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=self.cancel
        ).pack(side="left", padx=10)

    def generate(self):
        name = self.name_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()

        if not name or not email or not password:
            messagebox.showerror(
                "Validation Error",
                "All fields are required."
            )
            return

        self.result = {
            "key_size": self.key_size.get(),
            "name": name,
            "email": email,
            "password": password
        }

        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()