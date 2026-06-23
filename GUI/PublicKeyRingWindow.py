import base64
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

from PemFiles import export_public_key, import_public_key, pem_files_folder
from PgpService import PGP_Service
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

        self.tree.column("timestamp", width=45)
        self.tree.column("key_id", width=110)
        self.tree.column("public_key", width=400)
        self.tree.column("name", width=90)
        self.tree.column("email", width=110)

        self.tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.on_row_selected
        )

        self.row_data = {}

        self.selected_item_id = None

        self.refresh_table()

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=10)

        import_btn = ctk.CTkButton(
            button_frame,
            text="Import PEM",
            command=self.import_pem
        )
        import_btn.pack(side="left", padx=5)

        export_btn = ctk.CTkButton(
            button_frame,
            text="Export PEM",
            command=self.export_pem
        )
        export_btn.pack(side="left", padx=5)

        close_btn = ctk.CTkButton(
            button_frame,
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

        self.row_data.clear()

        self.selected_item_id = None

        for item in self.tree.get_children():
            self.tree.delete(item)

        for key_id, record in PGP_Service().public_key_ring.public_key_ring.items():
            timestamp = record.timestamp
            key_id_hex = hex(key_id)


            public_key_bytes = record.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')[:50] + "..."

            name = record.name
            email = record.email

            item_id = self.tree.insert(
                "",
                "end",
                values=(
                    int(timestamp),
                    key_id_hex,
                    public_key_b64,
                    name,
                    email
                )
            )

            self.row_data[item_id] = {
                "key_id": record.public_key.public_numbers().n % (2 ** 64),
                "public_key": base64.b64encode(record.public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode('utf-8')
            }
    def on_row_selected(self, event):
        selection = self.tree.selection()

        if not selection:
            return

        self.selected_item_id = selection[0]

    def import_pem(self):

        file_path = filedialog.askopenfilename(
            title="Import PEM Key",
            filetypes=[
                ("PEM files", "*.pem"),
                ("All files", "*.*")
            ],
            initialdir=pem_files_folder
        )

        if not file_path:
            return

        try:
            import_public_key(file_path)

            self.refresh_table()

            messagebox.showinfo(
                "Success",
                "Key imported successfully."
            )

        except Exception as e:
            messagebox.showerror(
                "Import Failed",
                str(e)
            )

    def export_pem(self):

        if self.selected_item_id is None:
            messagebox.showwarning(
                "No Selection",
                "Please select a key."
            )
            return

        try:
            key_id = self.row_data[self.selected_item_id]["key_id"]
            export_public_key(
                PGP_Service().public_key_ring.public_key_ring[key_id].public_key,
                PGP_Service().public_key_ring.public_key_ring[key_id].name,
                PGP_Service().public_key_ring.public_key_ring[key_id].email,
                PGP_Service().public_key_ring.public_key_ring[key_id].timestamp
            )

            messagebox.showinfo(
                "Success",
                "Key exported successfully."
            )

        except Exception as e:
            messagebox.showerror(
                "Export Failed",
                str(e)
            )