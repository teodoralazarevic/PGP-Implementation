import customtkinter as ctk

from GUI.PrivateKeyRingWindow import PrivateKeyRingWindow
from GUI.PublicKeyRingWIndow import PublicKeyRingWindow
from GUI.ReceiveMessageDialog import ReceiveMessageDialog
from GUI.SendMessageDialog import SendMessageDialog


class HomePage(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)

        # Title
        title = ctk.CTkLabel(
            self,
            text="Simple PGP Implementation",
            font=("Arial", 28, "bold")
        )
        title.pack(pady=(30, 20))

        # Container for buttons
        button_frame = ctk.CTkFrame(self)
        button_frame.pack(expand=True)

        button_frame.grid_columnconfigure((0, 1), weight=1)
        button_frame.grid_rowconfigure((0, 1), weight=1)

        btn_width = 220
        btn_height = 120

        public_btn = ctk.CTkButton(
            button_frame,
            text="Public Key Ring",
            width=btn_width,
            height=btn_height,
            command=lambda: PublicKeyRingWindow(self)
        )

        private_btn = ctk.CTkButton(
            button_frame,
            text="Private Key Ring",
            width=btn_width,
            height=btn_height,
            command=lambda: PrivateKeyRingWindow(self)
        )

        send_btn = ctk.CTkButton(
            button_frame,
            text="Send Message",
            width=btn_width,
            height=btn_height,
            command = self.open_send_message
        )

        receive_btn = ctk.CTkButton(
            button_frame,
            text="Receive Message",
            width=btn_width,
            height=btn_height,
            command = self.open_receive_message
        )

        public_btn.grid(row=0, column=0, padx=20, pady=20)
        private_btn.grid(row=0, column=1, padx=20, pady=20)

        send_btn.grid(row=1, column=0, padx=20, pady=20)
        receive_btn.grid(row=1, column=1, padx=20, pady=20)

        # Footer
        footer = ctk.CTkLabel(
            self,
            text="Projekat iz Zaštite Podataka 2026.\nTeodora Lazarević 0136/22\nStevan Vugdelija 0096/22",
            font=("Arial", 14)
        )
        footer.pack(pady=(10, 20))

    def open_send_message(self):
        send_dialog = SendMessageDialog(self)
        self.wait_window(send_dialog)

    def open_receive_message(self):
        receive_dialog = ReceiveMessageDialog(self)
        self.wait_window(receive_dialog)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Simple PGP Implementation")
        self.geometry("800x600")
        self.resizable(False, False)

        home = HomePage(self)
        home.pack(fill="both", expand=True)
