"""Consola de logs en temps real per mostrar la sortida de comandes externes."""
import datetime

import customtkinter as ctk


class LogConsole(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.textbox = ctk.CTkTextbox(
            self, wrap="word", font=("Consolas", 11), fg_color="#0D1117", text_color="#D6E2E9"
        )
        self.textbox.pack(fill="both", expand=True, padx=4, pady=4)
        self.textbox.configure(state="disabled")

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.textbox.configure(state="normal")
        self.textbox.insert("end", f"[{timestamp}] {message}\n")
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def clear(self):
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.textbox.configure(state="disabled")
