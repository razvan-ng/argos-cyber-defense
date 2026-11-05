"""Finestra amb l'explicació en llenguatge senzill d'una troballa, redactada per l'assistent d'IA."""
import customtkinter as ctk

from gui.theme import COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_PRIMARY_DARK, COLOR_TEXT_MUTED, FONT_DISPLAY_FAMILY

AI_NOTE = ("Explicació redactada amb un assistent d'IA ({provider}) a partir de les dades de l'auditoria. "
           "Reviseu-la abans de fer-la servir amb el client.")


class ExplanationDialog(ctk.CTkToplevel):
    def __init__(self, master, title, subtitle, explanation):
        super().__init__(master)
        self.title("Explicació de la troballa")
        self.geometry("640x540")
        self.minsize(480, 380)
        self.transient(master)

        ctk.CTkButton(self, text="Tanca", width=110, command=self.destroy, fg_color=COLOR_ACCENT,
                      hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK).pack(side="bottom", pady=(6, 14))
        note = AI_NOTE.format(provider=explanation.get("proveidor") or "Google Gemini")
        ctk.CTkLabel(self, text=note, text_color=COLOR_TEXT_MUTED, wraplength=580, justify="left").pack(
            side="bottom", padx=24, pady=(4, 0), anchor="w"
        )

        ctk.CTkLabel(self, text=title, font=(FONT_DISPLAY_FAMILY, 17, "bold"), text_color=COLOR_PRIMARY_DARK,
                     wraplength=590, justify="left").pack(padx=24, pady=(18, 0), anchor="w")
        ctk.CTkLabel(self, text=subtitle, text_color=COLOR_TEXT_MUTED, wraplength=590, justify="left").pack(
            padx=24, pady=(2, 8), anchor="w"
        )

        body = ctk.CTkScrollableFrame(self)
        body.pack(fill="both", expand=True, padx=20, pady=4)
        sections = (("Què és", explanation.get("que_es", "")),
                    ("Quin risc té per a l'empresa", explanation.get("risc", "")),
                    ("Què cal fer", "\n".join(f"•  {a}" for a in explanation.get("que_cal_fer", []))))
        for heading, text in sections:
            if not text:
                continue
            ctk.CTkLabel(body, text=heading.upper(), font=(FONT_DISPLAY_FAMILY, 11, "bold"),
                         text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=8, pady=(10, 2))
            ctk.CTkLabel(body, text=text, wraplength=540, justify="left", anchor="w").pack(anchor="w", padx=8)
        self.after(100, self.lift)
