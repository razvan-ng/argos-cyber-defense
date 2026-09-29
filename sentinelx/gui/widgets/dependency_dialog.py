"""Finestra emergent de comprovació de dependències del sistema (health check)."""
import customtkinter as ctk

from core.dependency_check import build_install_command, run_health_check, run_optional_check


class DependencyDialog(ctk.CTkToplevel):
    def __init__(self, master, on_continue=None):
        super().__init__(master)
        self.title("Comprovació de Dependències del Sistema")
        self.geometry("600x480")
        self.resizable(False, False)
        self.on_continue = on_continue
        self.transient(master)
        self.grab_set()

        ctk.CTkLabel(
            self, text="Comprovació d'Eines Externes Necessàries", font=("Segoe UI", 16, "bold")
        ).pack(pady=(20, 4))
        ctk.CTkLabel(
            self,
            text="SentinelX depèn d'eines natives del sistema operatiu per realitzar els escaneigs.",
            text_color="#5B6472",
        ).pack(pady=(0, 12))

        self.status_frame = ctk.CTkScrollableFrame(self, width=540, height=220)
        self.status_frame.pack(padx=20, pady=4, fill="both", expand=True)

        self.warning_label = ctk.CTkLabel(self, text="", text_color="#C62828", wraplength=540, justify="left")
        self.warning_label.pack(padx=20, pady=(8, 4), fill="x")

        self.install_box = ctk.CTkTextbox(self, height=56, font=("Consolas", 11))
        self.install_box.pack(padx=20, pady=(0, 8), fill="x")
        self.install_box.configure(state="disabled")

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=14)

        ctk.CTkButton(button_frame, text="Tornar a comprovar", command=self._recheck).grid(
            row=0, column=0, padx=8
        )
        ctk.CTkButton(
            button_frame,
            text="Continuar",
            command=self._continue,
            fg_color="#2E7D32",
            hover_color="#1B5E20",
        ).grid(row=0, column=1, padx=8)

        self._recheck()

    def _recheck(self):
        for widget in self.status_frame.winfo_children():
            widget.destroy()

        results, missing = run_health_check()
        optional_results, _ = run_optional_check()

        ctk.CTkLabel(self.status_frame, text="Eines obligatòries", font=("Segoe UI", 12, "bold")).pack(
            fill="x", pady=(4, 2), padx=6, anchor="w"
        )
        for tool, info in results.items():
            self._render_tool_row(tool, info)

        ctk.CTkLabel(self.status_frame, text="Eines opcionals", font=("Segoe UI", 12, "bold")).pack(
            fill="x", pady=(10, 2), padx=6, anchor="w"
        )
        for tool, info in optional_results.items():
            self._render_tool_row(tool, info)

        self.install_box.configure(state="normal")
        self.install_box.delete("1.0", "end")
        if missing:
            self.warning_label.configure(
                text=(
                    f"Falten {len(missing)} eina(es) obligatòria(es). Algunes funcionalitats no "
                    "estaran disponibles fins que s'instal·lin. Comanda d'instal·lació per a Ubuntu/Debian:"
                ),
                text_color="#C62828",
            )
            self.install_box.insert("1.0", build_install_command(missing))
        else:
            self.warning_label.configure(text="Totes les eines obligatòries estan disponibles.", text_color="#2E7D32")
            self.install_box.insert("1.0", "# Cap acció necessària")
        self.install_box.configure(state="disabled")

    def _render_tool_row(self, tool, info):
        color = "#2E7D32" if info["available"] else "#C62828"
        icon = "✓" if info["available"] else "✗"
        resolved = f" (detectada com '{info['resolved_as']}')" if info["available"] and info["resolved_as"] != tool else ""
        text = f"{icon}  {tool}{resolved} — {info['description']}"
        ctk.CTkLabel(self.status_frame, text=text, text_color=color, anchor="w", justify="left").pack(
            fill="x", pady=3, padx=6
        )

    def _continue(self):
        self.grab_release()
        self.destroy()
        if self.on_continue:
            self.on_continue()
