"""Execució asíncrona de comandes externes (nmap, traceroute, etc.).

Totes les comandes s'executen en un fil (thread) independent perquè la
interfície gràfica no es bloquegi, i la sortida es retransmet línia a
línia mitjançant un callback per mostrar-la en temps real als logs.
"""
import subprocess
import threading


class CommandRunner:
    def __init__(self):
        self._process = None
        self._lock = threading.Lock()

    def run_async(self, args, on_output, on_done):
        """Executa `args` (llista, sense shell) en un fil i retorna el Thread.

        on_output(line: str) es crida per cada línia de sortida (stdout+stderr).
        on_done(returncode: int) es crida en finalitzar.
        """

        def target():
            try:
                process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                with self._lock:
                    self._process = process
                for line in process.stdout:
                    on_output(line.rstrip("\n"))
                process.wait()
                on_done(process.returncode)
            except FileNotFoundError as exc:
                on_output(f"[ERROR] Comanda no trobada: {exc}")
                on_done(-1)
            except PermissionError as exc:
                on_output(
                    f"[ERROR] Permisos insuficients per executar la comanda: {exc}. "
                    "Prova d'executar l'aplicació amb privilegis d'administrador (sudo)."
                )
                on_done(-1)
            except Exception as exc:  # noqa: BLE001 - es vol capturar qualsevol error d'execució
                on_output(f"[ERROR] {exc}")
                on_done(-1)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    def terminate(self):
        with self._lock:
            if self._process and self._process.poll() is None:
                self._process.terminate()
