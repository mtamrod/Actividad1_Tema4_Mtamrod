import smtplib
import ssl
import tkinter as tk
from tkinter import ttk, messagebox
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class SMTPGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Envio SMTP (Mailtrap) - Tkinter")
        self.geometry("1100x650")
        self.minsize(1000, 600)
        self._build_ui()

    def _build_ui(self):
        # ======= Top frame =======
        top = ttk.LabelFrame(self, text="Configuración SMTP")
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(top, text="HOST").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.host_var = tk.StringVar(value="sandbox.smtp.mailtrap.io")
        ttk.Entry(top, textvariable=self.host_var, width=28).grid(row=0, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(top, text="PORT").grid(row=0, column=2, padx=6, pady=6, sticky="w")
        self.port_var = tk.StringVar(value="25")
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=0, column=3, padx=6, pady=6, sticky="w")

        ttk.Label(top, text="USERNAME").grid(row=0, column=4, padx=6, pady=6, sticky="w")
        self.user_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.user_var, width=28).grid(row=0, column=5, padx=6, pady=6, sticky="w")

        ttk.Label(top, text="PASSWORD").grid(row=0, column=6, padx=6, pady=6, sticky="w")
        self.pass_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.pass_var, width=28, show="*").grid(row=0, column=7, padx=6, pady=6, sticky="w")

        ttk.Label(top, text="FROM").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        self.from_var = tk.StringVar(value="mario@prueba.com")
        ttk.Entry(top, textvariable=self.from_var, width=28).grid(row=1, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(top, text="TO").grid(row=1, column=2, padx=6, pady=6, sticky="w")
        self.to_var = tk.StringVar(value="profe@prueba.com")
        ttk.Entry(top, textvariable=self.to_var, width=28).grid(row=1, column=3, padx=6, pady=6, sticky="w")

        ttk.Label(top, text="SUBJECT").grid(row=1, column=4, padx=6, pady=6, sticky="w")
        self.subj_var = tk.StringVar(value="Prueba Mailtrap")
        ttk.Entry(top, textvariable=self.subj_var, width=60).grid(row=1, column=5, columnspan=3, padx=6, pady=6, sticky="we")

        # ======= Middle frame: two big areas =======
        middle = ttk.Frame(self)
        middle.pack(fill="both", expand=True, padx=10, pady=8)
        middle.columnconfigure(0, weight=1)
        middle.columnconfigure(1, weight=1)
        middle.rowconfigure(1, weight=1)

        ttk.Label(middle, text="Cuerpo del correo (HTML)").grid(row=0, column=0, sticky="w")
        ttk.Label(middle, text="Salida / Log").grid(row=0, column=1, sticky="w")

        self.html_text = tk.Text(middle, wrap="word")
        self.html_text.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        self.html_text.insert(
            "1.0",
            "<h1>Hola</h1>\n"
            "<p>Esto es una <b>prueba</b> de envío SMTP con Mailtrap.</p>\n"
            "<p>Hecho con Tkinter.</p>\n"
        )

        left_scroll = ttk.Scrollbar(middle, orient="vertical", command=self.html_text.yview)
        left_scroll.grid(row=1, column=0, sticky="nse", padx=(0, 6))
        self.html_text.configure(yscrollcommand=left_scroll.set)

        self.log_text = tk.Text(middle, wrap="word", state="disabled")
        self.log_text.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

        right_scroll = ttk.Scrollbar(middle, orient="vertical", command=self.log_text.yview)
        right_scroll.grid(row=1, column=1, sticky="nse", padx=(6, 0))
        self.log_text.configure(yscrollcommand=right_scroll.set)

        # ======= Bottom buttons =======
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=(0, 10))

        ttk.Button(bottom, text="Limpiar log", command=self.clear_log).pack(side="right", padx=6)
        ttk.Button(bottom, text="ENVIAR", command=self.send_email).pack(side="right")

    def log(self, msg: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def send_email(self):
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        user = self.user_var.get().strip()
        password = self.pass_var.get().strip()
        from_addr = self.from_var.get().strip()
        to_addr = self.to_var.get().strip()
        subject = self.subj_var.get().strip()
        html_body = self.html_text.get("1.0", "end").strip()

        # Validations
        if not host or not port_str:
            messagebox.showerror("Error", "HOST y PORT son obligatorios.")
            return
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "PORT debe ser un número.")
            return
        if not user or not password:
            messagebox.showerror("Error", "USERNAME y PASSWORD son obligatorios.")
            return
        if not from_addr or not to_addr:
            messagebox.showerror("Error", "FROM y TO son obligatorios.")
            return
        if not subject:
            messagebox.showerror("Error", "SUBJECT es obligatorio.")
            return
        if not html_body:
            messagebox.showerror("Error", "El cuerpo HTML no puede estar vacío.")
            return

        # Build email
        msg = MIMEMultipart("alternative")
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        self.log("-----")
        self.log(f"[INFO] Conectando a {host}:{port}")

        try:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.set_debuglevel(0)

                self.log("[INFO] EHLO...")
                server.ehlo()
                self.log(f"[INFO] Servidor anuncia: STARTTLS={'starttls' in server.esmtp_features}")

                # STARTTLS automático si está disponible (sin opción en la UI)
                if "starttls" in server.esmtp_features:
                    self.log("[INFO] Activando STARTTLS (automático)...")
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    self.log("[INFO] EHLO tras STARTTLS...")
                    server.ehlo()
                else:
                    self.log("[INFO] STARTTLS no disponible. Continuando en plano...")

                self.log("[INFO] LOGIN...")
                server.login(user, password)

                self.log(f"[INFO] Enviando correo a {to_addr} ...")
                server.sendmail(from_addr, [to_addr], msg.as_string())

            self.log("[OK] Mensaje enviado correctamente ✅")
            messagebox.showinfo("OK", "Correo enviado. Revisa Mailtrap Inbox.")

        except smtplib.SMTPAuthenticationError as e:
            self.log("[ERROR] Autenticación fallida. Revisa USER/PASS.")
            self.log(f"Detalle: {e}")
            messagebox.showerror("Error", "Autenticación fallida (USER/PASS).")

        except (smtplib.SMTPConnectError, TimeoutError) as e:
            self.log("[ERROR] No se pudo conectar (puerto bloqueado o host incorrecto).")
            self.log(f"Detalle: {e}")
            messagebox.showerror("Error", "No se pudo conectar. Prueba 2525 si tu red bloquea el 25.")

        except smtplib.SMTPException as e:
            self.log("[ERROR] Error SMTP.")
            self.log(f"Detalle: {e}")
            messagebox.showerror("Error", "Error SMTP. Mira el log.")

        except Exception as e:
            self.log("[ERROR] Error inesperado.")
            self.log(f"Detalle: {e}")
            messagebox.showerror("Error", f"Error inesperado:\n{e}")


if __name__ == "__main__":
    SMTPGui().mainloop()
