import socket
import struct
import time
import datetime
import tkinter as tk
from tkinter import ttk, messagebox

# Intentamos usar requests para DoH (DNS público real). Si no existe, caemos a socket local.
try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False


# =========================
# DNS (DoH con Cloudflare)
# =========================
CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"


def doh_a_query(name: str) -> list[str]:
    """
    Resuelve A records usando DNS over HTTPS (Cloudflare).
    Devuelve lista de IPs (strings).
    """
    if not HAS_REQUESTS:
        # fallback: resolución local (depende del DNS del PC)
        try:
            infos = socket.getaddrinfo(name, None, family=socket.AF_INET)
            ips = sorted({info[4][0] for info in infos})
            return ips
        except Exception:
            return []

    headers = {"accept": "application/dns-json"}
    params = {"name": name, "type": "A"}
    r = requests.get(CLOUDFLARE_DOH, headers=headers, params=params, timeout=8)
    r.raise_for_status()
    data = r.json()
    ips = []
    for ans in data.get("Answer", []) or []:
        if ans.get("type") == 1:  # A
            ips.append(ans.get("data"))
    return ips


def doh_ptr_query(ip: str) -> str | None:
    """
    Reverse DNS (PTR) usando DoH.
    """
    if not HAS_REQUESTS:
        # fallback local
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return None

    headers = {"accept": "application/dns-json"}

    # Construir nombre PTR: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    ptr_name = ".".join(reversed(parts)) + ".in-addr.arpa"
    params = {"name": ptr_name, "type": "PTR"}

    r = requests.get(CLOUDFLARE_DOH, headers=headers, params=params, timeout=8)
    r.raise_for_status()
    data = r.json()

    for ans in data.get("Answer", []) or []:
        if ans.get("type") == 12:  # PTR
            # suele venir con punto final
            return str(ans.get("data", "")).rstrip(".")
    return None


# =========================
# NTP (UDP, RFC 5905 básico)
# =========================
def ntp_query(server: str, timeout: float = 4.0) -> datetime.datetime:
    """
    Consulta un servidor NTP y devuelve datetime UTC.
    Implementación mínima: manda paquete NTP (48 bytes) y lee transmit timestamp.
    """
    # NTP: segundos desde 1900-01-01
    NTP_EPOCH = 2208988800  # diferencia entre 1900 y 1970 en segundos

    addr = (server, 123)
    msg = b"\x1b" + 47 * b"\0"  # LI=0, VN=3, Mode=3 (client)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(msg, addr)
        data, _ = s.recvfrom(1024)

    if len(data) < 48:
        raise ValueError("Respuesta NTP inválida.")

    # Transmit Timestamp: bytes 40..47 (64-bit: seconds, fraction)
    sec = struct.unpack("!I", data[40:44])[0]
    frac = struct.unpack("!I", data[44:48])[0]

    unix_sec = sec - NTP_EPOCH
    micro = int((frac / 2**32) * 1_000_000)

    return datetime.datetime.utcfromtimestamp(unix_sec).replace(microsecond=micro, tzinfo=datetime.timezone.utc)


# =========================
# UI
# =========================
class NetworkLab(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetworkLab - DNS & NTP")
        self.geometry("1100x650")
        self.minsize(1000, 600)

        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.dns_tab = ttk.Frame(nb)
        self.ntp_tab = ttk.Frame(nb)

        nb.add(self.dns_tab, text="DNS")
        nb.add(self.ntp_tab, text="NTP")

        self._build_dns_tab()
        self._build_ntp_tab()

    # ---------- helpers ----------
    def log(self, widget: tk.Text, msg: str):
        widget.configure(state="normal")
        widget.insert("end", msg + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def clear_log(self, widget: tk.Text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.configure(state="disabled")

    # ---------- DNS tab ----------
    def _build_dns_tab(self):
        top = ttk.LabelFrame(self.dns_tab, text="DNS (dominio ↔ IP)")
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="Dominio").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.domain_var = tk.StringVar(value="example.com")
        ttk.Entry(top, textvariable=self.domain_var, width=45).grid(row=0, column=1, padx=6, pady=6, sticky="w")
        ttk.Button(top, text="Resolver", command=self.dns_resolve_domain).grid(row=0, column=2, padx=6, pady=6)

        ttk.Label(top, text="IP").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        self.ip_var = tk.StringVar(value="1.1.1.1")
        ttk.Entry(top, textvariable=self.ip_var, width=45).grid(row=1, column=1, padx=6, pady=6, sticky="w")
        ttk.Button(top, text="Reverse", command=self.dns_reverse_ip).grid(row=1, column=2, padx=6, pady=6)

        info = ttk.Label(
            top,
            text=f"DNS público: Cloudflare DoH (si no hay requests, usa DNS local). requests={'OK' if HAS_REQUESTS else 'NO'}",
        )
        info.grid(row=2, column=0, columnspan=3, padx=6, pady=(0, 6), sticky="w")

        # Log
        log_frame = ttk.LabelFrame(self.dns_tab, text="Salida / Log")
        log_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.dns_log = tk.Text(log_frame, wrap="word", state="disabled")
        self.dns_log.pack(fill="both", expand=True, padx=6, pady=6)

        btns = ttk.Frame(self.dns_tab)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="Limpiar", command=lambda: self.clear_log(self.dns_log)).pack(side="right")

    def dns_resolve_domain(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Introduce un dominio.")
            return

        self.log(self.dns_log, "-----")
        self.log(self.dns_log, f"[DNS] Resolviendo A para: {domain}")
        try:
            ips = doh_a_query(domain)
            if not ips:
                self.log(self.dns_log, "[DNS] No se encontraron IPs (A).")
            else:
                for ip in ips:
                    self.log(self.dns_log, f"[DNS] {domain} -> {ip}")
        except Exception as e:
            self.log(self.dns_log, f"[ERROR] {e}")

    def dns_reverse_ip(self):
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("Error", "Introduce una IP.")
            return

        self.log(self.dns_log, "-----")
        self.log(self.dns_log, f"[DNS] Reverse (PTR) para: {ip}")
        try:
            host = doh_ptr_query(ip)
            if not host:
                self.log(self.dns_log, f"[DNS] No hay PTR para {ip} (o no disponible).")
            else:
                self.log(self.dns_log, f"[DNS] {ip} -> {host}")
        except Exception as e:
            self.log(self.dns_log, f"[ERROR] {e}")

    # ---------- NTP tab ----------
    def _build_ntp_tab(self):
        top = ttk.LabelFrame(self.ntp_tab, text="NTP (hora oficial)")
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="Servidor NTP").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.ntp_server_var = tk.StringVar(value="pool.ntp.org")
        ttk.Entry(top, textvariable=self.ntp_server_var, width=45).grid(row=0, column=1, padx=6, pady=6, sticky="w")
        ttk.Button(top, text="Consultar NTP", command=self.ntp_get_time).grid(row=0, column=2, padx=6, pady=6)

        # Log
        log_frame = ttk.LabelFrame(self.ntp_tab, text="Salida / Log")
        log_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.ntp_log = tk.Text(log_frame, wrap="word", state="disabled")
        self.ntp_log.pack(fill="both", expand=True, padx=6, pady=6)

        btns = ttk.Frame(self.ntp_tab)
        btns.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btns, text="Limpiar", command=lambda: self.clear_log(self.ntp_log)).pack(side="right")

    def ntp_get_time(self):
        server = self.ntp_server_var.get().strip()
        if not server:
            messagebox.showerror("Error", "Introduce un servidor NTP.")
            return

        self.log(self.ntp_log, "-----")
        self.log(self.ntp_log, f"[NTP] Consultando: {server}:123/UDP")

        try:
            utc_dt = ntp_query(server)
            local_dt = utc_dt.astimezone()  # zona local del PC

            self.log(self.ntp_log, f"[NTP] Hora UTC : {utc_dt.strftime('%Y-%m-%d %H:%M:%S.%f %Z')}")
            self.log(self.ntp_log, f"[NTP] Hora local: {local_dt.strftime('%Y-%m-%d %H:%M:%S.%f %Z')}")
            self.log(self.ntp_log, "[OK] Consulta NTP completada ✅")
        except socket.timeout:
            self.log(self.ntp_log, "[ERROR] Timeout (sin respuesta del servidor NTP).")
        except Exception as e:
            self.log(self.ntp_log, f"[ERROR] {e}")


if __name__ == "__main__":
    NetworkLab().mainloop()
