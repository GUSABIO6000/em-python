#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import re
import time
import sys
import atexit
import threading
from datetime import datetime


class RouterNATManager:
    def __init__(self):
        self.ssh_client = None
        self.shell = None
        self.root = tk.Tk()
        self.root.title("NAT Manager - Completo v4.0")
        self.root.geometry("900x600")
        self.connection_status = "Desconectado"
        self.setup_gui()
        self.check_connection_periodically()
        self.root.bind("<Return>", self.send_command_from_cli)
        self.root.bind("<Control-space>", self.handle_space_pagination)
        atexit.register(self.cleanup)

    def setup_gui(self):
        self.canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        conn_frame = ttk.LabelFrame(self.scrollable_frame, text="Conexión al Router")
        conn_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew", columnspan=2)

        ttk.Label(conn_frame, text="IP del Router:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.router_ip = ttk.Entry(conn_frame, width=20)
        self.router_ip.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.router_ip.insert(0, "192.168.51.1")

        ttk.Label(conn_frame, text="Usuario:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.username = ttk.Entry(conn_frame, width=15)
        self.username.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.username.insert(0, "admemov")

        ttk.Label(conn_frame, text="Contraseña:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.password = ttk.Entry(conn_frame, show="*", width=20)
        self.password.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.password.insert(0, "cuYC00p3r.593")

        self.connect_button = ttk.Button(conn_frame, text="Conectar", command=self.connect_to_router)
        self.connect_button.grid(row=1, column=2, padx=10, pady=5)

        self.status_label = ttk.Label(conn_frame, text=f"Estado: {self.connection_status}", foreground="red")
        self.status_label.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        nat_frame = ttk.LabelFrame(self.scrollable_frame, text="Gestión de NAT")
        nat_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew", columnspan=2)

        ttk.Label(nat_frame, text="IP Interna:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.internal_ip = ttk.Entry(nat_frame, width=20)
        self.internal_ip.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(nat_frame, text="IP NAT:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.nat_ip = ttk.Entry(nat_frame, width=20)
        self.nat_ip.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        button_frame = ttk.Frame(nat_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)

        ttk.Button(button_frame, text="Verificar NAT", command=self.check_nat).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Agregar NAT", command=self.add_nat).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(button_frame, text="Modificar NAT", command=self.modify_nat).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(button_frame, text="Eliminar NAT", command=self.remove_nat).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Mostrar Todos", command=self.show_all_nats).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(button_frame, text="Limpiar Traducciones", command=self.clear_translations).grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(button_frame, text="Limpiar Texto", command=self.clear_text).grid(row=2, column=1, padx=5, pady=5)

        result_frame = ttk.LabelFrame(self.scrollable_frame, text="Resultados y CLI Interactiva")
        result_frame.grid(row=2, column=0, padx=10, pady=5, sticky="nsew", columnspan=2)

        self.result_text = tk.Text(result_frame, height=20, width=100, font=("Consolas", 9))
        self.result_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        result_scroll = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        result_scroll.grid(row=0, column=1, sticky="ns", pady=5)
        self.result_text.config(yscrollcommand=result_scroll.set)

        cli_frame = ttk.Frame(result_frame)
        cli_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        ttk.Label(cli_frame, text="CLI Command:").grid(row=0, column=0, padx=5, sticky="w")
        self.cli_entry = ttk.Entry(cli_frame, width=80)
        self.cli_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.cli_entry.insert(0, "Ingrese comando CLI (ej: sh ip nat translations)")
        self.cli_entry.bind("<FocusIn>", self.clear_placeholder)

        ttk.Button(cli_frame, text="Ejecutar", command=lambda: self.send_command_from_cli(None)).grid(row=0, column=2, padx=5)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        result_frame.grid_rowconfigure(0, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)
        cli_frame.grid_columnconfigure(1, weight=1)

        self.log_message("=== NAT Manager Iniciado ===")

    def log_message(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        self.result_text.insert(tk.END, timestamp + message + "\n")
        self.result_text.see(tk.END)

    def clear_placeholder(self, event):
        if self.cli_entry.get() == "Ingrese comando CLI (ej: sh ip nat translations)":
            self.cli_entry.delete(0, tk.END)

    def connect_to_router(self):
        ip = self.router_ip.get().strip()
        user = self.username.get().strip()
        passwd = self.password.get().strip()

        if not ip or not user or not passwd:
            messagebox.showwarning("Datos incompletos", "Por favor, complete IP, usuario y contraseña.")
            return

        self.log_message(f"Intentando conectar a {ip}...")
        self.connection_status = "Conectando..."
        self.update_status_label()

        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(ip, username=user, password=passwd, timeout=10)
            self.shell = self.ssh_client.invoke_shell()
            time.sleep(1)
            self.clear_buffer()
            self.connection_status = "Conectado"
            self.update_status_label()
            self.log_message(f"Conectado al router {ip}")
        except Exception as e:
            self.connection_status = "Desconectado"
            self.update_status_label()
            self.log_message(f"Error de conexión: {str(e)}")
            messagebox.showerror("Error de conexión", f"No se pudo conectar al router:\n{str(e)}")

    def clear_buffer(self):
        if self.shell is None:
            return
        while self.shell.recv_ready():
            self.shell.recv(1024)

    def send_command(self, command, wait=1):
        if self.shell is None:
            self.log_message("No conectado al router.")
            return ""
        self.shell.send(command + "\n")
        time.sleep(wait)
        output = ""
        while self.shell.recv_ready():
            output += self.shell.recv(65535).decode('utf-8', errors='ignore')
            time.sleep(0.1)
        return output

    def check_nat(self):
        internal_ip = self.internal_ip.get().strip()
        if not self.validate_ip(internal_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese una IP interna válida.")
            return
        self.log_message(f"Verificando NAT para IP interna {internal_ip}...")
        output = self.send_command(f"sh ip nat translations | include {internal_ip}")
        if output:
            self.log_message(output.strip())
        else:
            self.log_message("No se encontraron traducciones NAT para esa IP.")

    def add_nat(self):
        internal_ip = self.internal_ip.get().strip()
        nat_ip = self.nat_ip.get().strip()

        if not self.validate_ip(internal_ip) or not self.validate_ip(nat_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese IPs válidas para interna y NAT.")
            return

        self.log_message(f"Agregando NAT: {internal_ip} -> {nat_ip}...")

        # Comandos para agregar NAT (ejemplo típico)
        commands = [
            "configure terminal",
            f"ip nat inside source static {internal_ip} {nat_ip}",
            "end",
            "write memory"
        ]

        for cmd in commands:
            output = self.send_command(cmd)
            self.log_message(f"> {cmd}")
            time.sleep(0.5)

        self.log_message("NAT agregada correctamente.")

    def modify_nat(self):
        internal_ip = self.internal_ip.get().strip()
        nat_ip = self.nat_ip.get().strip()

        if not self.validate_ip(internal_ip) or not self.validate_ip(nat_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese IPs válidas para interna y NAT.")
            return

        self.log_message(f"Modificando NAT para IP interna {internal_ip}...")

        # En general, para modificar una traducción NAT estática hay que borrarla y crearla de nuevo
        self.remove_nat(confirm=False)
        time.sleep(1)
        self.add_nat()
        self.log_message("NAT modificada correctamente.")

    def remove_nat(self, confirm=True):
        internal_ip = self.internal_ip.get().strip()
        if not self.validate_ip(internal_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese una IP interna válida.")
            return
        if confirm:
            if not messagebox.askyesno("Confirmar eliminación", f"¿Eliminar NAT para IP interna {internal_ip}?"):
                return
        self.log_message(f"Eliminando NAT para IP interna {internal_ip}...")

        commands = [
            "configure terminal",
            f"no ip nat inside source static {internal_ip}",
            "end",
            "write memory"
        ]

        for cmd in commands:
            output = self.send_command(cmd)
            self.log_message(f"> {cmd}")
            time.sleep(0.5)

        self.log_message("NAT eliminada correctamente.")

    def show_all_nats(self):
        self.log_message("Mostrando todas las traducciones NAT...")
        output = self.send_command("sh ip nat translations")
        self.log_message(output.strip())

    def clear_translations(self):
        if not messagebox.askyesno("Confirmar limpieza", "¿Limpiar todas las traducciones NAT?"):
            return
        self.log_message("Limpiando todas las traducciones NAT...")

        commands = [
            "configure terminal",
            "clear ip nat translation *",
            "end"
        ]

        for cmd in commands:
            output = self.send_command(cmd)
            self.log_message(f"> {cmd}")
            time.sleep(0.5)

        self.log_message("Todas las traducciones NAT han sido limpiadas.")

    def clear_text(self):
        self.result_text.delete("1.0", tk.END)

    def validate_ip(self, ip):
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not pattern.match(ip):
            return False
        parts = ip.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return False
        return True

    def send_command_from_cli(self, event):
        command = self.cli_entry.get().strip()
        if not command or command == "Ingrese comando CLI (ej: sh ip nat translations)":
            messagebox.showwarning("Comando vacío", "Por favor ingrese un comando válido.")
            return
        self.log_message(f"Ejecutando comando CLI: {command}")
        output = self.send_command(command, wait=2)
        self.log_message(output.strip())

    def handle_space_pagination(self, event):
        # Para manejo futuro de paginación, si el router responde con '--More--'
        # Aquí puedes implementar lógica para enviar espacio y continuar mostrando texto
        pass

    def check_connection_periodically(self):
        def check():
            while True:
                time.sleep(10)
                if self.ssh_client:
                    transport = self.ssh_client.get_transport() if self.ssh_client else None
                    if transport and transport.is_active():
                        self.connection_status = "Conectado"
                    else:
                        self.connection_status = "Desconectado"
                    self.update_status_label()

        threading.Thread(target=check, daemon=True).start()

    def update_status_label(self):
        color = "green" if self.connection_status == "Conectado" else "red"
        self.status_label.config(text=f"Estado: {self.connection_status}", foreground=color)

    def cleanup(self):
        if self.shell:
            self.shell.close()
        if self.ssh_client:
            self.ssh_client.close()
        self.log_message("Sesión SSH cerrada y aplicación terminada.")

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    app = RouterNATManager()
    app.run()
