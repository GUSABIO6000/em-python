import paramiko
import tkinter as tk
from tkinter import messagebox, ttk
import re
import time
import sys
import atexit

class RouterNATManager:
    def __init__(self):
        self.ssh_client = None
        self.shell = None
        self.root = tk.Tk()
        self.root.title("NAT Manager")
        self.root.geometry("800x600")  # Tamaño inicial más grande
        self.setup_gui()

    def setup_gui(self):
        # Frame para conexión
        conn_frame = ttk.LabelFrame(self.root, text="Conexión al Router")
        conn_frame.grid(padx=10, pady=5, sticky="ew")

        ttk.Label(conn_frame, text="IP del Router:").grid(row=0, column=0, padx=5, pady=5)
        self.router_ip = ttk.Entry(conn_frame)
        self.router_ip.grid(row=0, column=1, padx=5, pady=5)
        self.router_ip.insert(0, "192.168.51.1")

        ttk.Label(conn_frame, text="Usuario:").grid(row=1, column=0, padx=5, pady=5)
        self.username = ttk.Entry(conn_frame)
        self.username.grid(row=1, column=1, padx=5, pady=5)
        self.username.insert(0, "admemov")

        ttk.Label(conn_frame, text="Contraseña:").grid(row=2, column=0, padx=5, pady=5)
        self.password = ttk.Entry(conn_frame, show="*")
        self.password.grid(row=2, column=1, padx=5, pady=5)
        self.password.insert(0, "cuYC00p3r.593")

        ttk.Button(conn_frame, text="Conectar", command=self.connect_to_router).grid(row=3, column=0, columnspan=2, pady=10)

        # Frame para gestión de NAT
        nat_frame = ttk.LabelFrame(self.root, text="Gestión de NAT")
        nat_frame.grid(padx=10, pady=5, sticky="ew")

        ttk.Label(nat_frame, text="IP Interna (ej. 172.20.3.123):").grid(row=0, column=0, padx=5, pady=5)
        self.internal_ip = ttk.Entry(nat_frame)
        self.internal_ip.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(nat_frame, text="(Formato: 172.16.x.x, ej. 172.20.3.123)", font=("Arial", 8)).grid(row=0, column=2, padx=5)

        ttk.Label(nat_frame, text="IP NAT (ej. 10.200.26.128):").grid(row=1, column=0, padx=5, pady=5)
        self.nat_ip = ttk.Entry(nat_frame)
        self.nat_ip.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(nat_frame, text="(Formato: 10.200.26.x, ej. 10.200.26.128-149 para estáticos)", font=("Arial", 8)).grid(row=1, column=2, padx=5)

        ttk.Button(nat_frame, text="Verificar NAT", command=self.check_nat).grid(row=2, column=0, pady=10)
        ttk.Button(nat_frame, text="Agregar/Modificar NAT", command=self.modify_nat).grid(row=2, column=1, pady=10)
        ttk.Button(nat_frame, text="Mostrar Todos los NATs", command=self.show_all_nats).grid(row=3, column=0, columnspan=2, pady=10)

        # Área de texto redimensionable como terminal
        self.result_text = tk.Text(self.root, height=20, width=90)
        self.result_text.grid(padx=10, pady=5, sticky="nsew")
        self.result_scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.result_text.yview)
        self.result_scroll.grid(row=4, column=1, sticky="ns")
        self.result_text.config(yscrollcommand=self.result_scroll.set)
        self.root.grid_rowconfigure(4, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Campo para comandos manuales
        self.command_entry = ttk.Entry(self.root)
        self.command_entry.grid(padx=10, pady=5, sticky="ew")
        ttk.Button(self.root, text="Enviar Comando", command=self.send_command).grid(padx=10, pady=5, sticky="ew")

    def connect_to_router(self):
        if self.ssh_client:
            messagebox.showinfo("Info", "Ya estás conectado.")
            return
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=self.router_ip.get(),
                username=self.username.get(),
                password=self.password.get(),
                timeout=10
            )
            self.shell = self.ssh_client.invoke_shell()
            time.sleep(1)  # Esperar a que la shell esté lista
            self.result_text.insert(tk.END, "Conexión SSH establecida.\n")
            self.shell.recv(65535)  # Limpiar buffer inicial
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo conectar al router: {str(e)}")

    def send_command(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        command = self.command_entry.get() + "\n"
        self.shell.send(command)
        time.sleep(1)  # Esperar respuesta
        output = self.shell.recv(65535).decode()
        self.result_text.insert(tk.END, f"Comando: {command.strip()}\nRespuesta: {output}\n")
        self.command_entry.delete(0, tk.END)

    def check_nat(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        if not internal_ip:
            messagebox.showerror("Error", "Por favor, ingrese una IP interna.")
            return
        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        time.sleep(1)
        output = self.shell.recv(65535).decode()
        self.result_text.insert(tk.END, f"Respuesta: {output}\n")

    def show_all_nats(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        command = "sh ip nat translations\n"
        self.shell.send(command)
        time.sleep(1)
        output = self.shell.recv(65535).decode()
        self.result_text.insert(tk.END, f"Respuesta: {output}\n")

    def modify_nat(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        nat_ip = self.nat_ip.get()
        if not internal_ip or not nat_ip:
            messagebox.showerror("Error", "Por favor, ingrese tanto la IP interna como la IP NAT.")
            return

        self.result_text.insert(tk.END, "Iniciando modificación de NAT...\n")
        commands = []

        # Verificar si la IP interna ya tiene un NAT
        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        time.sleep(1)
        output = self.shell.recv(65535).decode()
        if internal_ip in output:
            current_nat_ip = self.find_nat_ip(output)
            if current_nat_ip:
                commands.extend([
                    "conf t\n",
                    f"no ip nat inside source static {internal_ip} {current_nat_ip}\n",
                    "exit\n"
                ])

        # Agregar el nuevo NAT
        commands.extend([
            "conf t\n",
            f"ip nat inside source static {internal_ip} {nat_ip}\n",
            "exit\n",
            "wr mem\n",
            "copy running-config startup-config\n"
        ])

        # Ejecutar comandos
        for cmd in commands:
            self.result_text.insert(tk.END, f"Ejecutando: {cmd.strip()}\n")
            self.shell.send(cmd)
            time.sleep(1)
            output = self.shell.recv(65535).decode()
            self.result_text.insert(tk.END, f"Respuesta: {output}\n")

        # Verificar el cambio
        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        time.sleep(1)
        output = self.shell.recv(65535).decode()
        self.result_text.insert(tk.END, f"\nNAT actualizado:\n{output}\n")

    def find_nat_ip(self, output):
        match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", output)
        return match.group(1) if match else ""

    def cleanup(self):
        if self.shell:
            self.shell.close()
        if self.ssh_client:
            self.ssh_client.close()
        self.root.quit()

    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.cleanup()
            sys.exit(0)

if __name__ == "__main__":
    app = RouterNATManager()
    app.run()