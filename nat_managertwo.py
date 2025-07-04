from tkinter import simpledialog
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
        self.root.geometry("1000x700")  # Pantalla más grande
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
        ttk.Label(nat_frame, text="(Formato: 172.16.x.x)", font=("Arial", 8)).grid(row=0, column=2, padx=5)

        ttk.Label(nat_frame, text="IP NAT (ej. 10.200.26.128):").grid(row=1, column=0, padx=5, pady=5)
        self.nat_ip = ttk.Entry(nat_frame)
        self.nat_ip.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(nat_frame, text="(Formato: 10.200.26.x, 128-149 para estáticos)", font=("Arial", 8)).grid(row=1, column=2, padx=5)

        ttk.Button(nat_frame, text="Verificar NAT", command=self.check_nat).grid(row=2, column=0, pady=10)
        ttk.Button(nat_frame, text="Agregar NAT", command=self.add_nat).grid(row=2, column=1, pady=10)
        ttk.Button(nat_frame, text="Modificar NAT", command=self.modify_nat).grid(row=3, column=0, pady=10)
        ttk.Button(nat_frame, text="Mostrar Todos los NATs", command=self.show_all_nats).grid(row=3, column=1, pady=10)

        # Área de texto redimensionable como terminal
        self.result_text = tk.Text(self.root, height=25, width=120)
        self.result_text.grid(padx=10, pady=5, sticky="nsew")
        self.result_scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.result_text.yview)
        self.result_scroll.grid(row=4, column=1, sticky="ns")
        self.result_text.config(yscrollcommand=self.result_scroll.set)
        self.root.grid_rowconfigure(4, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Campo para comandos manuales
        self.command_entry = ttk.Entry(self.root)
        self.command_entry.grid(padx=10, pady=5, sticky="ew")
        ttk.Button(self.root, text="Enviar Comando", command=self.send_command).grid(row=5, column=0, padx=10, pady=5, sticky="ew")
        ttk.Button(self.root, text="Limpiar Datos", command=self.clear_text).grid(row=5, column=1, padx=10, pady=5, sticky="ew")

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
        self.highlight_result(command.strip())

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
        time.sleep(2)
        output = ""
        while self.shell.recv_ready():
            output += self.shell.recv(65535).decode()
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Respuesta: {output}\n")
        self.highlight_result(internal_ip)
        return output

    def show_all_nats(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        command = "sh ip nat translations\n"
        self.shell.send(command)
        time.sleep(2)
        output = ""
        while self.shell.recv_ready():
            output += self.shell.recv(65535).decode()
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Respuesta: {output}\n")

    def add_nat(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        nat_ip = self.nat_ip.get()
        if not internal_ip or not nat_ip:
            messagebox.showerror("Error", "Por favor, ingrese tanto la IP interna como la IP NAT.")
            return
        self.verify_and_add_modify_nat(internal_ip, nat_ip, is_add=True)

    def modify_nat(self):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        if not internal_ip:
            messagebox.showerror("Error", "Por favor, ingrese una IP interna.")
            return
        self.verify_and_add_modify_nat(internal_ip, None, is_add=False)

    def verify_and_add_modify_nat(self, internal_ip, initial_nat_ip, is_add):
        if not self.shell:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return

        self.result_text.insert(tk.END, "Verificando NAT existente...\n")
        output = self.check_nat()
        try:
            if internal_ip in output:
                current_nat_ip = self.find_nat_ip(output)
                if is_add:
                    messagebox.showerror("Error", f"La IP interna {internal_ip} ya tiene un NAT ({current_nat_ip}). Use 'Modificar NAT'.")
                    return
                else:
                    if messagebox.askyesno("Confirmar", f"La IP {internal_ip} ya tiene NAT {current_nat_ip}. ¿Desea cambiarla?"):
                        new_nat_ip = simpledialog.askstring("Nueva IP NAT", "Ingrese la nueva IP NAT (ej. 10.200.26.128):")
                        if new_nat_ip:
                            self.execute_nat_commands(internal_ip, current_nat_ip, new_nat_ip)
                        else:
                            messagebox.showinfo("Cancelado", "Modificación cancelada.")
                    return
            elif not is_add:
                messagebox.showinfo("Info", f"No se encontró NAT para {internal_ip}. Use 'Agregar NAT'.")
                return
            else:
                if initial_nat_ip:
                    self.execute_nat_commands(internal_ip, None, initial_nat_ip)
                else:
                    nat_ip = simpledialog.askstring("Nueva IP NAT", "Ingrese la IP NAT (ej. 10.200.26.128):")
                    if nat_ip:
                        self.execute_nat_commands(internal_ip, None, nat_ip)
                    else:
                        messagebox.showinfo("Cancelado", "Agregado cancelado.")
        except Exception as e:
            messagebox.showerror("Error", f"Error en el diálogo: {str(e)}")
            self.result_text.insert(tk.END, f"Error: {str(e)}\n")

    def execute_nat_commands(self, internal_ip, current_nat_ip, new_nat_ip):
        self.result_text.insert(tk.END, "Ejecutando comandos de NAT...\n")
        commands = [
            "clear ip nat translation *\n",
            "conf t\n",
        ]
        if current_nat_ip:
            commands.extend([
                "no ip nat inside source list 100 pool ANT\n",
                "no ip nat pool ANT 10.200.26.150 10.200.26.250 netmask 255.255.255.0\n",
                f"no ip nat inside source static {internal_ip} {current_nat_ip}\n",
            ])
        commands.extend([
            f"ip nat inside source static {internal_ip} {new_nat_ip}\n",
            "ip nat pool ANT 10.200.26.150 10.200.26.250 netmask 255.255.255.0\n",
            "ip nat inside source list 100 pool ANT\n",
            "exit\n",
            "wr mem\n",
            "copy running-config startup-config\n"
        ])

        for cmd in commands:
            self.result_text.insert(tk.END, f"Ejecutando: {cmd.strip()}\n")
            self.shell.send(cmd)
            time.sleep(3)  # Aumentado el retraso para evitar cuelgues
            output = ""
            while self.shell.recv_ready():
                output += self.shell.recv(65535).decode()
            self.result_text.insert(tk.END, f"Respuesta: {output}\n")

        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        time.sleep(3)
        output = ""
        while self.shell.recv_ready():
            output += self.shell.recv(65535).decode()
        self.result_text.insert(tk.END, f"\nNAT actualizado:\n{output}\n")
        self.highlight_result(internal_ip)

    def find_nat_ip(self, output):
        # Buscar la segunda IP en la salida (la IP NAT)
        matches = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", output)
        if len(matches) >= 2:
            return matches[1]  # La segunda IP es la NAT
        return ""

    def highlight_result(self, search_text):
        self.result_text.tag_remove("highlight", "1.0", tk.END)
        start = "1.0"
        while True:
            start = self.result_text.search(search_text, start, stopindex=tk.END)
            if not start:
                break
            end = f"{start}+{len(search_text)}c"
            self.result_text.tag_add("highlight", start, end)
            start = end
        self.result_text.tag_config("highlight", underline=True, foreground="blue")

    def clear_text(self):
        self.result_text.delete(1.0, tk.END)

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