from tkinter import simpledialog
import paramiko
import tkinter as tk
from tkinter import messagebox, ttk
import re
import time
import select
import sys
import atexit

class RouterNATManager:
    def __init__(self):
        self.ssh_client = None
        self.shell = None
        self.root = tk.Tk()
        self.root.title("NAT Manager")
        self.root.geometry("800x500")
        self.setup_gui()
        self.check_connection_periodically()
        self.root.bind("<Return>", self.send_command_from_cli)
        self.root.bind("<space>", self.handle_space_pagination)
        atexit.register(self.cleanup)

    def setup_gui(self):
        self.canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        conn_frame = ttk.LabelFrame(self.scrollable_frame, text="Conexión al Router")
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

        self.connect_button = ttk.Button(conn_frame, text="Conectar", command=self.connect_to_router)
        self.connect_button.grid(row=3, column=0, columnspan=2, pady=10)

        nat_frame = ttk.LabelFrame(self.scrollable_frame, text="Gestión de NAT")
        nat_frame.grid(padx=10, pady=5, sticky="ew")

        ttk.Label(nat_frame, text="IP Interna (ej. 172.20.3.123):").grid(row=0, column=0, padx=5, pady=5)
        self.internal_ip = ttk.Entry(nat_frame)
        self.internal_ip.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(nat_frame, text="(Formato: 172.16.x.x)", font=("Arial", 8)).grid(row=0, column=2, padx=5)

        ttk.Label(nat_frame, text="IP NAT (ej. 10.200.26.22):").grid(row=1, column=0, padx=5, pady=5)
        self.nat_ip = ttk.Entry(nat_frame)
        self.nat_ip.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(nat_frame, text="(Formato: 10.200.26.x)", font=("Arial", 8)).grid(row=1, column=2, padx=5)

        ttk.Button(nat_frame, text="Verificar NAT", command=self.check_nat).grid(row=2, column=0, pady=10)
        ttk.Button(nat_frame, text="Agregar NAT", command=self.add_nat).grid(row=2, column=1, pady=10)
        ttk.Button(nat_frame, text="Modificar NAT", command=self.modify_nat).grid(row=3, column=0, pady=10)
        ttk.Button(nat_frame, text="Eliminar NAT", command=self.remove_nat).grid(row=3, column=1, pady=10)
        ttk.Button(nat_frame, text="Mostrar Todos los NATs", command=self.show_all_nats).grid(row=4, column=0, columnspan=2, pady=10)

        self.exit_button = ttk.Button(self.scrollable_frame, text="Salir", command=self.cleanup)
        self.exit_button.grid(row=6, column=0, columnspan=2, pady=10)

        self.result_text = tk.Text(self.scrollable_frame, height=15, width=80)
        self.result_text.grid(padx=10, pady=5, sticky="nsew")
        self.result_scroll_text = ttk.Scrollbar(self.scrollable_frame, orient="vertical", command=self.result_text.yview)
        self.result_scroll_text.grid(row=5, column=1, sticky="ns")
        self.result_text.config(yscrollcommand=self.result_scroll_text.set)
        self.scrollable_frame.grid_rowconfigure(5, weight=1)
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

        self.cli_entry = ttk.Entry(self.scrollable_frame)
        self.cli_entry.grid(padx=10, pady=5, sticky="ew")
        self.cli_entry.insert(0, "Ingrese comando CLI (e.g., sh ip nat translations)")
        self.cli_entry.bind("<FocusIn>", lambda e: self.cli_entry.delete(0, tk.END) if self.cli_entry.get() == "Ingrese comando CLI (e.g., sh ip nat translations)" else None)
        ttk.Label(self.scrollable_frame, text="CLI Interactiva: Escribe y presiona Enter").grid(row=7, column=0, pady=5)

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
                timeout=15
            )
            self.shell = self.ssh_client.invoke_shell()
            time.sleep(1)
            self.result_text.insert(tk.END, "Conexión SSH establecida.\n")
            self.shell.recv(65535)
            self.connect_button.config(text="Reconectar")
            self.cli_entry.focus_set()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo conectar al router: {str(e)}")
            self.shell = None
            self.connect_button.config(text="Conectar")

    def check_connection_periodically(self):
        if self.shell:
            try:
                self.shell.send("\n")
                time.sleep(1)
                if not self.shell.recv_ready():
                    self.shell = None
                    self.connect_button.config(text="Conectar")
                    messagebox.showwarning("Conexión Perdida", "La conexión SSH se ha perdido. Por favor, reconecte.")
            except Exception:
                self.shell = None
                self.connect_button.config(text="Conectar")
                messagebox.showwarning("Conexión Perdida", "La conexión SSH se ha perdido. Por favor, reconecte.")
        self.root.after(30000, self.check_connection_periodically)

    def send_command_from_cli(self, event):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        command = self.cli_entry.get().strip()
        if not command or command == "Ingrese comando CLI (e.g., sh ip nat translations)":
            messagebox.showwarning("Advertencia", "Por favor, ingrese un comando válido.")
            return
        self.result_text.insert(tk.END, f"Comando: {command}\n")
        self.shell.send(command + "\n")
        self.process_command_output()
        self.cli_entry.delete(0, tk.END)
        self.cli_entry.insert(0, "Ingrese comando CLI (e.g., sh ip nat translations)")

    def handle_space_pagination(self, event):
        if self.shell and self.shell.recv_ready():
            self.shell.send(" ")  # Enviar Barra Espaciadora para paginación
            self.process_command_output()

    def process_command_output(self):
        if not self.shell:
            return
        try:
            output = ""
            start_time = time.time()
            while time.time() - start_time < 20:
                if select.select([self.shell], [], [], 0.1)[0]:
                    data = self.shell.recv(65535).decode(errors='ignore')
                    output += data
                    self.result_text.insert(tk.END, data)
                    self.result_text.see(tk.END)
                    if "--more--" in data:
                        self.shell.send("\n")  # Enviar Enter automáticamente
                        time.sleep(0.5)
                else:
                    time.sleep(0.1)
                    break
            self.result_text.insert(tk.END, "\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error al recibir respuesta: {str(e)}\n")

    def check_nat(self):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        if not internal_ip:
            messagebox.showerror("Error", "Por favor, ingrese una IP interna.")
            return
        self.shell.send("clear ip nat translation *\n")  # Limpiar traducciones
        time.sleep(0.5)
        self.shell.recv(65535)  # Limpiar buffer
        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        self.process_command_output()
        output = self.result_text.get("1.0", tk.END)
        nat_ip = self.find_nat_ip(output, internal_ip)
        self.result_text.insert(tk.END, f"Salida procesada para detección: {output.strip()}\n")  # Depuración completa
        self.result_text.insert(tk.END, f"IP NAT detectada: {nat_ip}\n")  # Depuración
        if not nat_ip:
            messagebox.showinfo("Info", f"No se encontró NAT asignado para {internal_ip}.")
        else:
            messagebox.showinfo("Info", f"NAT encontrado: {internal_ip} -> {nat_ip}")
        return output

    def show_all_nats(self):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        command = "sh ip nat translations\n"
        self.shell.send(command)
        time.sleep(0.5)
        self.process_command_output()

    def add_nat(self):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        nat_ip = self.nat_ip.get()
        if not internal_ip or not nat_ip:
            messagebox.showerror("Error", "Por favor, ingrese tanto la IP interna como la IP NAT.")
            return
        if not self.is_valid_nat_ip(nat_ip):
            messagebox.showerror("Error", "La IP NAT debe estar en el rango 10.200.26.x.")
            return
        self.verify_and_add_modify_nat(internal_ip, nat_ip, is_add=True)

    def modify_nat(self):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        if not internal_ip:
            messagebox.showerror("Error", "Por favor, ingrese una IP interna.")
            return
        self.verify_and_add_modify_nat(internal_ip, None, is_add=False)

    def remove_nat(self):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        internal_ip = self.internal_ip.get()
        if not internal_ip:
            messagebox.showerror("Error", "Por favor, ingrese una IP interna.")
            return
        self.result_text.insert(tk.END, "Verificando NAT existente para eliminación...\n")
        output = self.check_nat()
        nat_ip = self.find_nat_ip(output, internal_ip)
        if internal_ip in output and nat_ip:
            if messagebox.askyesno("Confirmar", f"¿Desea eliminar el NAT de {internal_ip} a {nat_ip}?"):
                self.execute_remove_commands(internal_ip, nat_ip)
            else:
                self.result_text.insert(tk.END, "Eliminación cancelada.\n")
        else:
            messagebox.showinfo("Info", f"No se encontró NAT para {internal_ip}.")

    def verify_and_add_modify_nat(self, internal_ip, initial_nat_ip, is_add):
        if not self.shell or not self.ssh_client:
            messagebox.showerror("Error", "No hay sesión SSH activa. Conéctese primero.")
            return
        self.result_text.insert(tk.END, "Verificando NAT existente...\n")
        output = self.check_nat()
        nat_ip = self.find_nat_ip(output, internal_ip)
        try:
            if internal_ip in output and nat_ip:
                if is_add:
                    messagebox.showerror("Error", f"La IP interna {internal_ip} ya tiene un NAT ({nat_ip}). Use 'Modificar NAT'.")
                    return
                else:
                    if messagebox.askyesno("Confirmar", f"La IP {internal_ip} ya tiene NAT {nat_ip}. ¿Desea cambiarla?"):
                        new_nat_ip = simpledialog.askstring("Nueva IP NAT", "Ingrese la nueva IP NAT (ej. 10.200.26.44):")
                        if new_nat_ip and self.is_valid_nat_ip(new_nat_ip):
                            self.execute_nat_commands(internal_ip, nat_ip, new_nat_ip)
                        else:
                            messagebox.showinfo("Cancelado", "Modificación cancelada o IP NAT inválida.")
                    return
            else:
                if is_add:
                    if initial_nat_ip and self.is_valid_nat_ip(initial_nat_ip):
                        self.execute_nat_commands(internal_ip, None, initial_nat_ip)
                    else:
                        nat_ip = simpledialog.askstring("Nueva IP NAT", "Ingrese la IP NAT (ej. 10.200.26.22):")
                        if nat_ip and self.is_valid_nat_ip(nat_ip):
                            self.execute_nat_commands(internal_ip, None, nat_ip)
                        else:
                            messagebox.showinfo("Cancelado", "Agregado cancelado o IP NAT inválida.")
                else:
                    messagebox.showinfo("Info", f"No se encontró NAT para {internal_ip}. Use 'Agregar NAT'.")
        except Exception as e:
            messagebox.showerror("Error", f"Error en el diálogo: {str(e)}")
            self.result_text.insert(tk.END, f"Error: {str(e)}\n")

    def execute_nat_commands(self, internal_ip, current_nat_ip, new_nat_ip):
        self.result_text.insert(tk.END, "Ejecutando comandos de NAT...\n")
        commands = ["clear ip nat translation *\n", "conf t\n"]
        if current_nat_ip:
            commands.append(f"no ip nat inside source static {internal_ip} {current_nat_ip}\n")
        commands.extend([
            f"ip nat inside source static {internal_ip} {new_nat_ip}\n",
            "ip nat pool ANT 10.200.26.150 10.200.26.250 netmask 255.255.255.0\n",
            "ip nat inside source list 100 pool ANT\n",
            "exit\n", "wr mem\n", "copy running-config startup-config\n"
        ])

        for cmd in commands:
            self.result_text.insert(tk.END, f"Ejecutando: {cmd.strip()}\n")
            self.shell.send(cmd)
            self.wait_for_command_completion()
            self.process_command_output()

        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        self.process_command_output()
        self.highlight_result(internal_ip)

    def execute_remove_commands(self, internal_ip, current_nat_ip):
        self.result_text.insert(tk.END, "Ejecutando comandos para eliminar NAT...\n")
        commands = [
            "clear ip nat translation *\n", "conf t\n",
            f"no ip nat inside source static {internal_ip} {current_nat_ip}\n",
            "ip nat pool ANT 10.200.26.150 10.200.26.250 netmask 255.255.255.0\n",
            "ip nat inside source list 100 pool ANT\n",
            "exit\n", "wr mem\n", "copy running-config startup-config\n"
        ]

        for cmd in commands:
            self.result_text.insert(tk.END, f"Ejecutando: {cmd.strip()}\n")
            self.shell.send(cmd)
            self.wait_for_command_completion()
            self.process_command_output()

        command = f"sh ip nat translations | i {internal_ip}\n"
        self.shell.send(command)
        self.process_command_output()
        self.highlight_result(internal_ip)

    def find_nat_ip(self, output, internal_ip):
        # Depuración: Mostrar la salida procesada
        self.result_text.insert(tk.END, f"Analizando salida: {output.strip()}\n")
        # Patrón para capturar la IP NAT después de la IP interna con separador ---
        pattern = rf"{re.escape(internal_ip)}\s*---+\s*(\d+\.\d+\.\d+\.\d+)"
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            return match.group(1)
        # Patrón genérico si el anterior falla
        pattern = rf"{re.escape(internal_ip)}\s+(\d+\.\d+\.\d+\.\d+)"
        match = re.search(pattern, output, re.MULTILINE)
        return match.group(1) if match else ""

    def is_valid_nat_ip(self, nat_ip):
        pattern = r"^10\.200\.26\.\d{1,3}$"
        return bool(re.match(pattern, nat_ip))

    def wait_for_command_completion(self):
        start_time = time.time()
        while time.time() - start_time < 5:
            if select.select([self.shell], [], [], 0.1)[0]:
                data = self.shell.recv(65535).decode(errors='ignore')
                if "# " in data or "(config)# " in data:
                    return
            time.sleep(0.1)

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