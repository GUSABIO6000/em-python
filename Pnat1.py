#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import atexit
import re
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import os
import sys

import paramiko


class RouterNATManager:
    def __init__(self):
        self.ssh_client = None
        self.shell = None
        self.root = tk.Tk()
        self.root.title("NAT Manager - Completo v4.1 - Corregido")
        self.root.geometry("900x600")
        self.connection_status = "Desconectado"

        # Configurar icono de la ventana
        self.set_window_icon()

        # Cargar logo para la interfaz
        self.load_logo()

        self.setup_gui()
        self.check_connection_periodically()
        self.root.bind("<Return>", self.send_command_from_cli)
        self.root.bind("<Control-space>", self.handle_space_pagination)
        atexit.register(self.cleanup)

    def resource_path(self, relative_path):
        """Obtiene la ruta absoluta del recurso, funciona para dev y para PyInstaller"""
        try:
            # PyInstaller crea una carpeta temporal y almacena la ruta en _MEIPASS
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")

        return os.path.join(base_path, relative_path)

    def set_window_icon(self):
        """Configura el icono de la ventana"""
        try:
            icon_path = self.resource_path("logocalvo.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
            else:
                print(f"Icono no encontrado: {icon_path}")
        except Exception as e:
            print(f"Error al cargar icono: {e}")

    def load_logo(self):
        """Carga el logo para mostrar en la interfaz"""
        try:
            logo_path = self.resource_path("logogus.png")
            if os.path.exists(logo_path):
                # Cargar y redimensionar imagen
                image = Image.open(logo_path)
                # Redimensionar a tamaño apropiado (ajusta según necesites)
                image = image.resize((80, 80), Image.Resampling.LANCZOS)
                self.logo_image = ImageTk.PhotoImage(image)
            else:
                print(f"Logo no encontrado: {logo_path}")
                self.logo_image = None
        except Exception as e:
            print(f"Error al cargar logo: {e}")
            self.logo_image = None

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

        # Frame para NAT con logo
        nat_main_frame = ttk.Frame(self.scrollable_frame)
        nat_main_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew", columnspan=2)

        nat_frame = ttk.LabelFrame(nat_main_frame, text="Gestión de NAT")
        nat_frame.grid(row=0, column=0, padx=0, pady=0, sticky="ew")

        # Agregar logo en la parte derecha del frame NAT
        if self.logo_image:
            logo_label = ttk.Label(nat_main_frame, image=self.logo_image)
            logo_label.grid(row=0, column=1, padx=10, pady=5, sticky="ne")

        # Configurar el grid para que el nat_frame se expanda
        nat_main_frame.grid_columnconfigure(0, weight=1)

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
        ttk.Button(button_frame, text="Limpiar Traducciones", command=self.clear_translations).grid(row=1, column=2,
                                                                                                    padx=5, pady=5)
        ttk.Button(button_frame, text="Cerrar Sesiones", command=self.close_active_sessions).grid(row=2, column=0,
                                                                                                  padx=5, pady=5)
        ttk.Button(button_frame, text="Limpiar Texto", command=self.clear_text).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(button_frame, text="Salir", command=self.safe_exit).grid(row=2, column=2, padx=5, pady=5)

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

        ttk.Button(cli_frame, text="Ejecutar", command=lambda: self.send_command_from_cli(None)).grid(row=0, column=2,
                                                                                                      padx=5)
        ttk.Button(cli_frame, text="Enter", command=self.send_enter).grid(row=0, column=3, padx=2)
        ttk.Button(cli_frame, text="Space", command=self.send_space).grid(row=0, column=4, padx=2)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        result_frame.grid_rowconfigure(0, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)
        cli_frame.grid_columnconfigure(1, weight=1)

        self.log_message("=== NAT Manager Iniciado - Versión Corregida ===")
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
            time.sleep(0.25) #de 1.5 a 0.25
            self.clear_buffer()

            # Configurar terminal para evitar paginación
            self.shell.send("terminal length 0\n")
            time.sleep(0.25) # de 0.8  a 0.25
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

    def send_command(self, command, wait=0.5): # de 1.5 a 0.5
        if self.shell is None:
            self.log_message("No conectado al router.")
            return ""

        self.shell.send(command + "\n")
        time.sleep(wait)
        output = ""
        max_attempts = 4
        attempts = 0

        while attempts < max_attempts:
            if self.shell.recv_ready():
                data = self.shell.recv(65535).decode('utf-8', errors='ignore')
                output += data
                attempts = 0  # Reset counter if we receive data
            else:
                attempts += 1
                time.sleep(0.1) # de 0.15 a 0.1

        return output

    def get_existing_nat(self, internal_ip):
        """Obtiene la IP NAT existente para una IP interna dada"""
        output = self.send_command(f"sh ip nat translations | include {internal_ip}")

        # Parsear la salida para obtener la IP NAT
        lines = output.strip().split('\n')
        for line in lines:
            if internal_ip in line and '---' in line:
                parts = line.split()
                if len(parts) >= 4:
                    nat_ip = parts[1]  # Segunda columna es la IP NAT
                    return nat_ip
        return None

    def check_nat(self):
        internal_ip = self.internal_ip.get().strip()
        if not self.validate_ip(internal_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese una IP interna válida.")
            return

        self.log_message(f"Verificando NAT para IP interna {internal_ip}...")

        # Primero limpiar traducciones dinámicas
        self.send_command("clear ip nat translation *")
        time.sleep(0.25) # de 0.8 a 0.25

        output = self.send_command(f"sh ip nat translations | include {internal_ip}")

        if output.strip():
            lines = output.strip().split('\n')
            for line in lines:
                if internal_ip in line and not line.startswith('RT-EMOV') and '---' in line:
                    self.log_message(f"NAT encontrado: {line.strip()}")
                    existing_nat = self.get_existing_nat(internal_ip)
                    if existing_nat:
                        self.log_message(f"IP NAT actual: {existing_nat}")
                        # Actualizar el campo NAT IP con la IP encontrada
                        self.nat_ip.delete(0, tk.END)
                        self.nat_ip.insert(0, existing_nat)
                    return

        self.log_message("No se encontraron traducciones NAT estáticas para esa IP.")

    def add_nat(self):
        internal_ip = self.internal_ip.get().strip()
        nat_ip = self.nat_ip.get().strip()

        if not self.validate_ip(internal_ip) or not self.validate_ip(nat_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese IPs válidas para interna y NAT.")
            return

        # Verificar si ya existe un NAT para esa IP
        existing_nat = self.get_existing_nat(internal_ip)
        if existing_nat:
            if not messagebox.askyesno("NAT existente",
                                       f"Ya existe un NAT para {internal_ip} -> {existing_nat}\n¿Desea reemplazarlo?"):
                return
            self.remove_nat_by_ips(internal_ip, existing_nat, confirm=False)

        self.log_message(f"Agregando NAT: {internal_ip} -> {nat_ip}...")

        commands = [
            "configure terminal",
            f"ip nat inside source static {internal_ip} {nat_ip}",
            "end",
            "write memory"
        ]

        success = True
        for cmd in commands:
            self.log_message(f"> {cmd}")
            output = self.send_command(cmd, wait=0.25) #de 0.8 a 0.25

            # Verificar si hay errores
            if "Invalid" in output or "Error" in output or "%" in output:
                self.log_message(f"ERROR: {output.strip()}")
                success = False
                break

            time.sleep(0.1) # de 0.3 a 0.1

        if success:
            self.log_message("NAT agregada correctamente.")
            # Verificar que se agregó correctamente
            time.sleep(0.25) # de 0.8 a 0.25
            self.check_nat()
        else:
            self.log_message("Error al agregar NAT.")

    def modify_nat(self):
        internal_ip = self.internal_ip.get().strip()
        new_nat_ip = self.nat_ip.get().strip()

        if not self.validate_ip(internal_ip) or not self.validate_ip(new_nat_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese IPs válidas para interna y NAT.")
            return

        # Obtener NAT existente
        existing_nat = self.get_existing_nat(internal_ip)
        if not existing_nat:
            messagebox.showwarning("NAT no encontrado", f"No existe NAT para la IP interna {internal_ip}")
            return

        if existing_nat == new_nat_ip:
            messagebox.showinfo("Sin cambios", "La IP NAT ya es la misma que desea configurar.")
            return

        self.log_message(f"Modificando NAT para IP interna {internal_ip}: {existing_nat} -> {new_nat_ip}")

        # Eliminar NAT existente
        if self.remove_nat_by_ips(internal_ip, existing_nat, confirm=False):
            time.sleep(0.25) # de 0.8 a 0.25
            # Agregar nuevo NAT
            self.add_nat()
        else:
            self.log_message("Error al modificar NAT - no se pudo eliminar el NAT existente.")

    def remove_nat_by_ips(self, internal_ip, nat_ip, confirm=True):
        """Elimina NAT especificando ambas IPs"""
        if confirm:
            if not messagebox.askyesno("Confirmar eliminación",
                                       f"¿Eliminar NAT {internal_ip} -> {nat_ip}?"):
                return False

        self.log_message(f"Eliminando NAT: {internal_ip} -> {nat_ip}...")

        commands = [
            "configure terminal",
            f"no ip nat inside source static {internal_ip} {nat_ip}",
            "end",
            "write memory"
        ]

        success = True
        for cmd in commands:
            self.log_message(f"> {cmd}")
            output = self.send_command(cmd, wait=0.25) # de 0.8 a 0.25

            # Verificar si hay errores
            if "Invalid" in output or "Error" in output or "%" in output:
                self.log_message(f"ERROR: {output.strip()}")
                success = False
                break

            time.sleep(0.1) # de 0.3 a 0.1

        if success:
            self.log_message("NAT eliminada correctamente.")
        else:
            self.log_message("Error al eliminar NAT.")

        return success

    def remove_nat(self, confirm=True):
        internal_ip = self.internal_ip.get().strip()
        if not self.validate_ip(internal_ip):
            messagebox.showwarning("IP inválida", "Por favor ingrese una IP interna válida.")
            return

        # Obtener NAT existente
        existing_nat = self.get_existing_nat(internal_ip)
        if not existing_nat:
            messagebox.showwarning("NAT no encontrado", f"No existe NAT para la IP interna {internal_ip}")
            return

        self.remove_nat_by_ips(internal_ip, existing_nat, confirm)

    def show_all_nats(self):
        self.log_message("Mostrando todas las traducciones NAT...")

        # Primero limpiar traducciones dinámicas
        self.send_command("clear ip nat translation *")
        time.sleep(0.25) # de 0.8 a 0.25

        output = self.send_command("sh ip nat translations", wait=1.0) # de 2.5 a 1.0

        if output.strip():
            lines = output.strip().split('\n')
            static_found = False
            for line in lines:
                if '---' in line and not line.startswith('RT-EMOV'):
                    self.log_message(f"NAT estático: {line.strip()}")
                    static_found = True

            if not static_found:
                self.log_message("No se encontraron traducciones NAT estáticas.")
        else:
            self.log_message("No se encontraron traducciones NAT.")

    def clear_translations(self):
        if not messagebox.askyesno("Confirmar limpieza", "¿Limpiar todas las traducciones NAT dinámicas?"):
            return

        self.log_message("Limpiando todas las traducciones NAT dinámicas...")

        output = self.send_command("clear ip nat translation *")
        self.log_message("Traducciones NAT dinámicas limpiadas.")

    def close_active_sessions(self):
        """Cierra las sesiones activas del router con manejo mejorado de sesiones"""
        if self.shell is None:
            messagebox.showwarning("No conectado", "No hay conexión activa al router.")
            return

        self.log_message("Obteniendo lista de sesiones activas...")

        # Obtener lista de usuarios conectados
        output = self.send_command("show users", wait=0.5) # de 1.5 a 0.5

        if not output.strip():
            self.log_message("No se pudo obtener información de usuarios.")
            return

        self.log_message("=== SESIONES ACTIVAS ===")
        self.log_message(output.strip())
        self.log_message("========================")

        # Parsear la salida para encontrar sesiones activas
        lines = output.strip().split('\n')
        current_session = None
        other_sessions = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('Line') or line.startswith('RT-EMOV'):
                continue

            # Buscar líneas que contengan información de sesiones
            if 'vty' in line.lower() or 'con' in line.lower():
                # Verificar si es la sesión actual (marcada con *)
                if line.startswith('*'):
                    # Extraer información de la sesión actual
                    parts = line.split()
                    if len(parts) >= 2:
                        session_line = parts[1]  # Línea de la sesión (ej: vty 0)
                        current_session = session_line
                        self.log_message(f"Sesión actual detectada: {session_line}")
                else:
                    # Sesión de otros usuarios
                    parts = line.split()
                    if len(parts) >= 2:
                        session_line = parts[1]  # Línea de la sesión
                        other_sessions.append(session_line)
                        self.log_message(f"Otra sesión detectada: {session_line}")

        # Manejar diferentes escenarios
        if not current_session and not other_sessions:
            self.log_message("No se pudieron identificar sesiones activas.")
            return

        if other_sessions:
            # Hay otras sesiones además de la actual
            session_list = "\n".join([f"- {session}" for session in other_sessions])
            message = f"Se encontraron {len(other_sessions)} sesiones adicionales:\n{session_list}\n\n¿Desea cerrar estas sesiones?"

            if messagebox.askyesno("Cerrar sesiones adicionales", message):
                self.log_message(f"Cerrando {len(other_sessions)} sesiones adicionales...")

                for session in other_sessions:
                    self.log_message(f"Cerrando sesión: {session}")
                    # Extraer solo el número de la línea VTY
                    if 'vty' in session.lower():
                        vty_num = session.split()[-1]  # Último elemento debería ser el número
                        output = self.send_command(f"clear line {session}", wait=1)
                        self.log_message(f"Resultado: {output.strip()}")
                        time.sleep(0.1) # de 0.3 a 0.1

                # Verificar sesiones restantes
                time.sleep(0.25) # de 1.5 a 0.25
                self.log_message("Verificando sesiones restantes...")
                final_output = self.send_command("show users", wait=0.25) # de 1.5 a 0.25
                self.log_message("=== SESIONES DESPUÉS DEL CIERRE ===")
                self.log_message(final_output.strip())
        else:
            # Solo hay la sesión actual
            if current_session:
                message = f"Solo se detectó su sesión actual: {current_session}\n\n"
                message += "¿Desea cerrar su propia sesión?\n\n"
                message += "ADVERTENCIA: Esto cerrará su conexión actual.\n"
                message += "Puede reconectarse usando el botón 'Conectar'."

                if messagebox.askyesno("Cerrar sesión actual", message):
                    self.log_message(f"Cerrando sesión actual: {current_session}")
                    self.log_message("ADVERTENCIA: La conexión se cerrará en 3 segundos...")

                    # Dar tiempo al usuario para ver el mensaje
                    time.sleep(1)
                    self.log_message("Cerrando en 2 segundos...")
                    time.sleep(1)
                    self.log_message("Cerrando en 1 segundo...")
                    time.sleep(1)

                    # Cerrar la sesión actual
                    try:
                        if 'vty' in current_session.lower():
                            vty_num = current_session.split()[-1]
                            self.send_command(f"clear line {current_session}", wait=0.25) # de 0.8 a 0.25

                        # La conexión se cerrará automáticamente
                        self.log_message("Sesión cerrada. Puede reconectarse usando el botón 'Conectar'.")
                        self.connection_status = "Desconectado"
                        self.update_status_label()

                        # Limpiar conexión
                        self.cleanup()

                    except Exception as e:
                        self.log_message(f"Error al cerrar sesión: {str(e)}")
                        self.connection_status = "Desconectado"
                        self.update_status_label()
                        self.cleanup()
            else:
                self.log_message("No se detectaron sesiones adicionales para cerrar.")

    def send_enter(self):
        """Envía un ENTER al router"""
        if self.shell is None:
            messagebox.showwarning("No conectado", "No hay conexión activa al router.")
            return

        self.log_message("Enviando ENTER...")
        self.shell.send("\n")
        time.sleep(0.25) # de 0.8 a 0.25

        # Capturar cualquier salida adicional
        output = ""
        attempts = 0
        while attempts < 3:
            if self.shell.recv_ready():
                data = self.shell.recv(4096).decode('utf-8', errors='ignore')
                output += data
                attempts = 0
            else:
                attempts += 1
                time.sleep(0.25)

        if output.strip():
            self.log_message(output.strip())

    def send_space(self):
        """Envía un ESPACIO al router (útil para paginación --More--)"""
        if self.shell is None:
            messagebox.showwarning("No conectado", "No hay conexión activa al router.")
            return

        self.log_message("Enviando ESPACIO...")
        self.shell.send(" ")
        time.sleep(0.25) # de 0.8a 0.25

        # Capturar cualquier salida adicional
        output = ""
        attempts = 0
        while attempts < 5:
            if self.shell.recv_ready():
                data = self.shell.recv(4096).decode('utf-8', errors='ignore')
                output += data
                attempts = 0
            else:
                attempts += 1
                time.sleep(0.25)

        if output.strip():
            self.log_message(output.strip())

    def safe_exit(self):
        """Cierra la aplicación de forma segura"""
        if messagebox.askyesno("Confirmar salida", "¿Está seguro de que desea salir de la aplicación?"):
            self.log_message("Cerrando aplicación...")
            self.cleanup()
            self.root.quit()
            self.root.destroy()

    def clear_text(self):
        self.result_text.delete("1.0", tk.END)
        self.log_message("=== Texto limpiado ===")

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
        output = self.send_command(command, wait=0.5) # de 1.5 a 0.5

        if output.strip():
            self.log_message(output.strip())
        else:
            self.log_message("Comando ejecutado (sin salida visible)")

        # Enviar ENTER adicional para asegurar que se complete el comando
        self.shell.send("\n")
        time.sleep(0.1) # de 0.25 a 0.1

        # Capturar cualquier salida adicional después del ENTER
        additional_output = ""
        attempts = 0
        while attempts < 3:
            if self.shell.recv_ready():
                data = self.shell.recv(4096).decode('utf-8', errors='ignore')
                additional_output += data
                attempts = 0
            else:
                attempts += 1
                time.sleep(0.1) # de 0.25 a 0.1

        if additional_output.strip():
            self.log_message(additional_output.strip())

        # Limpiar el campo CLI
        self.cli_entry.delete(0, tk.END)
        self.cli_entry.insert(0, "Ingrese comando CLI (ej: sh ip nat translations)")

    def handle_space_pagination(self, event):
        # Para manejo futuro de paginación, si el router responde con '--More--'
        if self.shell:
            self.shell.send(" ")

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
        try:
            if self.shell:
                self.shell.close()
            if self.ssh_client:
                self.ssh_client.close()
            self.log_message("Sesión SSH cerrada y aplicación terminada.")
        except Exception as e:
            print(f"Error durante cleanup: {e}")

    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.cleanup()
        except Exception as e:
            print(f"Error en la aplicación: {e}")
            self.cleanup()


if __name__ == '__main__':
    app = RouterNATManager()
    app.run()