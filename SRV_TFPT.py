import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import os
import socket
import configparser
import threading
import webbrowser
import platform
import time
from functools import partial


class ServerConfigApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Configurador Avanzado de Servidores")
        self.root.geometry("1000x750")

        # Variables de configuración
        self.server_ip = tk.StringVar(value=self.get_local_ip())
        self.tftp_port = tk.StringVar(value="69")
        self.ftp_port = tk.StringVar(value="21")
        self.http_port = tk.StringVar(value="80")
        self.https_port = tk.StringVar(value="443")
        self.server_type = tk.StringVar(value="Apache")
        self.server_status = tk.StringVar(value="Detenido")
        self.document_root = tk.StringVar(value=os.path.expanduser("~/server_files"))
        self.enable_https = tk.BooleanVar(value=False)
        self.allowed_extensions = tk.StringVar(value="*")  # Todos los archivos por defecto
        self.current_processes = {}  # Para manejar los procesos de los servidores

        self.create_ui()
        self.load_config()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def create_ui(self):
        # Notebook para pestañas
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Pestañas
        tabs = {
            "config": ttk.Frame(self.notebook),
            "status": ttk.Frame(self.notebook),
            "transfer": ttk.Frame(self.notebook),
            "help": ttk.Frame(self.notebook)
        }

        for name, frame in tabs.items():
            self.notebook.add(frame, text=name.capitalize())

        # Crear contenido de las pestañas
        self.create_config_tab(tabs["config"])
        self.create_status_tab(tabs["status"])
        self.create_transfer_tab(tabs["transfer"])
        self.create_help_tab(tabs["help"])

    def create_config_tab(self, parent):
        # Frame principal con scroll
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configuración de red
        network_frame = ttk.LabelFrame(scrollable_frame, text="Configuración de Red")
        network_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(network_frame, text="IP del Servidor:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(network_frame, textvariable=self.server_ip).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)

        # Configuración de servidores
        server_frame = ttk.LabelFrame(scrollable_frame, text="Configuración de Servidores")
        server_frame.pack(fill=tk.X, padx=5, pady=5)

        # Tipo de servidor
        ttk.Label(server_frame, text="Tipo de Servidor:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        server_types = ["Apache", "TFTP", "FTP", "Todos"]
        ttk.Combobox(server_frame, textvariable=self.server_type, values=server_types, state="readonly").grid(row=0,
                                                                                                              column=1,
                                                                                                              sticky=tk.EW,
                                                                                                              padx=5,
                                                                                                              pady=2)

        # Puertos
        ports_frame = ttk.Frame(server_frame)
        ports_frame.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=5)

        ttk.Label(ports_frame, text="Puerto TFTP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ports_frame, textvariable=self.tftp_port, width=10).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(ports_frame, text="Puerto FTP:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ports_frame, textvariable=self.ftp_port, width=10).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)

        ttk.Label(ports_frame, text="Puerto HTTP:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ports_frame, textvariable=self.http_port, width=10).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(ports_frame, text="Puerto HTTPS:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ports_frame, textvariable=self.https_port, width=10).grid(row=1, column=3, sticky=tk.W, padx=5,
                                                                            pady=2)

        ttk.Checkbutton(ports_frame, text="Habilitar HTTPS", variable=self.enable_https).grid(row=2, column=0,
                                                                                              columnspan=4, sticky=tk.W,
                                                                                              padx=5, pady=2)

        # Directorio raíz y tipos de archivo
        dir_frame = ttk.Frame(server_frame)
        dir_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=5)

        ttk.Label(dir_frame, text="Directorio Raíz:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(dir_frame, textvariable=self.document_root).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(dir_frame, text="Examinar...", command=self.browse_directory).grid(row=0, column=2, padx=5, pady=2)

        ttk.Label(dir_frame, text="Extensiones permitidas:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(dir_frame, textvariable=self.allowed_extensions).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(dir_frame, text="Todos", command=lambda: self.allowed_extensions.set("*")).grid(row=1, column=2,
                                                                                                   padx=5, pady=2)

        # Botones de control
        control_frame = ttk.Frame(scrollable_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=10)

        ttk.Button(control_frame, text="Guardar Configuración", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Iniciar Servidor", command=self.start_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Detener Servidor", command=self.stop_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Restablecer", command=self.reset_config).pack(side=tk.LEFT, padx=5)

    def create_status_tab(self, parent):
        # Estado del servidor
        status_frame = ttk.LabelFrame(parent, text="Estado del Servidor")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(status_frame, text="Estado:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.status_label = ttk.Label(status_frame, textvariable=self.server_status)
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        # Actualizar color según estado
        self.server_status.trace_add("write", self.update_status_color)

        # Logs del servidor
        log_frame = ttk.LabelFrame(parent, text="Registros del Servidor")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Botones de logs
        log_buttons = ttk.Frame(parent)
        log_buttons.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(log_buttons, text="Limpiar Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_buttons, text="Exportar Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)

    def create_transfer_tab(self, parent):
        # Configuración de transferencia
        transfer_frame = ttk.LabelFrame(parent, text="Transferencia de Archivos")
        transfer_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Panel de archivos
        file_frame = ttk.Frame(transfer_frame)
        file_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Árbol de archivos
        self.file_tree = ttk.Treeview(file_frame, columns=("name", "size", "modified"), selectmode="browse")
        self.file_tree.heading("#0", text="Directorio")
        self.file_tree.heading("name", text="Nombre")
        self.file_tree.heading("size", text="Tamaño")
        self.file_tree.heading("modified", text="Modificado")

        scrollbar = ttk.Scrollbar(file_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scrollbar.set)

        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Configurar doble clic para abrir archivos
        self.file_tree.bind("<Double-1>", self.on_file_double_click)

        # Botones de transferencia
        button_frame = ttk.Frame(transfer_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(button_frame, text="Subir Archivo", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Descargar Archivo", command=self.download_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Actualizar Lista", command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Abrir en Navegador", command=self.open_in_browser).pack(side=tk.RIGHT, padx=5)

    def create_help_tab(self, parent):
        # Pestaña de ayuda con información detallada
        help_notebook = ttk.Notebook(parent)
        help_notebook.pack(fill=tk.BOTH, expand=True)

        # Secciones de ayuda
        help_sections = {
            "Apache": self.get_apache_help(),
            "TFTP": self.get_tftp_help(),
            "FTP": self.get_ftp_help()
        }

        for section, content in help_sections.items():
            frame = ttk.Frame(help_notebook)
            help_notebook.add(frame, text=section)

            text = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
            text.insert(tk.INSERT, content)
            text.configure(state='disabled')
            text.pack(fill=tk.BOTH, expand=True)

    def get_apache_help(self):
        return """Configuración de Servidor Apache:

1. Directorio Raíz: Establece la ubicación de los archivos web (HTML, PHP, etc.)
2. Puerto HTTP: Normalmente 80, pero puedes cambiarlo si 80 está ocupado
3. Puerto HTTPS: Normalmente 443, requiere certificado SSL

Pasos para configurar:
1. Establece el directorio raíz donde estarán tus archivos web
2. Configura los puertos HTTP/HTTPS según necesites
3. Marca 'Habilitar HTTPS' si quieres soporte para conexiones seguras
4. Guarda la configuración
5. Inicia el servidor

Una vez iniciado, accede desde:
- http://[tu-ip]:[puerto-http]
- https://[tu-ip]:[puerto-https] (si habilitaste HTTPS)
"""

    def get_tftp_help(self):
        return """Configuración de Servidor TFTP:

1. Puerto TFTP: Normalmente 69, usado para transferencia de archivos pequeños
2. Directorio Raíz: Donde se almacenarán/leerán los archivos
3. Extensiones: Especifica qué tipos de archivos permitir (ej: .bin,.cfg)

Pasos para configurar:
1. Establece el directorio raíz para los archivos TFTP
2. Configura el puerto (69 por defecto)
3. Especifica extensiones permitidas (para actualización de teléfonos IP)
4. Guarda la configuración
5. Inicia el servidor

Uso típico para teléfonos IP:
1. Coloca los archivos de firmware en el directorio raíz
2. Configura el teléfono para buscar actualizaciones via TFTP
3. El teléfono descargará los archivos necesarios
"""

    def get_ftp_help(self):
        return """Configuración de Servidor FTP:

1. Puerto FTP: Normalmente 21, usado para transferencia de archivos
2. Directorio Raíz: Directorio base para las transferencias
3. Extensiones: Filtra tipos de archivos permitidos

Pasos para configurar:
1. Establece el directorio raíz para FTP
2. Configura el puerto (21 por defecto)
3. Especifica extensiones permitidas
4. Guarda la configuración
5. Inicia el servidor

Acceso desde cliente FTP:
- Usa cualquier cliente FTP (FileZilla, WinSCP)
- Conéctate a tu IP con el puerto configurado
- Usuario/anónimo según configuración
"""

    def update_status_color(self, *args):
        status = self.server_status.get()
        if status == "En ejecución":
            self.status_label.config(foreground="green")
        elif status == "Detenido":
            self.status_label.config(foreground="red")
        else:
            self.status_label.config(foreground="orange")

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.document_root.set(directory)
            self.refresh_file_list()

    def save_config(self):
        config = configparser.ConfigParser()
        config['NETWORK'] = {
            'server_ip': self.server_ip.get(),
            'tftp_port': self.tftp_port.get(),
            'ftp_port': self.ftp_port.get(),
            'http_port': self.http_port.get(),
            'https_port': self.https_port.get()
        }

        config['SERVER'] = {
            'server_type': self.server_type.get(),
            'document_root': self.document_root.get(),
            'enable_https': str(self.enable_https.get()),
            'allowed_extensions': self.allowed_extensions.get()
        }

        try:
            with open('server_config.ini', 'w') as configfile:
                config.write(configfile)
            self.log("Configuración guardada correctamente.")
            messagebox.showinfo("Éxito", "Configuración guardada correctamente.")
        except Exception as e:
            self.log(f"Error al guardar configuración: {str(e)}")
            messagebox.showerror("Error", f"No se pudo guardar la configuración: {str(e)}")

    def load_config(self):
        if os.path.exists('server_config.ini'):
            config = configparser.ConfigParser()
            config.read('server_config.ini')

            try:
                self.server_ip.set(config['NETWORK']['server_ip'])
                self.tftp_port.set(config['NETWORK']['tftp_port'])
                self.ftp_port.set(config['NETWORK']['ftp_port'])
                self.http_port.set(config['NETWORK']['http_port'])
                self.https_port.set(config['NETWORK']['https_port'])

                self.server_type.set(config['SERVER']['server_type'])
                self.document_root.set(config['SERVER']['document_root'])
                self.enable_https.set(config['SERVER'].getboolean('enable_https'))
                self.allowed_extensions.set(config['SERVER'].get('allowed_extensions', '*'))

                self.log("Configuración cargada correctamente.")
                self.refresh_file_list()
            except Exception as e:
                self.log(f"Error al cargar configuración: {str(e)}")

    def reset_config(self):
        self.server_ip.set(self.get_local_ip())
        self.tftp_port.set("69")
        self.ftp_port.set("21")
        self.http_port.set("80")
        self.https_port.set("443")
        self.server_type.set("Apache")
        self.document_root.set(os.path.expanduser("~/server_files"))
        self.enable_https.set(False)
        self.allowed_extensions.set("*")
        self.log("Configuración restablecida a valores predeterminados.")
        self.refresh_file_list()

    def start_server(self):
        server_type = self.server_type.get()
        self.server_status.set("Iniciando...")

        try:
            # Crear directorio si no existe
            if not os.path.exists(self.document_root.get()):
                os.makedirs(self.document_root.get())
                self.log(f"Directorio {self.document_root.get()} creado.")

            # Detener servidores si ya están corriendo
            self.stop_server(quiet=True)

            # Iniciar servidor según tipo
            if server_type in ["Apache", "Todos"]:
                self.start_apache()

            if server_type in ["TFTP", "Todos"]:
                self.start_tftp()

            if server_type in ["FTP", "Todos"]:
                self.start_ftp()

            self.server_status.set("En ejecución")
            self.log(f"Servidor {server_type} iniciado correctamente en {self.server_ip.get()}")
            messagebox.showinfo("Éxito", f"Servidor {server_type} iniciado correctamente.")
        except Exception as e:
            self.server_status.set("Error")
            self.log(f"Error al iniciar servidor: {str(e)}")
            messagebox.showerror("Error", f"No se pudo iniciar el servidor: {str(e)}")

    def stop_server(self, quiet=False):
        server_type = self.server_type.get()
        self.server_status.set("Deteniendo...")

        try:
            if server_type in ["Apache", "Todos"]:
                self.stop_apache()

            if server_type in ["TFTP", "Todos"]:
                self.stop_tftp()

            if server_type in ["FTP", "Todos"]:
                self.stop_ftp()

            self.server_status.set("Detenido")
            if not quiet:
                self.log(f"Servidor {server_type} detenido correctamente.")
                messagebox.showinfo("Éxito", f"Servidor {server_type} detenido correctamente.")
        except Exception as e:
            self.server_status.set("Error")
            self.log(f"Error al detener servidor: {str(e)}")
            if not quiet:
                messagebox.showerror("Error", f"No se pudo detener el servidor: {str(e)}")

    def start_apache(self):
        system = platform.system()
        try:
            if system == "Linux":
                cmd = ["sudo", "service", "apache2", "start"]
            elif system == "Windows":
                apache_path = self.find_apache_path()
                if apache_path:
                    cmd = [os.path.join(apache_path, "bin", "httpd.exe"), "-k", "start"]
                else:
                    raise Exception("No se encontró Apache instalado en Windows")

            self.current_processes['apache'] = subprocess.Popen(cmd)
            self.log(f"Apache iniciado en {system}")
        except Exception as e:
            self.log(f"Error al iniciar Apache: {str(e)}")
            raise

    def stop_apache(self):
        if 'apache' in self.current_processes:
            try:
                system = platform.system()
                if system == "Linux":
                    subprocess.run(["sudo", "service", "apache2", "stop"])
                elif system == "Windows":
                    apache_path = self.find_apache_path()
                    if apache_path:
                        subprocess.run([os.path.join(apache_path, "bin", "httpd.exe"), "-k", "stop"])

                self.current_processes['apache'].terminate()
                self.current_processes.pop('apache', None)
                self.log("Apache detenido")
            except Exception as e:
                self.log(f"Error al detener Apache: {str(e)}")
                raise

    def find_apache_path(self):
        # Buscar la instalación de Apache en Windows
        possible_paths = [
            "C:\\Apache24",
            "C:\\Program Files\\Apache Software Foundation\\Apache2.4",
            "C:\\Program Files (x86)\\Apache Software Foundation\\Apache2.4"
        ]

        for path in possible_paths:
            if os.path.exists(os.path.join(path, "bin", "httpd.exe")):
                return path
        return None

    def start_tftp(self):
        try:
            # Simulación de servidor TFTP (en producción usar un servidor real)
            self.log(f"Servidor TFTP simulado iniciado en {self.server_ip.get()}:{self.tftp_port.get()}")
            self.log("NOTA: Esta es una simulación. Para un servidor TFTP real, instala un paquete como tftpy")
        except Exception as e:
            self.log(f"Error al iniciar TFTP: {str(e)}")
            raise

    def stop_tftp(self):
        self.log("Servidor TFTP detenido")

    def start_ftp(self):
        try:
            # Simulación de servidor FTP (en producción usar un servidor real)
            self.log(f"Servidor FTP simulado iniciado en {self.server_ip.get()}:{self.ftp_port.get()}")
            self.log("NOTA: Esta es una simulación. Para un servidor FTP real, instala un paquete como pyftpdlib")
        except Exception as e:
            self.log(f"Error al iniciar FTP: {str(e)}")
            raise

    def stop_ftp(self):
        self.log("Servidor FTP detenido")

    def upload_file(self):
        file_types = []
        allowed_ext = self.allowed_extensions.get()

        if allowed_ext == "*":
            file_types = [("Todos los archivos", "*.*")]
        else:
            extensions = [ext.strip() for ext in allowed_ext.split(",") if ext.strip()]
            if extensions:
                file_types = [(f"Archivos {ext}", f"*{ext}") for ext in extensions]
                file_types.insert(0, ("Todos los archivos permitidos", ";".join(f"*{ext}" for ext in extensions)))

        file_path = filedialog.askopenfilename(filetypes=file_types)
        if file_path:
            try:
                dest_path = os.path.join(self.document_root.get(), os.path.basename(file_path))

                # Verificar extensión permitida
                if self.allowed_extensions.get() != "*":
                    ext = os.path.splitext(file_path)[1].lower()
                    allowed_exts = [e.strip().lower() for e in self.allowed_extensions.get().split(",")]
                    if ext not in allowed_exts:
                        raise Exception(f"Tipo de archivo {ext} no permitido")

                # Copiar archivo al directorio del servidor
                import shutil
                shutil.copy2(file_path, dest_path)

                self.log(f"Archivo {os.path.basename(file_path)} subido correctamente.")
                self.refresh_file_list()
                messagebox.showinfo("Éxito", "Archivo subido correctamente.")
            except Exception as e:
                self.log(f"Error al subir archivo: {str(e)}")
                messagebox.showerror("Error", f"No se pudo subir el archivo: {str(e)}")

    def download_file(self):
        selected_item = self.file_tree.selection()
        if selected_item:
            file_name = self.file_tree.item(selected_item)['values'][0]
            file_path = os.path.join(self.document_root.get(), file_name)

            dest_path = filedialog.asksaveasfilename(initialfile=file_name)

            if dest_path:
                try:
                    import shutil
                    shutil.copy2(file_path, dest_path)
                    self.log(f"Archivo {file_name} descargado correctamente.")
                    messagebox.showinfo("Éxito", "Archivo descargado correctamente.")
                except Exception as e:
                    self.log(f"Error al descargar archivo: {str(e)}")
                    messagebox.showerror("Error", f"No se pudo descargar el archivo: {str(e)}")

    def on_file_double_click(self, event):
        selected_item = self.file_tree.selection()
        if selected_item:
            file_name = self.file_tree.item(selected_item)['values'][0]
            file_path = os.path.join(self.document_root.get(), file_name)

            if os.path.isfile(file_path):
                try:
                    os.startfile(file_path)
                except:
                    self.log(f"No se pudo abrir el archivo {file_name}")

    def refresh_file_list(self):
        self.file_tree.delete(*self.file_tree.get_children())
        try:
            doc_root = self.document_root.get()
            if os.path.exists(doc_root):
                for item in os.listdir(doc_root):
                    item_path = os.path.join(doc_root, item)
                    if os.path.isfile(item_path):
                        size = os.path.getsize(item_path)
                        modified = os.path.getmtime(item_path)
                        self.file_tree.insert("", "end", text=doc_root,
                                              values=(item, self.format_size(size), self.format_time(modified)))
        except Exception as e:
            self.log(f"Error al actualizar lista de archivos: {str(e)}")

    def open_in_browser(self):
        url = f"http://{self.server_ip.get()}:{self.http_port.get()}"
        webbrowser.open_new_tab(url)

    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)

    def export_logs(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log("Registros exportados correctamente.")
            except Exception as e:
                self.log(f"Error al exportar registros: {str(e)}")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    @staticmethod
    def format_size(size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    @staticmethod
    def format_time(timestamp):
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerConfigApp(root)
    root.mainloop()