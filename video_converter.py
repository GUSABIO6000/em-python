import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import os
import platform

import self


class VideoConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Conversor de Videos AnyDesk/MP4")
        self.root.geometry("500x300")

        # Variables
        self.input_file = ""
        self.output_format = tk.StringVar(value="mp4")

        # Verificar FFmpeg al inicio
        self.ffmpeg_available = self.check_ffmpeg()
        if not self.ffmpeg_available:
            messagebox.showerror("Error",
                                 "FFmpeg no está instalado o no está en el PATH.\nDescárgalo de https://ffmpeg.org/")

        # Interfaz
        self.create_widgets()

    def check_ffmpeg(self):
        try:
            subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    def create_widgets(self):
        # Frame principal
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True, fill=tk.BOTH)

        # Botón para seleccionar archivo
        tk.Label(frame, text="Selecciona un video:").pack(pady=5)
        tk.Button(frame, text="Buscar archivo", command=self.browse_file).pack(pady=5)

        # Mostrar archivo seleccionado
        self.file_label = tk.Label(frame, text="Ningún archivo seleccionado", wraplength=400)
        self.file_label.pack(pady=5)

        # Selección de formato de salida
        tk.Label(frame, text="Formato de salida:").pack(pady=5)
        formats = ["mp4", "avi", "mov", "mkv", "flv", "wmv"]
        format_menu = ttk.Combobox(frame, textvariable=self.output_format, values=formats)
        format_menu.pack(pady=5)

        # Botón de conversión
        self.convert_btn = tk.Button(frame, text="Convertir Video", command=self.convert_video, bg="green", fg="white")
        self.convert_btn.pack(pady=20)

        # Barra de progreso
        self.progress = ttk.Progressbar(frame, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=5)

        # Deshabilitar botón si FFmpeg no está disponible
        if not self.ffmpeg_available:
            self.convert_btn.config(state=tk.DISABLED)

    def browse_file(self):
        self.input_file = filedialog.askopenfilename(
            title="Selecciona un video",
            filetypes=[("Videos AnyDesk", "*.anydesk"), ("Videos", "*.mp4 *.avi *.mov *.mkv *.flv *.wmv"),
                       ("Todos los archivos", "*.*")]
        )
        if self.input_file:
            self.file_label.config(text=f"Archivo seleccionado: {os.path.basename(self.input_file)}")
            # Verificar si el archivo existe realmente
            if not os.path.exists(self.input_file):
                messagebox.showerror("Error", "El archivo seleccionado no existe en la ubicación especificada.")
                self.input_file = ""
                self.file_label.config(text="Ningún archivo seleccionado")

    def convert_video(self):
        if not self.input_file:
            messagebox.showerror("Error", "¡Selecciona un archivo primero!")
            return

        if not os.path.exists(self.input_file):
            messagebox.showerror("Error", "El archivo de entrada ya no existe en la ubicación especificada.")
            return

        output_format = self.output_format.get()
        output_file = filedialog.asksaveasfilename(
            title="Guardar video como...",
            defaultextension=f".{output_format}",
            filetypes=[(f"Video {output_format.upper()}", f"*.{output_format}")]
        )

        if not output_file:
            return  # El usuario canceló

        try:
            # Comando FFmpeg para conversión
            command = [
                "ffmpeg",
                "-i", self.input_file,
                "-c:v", "libx264",
                "-crf", "23",
                "-preset", "fast",
                "-c:a", "aac",
                "-b:a", "192k",
                output_file
            ]

            self.progress["value"] = 20
            self.root.update()

            # Ejecutar FFmpeg mostrando la consola para ver errores
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                shell=(platform.system() == "Windows")  # Necesario en Windows para PATH
            )

            # Leer salida en tiempo real para progreso
            while True:
                output = process.stderr.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())  # Para depuración
                    # Aquí podrías analizar la salida para actualizar la barra de progreso

            self.progress["value"] = 100
            self.root.update()
            if self.input_file.endswith('.anydesk'):
                messagebox.showerror("Error",
                                     "Los archivos .anydesk no son videos estándar. "
                                     "Conviértelos primero desde AnyDesk usando la opción 'Export'.")
                return
            if process.returncode == 0:
                messagebox.showinfo("Éxito", f"¡Video convertido a {output_format.upper()} con éxito!")
            else:
                messagebox.showerror("Error",
                                     "Error al convertir el video. Verifica que el archivo de entrada sea un video válido.")

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo convertir el video:\n{str(e)}")
        finally:
            self.progress["value"] = 0


if __name__ == "__main__":
    root = tk.Tk()
    app = VideoConverterApp(root)
    root.mainloop()