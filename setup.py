#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup
import sys

# Configuración común
APP_NAME = 'RouterNATManager'
VERSION = '4.1'
DESCRIPTION = 'Gestor de NAT para routers Cisco'
AUTHOR = 'Tu Nombre'

# Archivos adicionales a incluir
data_files = [
    ('', ['logocalvo.ico', 'logogus.png']),  # Incluir iconos en el directorio raíz
]

# Configuración específica para cada plataforma
if sys.platform == 'win32':
    # Configuración para Windows con py2exe
    import py2exe

    setup(
        name=APP_NAME,
        version=VERSION,
        description=DESCRIPTION,
        author=AUTHOR,
        windows=[{
            'script': 'router_nat_manager.py',  # Tu archivo principal
            'icon_resources': [(1, 'logocalvo.ico')],
            'dest_base': APP_NAME
        }],
        data_files=data_files,
        options={
            'py2exe': {
                'bundle_files': 1,  # Todo en un solo archivo
                'compressed': True,
                'optimize': 2,
                'includes': ['tkinter', 'PIL', 'paramiko', 'threading', 'datetime', 're'],
                'excludes': ['_tkinter', 'tcl', 'tk'],
                'dll_excludes': ['w9xpopen.exe']
            }
        },
        zipfile=None,
    )

elif sys.platform.startswith('linux'):
    # Configuración para Linux con cx_Freeze
    from cx_Freeze import setup, Executable

    build_exe_options = {
        'packages': ['tkinter', 'PIL', 'paramiko', 'threading', 'datetime', 're'],
        'include_files': data_files,
        'optimize': 2,
        'excludes': ['test', 'unittest', 'pdb', 'doctest'],
    }

    setup(
        name=APP_NAME,
        version=VERSION,
        description=DESCRIPTION,
        author=AUTHOR,
        options={'build_exe': build_exe_options},
        executables=[Executable(
            'router_nat_manager.py',
            base='Win32GUI' if sys.platform == 'win32' else None,
            target_name=APP_NAME,
            icon='logocalvo.ico'
        )]
    )
else:
    # Configuración básica para otros sistemas
    setup(
        name=APP_NAME,
        version=VERSION,
        description=DESCRIPTION,
        author=AUTHOR,
        py_modules=['router_nat_manager'],
        data_files=data_files,
    )