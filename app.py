#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Herramienta de Análisis de Archivos .so
# Autor: Jamil Rodriguez
# Propósito: Esta herramienta busca posibles endpoints de API, direcciones IP, 
# correos electrónicos, credenciales y rutas locales en archivos binarios .so.
# Versión: 1.0
# Año: 2024
# -------------------------------------------------------------------------------
import re
import os
import time
from colorama import Fore, Style, init

init(autoreset=True)
class SOAnalyzer:
    def __init__(self, file_path, min_string_length=4, chunk_size=1024*1024):
        self.file_path = file_path
        self.min_string_length = min_string_length
        self.chunk_size = chunk_size
        self.results = {}

    def extract_strings(self):
        """
        Extrae cadenas legibles del archivo binario .so.
        :return: Lista de cadenas extraídas.
        """
        strings = []
        try:
            with open(self.file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    strings += re.findall(b'[\x20-\x7E]{%d,}' % self.min_string_length, chunk)
            print(Fore.GREEN + "Cadenas extraídas correctamente.")
        except FileNotFoundError:
            print(Fore.RED + f"El archivo {self.file_path} no fue encontrado.")
        except PermissionError:
            print(Fore.RED + f"No tienes permiso para leer el archivo {self.file_path}.")
        except OSError as e:
            print(Fore.RED + f"Error al leer el archivo: {e}")
        return [s.decode('utf-8', errors='ignore') for s in strings]

    def search_patterns(self, strings):
        """
        Busca patrones relacionados con redes o APIs, direcciones IP, emails y credenciales dentro de las cadenas extraídas.
        :param strings: Lista de cadenas extraídas del archivo.
        :return: Diccionario con resultados encontrados.
        """
        patterns = {
            'URLs': re.compile(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', re.IGNORECASE),
            'IPs': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'Emails': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b'),
            'Credentials': re.compile(r'\b(?:token|Bearer|JWT|password|passwd|auth|key|apikey|secret|credentials)\b', re.IGNORECASE),
            'Database': re.compile(r'\b(?:db|database|connection|conn|host|port)\b', re.IGNORECASE),
            'FilePaths': re.compile(r'(\/[A-Za-z0-9._%+-\/]+)')
        }

        self.results = {key: set() for key in patterns.keys()}
        
        for s in strings:
            for key, pattern in patterns.items():
                found_items = pattern.findall(s)
                if found_items:
                    self.results[key].update(found_items)

        return self.results

    def save_results_to_file(self):
        if not any(self.results.values()):
            print(Fore.YELLOW + "No hay resultados para guardar.")
            return

        if not os.path.exists('out'):
            os.makedirs('out')

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_dir = f'out/{timestamp}'

        os.makedirs(output_dir, exist_ok=True)
        
        for result_type, items in self.results.items():
            if items:
                output_file = os.path.join(output_dir, f"{result_type}.txt")
                with open(output_file, 'w') as f:
                    for item in sorted(items):
                        f.write(f"{item}\n")
                print(Fore.GREEN + f"Resultados de {result_type} guardados en {output_file}")

    def analyze(self):
        """
        Realiza el análisis completo de la búsqueda de cadenas y posibles patrones.
        """
        print(Fore.CYAN + "Iniciando análisis...")
        strings = self.extract_strings()
        if strings:
            results = self.search_patterns(strings)
            if any(results.values()):
                print(Fore.CYAN + "Posibles coincidencias encontradas:")
                for result_type, items in results.items():
                    if items:
                        print(Fore.YELLOW + f"\n--- {result_type} ---")
                        for item in items:
                            print(Fore.YELLOW + item)
            else:
                print(Fore.RED + "No se encontraron coincidencias.")
        else:
            print(Fore.RED + "No se encontraron cadenas en el archivo.")
        input(Fore.CYAN + "\nPresione cualquier tecla para volver al menú...")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def menu(self):
        while True:
            self.clear_screen()
            self.show_banner()
            print(Fore.BLUE + "--- Menú de Análisis de Archivos .so ---")
            print(Fore.BLUE + "1. Analizar archivo")
            print(Fore.BLUE + "2. Guardar resultados")
            print(Fore.BLUE + "3. Configuración")
            print(Fore.BLUE + "4. Salir" + Style.RESET_ALL)

            choice = input(Fore.GREEN + "Seleccione una opción: " + Style.RESET_ALL)

            if choice == '1':
                self.analyze()
            elif choice == '2':
                self.save_results_to_file()
                input(Fore.CYAN + "\nPresione cualquier tecla para volver al menú...")
            elif choice == '3':
                self.config_menu()
            elif choice == '4':
                print(Fore.CYAN + "Saliendo del programa. ¡Hasta luego!")
                break
            else:
                print(Fore.RED + "Opción no válida, por favor seleccione nuevamente.")
                input(Fore.CYAN + "\nPresione cualquier tecla para volver al menú...")

    def config_menu(self):
        """
        Permite al usuario configurar opciones avanzadas como longitud mínima de cadena y tamaño de chunk.
        """
        print(Fore.CYAN + "--- Configuración ---")
        self.min_string_length = int(input(Fore.GREEN + "Longitud mínima de las cadenas (actual: 4): ") or 4)
        self.chunk_size = int(input(Fore.GREEN + "Tamaño del chunk de lectura en bytes (actual: 1024*1024): ") or 1024*1024)
        input(Fore.CYAN + "\nConfiguración actualizada. Presione cualquier tecla para volver al menú...")

    def show_banner(self):
        banner = f"""
        {Fore.YELLOW}   _____ ____  ___                __                     
        {Fore.YELLOW}  / ___// __ \/   |  ____  ____ _/ /_  ______  ___  _____
        {Fore.YELLOW}  \__ \/ / / / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
        {Fore.YELLOW} ___/ / /_/ / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
        {Fore.YELLOW}/____/\____/_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
        {Fore.YELLOW}                                /____/   
        {Fore.CYAN}Herramienta de Análisis de Archivos .so
        {Fore.GREEN}Desarrollador: Jamil Rodriguez
        {Fore.GREEN}Año: 2024 {Style.RESET_ALL}
        """
        print(banner)

if __name__ == '__main__':
    analyzer = SOAnalyzer(None)
    analyzer.clear_screen()
    analyzer.show_banner()

    file_path = input(Fore.GREEN + "[+] Ingrese la ruta del archivo .so a analizar -> " + Style.RESET_ALL)

    if os.path.isfile(file_path):
        analyzer = SOAnalyzer(file_path)
        analyzer.menu()
    else:
        print(Fore.RED + "El archivo proporcionado no es válido.")
