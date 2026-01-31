#!/usr/bin/env python3
import hashlib
import time
import os
import sys
import ast
import re
import itertools
import string

# -------------------------------
# CONFIGURACIÓN
# -------------------------------
LISTA_PWD_FILE = "hola.txt"   
YEARS_START = 1995
YEARS_END = 2025
# Caracteres para Fuerza Bruta (ajustar según sospecha: letras, números, etc.)
CHARS_BRUTE = string.ascii_lowercase + string.digits 

# -------------------------------
# Hashes objetivo
# -------------------------------
hashes_objetivo = {
    "290e1fc4609f8c2af910ad751d9b7d1d737cd594361cb75a7ac076ca8eff5c69",
    "ee7942eac05f5f77a2dc0802c09b1f90266bde86e85fd01ae1d507fb8c096bc1",
    "f6cda156fbe8b0ecc41e007dac3f5a33221b18be6a41c8f53ac5092066428224",
    "724b5ec5ed8972e5b83a0aa97a4365f0f6f69d8e7bebc25ae045db9df84a9e50",
    "77a452fadad021e3e8df2e4f4bdc20b5d4ecc7ac8fc0f6b47fbb57ca7bd0bf9d",
    "9749143e9a1d33608549f229badc782b21b9d257f83bd0fa2ec50ccade3f3cc0",
    "8c497900ed63bfb4172a0470fed178b9ce3e46feb04f3e7cc102fc6fc2d3edf7",
    "9a00b44127f7ae27dd67e93780ec581768c5d1415a79acc4c8e94daf62ba82c7",
    "b239e2b0cde1f95a238bccecc184175e2233426d9d12e2a73afdae4d466cd788",
    "a1924bad90e9e1ad7ff33727210fe2b900570a7ab25faf0716f8192229abace8",
    "8ff206f903330ea92277b16059f446ef58912a89618db6481157d8a9f7534475",
    "4efc1d092a35864f0db5c705272351d2b06ddc1d403dac541f4529ec83151581",
    "a82691934ea147dfcc9c826280eb00f6a9f6f29c333a9b24b30e015328ac44f7",
    "f36b5f8f302de2e68cc94a1c0088eb1ee2eb140c1bc80642738a2896e89192e9",
    "0df69abc3a6357ebc7426c1c5743edf9076e6d03e26178720d708d3a114fee4f",
    "b6705e05fdf162d37a40ad2c8776df1df7458655c7a5c22df45c8c4d5bc59913",
    "2a09198c2b7e92a9cb49c1d18fa57c7fb82004f6b213976f3d4c385e34b160c9",
    "2ca6297e9f07d1e4871c545c50d474485190144a748c86d8f6416009efd86ff9",
    "997f085d352f06010ddd8f109698393f366e988c888d000e2144acce5ce44421",
    "ec81cb421727a3ddfef5db26bc8e2c7e645c70ed702f23799c9bbd7cf382acee",
    "7aabc6b49a586dd7415f4217c5d7b710ff487a8b76ecf69fc21f64069580559a",
    "629801f0c2b75711c4648c18183290756c84a80c3ddf38dec2621cf6e71950d1",
    "d5748539fb95e9a90b8b42976953845534913444acbbd779abc3ae276856c21d",
    "3dfb6496b4ba6d3c84529d77a56d918ca555abf358e086a7d0abec10e87e5969",
    "4faf4b856232f56ba7d017f328cda46f1924cbbcf824337e51d442937c6b5770",
    "4574eebc32224769c5893f0f7ebc8683f83600dac2a0dbe16fb43604e3927d4e",
    "f64342de4ee695748ec0bb55e29b89737ad57ff24c82ddcff22dcc96233b6bb4",
    "f7f95e46a75b616c94d31cdb623e2e05bff82dae1e5e602ed2f0e9f0c718d852",
    "f7ca254a1ac6bbabec4ecfe50911783036a24c20758742308d9f778aff38869f"
}

# -------------------------------
# Utilidades
# -------------------------------
def sha256_hash(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()

def load_passwords(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Archivo no encontrado: {path}")
    with open(path, "r", encoding="utf-8") as f:
        contenido = f.read()
    # Intenta extraer strings de la lista python o lineas simples
    quoted = re.findall(r'["\']([^"\']{1,200})["\']', contenido)
    if quoted: return list(set(quoted))
    return [line.strip() for line in contenido.splitlines() if line.strip()]

# -------------------------------
# ATAQUE 1: DICCIONARIO + REGLAS
# -------------------------------
def ataque_diccionario(passwords, hashes_pendientes):
    encontrados = {}
    print(f"[*] Probando {len(passwords)} palabras con sufijos de año...")
    for base in passwords:
        for year in range(YEARS_START, YEARS_END + 1):
            candidato = f"{base}{year}*"
            h = sha256_hash(candidato)
            if h in hashes_pendientes:
                encontrados[h] = candidato
                print(f"[!] ENCONTRADA (Diccionario): {candidato}")
                hashes_pendientes.remove(h)
                if not hashes_pendientes: return encontrados
    return encontrados

# -------------------------------
# ATAQUE 2: FUERZA BRUTA (Para las que no están en RockYou)
# -------------------------------
def ataque_fuerza_bruta(hashes_pendientes, max_length=8):
    """
    Intenta todas las combinaciones posibles de caracteres.
    ADVERTENCIA: Aumentar max_length incrementa el tiempo exponencialmente.
    """
    encontrados = {}
    print(f"[*] Iniciando Fuerza Bruta para {len(hashes_pendientes)} hashes restantes...")
    print(f"[*] Esto puede tardar dependiendo de la longitud de la contraseña.")

    for length in range(1, max_length + 1):
        print(f"    - Probando longitud: {length}...")
        for combination in itertools.product(CHARS_BRUTE, repeat=length):
            candidato = "".join(combination)
            h = sha256_hash(candidato)
            if h in hashes_pendientes:
                encontrados[h] = candidato
                print(f"[!] ENCONTRADA (Fuerza Bruta): {candidato}")
                hashes_pendientes.remove(h)
                if not hashes_pendientes: return encontrados
    return encontrados

# -------------------------------
# MAIN
# -------------------------------
def main():
    inicio_global = time.time()
    hashes_pendientes = set(hashes_objetivo)
    todas_encontradas = {}

    # 1. Cargar diccionario
    try:
        dict_pwds = load_passwords(LISTA_PWD_FILE)
        # 2. Ejecutar ataque diccionario
        res_dict = ataque_diccionario(dict_pwds, hashes_pendientes)
        todas_encontradas.update(res_dict)
    except Exception as e:
        print(f"[!] No se pudo cargar el diccionario: {e}")

    # 3. Si faltan hashes, ejecutar Fuerza Bruta
    if hashes_pendientes:
        print(f"\n[?] Quedan {len(hashes_pendientes)} hashes por descifrar.")
        res_brute = ataque_fuerza_bruta(hashes_pendientes, max_length=6) # Ajusta max_length
        todas_encontradas.update(res_brute)

    # 4. Resumen Final
    fin_global = time.time()
    print("\n" + "="*30)
    print("RESUMEN DE RESULTADOS")
    print("="*30)
    print(f"Tiempo total: {fin_global - inicio_global:.2f}s")
    print(f"Hashes totales: {len(hashes_objetivo)}")
    print(f"Descifrados: {len(todas_encontradas)}")
    
    if hashes_pendientes:
        print("\nHashes no encontrados (necesitas un rango de Fuerza Bruta mayor o más reglas):")
        for h in hashes_pendientes:
            print(f"- {h}")

if __name__ == "__main__":
    main()