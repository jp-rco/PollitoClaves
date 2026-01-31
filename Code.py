#!/usr/bin/env python3
# main.py
import hashlib
import random
import time
import os
import sys

# -------------------------------
# CONFIGURACIÓN
# -------------------------------
LISTA_PWD_FILE = "Lista Contraseñas.txt"   # tu archivo con: passwords = [ ... ]
TEST_MODE = False                          # True = prueba rápida con rango reducido
TEST_MAX_NUMBER = 100_000                  # rango reducido para pruebas
RANDOM_COUNT = 50                          # cantidad de números aleatorios
RANDOM_MIN = 1
RANDOM_MAX = 100_000_000                   # rango real pedido
YEARS_START = 1995
YEARS_END = 2025                           # inclusive

# -------------------------------
# Hashes objetivo (lista completa que pediste)
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

def load_passwords_from_python_list_file(path: str):
    """
    Lee un archivo que contiene una definición Python: passwords = [ ... ]
    y ejecuta su contenido de forma segura en un namespace local para obtener la variable 'passwords'.
    Nota: exec() se usa porque el usuario mantiene el archivo en formato lista Python.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontró el archivo: {path}")
    with open(path, "r", encoding="utf-8") as f:
        contenido = f.read()
    local_vars = {}
    # Ejecutar en un namespace controlado
    exec(contenido, {}, local_vars)
    if "passwords" not in local_vars:
        raise ValueError("El archivo no define la variable 'passwords'.")
    return local_vars["passwords"]

# -------------------------------
# Programa 1: Ataque de diccionario
# -------------------------------
def ataque_diccionario(passwords, hashes_objetivo_set):
    resultados = []
    encontrados_hashes = set()
    for i, base in enumerate(passwords):
        # Asegurarse que base sea str
        base_str = str(base)
        for year in range(YEARS_START, YEARS_END + 1):
            candidato = f"{base_str}{year}*"
            h = sha256_hash(candidato)
            if h in hashes_objetivo_set and h not in encontrados_hashes:
                encontrados_hashes.add(h)
                resultados.append({
                    "hash": h,
                    "contraseña": candidato,
                    "posicion_lista": i + 1,
                    "base": base_str,
                    "year": year
                })
        # Si ya encontramos todos los hashes, podemos salir temprano
        if encontrados_hashes == hashes_objetivo_set:
            return resultados
    return resultados

# -------------------------------
# Mostrar hashes no descubiertos
# -------------------------------
def mostrar_no_descubiertos(resultados, hashes_objetivo_set):
    encontrados = {r["hash"] for r in resultados}
    no_descubiertos = hashes_objetivo_set - encontrados
    print("\n=== Hashes NO descubiertos ===")
    if no_descubiertos:
        for h in sorted(no_descubiertos):
            print(h)
    else:
        print("Todos los hashes fueron descubiertos.")

# -------------------------------
# Programa 2: Análisis de rendimiento (números aleatorios)
# -------------------------------
def analisis_rendimiento(full_range=True):
    # 1) Generar 50 números aleatorios
    max_number = RANDOM_MAX if full_range else TEST_MAX_NUMBER
    if RANDOM_COUNT > max_number:
        raise ValueError("RANDOM_COUNT es mayor que el rango máximo.")
    numeros = random.sample(range(RANDOM_MIN, max_number + 1), RANDOM_COUNT)
    hashes_random = {sha256_hash(str(n)): n for n in numeros}  # map hash -> original number
    print(f"\nGenerados {len(numeros)} números aleatorios (muestra 5): {numeros[:5]} ...")
    print(f"Rango de búsqueda: 1 .. {max_number}")

    # 2) Recorrer todos los números y comparar
    inicio = time.time()
    encontrados = {}
    total_checked = 0
    # Para permitir ver progreso en rangos grandes, imprimimos cada cierto bloque
    progress_block = 1_000_000 if full_range else 10_000

    for n in range(1, max_number + 1):
        total_checked += 1
        h = sha256_hash(str(n))
        if h in hashes_random and h not in encontrados:
            encontrados[h] = n
            print(f"Coincidencia: número {n} (hash de uno de los aleatorios).")
            # Si encontramos todas las 50, podemos terminar temprano
            if len(encontrados) == len(hashes_random):
                break
        if total_checked % progress_block == 0:
            elapsed = time.time() - inicio
            print(f"Checked {total_checked} numbers, elapsed {elapsed:.1f}s")

    fin = time.time()
    elapsed_total = fin - inicio
    print(f"\nTiempo total de búsqueda: {elapsed_total:.2f} segundos")
    print(f"Total números verificados: {total_checked}")
    print(f"Coincidencias encontradas: {len(encontrados)} de {len(hashes_random)}")
    if encontrados:
        for h, n in encontrados.items():
            print(f"Hash: {h}  -> número original: {n}")
    else:
        print("No se encontraron coincidencias entre los 50 hashes y el rango verificado.")

    # Devolver métricas
    return {
        "elapsed_seconds": elapsed_total,
        "checked": total_checked,
        "found_map": encontrados,
        "random_numbers": numeros
    }

# -------------------------------
# MAIN
# -------------------------------
def main():
    print("Iniciando programa: Ataque diccionario + Análisis de rendimiento")
    # Cargar lista de contraseñas desde tu archivo en formato Python list
    try:
        passwords = load_passwords_from_python_list_file(LISTA_PWD_FILE)
        print(f"Cargadas {len(passwords)} contraseñas desde '{LISTA_PWD_FILE}'.")
    except Exception as e:
        print("Error cargando lista de contraseñas:", e)
        sys.exit(1)

    hashes_set = set(hashes_objetivo)

    # Programa 1: ataque de diccionario
    print("\n=== Programa 1: Ataque de diccionario (variantes año + '*') ===")
    inicio1 = time.time()
    resultados = ataque_diccionario(passwords, hashes_set)
    fin1 = time.time()
    print(f"Tiempo ataque diccionario: {fin1 - inicio1:.2f} segundos")
    if resultados:
        print(f"Se encontraron {len(resultados)} coincidencias:")
        for r in resultados:
            print(f"- Hash: {r['hash']}")
            print(f"  Contraseña encontrada: {r['contraseña']}")
            print(f"  Base: {r['base']} (posición {r['posicion_lista']}) año: {r['year']}")
    else:
        print("No se encontraron coincidencias en el ataque de diccionario.")

    mostrar_no_descubiertos(resultados, hashes_set)

    # Programa 2: análisis de rendimiento
    print("\n=== Programa 2: Análisis de rendimiento (números aleatorios) ===")
    if TEST_MODE:
        print("TEST_MODE activado: usando rango reducido para pruebas.")
    metrics = analisis_rendimiento(full_range=not TEST_MODE)

    # Resumen final
    print("\n=== Resumen final ===")
    print(f"Ataque diccionario: {len(resultados)} hashes descubiertos.")
    no_desc = hashes_set - {r["hash"] for r in resultados}
    print(f"Hashes no descubiertos: {len(no_desc)}")
    print(f"Analisis rendimiento: tiempo {metrics['elapsed_seconds']:.2f}s, verificados {metrics['checked']} números, coincidencias {len(metrics['found_map'])}")

if __name__ == "__main__":
    main()
