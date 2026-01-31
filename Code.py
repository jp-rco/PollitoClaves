import hashlib

def crack_pollito_passwords(dictionary_path):
    # Lista de hashes (SHA-256) proporcionada por Pollito con Papas
    target_hashes = [
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
    ]

    # Convertimos a set para búsquedas más rápidas y seguimiento de hallazgos
    hashes_to_crack = set(target_hashes)
    found_info = []
    
    try:
        # Abrimos hola.txt e iteramos línea por línea sin límite de palabras
        with open(dictionary_path, 'r', encoding='latin-1') as file:
            print(f"--- Iniciando ataque con diccionario: {dictionary_path} ---")
            
            for index, line in enumerate(file):
                base_word = line.strip()
                if not base_word: continue

                # Probar con años entre 1995 y 2026 seguidos de '*'
                for year in range(1995, 2027):
                    candidate = f"{base_word}{year}*"
                    candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()

                    if candidate_hash in hashes_to_crack:
                        # Registro de hallazgo y eliminación del set de pendientes
                        res = f"Posición: {index + 1} | Palabra: {base_word} | Completa: {candidate} | Hash: {candidate_hash}"
                        print(res)
                        found_info.append(res)
                        hashes_to_crack.remove(candidate_hash) # Ya no buscamos este hash

        # --- SECCIÓN DE REPORTES FINALES ---
        print("\n" + "="*50)
        print("RESUMEN DEL ATAQUE")
        print("="*50)
        print(f"Total de hashes analizados: {len(target_hashes)}")
        print(f"Hashes descifrados: {len(found_info)}")
        print(f"Hashes NO encontrados: {len(hashes_to_crack)}")
        
        # Mostrar los que faltaron [NUEVA FUNCIONALIDAD]
        if hashes_to_crack:
            print("\nLISTA DE HASHES QUE NO FUERON ENCONTRADOS:")
            for h in hashes_to_crack:
                print(f"- {h}")
        else:
            print("\n¡Felicidades! Se descifraron todos los hashes.")
        print("="*50)

    except FileNotFoundError:
        print(f"Error: El archivo '{dictionary_path}' no existe en el directorio.")

# Ejecución
crack_pollito_passwords("Pwdb_top-10000000.txt")