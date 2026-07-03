conteo = {}  
with open("sample-ssh-auth.log") as archivo:
    for linea in archivo:
        if "Failed password" in linea:
            palabras = linea.split()
            usuario = palabras[8]
            ip = palabras[10]
    
            clave = usuario + " " + ip
            if clave in conteo:
                conteo[clave] = conteo[clave] + 1
            else:
                conteo[clave] = 1
            
for clave, cantidad in conteo.items():
    if cantidad > 5:
        print("POSIBLE FUERZA BRUTA", clave,cantidad)
    