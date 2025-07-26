import secrets
import string
from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

# --- 1. CONFIGURACIÓN Y LÓGICA DE SEGURIDAD (igual que antes) ---
PASSWORD_FILE = "passwords.encrypted"
KEY_FILE = "secret.key"

fernet = None # Se inicializará después de cargar la clave

def load_key():
    """Carga la clave de cifrado del archivo o genera una nueva si no existe."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        messagebox.showinfo("Clave Generada", 
                            f"¡Atención! Se ha generado una nueva clave de cifrado en '{KEY_FILE}'.\n"
                            "Guarda este archivo en un lugar seguro y no lo compartas.")
        return key

def initialize_encryption():
    """Inicializa Fernet con la clave cargada."""
    global fernet
    try:
        key = load_key()
        fernet = Fernet(key)
        return True
    except Exception as e:
        messagebox.showerror("Error de Cifrado", 
                             f"Error al cargar la clave de cifrado. Asegúrate de que '{KEY_FILE}' no esté dañado o falte.\n"
                             f"Detalle: {e}")
        return False

# --- 2. GENERADOR DE CONTRASEÑAS (igual que antes) ---
def generate_password(length=12, use_lowercase=True, use_uppercase=True, use_digits=True, use_symbols=True):
    """Genera una contraseña segura basada en los parámetros dados."""
    characters = ""
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return "Error: Selecciona al menos un tipo de caracter."

    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

# --- 3. MÉTRICA DE FUERZA DE CONTRASEÑA (igual que antes) ---
def check_password_strength(password):
    """Evalúa la fuerza de una contraseña."""
    length_score = 0
    if len(password) >= 12:
        length_score = 3
    elif len(password) >= 8:
        length_score = 2
    else:
        length_score = 1

    char_types = 0
    if any(c.islower() for c in password):
        char_types += 1
    if any(c.isupper() for c in password):
        char_types += 1
    if any(c.isdigit() for c in password):
        char_types += 1
    if any(c in string.punctuation for c in password):
        char_types += 1

    total_score = length_score + char_types

    if total_score >= 7:
        return "Muy Fuerte"
    elif total_score >= 5:
        return "Fuerte"
    elif total_score >= 3:
        return "Moderada"
    else:
        return "Débil"

# --- 4. GESTOR DE CONTRASEÑAS (adaptado para GUI) ---

def load_passwords():
    """Carga y descifra las contraseñas del archivo."""
    passwords = {}
    if not fernet: # Asegurar que fernet esté inicializado
        return passwords
        
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "rb") as f:
            encrypted_data = f.read()
            if not encrypted_data:
                return passwords
            try:
                decrypted_data = fernet.decrypt(encrypted_data).decode()
                for line in decrypted_data.splitlines():
                    if line:
                        service, password = line.split(":", 1)
                        passwords[service] = password
            except Exception as e:
                messagebox.showerror("Error de Datos", 
                                     f"Error al descifrar el archivo de contraseñas. Podría estar corrupto o la clave es incorrecta.\n"
                                     f"Detalle: {e}")
                # Podrías considerar renombrar el archivo corrupto y empezar de nuevo
                return {} 
    return passwords

def save_passwords(passwords):
    """Cifra y guarda las contraseñas en el archivo."""
    if not fernet:
        messagebox.showerror("Error", "El sistema de cifrado no está inicializado.")
        return False

    lines = [f"{service}:{password}" for service, password in passwords.items()]
    plaintext_data = "\n".join(lines).encode()
    try:
        encrypted_data = fernet.encrypt(plaintext_data)
        with open(PASSWORD_FILE, "wb") as f:
            f.write(encrypted_data)
        return True
    except Exception as e:
        messagebox.showerror("Error al Guardar", f"No se pudo guardar la contraseña. Detalle: {e}")
        return False

# --- 5. FUNCIONES DE LA GUI ---

def generate_password_gui():
    """Función para generar contraseña desde la GUI."""
    top = tk.Toplevel(root)
    top.title("Generar Contraseña")

    tk.Label(top, text="Longitud:").grid(row=0, column=0, padx=5, pady=5)
    length_entry = tk.Entry(top)
    length_entry.insert(0, "12")
    length_entry.grid(row=0, column=1, padx=5, pady=5)

    use_lower = tk.BooleanVar(value=True)
    use_upper = tk.BooleanVar(value=True)
    use_digits = tk.BooleanVar(value=True)
    use_symbols = tk.BooleanVar(value=True)

    tk.Checkbutton(top, text="Minúsculas", variable=use_lower).grid(row=1, column=0, sticky="w", padx=5)
    tk.Checkbutton(top, text="Mayúsculas", variable=use_upper).grid(row=2, column=0, sticky="w", padx=5)
    tk.Checkbutton(top, text="Números", variable=use_digits).grid(row=3, column=0, sticky="w", padx=5)
    tk.Checkbutton(top, text="Símbolos", variable=use_symbols).grid(row=4, column=0, sticky="w", padx=5)

    generated_password_var = tk.StringVar()
    strength_var = tk.StringVar()

    def generate():
        try:
            length = int(length_entry.get())
            if length <= 0:
                messagebox.showerror("Error", "La longitud debe ser un número positivo.")
                return
            password = generate_password(length, use_lower.get(), use_upper.get(), use_digits.get(), use_symbols.get())
            generated_password_var.set(password)
            strength_var.set(f"Fuerza: {check_password_strength(password)}")
        except ValueError:
            messagebox.showerror("Error", "Longitud inválida. Introduce un número.")
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error al generar: {e}")

    tk.Button(top, text="Generar", command=generate).grid(row=5, column=0, columnspan=2, pady=10)

    tk.Label(top, text="Contraseña Generada:").grid(row=6, column=0, sticky="w", padx=5)
    tk.Entry(top, textvariable=generated_password_var, width=40, state="readonly").grid(row=6, column=1, padx=5, pady=5)
    tk.Label(top, textvariable=strength_var).grid(row=7, column=0, columnspan=2, padx=5, pady=5)

def add_password_gui():
    """Añadir o actualizar contraseña via GUI."""
    service = simpledialog.askstring("Añadir Contraseña", "Introduce el nombre del servicio (ej. 'Google'):")
    if not service:
        return

    passwords = load_passwords()
    current_password = passwords.get(service, "")

    top = tk.Toplevel(root)
    top.title(f"Añadir/Actualizar {service}")

    tk.Label(top, text=f"Servicio: {service}").grid(row=0, column=0, columnspan=2, padx=5, pady=5)
    
    tk.Label(top, text="Contraseña:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
    password_entry = tk.Entry(top, width=40, show="*") # Oculta la contraseña
    password_entry.insert(0, current_password)
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    def toggle_password_visibility():
        if password_entry.cget("show") == "*":
            password_entry.config(show="")
        else:
            password_entry.config(show="*")
            
    tk.Checkbutton(top, text="Mostrar/Ocultar", command=toggle_password_visibility).grid(row=2, column=0, columnspan=2, pady=5)

    strength_label = tk.Label(top, text="")
    strength_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def update_strength(*args):
        current_pass = password_entry.get()
        if current_pass:
            strength_label.config(text=f"Fuerza: {check_password_strength(current_pass)}")
        else:
            strength_label.config(text="")
    
    password_entry.bind("<KeyRelease>", update_strength)


    def save():
        new_password = password_entry.get()
        if not new_password:
            messagebox.showerror("Error", "La contraseña no puede estar vacía.")
            return

        passwords[service] = new_password
        if save_passwords(passwords):
            messagebox.showinfo("Éxito", f"Contraseña para '{service}' guardada con éxito.")
            top.destroy()
        else:
            messagebox.showerror("Error", "No se pudo guardar la contraseña.")

    tk.Button(top, text="Guardar", command=save).grid(row=4, column=0, columnspan=2, pady=10)


def view_password_gui():
    """Ver contraseña guardada via GUI."""
    service = simpledialog.askstring("Ver Contraseña", "Introduce el nombre del servicio:")
    if not service:
        return

    passwords = load_passwords()
    if service in passwords:
        messagebox.showinfo("Contraseña", f"La contraseña para '{service}' es:\n{passwords[service]}")
    else:
        messagebox.showinfo("No Encontrada", f"No se encontró una contraseña para el servicio '{service}'.")

def list_passwords_gui():
    """Lista todos los servicios guardados en una nueva ventana."""
    passwords = load_passwords()
    
    top = tk.Toplevel(root)
    top.title("Servicios Guardados")
    
    if not passwords:
        tk.Label(top, text="No hay contraseñas guardadas.").pack(padx=20, pady=20)
        return

    text_area = scrolledtext.ScrolledText(top, width=40, height=15, wrap=tk.WORD)
    text_area.pack(padx=10, pady=10)
    
    sorted_services = sorted(passwords.keys())
    for service in sorted_services:
        text_area.insert(tk.END, f"- {service}\n")
    
    text_area.config(state=tk.DISABLED) # Hacer que el texto no sea editable


def delete_password_gui():
    """Eliminar contraseña via GUI."""
    service = simpledialog.askstring("Eliminar Contraseña", "Introduce el nombre del servicio a eliminar:")
    if not service:
        return

    passwords = load_passwords()
    if service in passwords:
        if messagebox.askyesno("Confirmar Eliminación", f"¿Estás seguro de que quieres eliminar la contraseña para '{service}'?"):
            del passwords[service]
            if save_passwords(passwords):
                messagebox.showinfo("Éxito", f"Contraseña para '{service}' eliminada con éxito.")
            else:
                messagebox.showerror("Error", "No se pudo eliminar la contraseña.")
    else:
        messagebox.showinfo("No Encontrada", f"No se encontró una contraseña para el servicio '{service}'.")

# --- 6. CONFIGURACIÓN DE LA VENTANA PRINCIPAL DE TKINTER ---

# Inicializar el sistema de cifrado al inicio de la aplicación
if not initialize_encryption():
    exit() # Salir si no se puede inicializar el cifrado

root = tk.Tk()
root.title("Mi Gestor de Contraseñas Seguras")
root.geometry("400x300") # Tamaño inicial de la ventana

# Crear y empaquetar botones
tk.Button(root, text="Generar Contraseña", command=generate_password_gui, width=30, height=2).pack(pady=5)
tk.Button(root, text="Añadir/Actualizar Contraseña", command=add_password_gui, width=30, height=2).pack(pady=5)
tk.Button(root, text="Ver Contraseña", command=view_password_gui, width=30, height=2).pack(pady=5)
tk.Button(root, text="Listar Servicios", command=list_passwords_gui, width=30, height=2).pack(pady=5)
tk.Button(root, text="Eliminar Contraseña", command=delete_password_gui, width=30, height=2).pack(pady=5)
tk.Button(root, text="Salir", command=root.quit, width=30, height=2, bg="lightcoral").pack(pady=5) # Botón de salir

# Iniciar el bucle principal de la GUI
root.mainloop()
