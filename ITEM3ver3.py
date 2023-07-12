import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def hash_password(password):
    # Generar hash de la contraseña utilizando SHA-256
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/', methods=['POST'])
def registrar_usuario():
    nombre = request.form.get('nombre')
    contrasena = request.form.get('contrasena')

    if not nombre or not contrasena:
        return 'Nombre de usuario y contraseña requeridos', 400

    # Crear una nueva conexión y un nuevo cursor en este hilo
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    try:
        # Almacenar el nombre de usuario y la contraseña hasheada en la base de datos
        hashed_password = hash_password(contrasena)
        cursor.execute('INSERT INTO usuarios (nombre, contrasena) VALUES (?, ?)', (nombre, hashed_password))
        conn.commit()
        return 'Usuario registrado correctamente'
    except Exception as e:
        return f'Error al registrar el usuario: {str(e)}', 500
    finally:
        # Cerrar la conexión y el cursor al finalizar
        cursor.close()
        conn.close()


@app.route('/login', methods=['POST'])
def validar_usuario():
    nombre = request.form.get('nombre')
    contrasena = request.form.get('contrasena')

    if not nombre or not contrasena:
        return 'Nombre de usuario y contraseña requeridos', 400

    # Crear una nueva conexión y un nuevo cursor en este hilo
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    try:
        # Buscar al usuario en la base de datos y verificar la contraseña
        hashed_password = hash_password(contrasena)
        cursor.execute('SELECT * FROM usuarios WHERE nombre = ? AND contrasena = ?', (nombre, hashed_password))
        result = cursor.fetchone()

        if result is not None:
            return 'Usuario válido'
        else:
            return 'Usuario inválido'
    except Exception as e:
        return f'Error al validar el usuario: {str(e)}', 500
    finally:
        # Cerrar la conexión y el cursor al finalizar
        cursor.close()
        conn.close()


if __name__ == '__main__':
    app.run(port=9500)

