import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from Config.database_connection import create_connection
from werkzeug.security import generate_password_hash, check_password_hash
from Controllers import autenticacion
from Models.admin import AdminModel

app = Flask(__name__, template_folder='Views', static_folder='Static')
app.secret_key = 'clave_secreta_gestion_estudiantil_2023'

# --------------------------
# Manejador de errores
# --------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error/500.html'), 500

# --------------------------
# Rutas de Autenticación
# --------------------------
@app.route('/')
def home():
    if 'usuario' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth/login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'usuario' in session:
            return redirect(url_for('dashboard'))
        return render_template('auth/login.html')
    
    # POST handling
    correo = request.form.get('correo', '').strip()
    contraseña = request.form.get('contraseña', '').strip()
    
    if not correo or not contraseña:
        flash("Por favor complete todos los campos", "error")
        return redirect(url_for('login'))
    
    try:
        conexion = create_connection()
        if not conexion:
            flash("Error de conexión con la base de datos", "error")
            return redirect(url_for('login'))
            
        with conexion.cursor(dictionary=True) as cursor:
            query = "SELECT * FROM usuarios WHERE correo = %s"
            cursor.execute(query, (correo,))
            usuario = cursor.fetchone()
            
            if usuario and check_password_hash(usuario['contraseña'], contraseña):
                session['usuario'] = {
                    'id': usuario['id'],
                    'nombre': usuario['nombre'],
                    'correo': usuario['correo'],
                    'tipo': usuario['rol']
                }
                return redirect(url_for('dashboard'))
            
            flash("Correo o contraseña incorrectos.", "error")
            return redirect(url_for('login'))
            
    except Exception as e:
        app.logger.error(f"Error al iniciar sesión: {str(e)}")
        flash("Ocurrió un error al iniciar sesión.", "error")
        return redirect(url_for('login'))
    finally:
        if 'conexion' in locals() and conexion:
            conexion.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if 'usuario' in session:
            return redirect(url_for('dashboard'))
        return render_template('auth/register.html')
    
    # POST handling
    nombre = request.form.get('nombre', '').strip()
    correo = request.form.get('correo', '').strip()
    contraseña = request.form.get('contraseña', '').strip()
    rol = request.form.get('rol', '').strip()
    
    if not all([nombre, correo, contraseña, rol]):
        flash("Por favor complete todos los campos", "register_error")
        return redirect(url_for('register'))
    
    try:
        conexion = create_connection()
        if not conexion:
            flash("Error de conexión con la base de datos", "register_error")
            return redirect(url_for('register'))
            
        with conexion.cursor(dictionary=True) as cursor:
            # Verificar si el correo ya existe
            cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
            if cursor.fetchone():
                flash("El correo ya está registrado.", "register_error")
                return redirect(url_for('register'))
            
            # Registrar nuevo usuario
            hashed_password = generate_password_hash(contraseña)
            cursor.execute("""
                INSERT INTO usuarios (nombre, correo, contraseña, rol)
                VALUES (%s, %s, %s, %s)
            """, (nombre, correo, hashed_password, rol))
            
            # Insertar en la tabla específica según el rol
            if rol == 'estudiante':
                cursor.execute("INSERT INTO estudiantes (nombre, correo, contraseña) VALUES (%s, %s, %s)", 
                             (nombre, correo, hashed_password))
            elif rol == 'profesor':
                cursor.execute("INSERT INTO profesores (nombre, correo, contraseña) VALUES (%s, %s, %s)", 
                             (nombre, correo, hashed_password))
            elif rol == 'padre':
                cursor.execute("INSERT INTO padres (nombre, correo, contraseña) VALUES (%s, %s, %s)", 
                             (nombre, correo, hashed_password))
            
            conexion.commit()
            
            flash("Registro exitoso. Ahora puedes iniciar sesión.", "success")
            return redirect(url_for('login'))
            
    except Exception as e:
        app.logger.error(f"Error al registrar usuario: {str(e)}")
        flash("Ocurrió un error al registrarte. Intenta nuevamente.", "register_error")
        return redirect(url_for('register'))
    finally:
        if 'conexion' in locals() and conexion:
            conexion.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --------------------------
# Rutas del Dashboard
# --------------------------
@app.route('/dashboard')
def dashboard():
    if 'usuario' not in session:
        return redirect(url_for('home'))
    
    tipo_usuario = session['usuario']['tipo']
    dashboards = {
        'admin': 'admin_dashboard',
        'profesor': 'profesor_dashboard',
        'estudiante': 'estudiante_dashboard',
        'padre': 'padre_dashboard'
    }
    
    if tipo_usuario not in dashboards:
        flash("Rol desconocido. Contacta al administrador.", "error")
        return redirect(url_for('home'))
    
    return redirect(url_for(dashboards[tipo_usuario]))

# --------------------------
# Rutas específicas para cada rol
# --------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin/login.html')
    
    correo = request.form['correo']
    contraseña = request.form['contraseña']
    
    try:
        # Validar credenciales con el controlador de autenticación
        admin = autenticacion.login(correo, contraseña)
        if admin and isinstance(admin, admin):
            # Iniciar sesión como administrador
            session['usuario'] = {
                'id': admin.id,
                'nombre': admin.nombre,
                'correo': admin.correo,
                'tipo': 'admin'
            }
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Correo o contraseña incorrectos.", "error")
            return redirect(url_for('admin_login'))
    except Exception as e:
        app.logger.error(f"Error al iniciar sesión como administrador: {str(e)}")
        flash("Ocurrió un error al iniciar sesión.", "error")
        return redirect(url_for('admin_login'))

@app.route('/profesor/dashboard')
def profesor_dashboard():
    if 'usuario' not in session or session['usuario']['tipo'] != 'profesor':
        return redirect(url_for('home'))
    
    try:
        conexion = create_connection()
        if not conexion:
            flash("Error de conexión con la base de datos", "error")
            return render_template('profesor/dashboard.html', usuario=session['usuario'])
            
        with conexion.cursor(dictionary=True) as cursor:
            # Verificar si existe la tabla asignaciones
            cursor.execute("SHOW TABLES LIKE 'asignaciones'")
            if not cursor.fetchone():
                materias = []
            else:
                # Obtener materias asignadas al profesor
                cursor.execute("""
                    SELECT m.id, m.nombre 
                    FROM materias m
                    JOIN asignaciones a ON m.id = a.id_materia
                    WHERE a.id_profesor = %s
                """, (session['usuario']['id'],))
                materias = cursor.fetchall()
            
            return render_template('profesor/dashboard.html', 
                                usuario=session['usuario'],
                                materias=materias)
            
    except Exception as e:
        app.logger.error(f"Error en profesor dashboard: {str(e)}")
        flash("Ocurrió un error al cargar el dashboard", "error")
        return render_template('profesor/dashboard.html', usuario=session['usuario'])
    finally:
        if 'conexion' in locals() and conexion:
            conexion.close()

@app.route('/estudiante/dashboard')
def estudiante_dashboard():
    if 'usuario' not in session or session['usuario']['tipo'] != 'estudiante':
        return redirect(url_for('home'))
    
    try:
        conexion = create_connection()
        if not conexion:
            flash("Error de conexión con la base de datos", "error")
            return render_template('estudiante/dashboard.html', usuario=session['usuario'])
            
        with conexion.cursor(dictionary=True) as cursor:
            # Obtener notificaciones (verificando estructura de tabla)
            notificaciones = []
            cursor.execute("SHOW TABLES LIKE 'notificaciones'")
            if cursor.fetchone():
                cursor.execute("SHOW COLUMNS FROM notificaciones LIKE 'mensaje'")
                if cursor.fetchone():
                    cursor.execute("""
                        SELECT mensaje, fecha 
                        FROM notificaciones 
                        WHERE id_estudiante = %s
                        ORDER BY fecha DESC
                        LIMIT 5
                    """, (session['usuario']['id'],))
                    notificaciones = cursor.fetchall()
            
            # Obtener materias inscritas
            materias = []
            cursor.execute("SHOW TABLES LIKE 'inscripciones'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT m.id, m.nombre 
                    FROM inscripciones i
                    JOIN materias m ON i.id_materia = m.id
                    WHERE i.id_estudiante = %s
                """, (session['usuario']['id'],))
                materias = cursor.fetchall()
            
            return render_template('estudiante/dashboard.html', 
                                usuario=session['usuario'],
                                notificaciones=notificaciones,
                                materias=materias)
            
    except Exception as e:
        app.logger.error(f"Error en estudiante dashboard: {str(e)}")
        flash("Ocurrió un error al cargar el dashboard", "error")
        return render_template('estudiante/dashboard.html', usuario=session['usuario'])
    finally:
        if 'conexion' in locals() and conexion:
            conexion.close()

@app.route('/padre/dashboard')
def padre_dashboard():
    if 'usuario' not in session or session['usuario']['tipo'] != 'padre':
        return redirect(url_for('home'))
    
    try:
        conexion = create_connection()
        if not conexion:
            flash("Error de conexión con la base de datos", "error")
            return render_template('padre/dashboard.html', usuario=session['usuario'])
            
        with conexion.cursor(dictionary=True) as cursor:
            # Obtener estudiantes asociados al padre
            estudiantes = []
            cursor.execute("SHOW TABLES LIKE 'padres_estudiantes'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT e.id, e.nombre 
                    FROM padres_estudiantes pe
                    JOIN estudiantes e ON pe.id_estudiante = e.id
                    WHERE pe.id_padre = %s
                """, (session['usuario']['id'],))
                estudiantes = cursor.fetchall()
            
            return render_template('padre/dashboard.html', 
                                usuario=session['usuario'],
                                estudiantes=estudiantes)
            
    except Exception as e:
        app.logger.error(f"Error en padre dashboard: {str(e)}")
        flash("Ocurrió un error al cargar el dashboard", "error")
        return render_template('padre/dashboard.html', usuario=session['usuario'])
    finally:
        if 'conexion' in locals() and conexion:
            conexion.close()

# --------------------------
# Ruta para ver notas del estudiante (versión mejorada)
# --------------------------
@app.route('/estudiante/ver_notas')
def ver_notas():
    # Verificación de autenticación y rol
    if 'usuario' not in session or session['usuario']['tipo'] != 'estudiante':
        flash("Debes iniciar sesión como estudiante para acceder a esta página.", "error")
        return redirect(url_for('home'))
    
    try:
        # Establecer conexión a la base de datos
        conexion = create_connection()
        if not conexion:
            flash("Error al conectar con la base de datos.", "error")
            return redirect(url_for('estudiante_dashboard'))
        
        with conexion.cursor(dictionary=True) as cursor:
            # Consulta para obtener las notas del estudiante
            query = """
            SELECT 
                m.nombre AS materia,
                IFNULL(n.calificacion, 'Sin calificar') AS calificacion,
                m.descripcion
            FROM inscripciones i
            JOIN materias m ON i.id_materia = m.id
            LEFT JOIN notas n ON i.id_estudiante = n.id_estudiante AND i.id_materia = n.id_materia
            WHERE i.id_estudiante = %s
            ORDER BY m.nombre
            """
            cursor.execute(query, (session['usuario']['id'],))
            notas = cursor.fetchall()
            
            # Si no hay materias inscritas
            if not notas:
                flash("No estás inscrito en ninguna materia actualmente.", "info")
                return redirect(url_for('estudiante_dashboard'))
            
            return render_template('estudiante/ver_notas.html', usuario=session['usuario'], notas=notas)
    
    except Exception as e:
        app.logger.error(f"Error al obtener notas: {str(e)}")
        flash("Ocurrió un error al obtener tus notas.", "error")
        return redirect(url_for('estudiante_dashboard'))
    
    finally:
        if 'conexion' in locals() and conexion:
            conexion.close()

# Punto de entrada principal
if __name__ == '__main__':
    app.run(debug=True)