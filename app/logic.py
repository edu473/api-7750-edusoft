# app/logic.py
from pygnmi.client import gNMIclient
from . import models
from pysros.management import connect as pysros_connect
from pysros.exceptions import SrosMgmtError
import time
import os
from dotenv import load_dotenv

load_dotenv()

# Estas son las funciones que debes reemplazar con tu propia lógica.
# Por ahora, simplemente devuelven datos de ejemplo para que la API funcione.
username_gnmi= os.environ.get('username_gnmi')
password_gnmi= os.environ.get('password_gnmi')

DEVICES = {
    "bng-principal": {
        "host": "10.100.0.29",
        "port": 57400,
        "netconf_port": 830,
        "username": username_gnmi,
        "password": password_gnmi
    }
}


def get_all_subscribers_logic(bng: str, skip: int, limit: int):
    """
    (Versión final y optimizada)
    Obtiene una lista paginada de suscriptores de forma eficiente.
    """
    device_config = DEVICES.get(bng)
    if not device_config:
        return {"error": f"Configuración para el BNG '{bng}' no encontrada."}

    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host"

    try:
        with gNMIclient(
            target=(device_config["host"], device_config["port"]),
            username=device_config["username"],
            password=device_config["password"],
            insecure=True
        ) as client:
            
            gnmi_path_keys = f"{gnmi_base_path}/identification/subscriber-id"
            keys_response = client.get(path=[gnmi_path_keys], encoding='json_ietf')
            
            all_host_names = []
            updates_keys = keys_response.get("notification", [{}])[0].get("update", [])
            for update in updates_keys:
                full_sub_id = update.get("val")
                if full_sub_id and '_' in full_sub_id:
                    host_name = full_sub_id.split('_')[-1]
                    all_host_names.append(host_name)

            paginated_ids = all_host_names[skip : skip + limit]
            if not paginated_ids:
                return []

            paths_for_details = [f"{gnmi_base_path}[host-name={sub_id}]" for sub_id in paginated_ids]
            details_response = client.get(path=paths_for_details)
            
            # --- Procesamiento Final y Corregido ---
            final_results = []
            # La respuesta es una lista de notificaciones, una por cada path solicitado.
            notifications = details_response.get("notification", [])
            for notification in notifications:
                # Cada notificación tiene su propia lista de 'updates' (usualmente con un solo elemento)
                update_list = notification.get("update", [])
                if not update_list:
                    continue
                
                # Accedemos al primer elemento de 'update' para obtener los datos
                host_data = update_list[0].get("val", {})
                if not host_data:
                    continue
                
                # Mapeamos los datos a un diccionario simple (sin la envoltura "data")
                final_response ={
                        "host-name": host_data.get("host-name"),
                        "admin-state": host_data.get("admin-state"),
                        "host-identification": {
                            "mac": host_data.get("host-identification", {}).get("mac")
                        },
                        "identification": {
                            "option-number": str(host_data.get("identification", {}).get("option-number", "")),
                            "sla-profile-string": host_data.get("identification", {}).get("sla-profile-string"),
                            "sub-profile-string": host_data.get("identification", {}).get("sub-profile-string"),
                            "subscriber-id": host_data.get("identification", {}).get("subscriber-id")
                        },
                        "ipv4": {
                            "address": {
                                "pool": {
                                    "primary": host_data.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")
                                }
                            }
                        },
                        "ipv6": {
                            "address-pool": host_data.get("ipv6", {}).get("address-pool"),
                            "delegated-prefix-pool": host_data.get("ipv6", {}).get("delegated-prefix-pool")
                        }
                    }

                final_results.append({"data": final_response})
            
            return final_results

    except Exception as e:
        return {"error": f"Ocurrió un error al comunicarse con el BNG: {e}"}

def create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    """
    Crea un nuevo suscriptor en el BNG, solo si no existe previamente.
    Lanza un ValueError si el suscriptor ya existe.
    """
    device_config = DEVICES.get(bng)
    if not device_config:
        # Para errores de configuración, podemos seguir lanzando un error simple
        raise ValueError(f"Configuración para el BNG '{bng}' no encontrada.")

    host_name = subscriber_data.accountidbss
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
    gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"
    max_retries = 5  # Número máximo de intentos
    retry_delay_seconds = 3

    try:
        with gNMIclient(
            target=(device_config["host"], device_config["port"]),
            username=device_config["username"],
            password=device_config["password"],
            insecure=True
        ) as client:

            check_response = client.get(path=[gnmi_path])
            updates = check_response.get("notification", [{}])[0].get("update", [])
            
            if updates and "val" in updates[0]:
                raise ValueError(f"El suscriptor '{host_name}' ya existe.")

            payload = {
                "host-name": host_name,
                "admin-state": subscriber_data.state,
                "host-identification": { "mac": subscriber_data.mac },
                "identification": {
                    "option-number": 254,
                    "sla-profile-string": subscriber_data.plan,
                    "sub-profile-string": "DEFAULT-SUB-PROF",
                    "subscriber-id": f"{subscriber_data.subnatid}_{subscriber_data.accountidbss}"
                },
                "ipv4": { "address": { "pool": { "primary": subscriber_data.olt } } },
                "ipv6": { "address-pool": subscriber_data.olt, "delegated-prefix-pool": subscriber_data.olt }
            }
            
            for attempt in range(max_retries):
                try:
                    # Intentamos ejecutar el Set
                    client.set(update=[(gnmi_path, payload)])
                    
                    # Si la operación fue exitosa, salimos del bucle
                    print(f"Configuración para '{host_name}' aplicada con éxito en el intento {attempt + 1}.")
                    break
                
                except Exception as e:
                    # Si falla, verificamos si es el error de bloqueo
                    if "Commit or validate is in progress" in str(e):
                        print(f"Intento {attempt + 1}/{max_retries} fallido: Commit en progreso. Reintentando en {retry_delay_seconds} segundos...")
                        time.sleep(retry_delay_seconds) # Esperamos antes del siguiente intento
                    else:
                        # Si es otro error, no reintentamos y lanzamos la excepción
                        raise e
            else:
                # Este 'else' se ejecuta si el bucle 'for' termina sin un 'break'
                # Significa que todos los reintentos fallaron.
                raise Exception(f"No se pudo aplicar la configuración para '{host_name}' después de {max_retries} intentos.")

        return subscriber_data

    except ValueError:
        # Re-lanzamos el ValueError para que el router lo capture
        raise
    except Exception as e:
        # Para otros errores, lanzamos una excepción genérica
        raise Exception(f"Error de comunicación con el BNG: {e}")


def get_subscriber_by_name_logic(bng: str, accountidbss: str):
    """
    Se conecta a un BNG vía gNMI y extrae la información de un suscriptor.
    """
    device_config = DEVICES.get(bng)
    if not device_config:
        return {"error": f"Configuración para el BNG '{bng}' no encontrada."}

    gnmi_path = f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={accountidbss}]"

    try:
        with gNMIclient(
            target=(device_config["host"], device_config["port"]),
            username=device_config["username"],
            password=device_config["password"],
            insecure=True
        ) as client:
            gnmi_response = client.get(path=[gnmi_path])

        # --- Extracción y Mapeo de Datos (Versión Corregida) ---
        updates = gnmi_response.get("notification", [{}])[0].get("update", [])
        if not updates:
            return {"error": f"Suscriptor '{accountidbss}' no encontrado en el BNG '{bng}'."}

        host_data = updates[0].get("val", {})
        
        if not host_data:
            return {"error": "El campo 'val' estaba vacío en la respuesta del dispositivo."}
        
        # El resto del código de mapeo ahora funcionará correctamente
        final_response = {
            "data": {
                "host-name": host_data.get("host-name"),
                "admin-state": host_data.get("admin-state"),
                "host-identification": {
                    "mac": host_data.get("host-identification", {}).get("mac")
                },
                "identification": {
                    "option-number": str(host_data.get("identification", {}).get("option-number", "")),
                    "sla-profile-string": host_data.get("identification", {}).get("sla-profile-string"),
                    "sub-profile-string": host_data.get("identification", {}).get("sub-profile-string"),
                    "subscriber-id": host_data.get("identification", {}).get("subscriber-id")
                },
                "ipv4": {
                    "address": {
                        "pool": {
                            "primary": host_data.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")
                        }
                    }
                },
                "ipv6": {
                    "address-pool": host_data.get("ipv6", {}).get("address-pool"),
                    "delegated-prefix-pool": host_data.get("ipv6", {}).get("delegated-prefix-pool")
                }
            }
        }
        
        return final_response

    except Exception as e:
        return {"error": f"Ocurrió un error al comunicarse con el BNG: {e}"}

def delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    """
    (Versión con validación estricta)
    Elimina un suscriptor, pero solo si el subnatid y la olt coinciden.
    """
    device_config = DEVICES.get(bng)
    if not device_config:
        raise ValueError(f"Configuración para el BNG '{bng}' no encontrada.")

    host_name = accountidbss
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
    gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"

    max_retries = 5
    retry_delay_seconds = 3

    try:
        with gNMIclient(
            target=(device_config["host"], device_config["port"]),
            username=device_config["username"],
            password=device_config["password"],
            insecure=True
        ) as client:

            check_response = client.get(path=[gnmi_path])
            updates = check_response.get("notification", [{}])[0].get("update", [])
            
            if not (updates and "val" in updates[0]):
                raise ValueError(f"El suscriptor '{host_name}' no existe.")

            # --- NUEVO BLOQUE DE VALIDACIÓN ESTRICTA ---
            host_data = updates[0]["val"]
            
            # Extraemos los valores configurados en el router
            configured_sub_id = host_data.get("identification", {}).get("subscriber-id")
            configured_pool = host_data.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")

            # Comparamos con los valores recibidos en la API
            if configured_sub_id != subnatid:
                raise ValueError(f"Conflicto de datos: El subnatid proporcionado ('{subnatid}') no coincide con el configurado ('{configured_sub_id}').")
            
            if configured_pool != olt:
                raise ValueError(f"Conflicto de datos: La OLT/Pool proporcionada ('{olt}') no coincide con la configurada ('{configured_pool}').")
            
            # --- FIN DEL BLOQUE DE VALIDACIÓN ---

            # Si todas las validaciones pasan, procedemos con el borrado
            for attempt in range(max_retries):
                try:
                    client.set(delete=[gnmi_path])
                    print(f"Suscriptor '{host_name}' validado y eliminado con éxito.")
                    return
                
                except Exception as e:
                    if "Commit or validate is in progress" in str(e):
                        print(f"Intento {attempt + 1}/{max_retries} fallido: Commit en progreso...")
                        time.sleep(retry_delay_seconds)
                    else:
                        raise e
            else:
                raise Exception(f"No se pudo eliminar al suscriptor '{host_name}' después de {max_retries} intentos.")

    except ValueError:
        raise
    except Exception as e:
        raise Exception(f"Error en la lógica de eliminación: {e}")

def update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    """
    (Versión final robusta)
    Actualiza un suscriptor, aplicando lógica de reintentos tanto para
    la ejecución de comandos con pysros como para la actualización con pygnmi.
    """
    device_config = DEVICES.get(bng)
    if not device_config:
        raise ValueError(f"Configuración para el BNG '{bng}' no encontrada.")

    host_name = accountidbss
    
    max_retries = 5
    retry_delay_seconds = 3

    # --- PASO 1: Ejecutar comando previo con PYSROS (con reintentos) ---
    pysros_connection = None
    try:
        if update_data.plan is not None:
            command = f'tools perform subscriber-mgmt coa alc-subscr-id {subnatid}_{accountidbss} attr ["6527,13={update_data.plan}"]'
            print(f"Ejecutando comando previo con pysros: {command}")
            
            for attempt in range(max_retries):
                try:
                    pysros_connection = pysros_connect(
                        host=device_config["host"],
                        username=device_config["username"],
                        password=device_config["password"],
                        port=device_config.get("netconf_port", 830),
                        hostkey_verify=False
                    )
                    print(f"Conexión con pysros exitosa en el intento {attempt + 1}.")
                    break
                except SrosMgmtError as e:
                    if "Commit or validate is in progress" in str(e):
                        print(f"Intento de conexión {attempt + 1}/{max_retries} con pysros fallido: Commit en progreso. Reintentando...")
                        time.sleep(retry_delay_seconds)
                    else:
                        raise e
            else:
                raise SrosMgmtError(f"No se pudo conectar con pysros después de {max_retries} intentos debido a un bloqueo persistente.")

            result = pysros_connection.cli(command)
            print(f"Resultado del comando 'tools dump': {result}")
        
    except (SrosMgmtError, Exception) as e:
        raise Exception(f"Falló el comando previo con pysros: {e}")
    finally:
        if pysros_connection:
            pysros_connection.disconnect()
            
    # --- PASO 2: Proceder con la actualización gNMI ---
    print("Procediendo con la actualización de configuración vía gNMI...")
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
    gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"

    try:
        with gNMIclient(
            target=(device_config["host"], device_config.get("gnmi_port", 57400)),
            username=device_config["username"],
            password=device_config["password"],
            insecure=True
        ) as client:

            check_response = client.get(path=[gnmi_path])
            updates = check_response.get("notification", [{}])[0].get("update", [])
            if not (updates and "val" in updates[0]):
                raise ValueError(f"El suscriptor '{host_name}' no existe. No se puede actualizar.")

            payload = {}
            if update_data.mac is not None:
                payload["host-identification"] = {"mac": update_data.mac}
            if update_data.state is not None:
                payload["admin-state"] = update_data.state
            
            identification_payload = {}
            if update_data.plan is not None:
                identification_payload["sla-profile-string"] = update_data.plan
            
            if identification_payload:
                payload["identification"] = identification_payload
            
            if not payload:
                print("No hay campos para actualizar en la configuración gNMI.")
                host_data = updates[0]["val"]
                return {
                    "state": host_data.get("admin-state"),
                    "plan": host_data.get("identification", {}).get("sla-profile-string"),
                    "mac": host_data.get("host-identification", {}).get("mac"),
                }

            for attempt in range(max_retries):
                try:
                    client.set(update=[(gnmi_path, payload)])
                    print(f"Suscriptor '{host_name}' actualizado con éxito.")
                    break
                except Exception as e:
                    if "Commit or validate is in progress" in str(e):
                        print(f"Intento {attempt + 1}/{max_retries} de actualización gNMI fallido: Commit en progreso...")
                        time.sleep(retry_delay_seconds)
                    else:
                        raise e
            else:
                raise Exception(f"No se pudo actualizar al suscriptor '{host_name}' después de {max_retries} intentos.")

            # --- PASO 3: OBTENER Y DEVOLVER EL ESTADO FINAL CON EL FORMATO REQUERIDO ---
            final_state_response = client.get(path=[gnmi_path])
            final_updates = final_state_response.get("notification", [{}])[0].get("update", [])
            if final_updates and "val" in final_updates[0]:
                host_data = final_updates[0]["val"]
                # Construimos el objeto de respuesta final y plano
                response_object = {
                    "state": host_data.get("admin-state"),
                    "plan": host_data.get("identification", {}).get("sla-profile-string"),
                    "mac": host_data.get("host-identification", {}).get("mac"),
                }
                return response_object
            else:
                raise Exception("No se pudo obtener el estado final del suscriptor después de la actualización.")

    except ValueError:
        raise
    except Exception as e:
        raise Exception(f"Error en la lógica de actualización: {e}")