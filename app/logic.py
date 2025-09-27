import time
import asyncio
import os
from dotenv import load_dotenv
from pysros.management import connect as pysros_connect
from pysros.exceptions import SrosMgmtError
from pygnmi.client import gNMIclient
from . import models

load_dotenv()

username_gnmi = os.environ.get('username_gnmi')
password_gnmi = os.environ.get('password_gnmi')

# --- CONFIGURACIÓN DE DISPOSITIVOS Y CLUSTERS ---

DEVICES = {
    "bng-principal": {
        "host": "10.100.0.25",
        "gnmi_port": 57400,
        "netconf_port": 830,
        "username": username_gnmi,
        "password": password_gnmi
    },
    "bng-secundario": {
        "host": "10.100.0.29",
        "gnmi_port": 57400,
        "netconf_port": 830,
        "username": username_gnmi,
        "password": password_gnmi
    }
}

CLUSTERS = {
    "CCS-01": ["bng-principal", "bng-secundario"]
}

# --- FUNCIONES INTERNAS (WORKERS) - OPERAN EN UN SOLO BNG ---
# (Este es tu código original, renombrado y organizado)

def _internal_get_all_subscribers_logic(bng: str, skip: int, limit: int):
    device_config = DEVICES.get(bng)
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host"
    with gNMIclient(target=(device_config["host"], device_config["gnmi_port"]), username=device_config["username"], password=device_config["password"], insecure=True) as client:
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
        
        final_results = []
        notifications = details_response.get("notification", [])
        for notification in notifications:
            update_list = notification.get("update", [])
            if not update_list: continue
            host_data = update_list[0].get("val", {})
            if not host_data: continue
            
            # --- CAMBIO 1: La función interna ahora añade el objeto sin la envoltura "data" ---
            final_results.append(host_data)
            
        return final_results

def _internal_get_subscriber_by_name_logic(bng: str, accountidbss: str):
    device_config = DEVICES.get(bng)
    gnmi_path = f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={accountidbss}]"
    with gNMIclient(target=(device_config["host"], device_config["gnmi_port"]), username=device_config["username"], password=device_config["password"], insecure=True) as client:
        gnmi_response = client.get(path=[gnmi_path])
        updates = gnmi_response.get("notification", [{}])[0].get("update", [])
        if not (updates and "val" in updates[0]):
            raise ValueError(f"Suscriptor '{accountidbss}' no encontrado en BNG '{bng}'.")
        return updates[0]["val"]

def _internal_create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    device_config = DEVICES.get(bng)
    host_name = subscriber_data.accountidbss
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
    gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"
    max_retries, retry_delay_seconds = 5, 3
    with gNMIclient(target=(device_config["host"], device_config["gnmi_port"]), username=device_config["username"], password=device_config["password"], insecure=True) as client:
        check_response = client.get(path=[gnmi_path])
        updates = check_response.get("notification", [{}])[0].get("update", [])
        if updates and "val" in updates[0]:
            raise ValueError(f"El suscriptor '{host_name}' ya existe en {bng}.")
        payload = {
            "host-name": host_name, "admin-state": subscriber_data.state,
            "host-identification": { "mac": subscriber_data.mac },
            "identification": {
                "option-number": 254, "sla-profile-string": subscriber_data.plan,
                "sub-profile-string": "DEFAULT-SUB-PROF",
                "subscriber-id": f"{subscriber_data.subnatid}_{subscriber_data.accountidbss}"
            },
            "ipv4": { "address": { "pool": { "primary": subscriber_data.olt } } },
            "ipv6": { "address-pool": subscriber_data.olt, "delegated-prefix-pool": subscriber_data.olt }
        }
        for attempt in range(max_retries):
            try:
                client.set(update=[(gnmi_path, payload)])
                print(f"Configuración para '{host_name}' aplicada con éxito en {bng}.")
                return # Éxito
            except Exception as e:
                if "Commit or validate is in progress" in str(e):
                    time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo aplicar config para '{host_name}' en {bng} tras {max_retries} intentos.")

def _internal_delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    device_config = DEVICES.get(bng)
    host_name = accountidbss
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
    gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"
    max_retries, retry_delay_seconds = 5, 3
    with gNMIclient(target=(device_config["host"], device_config["gnmi_port"]), username=device_config["username"], password=device_config["password"], insecure=True) as client:
        check_response = client.get(path=[gnmi_path])
        updates = check_response.get("notification", [{}])[0].get("update", [])
        if not (updates and "val" in updates[0]):
            raise ValueError(f"El suscriptor '{host_name}' no existe en {bng}.")
        host_data = updates[0]["val"]
        configured_sub_id = host_data.get("identification", {}).get("subscriber-id")
        configured_pool = host_data.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")
        if configured_sub_id != f"{subnatid}_{accountidbss}":
            raise ValueError(f"Conflicto de datos en {bng}: El subnatid no coincide.")
        if configured_pool != olt:
            raise ValueError(f"Conflicto de datos en {bng}: La OLT/Pool no coincide.")
        for attempt in range(max_retries):
            try:
                client.set(delete=[gnmi_path])
                print(f"Suscriptor '{host_name}' eliminado con éxito de {bng}.")
                return # Éxito
            except Exception as e:
                if "Commit or validate is in progress" in str(e):
                    time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo eliminar al suscriptor '{host_name}' de {bng} tras {max_retries} intentos.")

def _internal_update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    # Esta es la lógica 'update' que ya teníamos
    # (Incluyendo pysros y reintentos)
    # ... (Por brevedad, se omite el código idéntico. Pega tu función 'update' aquí)
    print(f"EJECUTANDO UPDATE EN {bng}")
    # Esta es la implementación completa de tu 'update_subscriber_logic'
    device_config = DEVICES.get(bng)
    host_name = accountidbss
    max_retries, retry_delay_seconds = 5, 3
    pysros_connection = None
    try:
        if update_data.plan is not None:
            command = f'tools perform subscriber-mgmt coa alc-subscr-id {subnatid}_{accountidbss} attr ["6527,13={update_data.plan}"]'
            for attempt in range(max_retries):
                try:
                    pysros_connection = pysros_connect(host=device_config["host"], username=device_config["username"], password=device_config["password"], port=device_config.get("netconf_port", 830), hostkey_verify=False)
                    break
                except SrosMgmtError as e:
                    if "Commit or validate is in progress" in str(e): time.sleep(retry_delay_seconds)
                    else: raise e
            else:
                raise SrosMgmtError("No se pudo conectar con pysros por bloqueo persistente.")
            pysros_connection.cli(command)
    finally:
        if pysros_connection: pysros_connection.disconnect()
    with gNMIclient(target=(device_config["host"], device_config.get("gnmi_port", 57400)), username=device_config["username"], password=device_config["password"], insecure=True) as client:
        check_response = client.get(path=[f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={host_name}]"])
        updates = check_response.get("notification", [{}])[0].get("update", [])
        if not (updates and "val" in updates[0]):
            raise ValueError(f"El suscriptor '{host_name}' no existe.")
        payload = {}
        if update_data.mac is not None: payload["host-identification"] = {"mac": update_data.mac}
        if update_data.state is not None: payload["admin-state"] = update_data.state
        identification_payload = {}
        if update_data.plan is not None: identification_payload["sla-profile-string"] = update_data.plan
        if identification_payload: payload["identification"] = identification_payload
        if not payload:
            host_data = updates[0]["val"]
            return {"state": host_data.get("admin-state"), "plan": host_data.get("identification", {}).get("sla-profile-string"), "mac": host_data.get("host-identification", {}).get("mac")}
        for attempt in range(max_retries):
            try:
                client.set(update=[(f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={host_name}]", payload)])
                break
            except Exception as e:
                if "Commit or validate is in progress" in str(e): time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo actualizar al suscriptor '{host_name}'.")
        final_state_response = client.get(path=[f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={host_name}]"])
        final_updates = final_state_response.get("notification", [{}])[0].get("update", [])
        if final_updates and "val" in final_updates[0]:
            host_data = final_updates[0]["val"]
            return {"state": host_data.get("admin-state"), "plan": host_data.get("identification", {}).get("sla-profile-string"), "mac": host_data.get("host-identification", {}).get("mac")}
        else:
            raise Exception("No se pudo obtener el estado final del suscriptor.")

# --- FUNCIONES PÚBLICAS (DISPATCHERS) - GESTIONAN CLUSTERS ---

async def get_all_subscribers_logic(bng: str, skip: int, limit: int):
    """Lógica de lectura con Failover."""
    bng_list = CLUSTERS.get(bng, [bng])
    last_error = None
    for bng_node in bng_list:
        try:
            # Obtenemos la lista simple de suscriptores
            list_of_subscribers = await asyncio.to_thread(_internal_get_all_subscribers_logic, bng_node, skip, limit)
            
            return {"data": list_of_subscribers}
            
        except Exception as e:
            print(f"Fallo al consultar {bng_node} (get_all): {e}")
            last_error = e
    raise last_error

async def get_subscriber_by_name_logic(bng: str, accountidbss: str):
    """Lógica de lectura con Failover."""
    bng_list = CLUSTERS.get(bng, [bng])
    last_error = None
    for bng_node in bng_list:
        try:
            # 1. Obtenemos el resultado del BNG (que es el objeto del suscriptor)
            subscriber_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, bng_node, accountidbss)
            
            return {"data": subscriber_data}
            
        except Exception as e:
            print(f"Fallo al consultar {bng_node} (get_by_name): {e}")
            last_error = e
    raise last_error

async def _run_write_tasks_in_parallel(worker_func, bng_list, *args):
    """Función helper para ejecutar tareas de escritura en paralelo."""
    tasks = [asyncio.to_thread(worker_func, bng_node, *args) for bng_node in bng_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    failed = [res for res in results if isinstance(res, Exception)]
    if failed:
        # Agregamos los resultados de los BNGs que sí funcionaron para más contexto
        successful = [res for res in results if not isinstance(res, Exception)]
        error_message = f"Una o más operaciones fallaron. Errores: {[str(f) for f in failed]}. Éxitos: {successful}"
        raise Exception(error_message)
    return results

async def create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    """Lógica de creación en Paralelo."""
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    await _run_write_tasks_in_parallel(_internal_create_subscriber_logic, bng_list, subscriber_data)
    print(f"Creación exitosa en {bng_list}. Obteniendo estado final de {primary_bng}.")
    final_state = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, subscriber_data.accountidbss)
    return final_state

async def delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    """Lógica de borrado en Paralelo."""
    bng_list = CLUSTERS.get(bng, [bng])
    await _run_write_tasks_in_parallel(_internal_delete_subscriber_logic, bng_list, accountidbss, subnatid, olt)
    print(f"Borrado exitoso en {bng_list}.")
    # No hay estado final que devolver tras un borrado.
    return

async def update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    """Lógica de actualización en Paralelo."""
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    await _run_write_tasks_in_parallel(_internal_update_subscriber_logic, bng_list, accountidbss, subnatid, update_data)
    print(f"Actualización exitosa en {bng_list}. Obteniendo estado final de {primary_bng}.")
    final_state = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, accountidbss)
    # Mapeamos al formato de respuesta de update
    return {
        "state": final_state.get("admin-state"),
        "plan": final_state.get("identification", {}).get("sla-profile-string"),
        "mac": final_state.get("host-identification", {}).get("mac"),
    }