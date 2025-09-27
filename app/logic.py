import time
import asyncio
import os
from dotenv import load_dotenv
from pysros.management import connect as pysros_connect
from pysros.exceptions import SrosMgmtError
from pygnmi.client import gNMIclient
from . import models
import logging

logger = logging.getLogger(__name__)

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
    logger.info(f"INFO: Iniciando creación de suscriptor '{host_name}' en BNG '{bng}'.")
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
        logger.info(f"DEBUG: Payload de creación para '{host_name}': {payload}")
        
        for attempt in range(max_retries):
            try:
                client.set(update=[(gnmi_path, payload)])
                logger.info(f"SUCCESS: Configuración para '{host_name}' aplicada con éxito en '{bng}'.")
                return f"Suscriptor '{host_name}' creado exitosamente."
            except Exception as e:
                logger.warning(f"WARN: Intento {attempt + 1} fallido para crear '{host_name}' en '{bng}': {e}")
                if "Commit or validate is in progress" in str(e):
                    time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo aplicar config para '{host_name}' en {bng} tras {max_retries} intentos.")

def _internal_delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    device_config = DEVICES.get(bng)
    host_name = accountidbss
    logger.info(f"INFO: Iniciando eliminación de suscriptor '{host_name}' en BNG '{bng}'.")
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
            raise ValueError(f"Conflicto de datos en {bng}: El subnatid no coincide para '{host_name}'.")
        if configured_pool != olt:
            raise ValueError(f"Conflicto de datos en {bng}: La OLT/Pool no coincide para '{host_name}'.")

        for attempt in range(max_retries):
            try:
                client.set(delete=[gnmi_path])
                logger.info(f"SUCCESS: Suscriptor '{host_name}' eliminado con éxito de '{bng}'.")
                return f"Suscriptor '{host_name}' eliminado exitosamente."
            except Exception as e:
                logger.warning(f"WARN: Intento {attempt + 1} fallido para eliminar '{host_name}' en '{bng}': {e}")
                if "Commit or validate is in progress" in str(e):
                    time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo eliminar al suscriptor '{host_name}' de {bng} tras {max_retries} intentos.")

def _internal_update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    device_config = DEVICES.get(bng)
    host_name = accountidbss
    logger.info(f"INFO: Iniciando actualización de suscriptor '{host_name}' en BNG '{bng}'.")
    max_retries, retry_delay_seconds = 5, 3
    pysros_connection = None
    
    try:
        if update_data.plan is not None:
            logger.info(f"DEBUG: Plan no es nulo, ejecutando CoA para cambiar plan a '{update_data.plan}'.")
            command = f'tools perform subscriber-mgmt coa alc-subscr-id {subnatid}_{accountidbss} attr ["6527,13={update_data.plan}"]'
            for attempt in range(max_retries):
                try:
                    pysros_connection = pysros_connect(host=device_config["host"], username=device_config["username"], password=device_config["password"], port=device_config.get("netconf_port", 830), hostkey_verify=False, allow_agent=False, look_for_keys=False)
                    break
                except SrosMgmtError as e:
                    logger.warning(f"WARN: Intento {attempt + 1} de conexión pysros fallido: {e}")
                    if "Commit or validate is in progress" in str(e): time.sleep(retry_delay_seconds)
                    else: raise e
            else:
                raise SrosMgmtError("No se pudo conectar con pysros por bloqueo persistente.")
            pysros_connection.cli(command)
            logger.info(f"SUCCESS: Comando CoA ejecutado en '{bng}'.")
    finally:
        if pysros_connection: pysros_connection.disconnect()

    with gNMIclient(target=(device_config["host"], device_config.get("gnmi_port", 57400)), username=device_config["username"], password=device_config["password"], insecure=True) as client:
        gnmi_path = f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={host_name}]"
        check_response = client.get(path=[gnmi_path])
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
            logger.info(f"INFO: No hay cambios en el payload para '{host_name}', se omite la operación 'set'.")
            host_data = updates[0]["val"]
            return {"state": host_data.get("admin-state"), "plan": host_data.get("identification", {}).get("sla-profile-string"), "mac": host_data.get("host-identification", {}).get("mac")}

        logger.info(f"DEBUG: Payload de actualización para '{host_name}': {payload}")
        for attempt in range(max_retries):
            try:
                client.set(update=[(gnmi_path, payload)])
                logger.info(f"SUCCESS: Payload de actualización aplicado para '{host_name}' en '{bng}'.")
                break
            except Exception as e:
                logger.warning(f"WARN: Intento {attempt + 1} fallido para actualizar '{host_name}' en '{bng}': {e}")
                if "Commit or validate is in progress" in str(e): time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo actualizar al suscriptor '{host_name}'.")

        final_state_response = client.get(path=[gnmi_path])
        final_updates = final_state_response.get("notification", [{}])[0].get("update", [])
        if final_updates and "val" in final_updates[0]:
            host_data = final_updates[0]["val"]
            return {"state": host_data.get("admin-state"), "plan": host_data.get("identification", {}).get("sla-profile-string"), "mac": host_data.get("host-identification", {}).get("mac")}
        else:
            raise Exception("No se pudo obtener el estado final del suscriptor.")

# --- FUNCIONES PÚBLICAS (DISPATCHERS) - GESTIONAN CLUSTERS ---

async def get_all_subscribers_logic(bng: str, skip: int, limit: int):
    bng_list = CLUSTERS.get(bng, [bng])
    last_error = None
    for bng_node in bng_list:
        try:
            list_of_subscribers = await asyncio.to_thread(_internal_get_all_subscribers_logic, bng_node, skip, limit)
            return {"data": list_of_subscribers}
        except Exception as e:
            logger.error(f"ERROR: Fallo al consultar {bng_node} (get_all): {e}")
            last_error = e
    raise last_error

async def get_subscriber_by_name_logic(bng: str, accountidbss: str):
    bng_list = CLUSTERS.get(bng, [bng])
    last_error = None
    for bng_node in bng_list:
        try:
            subscriber_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, bng_node, accountidbss)
            return {"data": subscriber_data}
        except Exception as e:
            logger.error(f"ERROR: Fallo al consultar {bng_node} (get_by_name): {e}")
            last_error = e
    raise last_error

async def _run_write_tasks_in_parallel(worker_func, bng_list, *args):
    """Ejecuta tareas de escritura en paralelo y reporta éxitos y fallos."""
    tasks = [asyncio.to_thread(worker_func, bng_node, *args) for bng_node in bng_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    successful_nodes = {}
    failed_nodes = {}
    
    for bng_node, res in zip(bng_list, results):
        if isinstance(res, Exception):
            failed_nodes[bng_node] = str(res)
            logger.error(f"ERROR: La operación falló en el nodo '{bng_node}': {res}")
        else:
            successful_nodes[bng_node] = res
            logger.info(f"SUCCESS: La operación tuvo éxito en el nodo '{bng_node}'.")

    return {"successful_nodes": successful_nodes, "failed_nodes": failed_nodes}

async def create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    """Lógica de creación en Paralelo con reporte detallado."""
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    
    results = await _run_write_tasks_in_parallel(_internal_create_subscriber_logic, bng_list, subscriber_data)

    if results["failed_nodes"]:
        # Si hay fallos, el resultado ya contiene el detalle para la excepción
        return results

    logger.info(f"INFO: Creación exitosa en todos los nodos: {list(results['successful_nodes'].keys())}. Obteniendo estado final de '{primary_bng}'.")
    final_state = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, subscriber_data.accountidbss)
    full_sub_id = final_state.get("identification", {}).get("subscriber-id", "")
    subnatid = full_sub_id.split('_')[0] if '_' in full_sub_id else None

    response_data = {
        "accountidbss": final_state.get("host-name"),
        "state": final_state.get("admin-state"),
        "mac": final_state.get("host-identification", {}).get("mac"),
        "subnatid": subnatid,
        "plan": final_state.get("identification", {}).get("sla-profile-string"),
        "olt": final_state.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")
    }
    
    results["data"] = response_data
    return results


async def delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    """Lógica de borrado en Paralelo con reporte detallado."""
    bng_list = CLUSTERS.get(bng, [bng])
    results = await _run_write_tasks_in_parallel(_internal_delete_subscriber_logic, bng_list, accountidbss, subnatid, olt)
    return results

async def update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    """Lógica de actualización en Paralelo con reporte detallado."""
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    
    results = await _run_write_tasks_in_parallel(_internal_update_subscriber_logic, bng_list, accountidbss, subnatid, update_data)

    if results["failed_nodes"]:
        return results

    logger.info(f"INFO: Actualización exitosa en todos los nodos: {list(results['successful_nodes'].keys())}. Obteniendo estado final de '{primary_bng}'.")
    final_state = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, accountidbss)
    
    mapped_response = {
        "state": final_state.get("admin-state"),
        "plan": final_state.get("identification", {}).get("sla-profile-string"),
        "mac": final_state.get("host-identification", {}).get("mac"),
    }
    results["data"] = mapped_response
    return results