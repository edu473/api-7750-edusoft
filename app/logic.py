# app/logic.py
import time
import asyncio
import os
from dotenv import load_dotenv
from pysros.management import connect as pysros_connect
from pysros.exceptions import SrosMgmtError
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from pygnmi.client import gNMIclient
from . import models
import logging

logger = logging.getLogger("app")

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

# --- GESTIÓN DE CONEXIONES Y CONCURRENCIA (NUEVO) ---

# Pool para reutilizar clientes gNMI y evitar abrir sesiones innecesarias
GNMI_CLIENTS = {}
# Un Lock por cada BNG para evitar escrituras simultáneas que causan conflictos
BNG_WRITE_LOCKS = {bng: asyncio.Lock() for bng in DEVICES}

def get_gnmi_client(bng: str) -> gNMIclient:
    """
    Crea o reutiliza una conexión de cliente gNMI para un BNG específico.
    Esto previene el agotamiento de sesiones en el dispositivo.
    """
    if bng not in GNMI_CLIENTS:
        logger.info(f"Creando nueva conexión gNMI para {bng}")
        device_config = DEVICES.get(bng)
        client = gNMIclient(
            target=(device_config["host"], device_config["gnmi_port"]),
            username=device_config["username"],
            password=device_config["password"],
            insecure=True
        )
        # Se conecta al crear la instancia
        GNMI_CLIENTS[bng] = client
    return GNMI_CLIENTS[bng]


# --- FUNCIONES INTERNAS (WORKERS) - OPERAN EN UN SOLO BNG ---
# Nota: Las funciones de escritura ahora son `async` y usan el Lock.

def _internal_get_all_subscribers_logic(bng: str, skip: int, limit: int):
    client = get_gnmi_client(bng)
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host"
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
    client = get_gnmi_client(bng)
    gnmi_path = f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={accountidbss}]"
    gnmi_response = client.get(path=[gnmi_path])
    updates = gnmi_response.get("notification", [{}])[0].get("update", [])
    if not (updates and "val" in updates[0]):
        raise ValueError(f"Suscriptor '{accountidbss}' no encontrado.")
    return updates[0]["val"]

async def _internal_create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    async with BNG_WRITE_LOCKS[bng]:
        client = get_gnmi_client(bng)
        host_name = subscriber_data.accountidbss
        logger.info(f"INFO: Iniciando creación de suscriptor '{host_name}' en BNG '{bng}'.")
        gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
        gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"
        max_retries, retry_delay_seconds = 20, 3
        
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
                if "reached maximum number of private sessions" in str(e):
                    try:
                        await asyncio.to_thread(_disconnect_netconf_sessions, bng)
                        await asyncio.sleep(retry_delay_seconds)
                        continue
                    except Exception as disconnect_e:
                        logger.error(f"Error al intentar limpiar sesiones en {bng}: {disconnect_e}")
                if ("Commit or validate is in progress" in str(e)) or ("Database write access is not available" in str(e)):
                    await asyncio.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo aplicar config para '{host_name}' en {bng} tras {max_retries} intentos.")

async def _internal_delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    async with BNG_WRITE_LOCKS[bng]:
        client = get_gnmi_client(bng)
        host_name = accountidbss
        logger.info(f"INFO: Iniciando eliminación de suscriptor '{host_name}' en BNG '{bng}'.")
        gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe"
        gnmi_path = f"{gnmi_base_path}/host[host-name={host_name}]"
        max_retries, retry_delay_seconds = 20, 3

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
                if "reached maximum number of private sessions" in str(e):
                    try:
                        await asyncio.to_thread(_disconnect_netconf_sessions, bng)
                        await asyncio.sleep(retry_delay_seconds)
                        continue
                    except Exception as disconnect_e:
                        logger.error(f"Error al intentar limpiar sesiones en {bng}: {disconnect_e}")
                if ("Commit or validate is in progress" in str(e)) or ("Database write access is not available" in str(e)):
                    await asyncio.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo eliminar al suscriptor '{host_name}' de {bng} tras {max_retries} intentos.")

async def _internal_update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    async with BNG_WRITE_LOCKS[bng]:
        device_config = DEVICES.get(bng)
        client = get_gnmi_client(bng)
        host_name = accountidbss
        logger.info(f"INFO: Iniciando actualización de suscriptor '{host_name}' en BNG '{bng}'.")
        max_retries, retry_delay_seconds = 20, 3
        
        if update_data.plan is not None:
            logger.info(f"DEBUG: Plan no es nulo, ejecutando CoA para cambiar plan a '{update_data.plan}'.")
            command = f'tools perform subscriber-mgmt coa alc-subscr-id {subnatid}_{accountidbss} attr ["6527,13={update_data.plan}"]'
            
            def coa_task():
                pysros_connection = None
                try:
                    for attempt in range(max_retries):
                        try:
                            pysros_connection = pysros_connect(host=device_config["host"], username=device_config["username"], password=device_config["password"], port=device_config.get("netconf_port", 830), hostkey_verify=False)
                            break
                        except SrosMgmtError as e:
                            logger.warning(f"WARN: Intento {attempt + 1} de conexión pysros fallido: {e}")
                            if "reached maximum number of private sessions" in str(e):
                                try:
                                    _disconnect_netconf_sessions(bng)
                                    time.sleep(retry_delay_seconds)
                                except Exception as disconnect_e:
                                    logger.error(f"Error al intentar limpiar sesiones en {bng}: {disconnect_e}")
                            if ("Commit or validate is in progress" in str(e)) or ("Database write access is not available" in str(e)): time.sleep(retry_delay_seconds)
                            else: raise e
                    else:
                        raise SrosMgmtError("No se pudo conectar con pysros por bloqueo persistente.")
                    pysros_connection.cli(command)
                    logger.info(f"SUCCESS: Comando CoA ejecutado en '{bng}'.")
                finally:
                    if pysros_connection: pysros_connection.disconnect()
            
            await asyncio.to_thread(coa_task)

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
                if "reached maximum number of private sessions" in str(e):
                    try:
                        await asyncio.to_thread(_disconnect_netconf_sessions, bng)
                        await asyncio.sleep(retry_delay_seconds)
                        continue
                    except Exception as disconnect_e:
                        logger.error(f"Error al intentar limpiar sesiones en {bng}: {disconnect_e}")
                if ("Commit or validate is in progress" in str(e)) or ("Database write access is not available" in str(e)): await asyncio.sleep(retry_delay_seconds)
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

def _internal_clear_ipoe_sessions(bng: str, customers_to_clear: dict):
    # Esta función es síncrona y se llamará con asyncio.to_thread
    device_config = DEVICES.get(bng)
    max_retries, retry_delay_seconds = 20, 3
    pysros_connection = None

    if not customers_to_clear:
        logger.info(f"No hay sesiones de suscriptor para limpiar en {bng}.")
        return "No se requirió limpieza de sesión."
    
    logger.info(f"Iniciando limpieza de sesión para {len(customers_to_clear)} suscriptores en {bng}.")

    try:
        for attempt in range(max_retries):
            try:
                pysros_connection = pysros_connect(host=device_config["host"], username=device_config["username"], password=device_config["password"], port=device_config.get("netconf_port", 830), hostkey_verify=False)
                break
            except SrosMgmtError as e:
                logger.warning(f"WARN: Intento {attempt + 1} de conexión pysros fallido en '{bng}': {e}")
                if "reached maximum number of private sessions" in str(e):
                    try:
                        _disconnect_netconf_sessions(bng)
                        time.sleep(retry_delay_seconds)
                        continue
                    except Exception as disconnect_e:
                        logger.error(f"Error al intentar limpiar sesiones en {bng}: {disconnect_e}")
                if ("Commit or validate is in progress" in str(e)) or ("Database write access is not available" in str(e)):
                    time.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise SrosMgmtError(f"No se pudo conectar con pysros a {bng} por bloqueo persistente.")
        
        for customer_id, data in customers_to_clear.items():
            subscriber_id = data.get("subscriber_id")
            interface = data.get("interface")
            
            if subscriber_id and interface:
                command = f'clear service id "100" ipoe session subscriber "{subscriber_id}" interface "SUBSCRIBER-INTERFACE-1"'
                logger.info(f"Ejecutando en {bng}: {command}")
                pysros_connection.cli(command)
            else:
                logger.warning(f"No se pudo construir comando para {customer_id} en {bng} por falta de datos.")

        logger.info(f"SUCCESS: Comandos de limpieza de sesión ejecutados en '{bng}'.")
        return f"Limpieza de sesión exitosa para {len(customers_to_clear)} suscriptores."

    finally:
        if pysros_connection:
            pysros_connection.disconnect()

def _disconnect_netconf_sessions(bng: str):
    # Esta función es síncrona
    device_config = DEVICES.get(bng)
    net_connect = None
    logger.info(f"Iniciando limpieza de sesiones NETCONF en {bng} con Netmiko (SSH).")
    netmiko_device = {'device_type': 'nokia_sros', 'host': device_config["host"], 'username': device_config["username"], 'password': device_config["password"], 'port': 22}
    try:
        net_connect = ConnectHandler(**netmiko_device)
        command = 'admin disconnect session-type netconf'
        logger.info(f"Ejecutando en {bng}: Desconectando sesiones NETCONF")
        net_connect.send_command(command, read_timeout=60)
        logger.info(f"SUCCESS: Se desconectaron las sesiones NETCONF en '{bng}'.")
        return "Limpieza de sesiones NETCONF finalizada."
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logger.error(f"Error de conexión Netmiko al limpiar sesiones en {bng}: {e}")
        raise e
    finally:
        if net_connect:
            net_connect.disconnect()
            logger.info(f"Sesión de limpieza Netmiko desconectada de {bng}.")

async def _internal_bulk_update_state(bng: str, customers_to_update: dict, new_state: str):
    async with BNG_WRITE_LOCKS[bng]:
        client = get_gnmi_client(bng)
        gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host"
        max_retries, retry_delay_seconds = 20, 3

        update_payloads = []
        for customer_id in customers_to_update:
            gnmi_path = f"{gnmi_base_path}[host-name={customer_id}]"
            payload = {"admin-state": new_state}
            update_payloads.append((gnmi_path, payload))

        if not update_payloads:
            logger.info("No hay suscriptores para actualizar en este lote.")
            return "No se realizaron cambios."

        logger.info(f"Iniciando actualización masiva de estado para {len(update_payloads)} suscriptores en {bng}.")

        for attempt in range(max_retries):
            try:
                client.set(update=update_payloads)
                logger.info(f"SUCCESS: Actualización masiva aplicada con éxito en '{bng}'.")
                return f"Actualización masiva exitosa para {len(update_payloads)} suscriptores."
            except Exception as e:
                logger.warning(f"WARN: Intento {attempt + 1} de actualización masiva fallido en '{bng}': {e}")
                if "reached maximum number of private sessions" in str(e):
                    try:
                        await asyncio.to_thread(_disconnect_netconf_sessions, bng)
                        await asyncio.sleep(retry_delay_seconds)
                        continue
                    except Exception as disconnect_e:
                        logger.error(f"Error al intentar limpiar sesiones en {bng}: {disconnect_e}")
                if ("Commit or validate is in progress" in str(e)) or ("Database write access is not available" in str(e)):
                    await asyncio.sleep(retry_delay_seconds)
                else: raise e
        else:
            raise Exception(f"No se pudo aplicar la configuración masiva en {bng} tras {max_retries} intentos.")

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
    """Ejecuta tareas de escritura (que ahora son async) en paralelo."""
    tasks = [worker_func(bng_node, *args) for bng_node in bng_list]
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
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    results = await _run_write_tasks_in_parallel(_internal_create_subscriber_logic, bng_list, subscriber_data)
    if results["failed_nodes"]:
        return results
    logger.info(f"INFO: Creación exitosa en todos los nodos: {list(results['successful_nodes'].keys())}. Obteniendo estado final de '{primary_bng}'.")
    final_state = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, subscriber_data.accountidbss)
    full_sub_id = final_state.get("identification", {}).get("subscriber-id", "")
    subnatid = full_sub_id.split('_')[0] if '_' in full_sub_id else None
    response_data = {
        "accountidbss": final_state.get("host-name"), "state": final_state.get("admin-state"),
        "mac": final_state.get("host-identification", {}).get("mac"), "subnatid": subnatid,
        "plan": final_state.get("identification", {}).get("sla-profile-string"),
        "olt": final_state.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")
    }
    results["data"] = response_data
    return results

async def delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    bng_list = CLUSTERS.get(bng, [bng])
    results = await _run_write_tasks_in_parallel(_internal_delete_subscriber_logic, bng_list, accountidbss, subnatid, olt)
    return results

async def update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
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

async def bulk_update_subscriber_state_logic(bng: str, request_data: models.BulkUpdateStateRequest):
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    updated_customers_report = []
    not_found_customers = []
    customers_to_process = {}

    for customer_id in request_data.customer_ids:
        try:
            initial_state_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, customer_id)
            primary_pool = initial_state_data.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary")
            customers_to_process[customer_id] = {
                "state_before": initial_state_data.get("admin-state"),
                "subscriber_id": initial_state_data.get("identification", {}).get("subscriber-id"),
                "interface": f"OLT-{primary_pool}" if primary_pool else None
            }
        except ValueError:
            not_found_customers.append(customer_id)
        except Exception as e:
            updated_customers_report.append(models.CustomerState(customer_id=customer_id, error=f"Error al obtener estado inicial: {e}"))
    
    if request_data.state == "disable" and customers_to_process:
        clear_results = await _run_write_tasks_in_parallel(_internal_clear_ipoe_sessions, bng_list, customers_to_process)
        if clear_results["failed_nodes"]:
            error_detail = ", ".join([f"{node}: {err}" for node, err in clear_results["failed_nodes"].items()])
            for customer_id, data in customers_to_process.items():
                updated_customers_report.append(models.CustomerState(customer_id=customer_id, state_before=data["state_before"], state_after=data["state_before"], error=f"Falló la limpieza de sesión: {error_detail}"))
            return models.BulkUpdateStateResponse(updated_customers=updated_customers_report, not_found_customers=not_found_customers)

    if customers_to_process:
        update_results = await _run_write_tasks_in_parallel(_internal_bulk_update_state, bng_list, customers_to_process, request_data.state)
        if update_results["failed_nodes"]:
            error_detail = ", ".join([f"{node}: {err}" for node, err in update_results["failed_nodes"].items()])
            for customer_id, data in customers_to_process.items():
                updated_customers_report.append(models.CustomerState(customer_id=customer_id, state_before=data["state_before"], state_after=data["state_before"], error=f"Falló la actualización de estado: {error_detail}"))
        else:
            for customer_id, data in customers_to_process.items():
                try:
                    final_state_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, customer_id)
                    updated_customers_report.append(models.CustomerState(customer_id=customer_id, state_before=data["state_before"], state_after=final_state_data.get("admin-state")))
                except Exception as e:
                    updated_customers_report.append(models.CustomerState(customer_id=customer_id, state_before=data["state_before"], error=f"Error al obtener estado final: {e}"))

    return models.BulkUpdateStateResponse(updated_customers=updated_customers_report, not_found_customers=not_found_customers)