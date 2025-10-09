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
from contextlib import asynccontextmanager

logger = logging.getLogger("app")

load_dotenv()

username_env = os.environ.get('username_gnmi')
password_env = os.environ.get('password_gnmi')

# --- CONFIGURACIÓN DE DISPOSITIVOS Y CLUSTERS ---

DEVICES = {
    "bng-principal": {
        "host": "10.100.0.25",
        "gnmi_port": 57400,
        "netconf_port": 830,
        "username": username_env,
        "password": password_env
    },
    "bng-secundario": {
        "host": "10.100.0.29",
        "gnmi_port": 57400,
        "netconf_port": 830,
        "username": username_env,
        "password": password_env
    }
}

CLUSTERS = {
    "CCS-01": ["bng-principal", "bng-secundario"]
}

# --- GESTIÓN DE CONCURRENCIA ---
BNG_WRITE_LOCKS = {bng: asyncio.Lock() for bng in DEVICES}

# --- GESTOR DE CONEXIONES PYSROS ---
@asynccontextmanager
async def pysros_connection(bng: str):
    """
    Un context manager asíncrono para manejar conexiones pysros con reintentos
    y desconexión garantizada.
    """
    device_config = DEVICES.get(bng)
    max_retries, retry_delay_seconds = 20, 3
    connection = None

    # CORRECCIÓN: El bloque try/finally ahora envuelve toda la lógica para
    # garantizar que 'finally' se ejecute incluso si hay un error en el bloque 'with'.
    try:
        for attempt in range(max_retries):
            try:
                logger.info(f"Intentando conectar a {bng} (Intento {attempt + 1}/{max_retries})...")
                connection = await asyncio.to_thread(
                    pysros_connect,
                    host=device_config["host"],
                    username=device_config["username"],
                    password=device_config["password"],
                    port=device_config.get("netconf_port", 830),
                    hostkey_verify=False
                )
                logger.info(f"Conexión Pysros a {bng} establecida.")
                break  # Salir del bucle si la conexión es exitosa
            except SrosMgmtError as e:
                logger.warning(f"WARN: Intento {attempt + 1} de conexión pysros a '{bng}' fallido: {e}")
                if "reached maximum number of private sessions" in str(e):
                    logger.warning(f"Se alcanzó el máximo de sesiones privadas en {bng}. Intentando limpiar...")
                    await asyncio.to_thread(_disconnect_netconf_sessions, bng)
                    await asyncio.sleep(retry_delay_seconds)
                elif "Commit or validate is in progress" in str(e) or "Database write access is not available" in str(e):
                    await asyncio.sleep(retry_delay_seconds)
                else:
                    raise e # Relanzar otros errores de conexión
        
        if not connection:
            raise SrosMgmtError(f"No se pudo conectar con pysros a {bng} por bloqueo persistente.")

        # Entregar la conexión al bloque 'with'
        yield connection

    finally:
        # Este bloque se ejecutará SIEMPRE al salir del 'with',
        # ya sea por éxito o por cualquier excepción.
        if connection:
            logger.info(f"Cerrando conexión NETCONF a {bng}.")
            await asyncio.to_thread(connection.disconnect)


# --- FUNCIONES DE LECTURA (gNMI - SIN CAMBIOS) ---
def _internal_get_all_subscribers_logic(bng: str, skip: int, limit: int):
    # Sin cambios aquí
    device_config = DEVICES.get(bng)
    gnmi_base_path = "/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host"
    with gNMIclient(target=(device_config["host"], device_config["gnmi_port"]), username=device_config["username"], password=device_config["password"], insecure=True, timeout=15) as client:
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
        if not paginated_ids: return []
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
    # Sin cambios aquí
    device_config = DEVICES.get(bng)
    gnmi_path = f"/configure/subscriber-mgmt/local-user-db[name=LUDB-SIMPLE]/ipoe/host[host-name={accountidbss}]"
    with gNMIclient(target=(device_config["host"], device_config["gnmi_port"]), username=device_config["username"], password=device_config["password"], insecure=True, timeout=15) as client:
        gnmi_response = client.get(path=[gnmi_path])
        updates = gnmi_response.get("notification", [{}])[0].get("update", [])
        if not (updates and "val" in updates[0]):
            raise ValueError(f"Suscriptor '{accountidbss}' no encontrado.")
        return updates[0]["val"]

# --- FUNCIONES DE ESCRITURA (CORREGIDAS PARA USAR EL MODELO DE OBJETOS PYSROS) ---

async def _internal_create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    host_name = subscriber_data.accountidbss
    try:
        await asyncio.to_thread(_internal_get_subscriber_by_name_logic, bng, host_name)
        raise ValueError(f"El suscriptor '{host_name}' ya existe en {bng}.")
    except ValueError:
        pass

    # CORRECCIÓN: Usar el método .set() con un path y un diccionario como payload
    path = f'/configure/subscriber-mgmt/local-user-db[name="LUDB-SIMPLE"]/ipoe/host[host-name="{host_name}"]'
    payload = {
        "admin-state": subscriber_data.state,
        "host-identification": {"mac": subscriber_data.mac},
        "identification": {
            "option-number": 254,
            "sla-profile-string": subscriber_data.plan,
            "sub-profile-string": "DEFAULT-SUB-PROF",
            "subscriber-id": f"{subscriber_data.subnatid}_{host_name}"
        },
        "ipv4": {"address": {"pool": {"primary": subscriber_data.olt}}},
        "ipv6": {
            "address-pool": subscriber_data.olt,
            "delegated-prefix-pool": subscriber_data.olt
        }
    }
    
    async with BNG_WRITE_LOCKS[bng]:
        async with pysros_connection(bng) as conn:
            logger.info(f"Creando suscriptor '{host_name}' en BNG '{bng}' vía pysros object model.")
            await asyncio.to_thread(conn.candidate.set, path, payload)
            await asyncio.to_thread(conn.candidate.commit)
            logger.info(f"SUCCESS: Suscriptor '{host_name}' creado exitosamente en '{bng}'.")
            return f"Suscriptor '{host_name}' creado exitosamente."


async def _internal_delete_subscriber_logic(bng: str, accountidbss: str, subnatid: str, olt: str):
    host_name = accountidbss
    try:
        host_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, bng, host_name)
        if host_data.get("identification", {}).get("subscriber-id") != f"{subnatid}_{accountidbss}":
            raise ValueError(f"Conflicto de datos en {bng}: El subnatid no coincide para '{host_name}'.")
        if host_data.get("ipv4", {}).get("address", {}).get("pool", {}).get("primary") != olt:
            raise ValueError(f"Conflicto de datos en {bng}: La OLT/Pool no coincide para '{host_name}'.")
    except ValueError as e:
        logger.warning(f"No se puede eliminar '{host_name}': {e}")
        raise e

    # CORRECCIÓN: Usar el método .delete()
    path = f'/configure/subscriber-mgmt/local-user-db[name="LUDB-SIMPLE"]/ipoe/host[host-name="{host_name}"]'

    async with BNG_WRITE_LOCKS[bng]:
        async with pysros_connection(bng) as conn:
            logger.info(f"Eliminando suscriptor '{host_name}' de BNG '{bng}' vía pysros object model.")
            await asyncio.to_thread(conn.candidate.delete, path)
            await asyncio.to_thread(conn.candidate.commit)
            logger.info(f"SUCCESS: Suscriptor '{host_name}' eliminado con éxito de '{bng}'.")
            return f"Suscriptor '{host_name}' eliminado exitosamente."


async def _internal_update_subscriber_logic(bng: str, accountidbss: str, subnatid: str, update_data: models.UpdateSubscriber):
    host_name = accountidbss
    await asyncio.to_thread(_internal_get_subscriber_by_name_logic, bng, host_name)

    base_path = f'/configure/subscriber-mgmt/local-user-db[name="LUDB-SIMPLE"]/ipoe/host[host-name="{host_name}"]'

    async with BNG_WRITE_LOCKS[bng]:
        async with pysros_connection(bng) as conn:
            if update_data.plan is not None:
                logger.info(f"Ejecutando CoA para cambiar plan de '{host_name}' a '{update_data.plan}'.")
                coa_command = f'tools perform subscriber-mgmt coa alc-subscr-id {subnatid}_{host_name} attr ["6527,13={update_data.plan}"]'
                await asyncio.to_thread(conn.cli, coa_command)
                logger.info(f"SUCCESS: Comando CoA ejecutado para '{host_name}'.")

            # CORRECCIÓN: Realizar un .set() para cada atributo a cambiar
            changes_made = False
            if update_data.mac is not None:
                await asyncio.to_thread(conn.candidate.set, f"{base_path}/host-identification/mac", update_data.mac)
                changes_made = True
            if update_data.state is not None:
                await asyncio.to_thread(conn.candidate.set, f"{base_path}/admin-state", update_data.state)
                changes_made = True
            if update_data.plan is not None:
                await asyncio.to_thread(conn.candidate.set, f"{base_path}/identification/sla-profile-string", update_data.plan)
                changes_made = True

            if changes_made:
                logger.info(f"Aplicando actualización para '{host_name}' en '{bng}'.")
                await asyncio.to_thread(conn.candidate.commit)
                logger.info(f"SUCCESS: Payload de actualización aplicado para '{host_name}' en '{bng}'.")

            if update_data.state == "disable":
                logger.info(f"Suscriptor '{host_name}' deshabilitado. Procediendo a limpiar la sesión IPoE.")
                subscriber_id = f"{subnatid}_{host_name}"
                clear_command = f'clear service id "100" ipoe session subscriber "{subscriber_id}" interface "SUBSCRIBER-INTERFACE-1"'
                try:
                    await asyncio.to_thread(conn.cli, clear_command)
                    logger.info(f"SUCCESS: Sesión IPoE para '{subscriber_id}' limpiada en '{bng}'.")
                except SrosMgmtError as e:
                    logger.error(f"ERROR: Falló la limpieza de sesión IPoE para '{subscriber_id}' en '{bng}': {e}")
                    raise Exception(f"Limpieza de sesión IPoE falló: {e}")

            final_state = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, bng, host_name)
            return {
                "state": final_state.get("admin-state"),
                "plan": final_state.get("identification", {}).get("sla-profile-string"),
                "mac": final_state.get("host-identification", {}).get("mac")
            }


async def _internal_bulk_update_and_clear_logic(bng: str, customers_to_update: dict, new_state: str):
    if not customers_to_update:
        logger.info(f"No hay suscriptores para procesar en {bng}.")
        return "No se realizaron cambios."

    async with BNG_WRITE_LOCKS[bng]:
        async with pysros_connection(bng) as conn:
            logger.info(f"Iniciando actualización masiva de estado para {len(customers_to_update)} suscriptores en {bng}.")
            
            # CORRECCIÓN: Iterar y hacer .set() para cada cliente. La librería agrupará los cambios.
            for customer_id in customers_to_update:
                path = f'/configure/subscriber-mgmt/local-user-db[name="LUDB-SIMPLE"]/ipoe/host[host-name="{customer_id}"]/admin-state'
                await asyncio.to_thread(conn.candidate.set, path, new_state)
            
            await asyncio.to_thread(conn.candidate.commit)
            logger.info(f"SUCCESS: Actualización masiva de estado aplicada en '{bng}'.")

            if new_state == "disable":
                logger.info(f"Estado es 'disable', procediendo a limpiar {len(customers_to_update)} sesiones en {bng}.")
                errors = {}
                for customer_id, data in customers_to_update.items():
                    subscriber_id = data.get("subscriber_id")
                    if not subscriber_id:
                        logger.warning(f"No se puede limpiar sesión para {customer_id}, falta subscriber_id.")
                        continue
                    
                    clear_command = f'clear service id "100" ipoe session subscriber "{subscriber_id}" interface "SUBSCRIBER-INTERFACE-1"'
                    try:
                        await asyncio.to_thread(conn.cli, clear_command)
                        logger.info(f"Sesión para {subscriber_id} limpiada.")
                    except SrosMgmtError as e:
                        logger.error(f"Fallo al limpiar sesión para {subscriber_id}: {e}")
                        errors[customer_id] = str(e)
                
                if errors:
                    raise Exception(f"Fallaron las siguientes limpiezas de sesión: {errors}")

    return f"Operación masiva completada exitosamente en {bng}."


def _disconnect_netconf_sessions(bng: str):
    device_config = DEVICES.get(bng)
    net_connect = None
    logger.info(f"Iniciando limpieza de sesiones NETCONF en {bng} con Netmiko (SSH).")
    netmiko_device = {'device_type': 'nokia_sros', 'host': device_config["host"], 'username': device_config["username"], 'password': device_config["password"], 'port': 22}
    try:
        net_connect = ConnectHandler(**netmiko_device)
        command = 'admin disconnect session-type netconf'
        net_connect.send_command(command, read_timeout=60)
        logger.info(f"SUCCESS: Se desconectaron las sesiones NETCONF en '{bng}'.")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logger.error(f"Error de conexión Netmiko al limpiar sesiones en {bng}: {e}")
        raise e
    finally:
        if net_connect:
            net_connect.disconnect()


# --- FUNCIONES PÚBLICAS (DISPATCHERS) ---
# Sin cambios en esta sección
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
    tasks = [worker_func(bng_node, *args) for bng_node in bng_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    successful_nodes, failed_nodes = {}, {}
    for bng_node, res in zip(bng_list, results):
        if isinstance(res, Exception):
            failed_nodes[bng_node] = repr(res)
            logger.error(f"ERROR: La operación falló en el nodo '{bng_node}': {repr(res)}")
        else:
            successful_nodes[bng_node] = res
            logger.info(f"SUCCESS: La operación tuvo éxito en el nodo '{bng_node}'.")
    return {"successful_nodes": successful_nodes, "failed_nodes": failed_nodes}

async def create_subscriber_logic(bng: str, subscriber_data: models.Subscriber):
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    results = await _run_write_tasks_in_parallel(_internal_create_subscriber_logic, bng_list, subscriber_data)
    if results["failed_nodes"]: return results
    logger.info(f"INFO: Creación exitosa en todos los nodos. Obteniendo estado final de '{primary_bng}'.")
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
    if results["failed_nodes"]: return results
    successful_data = results.get("successful_nodes", {}).get(primary_bng, {})
    results["data"] = successful_data
    return results

async def bulk_update_subscriber_state_logic(bng: str, request_data: models.BulkUpdateStateRequest):
    bng_list = CLUSTERS.get(bng, [bng])
    primary_bng = bng_list[0]
    updated_customers_report, not_found_customers, customers_to_process = [], [], {}

    for customer_id in request_data.customer_ids:
        try:
            initial_state_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, customer_id)
            customers_to_process[customer_id] = {
                "state_before": initial_state_data.get("admin-state"),
                "subscriber_id": initial_state_data.get("identification", {}).get("subscriber-id"),
            }
        except ValueError:
            not_found_customers.append(customer_id)
        except Exception as e:
            updated_customers_report.append(models.CustomerState(customer_id=customer_id, error=f"Error al obtener estado inicial: {e}"))

    if not customers_to_process:
        return models.BulkUpdateStateResponse(updated_customers=updated_customers_report, not_found_customers=not_found_customers)
    
    results = await _run_write_tasks_in_parallel(_internal_bulk_update_and_clear_logic, bng_list, customers_to_process, request_data.state)
    failed_nodes_detail = results.get("failed_nodes")

    if failed_nodes_detail:
        error_detail = ", ".join([f"{node}: {err}" for node, err in failed_nodes_detail.items()])
        for customer_id, data in customers_to_process.items():
            updated_customers_report.append(models.CustomerState(
                customer_id=customer_id, state_before=data["state_before"], state_after=data["state_before"],
                error=f"Falló la operación masiva: {error_detail}"
            ))
    else:
        for customer_id, data in customers_to_process.items():
            try:
                final_state_data = await asyncio.to_thread(_internal_get_subscriber_by_name_logic, primary_bng, customer_id)
                updated_customers_report.append(models.CustomerState(
                    customer_id=customer_id, state_before=data["state_before"],
                    state_after=final_state_data.get("admin-state")
                ))
            except Exception as e:
                updated_customers_report.append(models.CustomerState(
                    customer_id=customer_id, state_before=data["state_before"],
                    error=f"La actualización fue exitosa, pero falló la verificación del estado final: {e}"
                ))

    return models.BulkUpdateStateResponse(updated_customers=updated_customers_report, not_found_customers=not_found_customers)