# app/routers/subscribers.py
from fastapi import APIRouter, Path, Query, Body, status, HTTPException
from typing import List, Any

from .. import models
from .. import logic

# APIRouter nos permite agrupar rutas y luego incluirlas en la app principal.
router = APIRouter(
    prefix="/simple", # Todas las rutas en este archivo comenzarán con /simple
    tags=["Subscriptores"] # Agrupa estas rutas en la UI de Swagger
)

@router.get("/{bng}", response_model=Any)
async def get_subscribers(
    bng: str = Path(..., description="BNG al que se consultará"),
    skip: int = Query(0, description="Número de registros a omitir"),
    limit: int = Query(20, description="Número de registros a retornar")
):
    try:
        return await logic.get_all_subscribers_logic(bng=bng, skip=skip, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No se pudieron obtener suscriptores: {e}")

@router.post("/{bng}", response_model=Any, status_code=status.HTTP_201_CREATED)
async def create_subscriber(
    bng: str = Path(..., description="BNG donde se creará el suscriptor"),
    subscriber: models.Subscriber = Body(...)
):
    try:
        result = await logic.create_subscriber_logic(bng=bng, subscriber_data=subscriber)
        if result.get("failed_nodes"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"message": "La operación de creación falló en uno o más nodos.", **result}
            )
        return result.get("data")
    except HTTPException as http_exc:
        raise http_exc # Re-lanza la excepción HTTP para que FastAPI la maneje
    except Exception as e:
        # Captura cualquier otro error inesperado
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{bng}/{accountidbss}", response_model=Any)
async def get_subscriber_by_name(
    bng: str = Path(..., description="BNG del suscriptor"),
    accountidbss: str = Path(..., description="ID de cuenta del suscriptor")
):
    try:
        subscriber = await logic.get_subscriber_by_name_logic(bng=bng, accountidbss=accountidbss)
        return subscriber
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

@router.delete("/{bng}/{accountidbss}/{subnatid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscriber(
    bng: str = Path(..., description="BNG del suscriptor"),
    accountidbss: str = Path(..., description="ID de cuenta del suscriptor"),
    subnatid: str = Path(..., description="Subnet ID del suscriptor"),
    olt: str = Query(..., description="Interface de la OLT")
):
    try:
        result = await logic.delete_subscriber_logic(bng=bng, accountidbss=accountidbss, subnatid=subnatid, olt=olt)
        if result.get("failed_nodes"):
            # Si un nodo falla, se devuelve un error 409 con el detalle
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"message": "La operación de eliminación falló en uno o más nodos.", **result}
            )
        # Si todos tienen éxito, se devuelve 204 No Content
        return
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.patch("/{bng}/{accountidbss}/{subnatid}", response_model=models.UpdateSubscriberResponse)
async def update_subscriber(
    bng: str = Path(..., description="BNG del suscriptor"),
    accountidbss: str = Path(..., description="ID de cuenta del suscriptor"),
    subnatid: str = Path(..., description="Subnet ID del suscriptor"),
    update_data: models.UpdateSubscriber = Body(...)
):
    try:
        result = await logic.update_subscriber_logic(
            bng=bng, accountidbss=accountidbss, subnatid=subnatid, update_data=update_data
        )
        if result.get("failed_nodes"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"message": "La operación de actualización falló en uno o más nodos.", **result}
            )
        return result.get("data")
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



@router.post("/{bng}/bulk-update-state", response_model=models.BulkUpdateStateResponse)
async def bulk_update_state(
    bng: str = Path(..., description="BNG donde se actualizarán los suscriptores"),
    request_data: models.BulkUpdateStateRequest = Body(...)
):
    try:
        result = await logic.bulk_update_subscriber_state_logic(bng=bng, request_data=request_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))