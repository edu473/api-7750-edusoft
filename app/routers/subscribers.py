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
        created_subscriber = await logic.create_subscriber_logic(bng=bng, subscriber_data=subscriber)
        return created_subscriber
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
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
        await logic.delete_subscriber_logic(bng=bng, accountidbss=accountidbss, subnatid=subnatid, olt=olt)
        return
    except ValueError as e:
        error_message = str(e)
        if "no existe" in error_message:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_message)
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=error_message)
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
        updated_subscriber = await logic.update_subscriber_logic(
            bng=bng, accountidbss=accountidbss, subnatid=subnatid, update_data=update_data
        )
        return updated_subscriber
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))