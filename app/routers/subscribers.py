# app/routers/subscribers.py
from fastapi import APIRouter, Path, Query, Body, status, HTTPException
from typing import List, Any

from .. import models
from .. import logic # Importamos nuestra lógica simulada

# APIRouter nos permite agrupar rutas y luego incluirlas en la app principal.
router = APIRouter(
    prefix="/simple", # Todas las rutas en este archivo comenzarán con /simple
    tags=["Subscriptores"] # Agrupa estas rutas en la UI de Swagger
)

# GET /simple/{bng} [cite: 6]
@router.get("/{bng}", response_model=List[Any])
async def get_subscribers(
    bng: str = Path(..., description="BNG al que se consultará"), # [cite: 11]
    skip: int = Query(0, description="Número de registros a omitir"), # [cite: 13, 17, 18]
    limit: int = Query(20, description="Número de registros a retornar") # [cite: 15, 21, 22]
):
    """Obtiene una lista de suscriptores."""
    return logic.get_all_subscribers_logic(bng=bng, skip=skip, limit=limit)

# POST /simple/{bng} [cite: 58]
@router.post("/{bng}", response_model=models.Subscriber, status_code=status.HTTP_201_CREATED)
async def create_subscriber(
    bng: str = Path(..., description="BNG donde se creará el suscriptor"),
    subscriber: models.Subscriber = Body(...)
):
    """Crea un nuevo suscriptor."""
    try:
        created_subscriber = logic.create_subscriber_logic(bng=bng, subscriber_data=subscriber)
        return created_subscriber
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# GET /simple/{bng}/{accountidbss} [cite: 120]
@router.get("/{bng}/{accountidbss}", response_model=Any)
async def get_subscriber_by_name(
    bng: str = Path(..., description="BNG del suscriptor"), # [cite: 124]
    accountidbss: str = Path(..., description="ID de cuenta del suscriptor") # [cite: 127]
):
    """Obtiene un suscriptor específico por su ID de cuenta."""
    return logic.get_subscriber_by_name_logic(bng=bng, accountidbss=accountidbss)

# DELETE /simple/{bng}/{accountidbss}/{subnatid} [cite: 167]
@router.delete("/{bng}/{accountidbss}/{subnatid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscriber(
    bng: str = Path(..., description="BNG del suscriptor"),
    accountidbss: str = Path(..., description="ID de cuenta del suscriptor"),
    subnatid: str = Path(..., description="Subnet ID del suscriptor"),
    olt: str = Query(..., description="Interface de la OLT")
):
    """Elimina un suscriptor."""
    try:
        logic.delete_subscriber_logic(bng=bng, accountidbss=accountidbss, subnatid=subnatid, olt=olt)
        return
    except ValueError as e:
        # Verificamos el mensaje de error para decidir el código de estado
        error_message = str(e)
        if "no existe" in error_message:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_message)
        else:
            # Asumimos que cualquier otro ValueError es un conflicto de datos
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=error_message)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# PATCH /simple/{bng}/{accountidbss}/{subnatid} [cite: 218]
# app/logic.py
# (El resto del archivo se mantiene igual)

@router.patch("/{bng}/{accountidbss}/{subnatid}", response_model=Any)
async def update_subscriber(
    bng: str = Path(..., description="BNG del suscriptor"),
    accountidbss: str = Path(..., description="ID de cuenta del suscriptor"),
    subnatid: str = Path(..., description="Subnet ID del suscriptor"),
    update_data: models.UpdateSubscriber = Body(...)
):
    """Actualiza parcialmente un suscriptor."""
    try:
        updated_subscriber = logic.update_subscriber_logic(
            bng=bng,
            accountidbss=accountidbss,
            subnatid=subnatid,
            update_data=update_data
        )
        return updated_subscriber
    except ValueError as e:
        # Si el suscriptor no existe, devolvemos 404
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        # Cualquier otro error se convierte en un 500
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))