# app/models.py

from typing import Optional, List
from pydantic import BaseModel, validator

# Este modelo corresponde al schema "Subs" [cite: 260] y al cuerpo de la solicitud POST.
# Pydantic valida que los datos recibidos tengan esta estructura.
class Subscriber(BaseModel):
    accountidbss: str # [cite: 262, 69]
    state: str # [cite: 263, 70]
    mac: str # [cite: 264, 71]
    subnatid: Optional[str] = None # [cite: 265, 72] - Es opcional en el schema base
    plan: str # [cite: 266, 73]
    olt: str # [cite: 267, 74]

# Este modelo corresponde al schema "UpdateSubs" [cite: 268] y al cuerpo de la solicitud PATCH.
# Los campos opcionales permiten actualizaciones parciales.
class UpdateSubscriber(BaseModel):
    state: Optional[str] = None # [cite: 269]
    plan: Optional[str] = None # [cite: 274]
    mac: str # [cite: 280] - En el schema PATCH, 'mac' es el único campo obligatorio.

# Modelo para la respuesta de error de validación estándar de FastAPI.
# No necesitas crearlo manualmente en tus endpoints, pero es bueno saber cómo es.
class ValidationError(BaseModel):
    loc: List[str] # [cite: 251]
    msg: str # [cite: 258]
    type: str # [cite: 259]

class HTTPValidationError(BaseModel):
    detail: List[ValidationError] # [cite: 246]

class UpdateSubscriberResponse(BaseModel):
    state: str
    plan: str
    mac: str


class BulkUpdateStateRequest(BaseModel):
    customer_ids: List[str]
    state: str

    @validator('state')
    def state_must_be_enable_or_disable(cls, v):
        if v not in ['enable', 'disable']:
            raise ValueError('El estado debe ser "enable" o "disable"')
        return v

class CustomerState(BaseModel):
    customer_id: str
    state_before: Optional[str] = None
    state_after: Optional[str] = None
    error: Optional[str] = None

class BulkUpdateStateResponse(BaseModel):
    updated_customers: List[CustomerState]
    not_found_customers: List[str]