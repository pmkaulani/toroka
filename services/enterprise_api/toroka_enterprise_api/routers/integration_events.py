"""Authenticated webhook event ingestion endpoint with HMAC verification and replay protection."""
from __future__ import annotations

import hashlib
import json
import logging
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from toroka_enterprise.integrations.connectors.events import BankEventConnector
from toroka_enterprise.integrations.exceptions import ReplayError, SchemaValidationError
from toroka_enterprise.integrations.ingestion import ingest_batch
from toroka_enterprise.integrations.models import IntegrationEventInbox, utc_now
from toroka_enterprise.integrations.registry import DEFAULT_CONNECTOR_REGISTRY

from ..dependencies import get_db, get_installation_id
from ..integration_schemas import IncomingEventResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/enterprise/v1/integrations/events",
    tags=["Enterprise Event Ingestion"],
)


@router.post(
    "",
    response_model=IncomingEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def receive_signed_event(
    request: Request,
    response: Response,
    x_connector_id: str = Header(..., alias="X-Connector-ID"),
    x_signature: str = Header(..., alias="X-Signature"),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Receive, authenticate, and ingest signed real-time bank events.
    
    Guarantees:
    1. Replay prevention: re-delivered event IDs are acknowledged idempotently.
    2. HMAC-SHA256 signature verification over raw request body.
    3. Clock skew tolerance check (within 300 seconds).
    4. Canonical translation and transactional database storage.
    """
    conn = DEFAULT_CONNECTOR_REGISTRY.get(installation_id, x_connector_id)
    if conn is None or not isinstance(conn, BankEventConnector):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signed event connector '{x_connector_id}' not found or invalid",
        )

    raw_body = await request.body()
    try:
        event_id, event_type, canonical_record = conn.verify_and_parse_event(
            body=raw_body,
            signature=x_signature,
            installation_id=installation_id,
        )
    except ReplayError as exc:
        logger.warning("Event authentication/replay failure for connector %s: %s", x_connector_id, exc)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except SchemaValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    payload_digest = hashlib.sha256(raw_body).hexdigest()

    # Check for existing event in inbox (idempotent replay acknowledgement)
    inbox_key = (event_id, installation_id, x_connector_id)
    existing_inbox = db.get(IntegrationEventInbox, inbox_key)
    if existing_inbox is not None:
        logger.info("Duplicate event %s acknowledged idempotently", event_id)
        response.status_code = status.HTTP_200_OK
        return IncomingEventResponse(
            status="duplicate_acknowledged",
            event_id=event_id,
            payload_digest=existing_inbox.payload_digest,
            received_at=existing_inbox.received_at,
        )

    now = utc_now()
    inbox_record = IntegrationEventInbox(
        event_id=event_id,
        installation_id=installation_id,
        connector_id=x_connector_id,
        event_type=event_type,
        payload_digest=payload_digest,
        payload=json.loads(raw_body.decode("utf-8")),
        status="received",
        received_at=now,
    )
    db.add(inbox_record)
    db.flush()

    # Ingest canonical record into operational integration storage
    ingest_batch(
        db,
        installation_id=installation_id,
        connector_id=x_connector_id,
        records=[canonical_record],
    )

    inbox_record.status = "processed"
    inbox_record.processed_at = utc_now()
    db.commit()

    return IncomingEventResponse(
        status="processed",
        event_id=event_id,
        payload_digest=payload_digest,
        received_at=now,
    )
