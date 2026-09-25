"""What kind of thing an asset is, as far as coverage expectations go.

Only machines (servers, VMs, laptops, workstations) can run an EDR agent. Storage accounts, buckets, databases and
other managed cloud resources cannot, so reporting them as "missing EDR" (or scoring them for it) is wrong.
"""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import Entity, EntityKey, SourceRecord

# cloud resource types (Wiz / CSPM) that are not machines
NON_COMPUTE_TYPES = {"BUCKET", "STORAGE_ACCOUNT", "DATABASE", "DB_SERVER", "SERVERLESS", "FUNCTION", "CONTAINER_REGISTRY",
                     "KEY_VAULT", "SECRET", "NETWORK_SECURITY_GROUP", "LOAD_BALANCER", "VIRTUAL_NETWORK", "IAM_ROLE",
                     "SERVICE_ACCOUNT", "USER_ACCOUNT", "DNS_ZONE", "API_GATEWAY", "MANAGED_IDENTITY", "QUEUE"}
# cloud resource ids of non-machine services (Azure resource providers, AWS ARNs, GCP storage)
NON_COMPUTE_PATH = re.compile(
    r"/providers/microsoft\.(storage|sql|dbfor\w+|documentdb|keyvault|web|network|containerregistry|servicebus|eventhub)/"
    r"|^arn:aws:(s3|rds|dynamodb|lambda|iam|kms|sqs|sns|secretsmanager):|//storage\.googleapis\.com/|/buckets/",
    re.IGNORECASE)


def needs_endpoint_agent(session: Session, entity: Entity) -> bool:
    """True for machines (and for assets we know too little about); False for managed cloud resources."""
    attrs = entity.attributes or {}
    types = {str(attrs.get(k) or "").upper() for k in ("resource_type", "cloud_type")}
    for tool_attrs in (attrs.get("by_tool") or {}).values():
        types |= {str((tool_attrs or {}).get(k) or "").upper() for k in ("resource_type", "cloud_type")}
    for (norm,) in session.execute(select(SourceRecord.normalized).where(SourceRecord.entity_id == entity.id)).all():
        a = (norm or {}).get("attributes", norm or {})
        types |= {str(a.get(k) or "").upper() for k in ("resource_type", "cloud_type")}
    if types & NON_COMPUTE_TYPES:
        return False
    for (value,) in session.execute(select(EntityKey.key_value).where(EntityKey.entity_id == entity.id,
                                                                      EntityKey.key_name == "cloud_resource_id")).all():
        if NON_COMPUTE_PATH.search(value or ""):
            return False
    return True
