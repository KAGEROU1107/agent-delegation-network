"""Trusted runtime-mode and worker authorization policy helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal, Optional, cast


RuntimeMode = Literal["live", "demo", "test"]
VALID_RUNTIME_MODES: set[str] = {"live", "demo", "test"}
RUNTIME_MODE_ERROR = "ADN_RUNTIME_MODE must be live, demo, or test"


def resolve_runtime_mode(value: Optional[str] = None) -> RuntimeMode:
    """Resolve ADN_RUNTIME_MODE from trusted process configuration.

    Unknown modes fail closed so typos like "prod" cannot silently disable
    live-mode authorization or replay protections.
    """
    raw_mode = os.environ.get("ADN_RUNTIME_MODE", "live") if value is None else value
    mode = str(raw_mode).strip().lower()
    if mode not in VALID_RUNTIME_MODES:
        raise RuntimeError(RUNTIME_MODE_ERROR)
    return cast(RuntimeMode, mode)


def gateway_context_configured(
    expected_gateway_public_key_hex: Optional[str] = None,
    expected_gateway_key_id: Optional[str] = None,
    expected_build_config_id: Optional[str] = None,
) -> bool:
    return bool(expected_gateway_public_key_hex or expected_gateway_key_id or expected_build_config_id)


@dataclass(frozen=True)
class WorkerAuthorizationContext:
    runtime_mode: RuntimeMode
    require_tee_authorization: bool
    expected_gateway_public_key_hex: str = ""
    expected_gateway_key_id: str = ""
    expected_build_config_id: str = ""

    @classmethod
    def from_trusted_config(
        cls,
        *,
        expected_gateway_public_key_hex: Optional[str] = None,
        expected_gateway_key_id: Optional[str] = None,
        expected_build_config_id: Optional[str] = None,
        require_tee_authorization: Optional[bool] = None,
    ) -> "WorkerAuthorizationContext":
        runtime_mode = resolve_runtime_mode()
        gateway_configured = gateway_context_configured(
            expected_gateway_public_key_hex,
            expected_gateway_key_id,
            expected_build_config_id,
        )
        trusted_requirement = (
            runtime_mode == "live"
            or gateway_configured
            or bool(require_tee_authorization)
        )
        return cls(
            runtime_mode=runtime_mode,
            require_tee_authorization=trusted_requirement,
            expected_gateway_public_key_hex=expected_gateway_public_key_hex or "",
            expected_gateway_key_id=expected_gateway_key_id or "",
            expected_build_config_id=expected_build_config_id or "",
        )
