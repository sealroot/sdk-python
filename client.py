"""
AIA Python SDK — 6 core methods for the AICP v0.2 protocol.

Usage:
    from aia.sdk import AIAClient

    client = AIAClient(base_url="http://localhost:8000", api_key="your-key")
    agent = client.register_agent("my-agent")
    capability = client.issue_capability(agent["agent_id"], "read_database")
    sie = client.generate_sie(agent, capability["token"], intent={"capability": "read_database"})
    result = client.verify(sie)
"""
import hashlib
import json
import secrets
import uuid
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from typing import Any

import httpx
import nacl.signing

from aia.services.crypto import (
    b64url_encode,
    canonicalize,
    generate_nonce,
    sha256_hex,
    sign_bytes,
)


class AIAError(Exception):
    """Base SDK exception."""


class AgentNotFoundError(AIAError):
    pass


class VerificationDeniedError(AIAError):
    def __init__(self, reason: str, verification_id: str):
        super().__init__(f"Verification denied: {reason}")
        self.reason = reason
        self.verification_id = verification_id


class RevocationError(AIAError):
    pass


class AIAClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        self._timeout = timeout

    def _http(self) -> httpx.Client:
        return httpx.Client(base_url=self._base_url, headers=self._headers, timeout=self._timeout)

    # ------------------------------------------------------------------
    # 1. register_agent
    # ------------------------------------------------------------------
    def register_agent(
        self,
        agent_name: str,
        validity_hours: int = 24,
        metadata: dict[str, Any] | None = None,
    ) -> dict:
        """
        Register a new agent and receive an AIC + private key.
        Returns the full registration response dict.
        WARNING: Store the returned private_key securely — it is returned ONCE only.
        """
        with self._http() as client:
            resp = client.post(
                "/agents",
                json={"agent_name": agent_name, "validity_hours": validity_hours, "metadata": metadata},
            )
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # 2. issue_capability
    # ------------------------------------------------------------------
    def issue_capability(
        self,
        agent_id: str,
        capability_name: str,
        parameters: dict[str, Any] | None = None,
        validity_seconds: int = 3600,
    ) -> dict:
        """Issue a scoped Capability Token (ACT) for an agent."""
        with self._http() as client:
            resp = client.post(
                "/capabilities",
                json={
                    "agent_id": agent_id,
                    "capability_name": capability_name,
                    "parameters": parameters,
                    "validity_seconds": validity_seconds,
                },
            )
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # 3. generate_sie (local — no network call)
    # ------------------------------------------------------------------
    def generate_sie(
        self,
        agent_registration: dict,
        capability_token: str,
        intent: dict[str, Any],
        reasoning: str | None = None,
    ) -> dict:
        """
        Generate a Signed Intent Envelope (SIE) locally using the agent's private key.
        JCS canonicalization (RFC 8785) is applied before signing.

        Args:
            agent_registration: The dict returned by register_agent() — must contain
                                 'certificate' and 'private_key'.
            capability_token: The ACT JWT string from issue_capability().
            intent: Dict describing the action (must include 'capability' key).
            reasoning: Optional human-readable reasoning string.

        Returns:
            The complete signed SIE dict ready for POST /verify.
        """
        private_key_b64 = agent_registration["private_key"]
        # base64url decode
        private_key_bytes = _b64url_decode(private_key_b64)
        aic = agent_registration["certificate"]

        now = datetime.now(timezone.utc)
        nonce = generate_nonce()

        # reasoning_hash: cryptographic commitment to reasoning (Layer 4 anti-replay)
        # Format: sha256:<64 hex chars> — matches server validation pattern
        reasoning_hash = "sha256:" + sha256_hex((reasoning or "").encode())

        sie_payload = {
            "version": "0.2",
            "agent_id": agent_registration["agent_id"],
            "agent_certificate": aic,
            "capability_token": capability_token,
            "intent": intent,
            "reasoning_hash": reasoning_hash,
            "nonce": nonce,
            "timestamp": now.isoformat(),
        }

        # JCS canonicalize then sign
        canonical_bytes = canonicalize(sie_payload)
        signature = sign_bytes(private_key_bytes, canonical_bytes)

        return {
            **sie_payload,
            "signature": b64url_encode(signature),
        }

    # ------------------------------------------------------------------
    # 4. verify
    # ------------------------------------------------------------------
    def verify(self, sie: dict) -> dict:
        """
        Submit a SIE to POST /verify (unauthenticated endpoint).
        Raises VerificationDeniedError if denied.
        Returns the full verify response dict if allowed.
        """
        with httpx.Client(base_url=self._base_url, timeout=self._timeout) as client:
            resp = client.post("/verify", json={"sie": sie})
            resp.raise_for_status()
            data = resp.json()
            if data["result"] == "deny":
                raise VerificationDeniedError(
                    reason=data.get("reason", "unknown"),
                    verification_id=data.get("verification_id", ""),
                )
            return data

    # ------------------------------------------------------------------
    # 5. revoke_agent
    # ------------------------------------------------------------------
    def revoke_agent(self, agent_id: str, reason: str | None = None) -> dict:
        """Revoke an agent. Propagates to the revocation list immediately."""
        with self._http() as client:
            resp = client.request(
                "DELETE",
                f"/agents/{agent_id}",
                json={"reason": reason},
            )
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # 6. get_audit_log
    # ------------------------------------------------------------------
    def get_audit_log(
        self,
        agent_id: str | None = None,
        result: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """Fetch the audit log with optional filters."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if agent_id:
            params["agent_id"] = agent_id
        if result:
            params["result"] = result

        with self._http() as client:
            resp = client.get("/audit", params=params)
            resp.raise_for_status()
            return resp.json()


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    import base64
    return base64.b64decode(s)
