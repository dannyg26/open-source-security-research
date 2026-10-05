"""Reusable HTTP comparisons for an explicitly local target instance.

These helpers collect observations. They do not decide whether a vulnerability exists.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urljoin

import httpx

from .safety import assert_local_url

MAX_PROBES = 100
MAX_BODY_CAPTURE = 2_000


@dataclass(frozen=True)
class Observation:
    label: str
    method: str
    url: str
    status_code: int
    elapsed_ms: float
    content_length: int
    content_type: str
    location: str
    body_preview: str

    @classmethod
    def from_response(cls, label: str, response: httpx.Response) -> "Observation":
        location = response.headers.get("location", "")
        if location:
            destination = urljoin(str(response.url), location)
            assert_local_url(destination)
        content_type = response.headers.get("content-type", "")
        preview = ""
        if content_type.startswith(("text/", "application/json", "application/xml")):
            preview = response.text[:MAX_BODY_CAPTURE]
        return cls(
            label=label,
            method=response.request.method,
            url=str(response.url),
            status_code=response.status_code,
            elapsed_ms=round(response.elapsed.total_seconds() * 1000, 2),
            content_length=len(response.content),
            content_type=content_type,
            location=location,
            body_preview=preview,
        )


class VerificationClient:
    """An HTTP client that refuses non-loopback targets and redirects."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        verify_tls: bool = True,
    ) -> None:
        assert_local_url(base_url)
        self.base_url = base_url.rstrip("/") + "/"
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=False,
        )

    def __enter__(self) -> "VerificationClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(self, label: str, method: str, path: str, **kwargs: Any) -> Observation:
        absolute = urljoin(self.base_url, path.lstrip("/"))
        assert_local_url(absolute)
        response = self._client.request(method, path.lstrip("/"), **kwargs)
        return Observation.from_response(label, response)

    def compare_auth(
        self,
        method: str,
        path: str,
        *,
        authenticated_headers: Mapping[str, str],
        unauthenticated_headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> list[Observation]:
        """Send the same request with and without caller-supplied authentication."""
        return [
            self.request(
                "authenticated", method, path, headers=dict(authenticated_headers), **kwargs
            ),
            self.request(
                "unauthenticated", method, path, headers=dict(unauthenticated_headers or {}), **kwargs
            ),
        ]

    def probe_ids(
        self,
        method: str,
        path_template: str,
        identifiers: Iterable[int | str],
        *,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> list[Observation]:
        """Request caller-selected IDs; ``path_template`` must contain ``{id}``."""
        if "{id}" not in path_template:
            raise ValueError("path_template must contain {id}")
        ids = list(identifiers)
        if len(ids) > MAX_PROBES:
            raise ValueError(f"at most {MAX_PROBES} IDs may be checked per call")
        return [
            self.request(
                f"id={identifier}", method, path_template.format(id=identifier),
                headers=dict(headers or {}), **kwargs
            )
            for identifier in ids
        ]

    def compare_variants(
        self,
        method: str,
        path: str,
        variants: Iterable[tuple[str, Mapping[str, str], Mapping[str, str]]],
        **kwargs: Any,
    ) -> list[Observation]:
        """Compare explicitly supplied header/parameter variants against a local route."""
        cases = list(variants)
        if len(cases) > MAX_PROBES:
            raise ValueError(f"at most {MAX_PROBES} variants may be checked per call")
        return [
            self.request(label, method, path, headers=dict(headers), params=dict(params), **kwargs)
            for label, headers, params in cases
        ]


def save_observations(path: Path, observations: Iterable[Observation]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([asdict(observation) for observation in observations], indent=2),
        encoding="utf-8",
    )
