"""Public catalog pricing. This never sends an API key or calls a model."""
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from .http import request
from .scope import Refusal

PRICE_FIELDS = ("input_usd_per_mtok", "cached_input_usd_per_mtok", "output_usd_per_mtok")


def prices(api_base, model):
    try:
        url = urlsplit(api_base)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Invalid API base")
        if url.scheme == "http" and url.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Use HTTPS outside the localhost demo")
        catalog = request(f"{url.scheme}://{url.netloc}/api/catalog")
        matches = [m for m in catalog["models"] if m["id"] == model]
        if len(matches) != 1 or matches[0].get("available") is not True:
            raise ValueError("Model absent or unavailable")
        values = {key: Decimal(str(matches[0]["pricing"][key])) for key in PRICE_FIELDS}
        if any(not v.is_finite() or v < 0 for v in values.values()):
            raise ValueError("Invalid price")
        if values["input_usd_per_mtok"] <= 0 or values["output_usd_per_mtok"] <= 0:
            raise ValueError("Input and output prices must be positive")
        return {k: format(v, "f") for k, v in values.items()}
    except (OSError, ValueError, KeyError, TypeError, InvalidOperation) as exc:
        raise Refusal("prices-unavailable", "Choose an available catalog model with all three prices and a reachable API origin.") from exc
