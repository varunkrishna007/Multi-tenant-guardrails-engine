"""The guard service: the check listener of the guard as its own process (M7-10).

``wire`` is the contract, shared with the SDK's remote checker, and imports no web framework.
The listener itself, ``adapters.fastapi_app.create_check_app``, needs FastAPI and is imported from
there on purpose: only an adapter may import a web framework.
"""
