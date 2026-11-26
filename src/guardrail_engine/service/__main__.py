"""``python -m guardrail_engine.service``: the local process runner (M7-10).

The runner is composition (it builds the engine), and only the composition root, ``engine/``, may
import the engine's wiring, so this module starts it by name instead of importing it.
"""

import runpy

runpy.run_module("guardrail_engine.engine.serve", run_name="__main__", alter_sys=True)
