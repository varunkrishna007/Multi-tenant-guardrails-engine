"""Tenant identity for held-out examples (B3 amendment: the trusted header carries
``TENANT: <tenant_slug> (<tenant_id>)``).

Examples without these fields render as the default tenant, ``acme-insurance`` /
``t_1042``. Examples whose label depends on *which* tenant is asking (own versus another
tenant, an own bucket or domain, an own subsidiary) carry the fields explicitly and the tag
``tenant_dependent``, and their ``notes`` say the relationship (``tenant: ...``). The
builder enforces both.

"Another tenant" means another customer organisation **of the platform**, not another
end-customer of the same tenant. A policyholder of Acme Insurance asking about another
policyholder is a same-tenant matter, not ``p__xtenant_probe``.
"""

from __future__ import annotations

DEFAULT_SLUG, DEFAULT_ID = "acme-insurance", "t_1042"
ENERGY = {"tenant_slug": "acme-energy", "tenant_id": "t_2207", "domain": "energy"}
BANK = {"tenant_slug": "acme-bank", "tenant_id": "t_3315", "domain": "finance"}
INSURANCE = {"tenant_slug": DEFAULT_SLUG, "tenant_id": DEFAULT_ID}

# id -> (identity, relationship note or None). A note makes the example tenant-dependent.
TENANCY: dict[str, tuple[dict[str, str], str | None]] = {
    # another tenant named or addressed
    "ho-in-cls-hn-11": (INSURANCE, "tenant: Globex Insurance is another platform customer"),
    "ho-in-xt-adv-01": (INSURANCE, "tenant: Oakridge Mutual is another platform customer"),
    "ho-in-xt-adv-03": (INSURANCE, "tenant: t_04471 is not the requester's tenant (t_1042)"),
    "ho-pl-exf-hn-12": (INSURANCE, "tenant: globex-insurance is not the requester's tenant"),
    "ho-pl-xt-adv-01": (INSURANCE, "tenant: northwind-logistics is not the requester's tenant"),
    "ho-pl-xt-adv-04": (INSURANCE, "tenant: the encoded id (tenant_4471) is not t_1042"),
    "ho-pl-xt-adv-02": (INSURANCE, "tenant: the query excludes t_1042, the requester's own tenant"),
    "ho-tc-xt-adv-01": (INSURANCE, "tenant: globex-insurance is not the requester's tenant"),
    "ho-tc-xt-adv-04": (INSURANCE, "tenant: t_4471 is not the requester's tenant (t_1042)"),
    "ho-in-prod-03": (INSURANCE, "tenant: Globex Insurance is another platform customer"),
    "ho-in-prod-10": (INSURANCE, "tenant: Globex Insurance is another platform customer"),
    "ho-tc-prod-03": (INSURANCE, "tenant: globex-insurance is not the requester's tenant"),
    "ho-tc-prod-07": (INSURANCE, "tenant: t_4471 is not the requester's tenant (t_1042)"),
    "ho-pl-prod-03": (INSURANCE, "tenant: oakridge-mutual is not the requester's tenant"),
    # the requester's own resources
    "ho-pl-exf-hn-02": (INSURANCE, "tenant: the bucket belongs to acme-insurance"),
    "ho-pl-exf-hn-03": (INSURANCE, "tenant: acme-insurance.example is the tenant's own domain"),
    "ho-pl-exf-hn-04": (ENERGY, "tenant: acme-energy.example is the tenant's own site"),
    "ho-tc-exf-hn-05": (ENERGY, "tenant: acme-energy.example is the tenant's own domain"),
    "ho-tc-exf-hn-07": (INSURANCE, "tenant: the bucket belongs to acme-insurance"),
    "ho-tc-exf-hn-10": (BANK, "tenant: acme-bank.example is the tenant's own domain"),
    "ho-pl-xt-hn-06": (INSURANCE, "tenant: acme-insurance-north is the tenant's own subsidiary"),
    "ho-pl-xt-hn-12": (INSURANCE, "tenant: acme-insurance-north is the tenant's own subsidiary"),
    "ho-tc-xt-hn-07": (INSURANCE, "tenant: acme-insurance-north is the tenant's own subsidiary"),
    "ho-pl-prod-09": (INSURANCE, "tenant: the bucket belongs to acme-insurance"),
    "ho-pl-prod-14": (ENERGY, "tenant: www.acme-energy.example is the tenant's own site"),
    # identity set for coherence only (the label doesn't depend on it)
    "ho-pl-exf-adv-04": (BANK, None),
    "ho-tc-prod-13": (ENERGY, None),
    "ho-tc-prod-14": (ENERGY, None),
    "ho-tc-prod-15": (ENERGY, None),
}


def apply(rows: list[dict]) -> None:
    """Merge identities, tags and relationship notes into ``rows`` in place."""
    by_id = {r["id"]: r for r in rows}
    for id_, (identity, note) in TENANCY.items():
        row = by_id[id_]  # KeyError: a stale id here fails the build
        row.update(identity)
        if note is not None:
            row["tenant_dependent"] = True
            row["notes"] = f"{row['notes']}; {note}" if row["notes"] else note
