"""
PoWS - Proof-of-Web-State Consensus Module
Shared logic for consensus computation and result formatting.
Used by both CLI (demo.py) and Web Server (coordinator.py).
"""

import hashlib
import time


def sha256(data: str | bytes) -> str:
    """Compute SHA256 hash of string or bytes."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def build_merkle_root(hashes: list[str]) -> str:
    """Simple binary merkle tree over resource hashes."""
    if not hashes:
        return sha256("empty")
    nodes = [bytes.fromhex(h) for h in hashes]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256(nodes[i] + nodes[i + 1]).digest()
            for i in range(0, len(nodes), 2)
        ]
    return nodes[0].hex()


def compute_consensus(results: list[dict], threshold: int = 2) -> dict:
    """
    Compute consensus across multiple validator results.
    Compares final_fingerprint (dom_hash + resource_merkle_root + layout_hash).
    
    Args:
        results: List of validator result dicts
        threshold: Minimum agreement count for certification (default: 2 of 3)
    
    Returns:
        Dict with consensus verdict and details
    """
    fingerprints = [r.get("final_fingerprint") for r in results if r.get("final_fingerprint")]
    
    # Count fingerprint occurrences
    fp_count: dict[str, int] = {}
    for fp in fingerprints:
        fp_count[fp] = fp_count.get(fp, 0) + 1
    
    # Find dominant fingerprint
    dominant_fp = max(fp_count, key=fp_count.get) if fp_count else None
    dominant_count = fp_count.get(dominant_fp, 0) if dominant_fp else 0
    
    # Certification: need threshold agreement
    certified = dominant_count >= threshold
    
    # Detect field-level mismatches
    mismatches = []
    if not certified and len(results) >= 2:
        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                ri, rj = results[i], results[j]
                for field in ["dom_hash", "layout_hash", "resource_merkle_root"]:
                    if ri.get(field) and rj.get(field) and ri[field] != rj[field]:
                        mismatches.append({
                            "field": field,
                            "validator_a": ri.get("validator_id"),
                            "validator_b": rj.get("validator_id"),
                            "hash_a": (ri[field][:16] + "…") if ri[field] else "N/A",
                            "hash_b": (rj[field][:16] + "…") if rj[field] else "N/A",
                        })
    
    # Build evidence hash for blockchain notarization
    evidence_str = (dominant_fp or "") + "|" + "|".join(str(r.get("final_fingerprint", "")) for r in results)
    evidence_hash = sha256(evidence_str + str(time.time()))
    
    return {
        "certified": certified,
        "dominant_fingerprint": dominant_fp,
        "agreement_count": dominant_count,
        "total_validators": len(results),
        "threshold": threshold,
        "mismatches": mismatches,
        "evidence_hash": evidence_hash[:32] + "…",
        "verdict": "✅ CERTIFIED" if certified else "❌ MISMATCH DETECTED",
    }
