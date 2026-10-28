"""
engines/distance.py
--------------------
Pairwise distance matrix computation for Mode 2 campaign clustering.

Formula (from proposal §3.2 Objective 2):
    dist_cosine(A,B)  = 1 - cosine_similarity(embed_A, embed_B)  [0,1]
    dist_jaccard(A,B) = 1 - mean(Jaccard(IPs), Jaccard(ASNs), Jaccard(domains))  [0,1]
    dist_combined     = 0.4 * dist_cosine + 0.6 * dist_jaccard

Public API:
    compute_distance_matrix(
        embeddings: np.ndarray,          # (N, 384) unit-normalized
        ip_sets:     list[set[str]],     # relay IP sets per email
        asn_sets:    list[set[str]],     # ASN sets per email
        domain_sets: list[set[str]],     # originating domain sets per email
        w_semantic=0.4, w_infra=0.6
    ) -> np.ndarray  # (N, N) combined distance matrix
"""

from __future__ import annotations
import numpy as np
from typing import List, Set


def _jaccard(a: set, b: set) -> float:
    """Jaccard distance: 1 - |A intersect B| / |A union B|. Returns 0.5 if both empty (neutral signal)."""
    if not a and not b:
        return 0.5   # Neutral: missing infrastructure on both ends should not artificially maximize distance
    u = len(a | b)
    if u == 0:
        return 0.5
    return 1.0 - len(a & b) / u


def _jaccard_distance_matrix(sets: List[Set[str]]) -> np.ndarray:
    """Compute NxN pairwise Jaccard distance matrix for a list of sets."""
    n = len(sets)
    mat = np.zeros((n, n), dtype=np.float64)
    for i in range(n):
        for j in range(i + 1, n):
            d = _jaccard(sets[i], sets[j])
            mat[i, j] = d
            mat[j, i] = d
    return mat


def compute_distance_matrix(
    embeddings:  np.ndarray,
    ip_sets:     List[Set[str]],
    asn_sets:    List[Set[str]],
    domain_sets: List[Set[str]],
    w_semantic:  float = 0.4,
    w_infra:     float = 0.6,
) -> np.ndarray:
    """
    Compute the composite NxN precomputed distance matrix.
    Both dist_cosine and dist_jaccard are in [0,1]; no dimensionality bias.
    """
    n = len(ip_sets)
    if n == 0:
        return np.zeros((0, 0))

    # Cosine distance from unit-normalized embeddings: dist = 1 - dot(a, b)
    if embeddings is not None and len(embeddings) == n and embeddings.shape[1] > 0:
        # Clip to [0,1] due to floating point
        cos_sim = np.clip(embeddings @ embeddings.T, -1.0, 1.0)
        dist_cosine = 1.0 - cos_sim
        np.fill_diagonal(dist_cosine, 0.0)
    else:
        dist_cosine = np.ones((n, n), dtype=np.float64)
        np.fill_diagonal(dist_cosine, 0.0)

    # Jaccard distance on each infrastructure signal set
    d_ip     = _jaccard_distance_matrix(ip_sets)
    d_asn    = _jaccard_distance_matrix(asn_sets)
    d_domain = _jaccard_distance_matrix(domain_sets)
    dist_jaccard = (d_ip + d_asn + d_domain) / 3.0

    # Weighted combination
    dist_combined = w_semantic * dist_cosine + w_infra * dist_jaccard
    np.fill_diagonal(dist_combined, 0.0)

    return np.clip(dist_combined, 0.0, 1.0)
