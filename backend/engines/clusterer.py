"""
engines/clusterer.py
---------------------
UMAP + HDBSCAN campaign clustering with Agglomerative fallback for small batches.

From proposal §3.2 Objective 2:
  >= 20 emails: UMAP (metric='precomputed') -> HDBSCAN
  <  20 emails: AgglomerativeClustering (Ward linkage)
  Noise emails -> label -1 -> "Unclustered"

Public API:
    cluster_emails(dist_matrix: np.ndarray, n_emails: int, min_cluster_size: int = 3)
        -> ClusterResult
"""

from __future__ import annotations
import logging
import numpy as np
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)

SMALL_BATCH_THRESHOLD = 20


@dataclass
class ClusterResult:
    labels:        List[int]    # -1 = noise, 0..K-1 = cluster id
    n_clusters:    int
    n_noise:       int
    algorithm:     str          # "HDBSCAN" or "Agglomerative"
    min_cluster_size: int
    umap_embedding: object = None  # (N, 2) array for visualization, or None


def _run_hdbscan(dist_matrix: np.ndarray, min_cluster_size: int) -> ClusterResult:
    # 1. 2D Manifold Projection (UMAP with MDS fallback)
    embedding = None
    try:
        import umap
        reducer = umap.UMAP(
            n_components=2,
            metric="precomputed",
            n_neighbors=max(2, min(15, len(dist_matrix) - 1)),
            min_dist=0.1,
            random_state=42,
        )
        embedding = reducer.fit_transform(dist_matrix).tolist()
    except Exception as e:
        logger.info(f"[clusterer] UMAP unavailable ({e}) — falling back to MDS manifold projection.")
        try:
            from sklearn.manifold import MDS
            mds = MDS(n_components=2, dissimilarity="precomputed", random_state=42, normalized_stress="auto")
            embedding = mds.fit_transform(dist_matrix).tolist()
        except Exception as mds_e:
            logger.warning(f"[clusterer] MDS projection also failed: {mds_e}")
            embedding = None

    # 2. HDBSCAN Clustering (sklearn native with fallback)
    labels = None
    try:
        from sklearn.cluster import HDBSCAN
        clusterer = HDBSCAN(
            min_cluster_size=min_cluster_size,
            metric="precomputed",
            cluster_selection_method="eom",
        )
        labels = clusterer.fit_predict(dist_matrix).tolist()
    except Exception as sk_e:
        try:
            import hdbscan
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=min_cluster_size,
                metric="precomputed",
                cluster_selection_method="eom",
            )
            labels = clusterer.fit_predict(dist_matrix).tolist()
        except Exception as e:
            logger.error(f"[clusterer] HDBSCAN failed: {e}")
            labels = [-1] * len(dist_matrix)

    unique = set(l for l in labels if l >= 0)

    # If HDBSCAN labeled everything as noise (-1), fall back to Agglomerative clustering
    if len(unique) == 0 and len(dist_matrix) >= 2:
        logger.info("[clusterer] HDBSCAN labeled all emails as noise — falling back to Agglomerative.")
        n_clusters = min(5, max(2, int(len(dist_matrix) ** 0.5)))
        fallback_res = _run_agglomerative(dist_matrix, n_clusters)
        fallback_res.umap_embedding = embedding
        return fallback_res

    return ClusterResult(
        labels=labels,
        n_clusters=len(unique),
        n_noise=labels.count(-1),
        algorithm="HDBSCAN",
        min_cluster_size=min_cluster_size,
        umap_embedding=embedding,
    )


def _run_agglomerative(dist_matrix: np.ndarray, n_clusters: int) -> ClusterResult:
    from sklearn.cluster import AgglomerativeClustering
    n = len(dist_matrix)
    n_clusters = min(n_clusters, max(1, n - 1))
    try:
        agg = AgglomerativeClustering(
            n_clusters=n_clusters,
            metric="precomputed",
            linkage="average",
        )
        labels = agg.fit_predict(dist_matrix).tolist()
    except Exception as e:
        logger.error(f"[clusterer] AgglomerativeClustering failed: {e}")
        labels = [0] * n

    # Compute 2D projection via MDS if possible
    embedding = None
    try:
        from sklearn.manifold import MDS
        mds = MDS(n_components=2, dissimilarity="precomputed", random_state=42, normalized_stress="auto")
        embedding = mds.fit_transform(dist_matrix).tolist()
    except Exception:
        embedding = None

    unique = set(labels)
    return ClusterResult(
        labels=labels,
        n_clusters=len(unique),
        n_noise=0,
        algorithm="Agglomerative Clustering",
        min_cluster_size=1,
        umap_embedding=embedding,
    )


def cluster_emails(
    dist_matrix:      np.ndarray,
    min_cluster_size: int = 3,
    force_algorithm:  str = None,   # "hdbscan" | "agglomerative" | None (auto)
) -> ClusterResult:
    """
    Cluster emails using the precomputed distance matrix.
    Auto-selects algorithm based on batch size.
    """
    n = len(dist_matrix)
    if n == 0:
        return ClusterResult([], 0, 0, "none", 0)
    if n == 1:
        return ClusterResult([0], 1, 0, "single", 1)

    use_hdbscan = (
        force_algorithm == "hdbscan"
        or (force_algorithm is None and n >= SMALL_BATCH_THRESHOLD)
    )

    if use_hdbscan:
        return _run_hdbscan(dist_matrix, min_cluster_size)
    else:
        # Small batch: auto-choose n_clusters (heuristic: sqrt(n) capped at 5)
        n_clusters = min(5, max(2, int(n ** 0.5)))
        return _run_agglomerative(dist_matrix, n_clusters)
