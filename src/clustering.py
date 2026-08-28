from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass
class Cluster:
    cluster_id: str
    members: List[str]


def build_clusters(shas: List[str],
                   matches: Iterable[Tuple[str, str]]) -> List[Cluster]:
    parent = {s: s for s in shas}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]

        return x

    def union(a: str, b: str):
        ra, rb = find(a), find(b)
        if ra != rb:
            # deterministic root
            if rb < ra:
                ra, rb = rb, ra
            parent[rb] = ra

    for a, b in matches:
        if a == b or a not in parent or b not in parent:
            continue
        union(a, b)

    groups = {}
    for s in sorted(parent):
        groups.setdefault(find(s), []).append(s)

    clusters = [Cluster(root[:8], members)
                for root, members in groups.items()]
    clusters.sort(key=lambda c: (-len(c.members), c.cluster_id))

    return clusters
