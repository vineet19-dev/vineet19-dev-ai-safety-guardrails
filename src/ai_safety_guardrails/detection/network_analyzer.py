from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import networkx as nx


@dataclass
class Network:
    graph: Any  # nx.Graph
    entities: List[str]


@dataclass
class Cluster:
    members: List[str]
    density: float
    suspicion_score: float


class NetworkAnalyzer:
    """Graph-based network analysis for detecting collusion and suspicious connections."""

    def build_network(self, entities: list, relationships: list) -> Network:
        """Build a network graph from entities and relationships."""
        G = nx.Graph()

        for entity in entities:
            entity_id = entity if isinstance(entity, str) else entity.get('id', str(entity))
            G.add_node(entity_id)

        for rel in relationships:
            if isinstance(rel, (list, tuple)) and len(rel) >= 2:
                G.add_edge(str(rel[0]), str(rel[1]))
            elif isinstance(rel, dict):
                source = rel.get('source') or rel.get('from')
                target = rel.get('target') or rel.get('to')
                weight = rel.get('weight', 1.0)
                if source and target:
                    G.add_edge(str(source), str(target), weight=weight)

        entity_ids = [e if isinstance(e, str) else e.get('id', str(e)) for e in entities]
        return Network(graph=G, entities=entity_ids)

    def detect_collusion_clusters(self, network: Network) -> List[Cluster]:
        """Detect clusters of colluding entities."""
        G = network.graph
        clusters = []

        for component in nx.connected_components(G):
            if len(component) >= 2:
                subgraph = G.subgraph(component)
                density = nx.density(subgraph)
                suspicion = density * min(len(component) / 5.0, 1.0)

                clusters.append(Cluster(
                    members=list(component),
                    density=density,
                    suspicion_score=suspicion
                ))

        return sorted(clusters, key=lambda c: c.suspicion_score, reverse=True)

    def find_suspicious_connections(self, entity_id: str, network: Network) -> list:
        """Find suspicious connections for a given entity."""
        G = network.graph

        if entity_id not in G:
            return []

        suspicious = []
        neighbors = list(G.neighbors(entity_id))

        for neighbor in neighbors:
            degree = G.degree(neighbor)
            if degree > 3:
                suspicious.append({
                    'entity': neighbor,
                    'type': 'high_connectivity_hub',
                    'degree': degree,
                    'suspicion_level': min(degree / 10.0, 1.0)
                })

        # Check for triangles (tight-knit groups)
        triangle_dict = nx.triangles(G)
        triangles = triangle_dict.get(entity_id, 0)
        if triangles > 0:
            suspicious.append({
                'entity': entity_id,
                'type': 'triangle_cluster',
                'triangle_count': triangles,
                'suspicion_level': min(triangles / 5.0, 1.0)
            })

        return suspicious
