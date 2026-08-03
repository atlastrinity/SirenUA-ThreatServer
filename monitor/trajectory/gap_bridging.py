"""
Trajectory pathfinding, gap bridging, and inland ingress extrapolation engine.
"""

from typing import List, Optional, Set, Dict
from core.topology import UKRAINE_TOPOLOGY
from core.regions import get_genitive_region, get_ukrainian_threat_type

INLAND_TRANSIT_OBLASTS = (
    "Чернігівська область", "Сумська область", "Житомирська область",
    "Черкаська область", "Полтавська область", "Кіровоградська область",
    "Вінницька область", "Київська область", "Хмельницька область"
)

EXTRAPOLATED_INGRESS_CORRIDORS: Dict[str, str] = {
    "Дніпропетровська область": "Запорізька область",
    "Полтавська область": "Сумська область",
    "Черкаська область": "Кіровоградська область",
    "Вінницька область": "Одеська область",
    "Житомирська область": "Чернігівська область",
    "Хмельницька область": "Вінницька область",
    "Рівненська область": "Житомирська область",
    "Тернопільська область": "Хмельницька область",
    "Чернівецька область": "Вінницька область",
    "Івано-Франківська область": "Чернівецька область",
    "Закарпатська область": "Івано-Франківська область",
    "Львівська область": "Тернопільська область",
    "Волинська область": "Рівненська область"
}


def find_shortest_path(start_region: str, end_region: str) -> List[str]:
    """BFS algorithm to find the shortest topological path between two regions in Ukraine."""
    if start_region not in UKRAINE_TOPOLOGY or end_region not in UKRAINE_TOPOLOGY:
        return []
    
    queue = [[start_region]]
    visited = set([start_region])
    
    while queue:
        path = queue.pop(0)
        node = path[-1]
        
        if node == end_region:
            return path
            
        for adjacent in UKRAINE_TOPOLOGY.get(node, []):
            if adjacent not in visited:
                visited.add(adjacent)
                new_path = list(path)
                new_path.append(adjacent)
                queue.append(new_path)
    return []
