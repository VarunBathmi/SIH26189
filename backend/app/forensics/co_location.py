import math
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def haversine_distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two GPS coordinates in meters.
    """
    R = 6371000.0 # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return R * c

def detect_co_locations(
    locations: List[Dict[str, Any]],
    distance_threshold_meters: float = 100.0
) -> List[Dict[str, Any]]:
    """
    Detect suspect co-location events:
    Flags pairs of individuals positioned within distance_threshold_meters (e.g. 100m).
    """
    co_locations = []
    n = len(locations)

    for i in range(n):
        for j in range(i + 1, n):
            loc1 = locations[i]
            loc2 = locations[j]
            p1 = loc1.get("person_name")
            p2 = loc2.get("person_name")

            if not p1 or not p2 or p1 == p2:
                continue

            dist = haversine_distance_meters(
                loc1["latitude"], loc1["longitude"],
                loc2["latitude"], loc2["longitude"]
            )

            if dist <= distance_threshold_meters:
                co_locations.append({
                    "person1": p1,
                    "person2": p2,
                    "distance_meters": round(dist, 2),
                    "timestamp1": loc1.get("timestamp", ""),
                    "timestamp2": loc2.get("timestamp", ""),
                    "location_name": loc1.get("location_name") or loc2.get("location_name") or "Co-located GPS Coordinate",
                    "confidence": "requires_investigator_review"
                })

    return co_locations
