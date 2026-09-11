"""
Synthetic Forensic Data Generator
----------------------------------
Generates FAKE digital-forensic artifacts for demo/testing purposes only:
  - Call Detail Records (CDR)
  - Browser history exports
  - Chat/message metadata exports
  - File system artifact logs (creation/access/transfer timestamps)

No real names, numbers, or case data are used. This exists purely so the
analysis platform has realistic-shaped data to ingest and graph.
"""
import json
import random
import uuid
from datetime import datetime, timedelta

random.seed(42)

FAKE_FIRST_NAMES = ["Arjun", "Priya", "Rohan", "Sneha", "Vikram", "Kavya",
                     "Aditya", "Meera", "Karan", "Divya", "Suresh", "Anita",
                     "Rahul", "Neha", "Manoj", "Pooja"]
FAKE_LAST_NAMES = ["Sharma", "Verma", "Iyer", "Reddy", "Nair", "Gupta",
                    "Rao", "Menon", "Joshi", "Kapoor"]

DOMAINS = ["mailhub.test", "chatline.test", "quicknote.test", "filedrop.test"]

def fake_name():
    return f"{random.choice(FAKE_FIRST_NAMES)} {random.choice(FAKE_LAST_NAMES)}"

def fake_phone():
    return f"+91-9{random.randint(100000000, 999999999)}"

def fake_ip():
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def fake_device_id():
    return "DEV-" + uuid.uuid4().hex[:8].upper()

def random_time(start_days_ago=30):
    base = datetime.now() - timedelta(days=random.randint(0, start_days_ago))
    return (base + timedelta(hours=random.randint(0, 23),
                              minutes=random.randint(0, 59))).isoformat()


def generate_entities(n=14, n_groups=3):
    """Create a fixed pool of synthetic 'persons' each with a phone/device/IP,
    assigned to a small number of loose groups so the resulting graph forms
    realistic clusters instead of one dense blob."""
    entities = []
    for i in range(n):
        entities.append({
            "entity_id": f"P{i+1:03d}",
            "name": fake_name(),
            "phone": fake_phone(),
            "device_id": fake_device_id(),
            "ip": fake_ip(),
            "_group": i % n_groups,  # internal only, not exported in artifacts
        })
    return entities


def _weighted_pair(entities):
    """Picks two entities, biased heavily toward same-group pairs so clusters
    emerge, with occasional cross-group links (the 'hidden connections')."""
    a = random.choice(entities)
    if random.random() < 0.82:
        same_group = [e for e in entities if e["_group"] == a["_group"] and e != a]
        b = random.choice(same_group) if same_group else random.choice([e for e in entities if e != a])
    else:
        b = random.choice([e for e in entities if e != a])
    return a, b


def generate_call_logs(entities, n=70):
    """CDR-style records: caller -> callee, duration, timestamp, tower/cell (fake)."""
    records = []
    for _ in range(n):
        a, b = _weighted_pair(entities)
        records.append({
            "record_type": "call",
            "record_id": str(uuid.uuid4()),
            "caller_phone": a["phone"],
            "caller_id": a["entity_id"],
            "callee_phone": b["phone"],
            "callee_id": b["entity_id"],
            "duration_sec": random.randint(5, 1800),
            "timestamp": random_time(),
            "cell_tower": f"TWR-{random.randint(1,9)}",
        })
    return records


def generate_chat_metadata(entities, n=55):
    """Chat export metadata only (sender/receiver/platform/timestamp) —
    no message content, to keep this strictly metadata-level analysis."""
    records = []
    for _ in range(n):
        a, b = _weighted_pair(entities)
        records.append({
            "record_type": "chat",
            "record_id": str(uuid.uuid4()),
            "sender_id": a["entity_id"],
            "receiver_id": b["entity_id"],
            "platform": random.choice(["SecureChatX", "QuickMsg", "NoteDrop"]),
            "timestamp": random_time(),
        })
    return records


def generate_browser_history(entities, n=200):
    records = []
    for _ in range(n):
        a = random.choice(entities)
        records.append({
            "record_type": "browser_history",
            "record_id": str(uuid.uuid4()),
            "entity_id": a["entity_id"],
            "device_id": a["device_id"],
            "url": f"https://{random.choice(DOMAINS)}/{uuid.uuid4().hex[:6]}",
            "timestamp": random_time(),
        })
    return records


def generate_file_artifacts(entities, n=45):
    """File transfer / access artifacts, sometimes between two entities
    (simulating a file sent from one device and received on another)."""
    records = []
    for _ in range(n):
        involves_transfer = random.random() < 0.4
        a = random.choice(entities)
        rec = {
            "record_type": "file_artifact",
            "record_id": str(uuid.uuid4()),
            "owner_id": a["entity_id"],
            "device_id": a["device_id"],
            "filename": f"file_{uuid.uuid4().hex[:6]}.dat",
            "hash_sha256": uuid.uuid4().hex + uuid.uuid4().hex,
            "timestamp": random_time(),
        }
        if involves_transfer:
            same_group = [e for e in entities if e["_group"] == a["_group"] and e != a]
            pool = same_group if (same_group and random.random() < 0.82) else [e for e in entities if e != a]
            b = random.choice(pool)
            rec["transferred_to_id"] = b["entity_id"]
        records.append(rec)
    return records


def generate_location_pings(entities, n=110):
    """Device location pings (cell/GPS-derived). Unlike calls/chats, these are
    single-entity events — but two entities pinging near the same coordinates
    within a short time window is itself a forensic signal (co-location),
    computed later by the graph engine rather than encoded here."""
    # A handful of fixed "hotspot" coordinates per group so co-location has
    # something real to find, plus general noise locations.
    group_hotspots = {}
    records = []
    for e in entities:
        g = e["_group"]
        if g not in group_hotspots:
            group_hotspots[g] = (round(random.uniform(12.8, 13.1), 4),
                                  round(random.uniform(77.5, 77.7), 4))

    for _ in range(n):
        a = random.choice(entities)
        base_lat, base_lng = group_hotspots[a["_group"]]
        # Most pings cluster near the group hotspot (jitter), some are noise.
        if random.random() < 0.75:
            lat = round(base_lat + random.uniform(-0.01, 0.01), 5)
            lng = round(base_lng + random.uniform(-0.01, 0.01), 5)
        else:
            lat = round(random.uniform(12.8, 13.1), 5)
            lng = round(random.uniform(77.5, 77.7), 5)
        records.append({
            "record_type": "location_ping",
            "record_id": str(uuid.uuid4()),
            "entity_id": a["entity_id"],
            "device_id": a["device_id"],
            "lat": lat,
            "lng": lng,
            "timestamp": random_time(),
        })
    return records


def build_case(case_name="DEMO-CASE-001", n_entities=16, n_groups=3):
    entities = generate_entities(n_entities, n_groups)
    export_entities = [{k: v for k, v in e.items() if not k.startswith("_")} for e in entities]
    case = {
        "case_id": case_name,
        "generated_at": datetime.now().isoformat(),
        "note": "SYNTHETIC DATA — for testing/demo purposes only. No real persons.",
        "entities": export_entities,
        "artifacts": (
            generate_call_logs(entities)
            + generate_chat_metadata(entities)
            + generate_browser_history(entities)
            + generate_file_artifacts(entities)
            + generate_location_pings(entities)
        ),
    }
    return case


if __name__ == "__main__":
    case = build_case()
    out_path = "synthetic_case_demo001.json"
    with open(out_path, "w") as f:
        json.dump(case, f, indent=2)
    print(f"Wrote {len(case['artifacts'])} artifacts across {len(case['entities'])} entities to {out_path}")
