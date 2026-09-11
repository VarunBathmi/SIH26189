import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set Neo4j connection env
os.environ["NEO4J_URI"] = "bolt://localhost:7687"
os.environ["NEO4J_USER"] = "neo4j"
os.environ["NEO4J_PASSWORD"] = "sih_pass123"

from app.graph.neo4j_engine import Neo4jGraphEngine

def test_neo4j_audit_live():
    engine = Neo4jGraphEngine()
    driver = engine.get_driver()
    assert driver is not None, "Driver must be connected"
    
    # 1. Clean up any leftover test cases
    engine.delete_case("CASE-AUDIT-ISO-1")
    engine.delete_case("CASE-AUDIT-ISO-2")
    
    # 2. Ingest Case 1 and Case 2 with same entity ID 'A'
    c1 = {
        'case_id': 'CASE-AUDIT-ISO-1',
        'entities': [{'entity_id': 'A', 'name': 'Alpha 1', 'phone': '+919876543210'}],
        'artifacts': [{'record_type': 'call', 'caller_id': 'A', 'callee_id': 'B1', 'timestamp': '2026-01-01T10:00:00Z', 'record_id': 'REC001'}]
    }
    c2 = {
        'case_id': 'CASE-AUDIT-ISO-2',
        'entities': [{'entity_id': 'A', 'name': 'Alpha 2', 'phone': '+919123456780'}],
        'artifacts': [{'record_type': 'call', 'caller_id': 'A', 'callee_id': 'B2', 'timestamp': '2026-02-02T15:30:00Z', 'record_id': 'REC002'}]
    }
    
    engine.load_case(c1)
    engine.load_case(c2)
    
    # 3. Cypher query to verify 2 distinct nodes
    with driver.session() as session:
        query = 'MATCH (e:Entity {entity_id: "A"}) RETURN e.entity_id AS id, e.case_id AS case_id, e.name AS name ORDER BY e.case_id'
        records = session.run(query).data()
        print("\n--- CYPHER QUERY FOR ENTITY 'A' ---")
        print("Query:", query)
        print("Result:", records)
        assert len(records) == 2, f"Expected 2 nodes for entity A across cases, got {len(records)}"
        assert records[0]['case_id'] == 'CASE-AUDIT-ISO-1' and records[0]['name'] == 'Alpha 1'
        assert records[1]['case_id'] == 'CASE-AUDIT-ISO-2' and records[1]['name'] == 'Alpha 2'
        print("PASS: Entity A created as 2 distinct nodes with case-specific case_id.")
        
        # Check relationships
        rel_q = 'MATCH (a:Entity {case_id: "CASE-AUDIT-ISO-1"})-[r]->(b) RETURN type(r) AS rel, r.record_id AS record_id, r.case_id AS case_id, r.timestamp AS timestamp'
        rel_records = session.run(rel_q).data()
        print("\n--- CASE 1 RELATIONSHIPS IN NEO4J ---")
        print(rel_records)
        for r in rel_records:
            assert r['case_id'] == 'CASE-AUDIT-ISO-1', f"Cross-case relation found: {r}"
            assert r['record_id'] != "" or r['rel'] == "HAS_ENTITY", f"Relationship missing record_id: {r}"
        
        # 4. Test to_graph_json isolation
        g1 = engine.to_graph_json('CASE-AUDIT-ISO-1')
        g2 = engine.to_graph_json('CASE-AUDIT-ISO-2')
        
        g1_node_ids = {n['id'] for n in g1['nodes']}
        g2_node_ids = {n['id'] for n in g2['nodes']}
        
        print("\n--- TO_GRAPH_JSON OUTPUT ---")
        print("Case 1 Engine:", g1['metadata']['engine'])
        print("Case 1 Nodes:", g1_node_ids)
        print("Case 2 Nodes:", g2_node_ids)
        
        assert 'B1' in g1_node_ids and 'B2' not in g1_node_ids, "Case 1 leaked Case 2 nodes!"
        assert 'B2' in g2_node_ids and 'B1' not in g2_node_ids, "Case 2 leaked Case 1 nodes!"
        print("PASS: Zero cross-case graph leakage detected.")
        
        # 5. Delete Case 1 and verify Case 2 remains
        engine.delete_case('CASE-AUDIT-ISO-1')
        records_after_del = session.run(query).data()
        print("\n--- AFTER DELETING CASE-AUDIT-ISO-1 ---")
        print("Remaining entity 'A' nodes:", records_after_del)
        assert len(records_after_del) == 1
        assert records_after_del[0]['case_id'] == 'CASE-AUDIT-ISO-2'
        print("PASS: Case deletion did not affect Case 2 nodes.")
        
        # Cleanup Case 2
        engine.delete_case('CASE-AUDIT-ISO-2')
        records_clean = session.run(query).data()
        assert len(records_clean) == 0
        print("PASS: Cleanup verified.")

def test_mutation_check():
    """
    Spot-check mutation: Deliberately execute an unisolated Cypher query (without case_id filter)
    and verify that it fails the case-isolation boundary by returning cross-case contaminated data.
    """
    engine = Neo4jGraphEngine()
    driver = engine.get_driver()
    assert driver is not None
    
    c1 = {
        'case_id': 'CASE-MUTATION-01',
        'entities': [{'entity_id': 'ALPHA', 'name': 'Target Alpha'}],
        'artifacts': [{'record_type': 'call', 'caller_id': 'ALPHA', 'callee_id': 'TARGET-CASE1', 'timestamp': '2026-01-01', 'record_id': 'R1'}]
    }
    c2 = {
        'case_id': 'CASE-MUTATION-02',
        'entities': [{'entity_id': 'ALPHA', 'name': 'Target Alpha'}],
        'artifacts': [{'record_type': 'call', 'caller_id': 'ALPHA', 'callee_id': 'TARGET-CASE2', 'timestamp': '2026-02-02', 'record_id': 'R2'}]
    }
    engine.load_case(c1)
    engine.load_case(c2)
    
    with driver.session() as session:
        # Deliberately broken query (omits case_id filter)
        unscoped_query = "MATCH (a:Entity {entity_id: 'ALPHA'})-[:CALLED]->(b) RETURN b.entity_id AS target"
        unscoped_targets = [r['target'] for r in session.run(unscoped_query).data()]
        print("\n--- MUTATION CHECK (UNSCOPED QUERY) ---")
        print("Unscoped targets returned:", unscoped_targets)
        # Unscoped query leaks both targets across cases
        assert 'TARGET-CASE1' in unscoped_targets and 'TARGET-CASE2' in unscoped_targets, "Unscoped query should leak cross-case"
        
        # Scoped query (with case_id filter)
        scoped_query = "MATCH (a:Entity {entity_id: 'ALPHA', case_id: $cid})-[:CALLED {case_id: $cid}]->(b {case_id: $cid}) RETURN b.entity_id AS target"
        scoped_targets = [r['target'] for r in session.run(scoped_query, cid='CASE-MUTATION-01').data()]
        print("Scoped targets returned for CASE-MUTATION-01:", scoped_targets)
        assert 'TARGET-CASE1' in scoped_targets and 'TARGET-CASE2' not in scoped_targets, "Scoped query must NOT leak"
        print("PASS: Mutation check verified — unscoped Cypher produces cross-case pollution, scoped Cypher strictly enforces isolation.")
        
    engine.delete_case('CASE-MUTATION-01')
    engine.delete_case('CASE-MUTATION-02')

if __name__ == "__main__":
    test_neo4j_audit_live()
    test_mutation_check()
