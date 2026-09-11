import logging
from flask import Blueprint, request, jsonify, Response
from app.services import case_store
from app.services import report_generator

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__)

MAX_UPLOAD_ENTITIES = 2000
MAX_UPLOAD_ARTIFACTS = 50000


# ---------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------
@api_bp.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request", "detail": str(e)}), 400


@api_bp.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@api_bp.errorhandler(500)
def server_error(e):
    logger.exception("Unhandled server error")
    return jsonify({"error": "Internal server error"}), 500


def _get_engine_or_error(case_id):
    """Returns (engine, error_response). error_response is None on success."""
    engine = case_store.get_engine(case_id)
    if engine is None:
        return None, (jsonify({"error": f"Case '{case_id}' not found. It may not have been "
                                          "loaded yet, or the server restarted (case data is "
                                          "in-memory only)."}), 404)
    return engine, None


def _validate_case_payload(data):
    if not isinstance(data, dict):
        return "Request body must be a JSON object."
    if "entities" not in data or "artifacts" not in data:
        return "Case file must contain 'entities' and 'artifacts' keys."
    if not isinstance(data["entities"], list) or not isinstance(data["artifacts"], list):
        return "'entities' and 'artifacts' must both be arrays."
    if len(data["entities"]) == 0:
        return "Case file has no entities."
    if len(data["entities"]) > MAX_UPLOAD_ENTITIES:
        return f"Too many entities (max {MAX_UPLOAD_ENTITIES})."
    if len(data["artifacts"]) > MAX_UPLOAD_ARTIFACTS:
        return f"Too many artifacts (max {MAX_UPLOAD_ARTIFACTS})."
    valid_ids = {e.get("entity_id") for e in data["entities"] if isinstance(e, dict)}
    if len(valid_ids) != len(data["entities"]):
        return "Every entity must have a unique, non-null 'entity_id'."
    return None


# ---------------------------------------------------------------------
# Case management
# ---------------------------------------------------------------------
@api_bp.post("/cases/load-demo")
def load_demo():
    try:
        case_id = case_store.load_demo_case()
        return jsonify({"case_id": case_id})
    except FileNotFoundError:
        logger.exception("Demo dataset missing")
        return jsonify({"error": "Demo dataset file is missing on the server."}), 500


@api_bp.post("/cases/upload")
def upload_case():
    data = request.get_json(force=True, silent=True)
    err = _validate_case_payload(data)
    if err:
        return jsonify({"error": err}), 400
    try:
        case_id = case_store.load_case_from_dict(data)
    except Exception:
        logger.exception("Failed to build graph from uploaded case")
        return jsonify({"error": "Could not process this case file. Check that artifact "
                                  "records reference valid entity_ids."}), 400
    return jsonify({"case_id": case_id})


@api_bp.get("/cases")
def list_cases():
    return jsonify(case_store.list_cases())


@api_bp.get("/cases/<case_id>/log")
def get_case_log(case_id):
    log = case_store.get_log(case_id)
    if log is None:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(log)


# ---------------------------------------------------------------------
# Graph + analysis
# ---------------------------------------------------------------------
@api_bp.get("/cases/<case_id>/graph")
def get_graph(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    case_store.log_action(case_id, "graph_viewed")
    return jsonify(engine.to_graph_json())


@api_bp.get("/cases/<case_id>/centrality")
def get_centrality(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    case_store.log_action(case_id, "centrality_analysis_run")
    return jsonify(engine.centrality_analysis())


@api_bp.get("/cases/<case_id>/communities")
def get_communities(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    case_store.log_action(case_id, "community_detection_run")
    return jsonify(engine.community_detection())


@api_bp.get("/cases/<case_id>/anomalies")
def get_anomalies(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    case_store.log_action(case_id, "anomaly_scoring_run")
    return jsonify(engine.anomaly_scores())


@api_bp.get("/cases/<case_id>/link-predictions")
def get_link_predictions(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    case_store.log_action(case_id, "link_prediction_run")
    return jsonify(engine.link_prediction())


@api_bp.get("/cases/<case_id>/path")
def get_shortest_path(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    source = request.args.get("source")
    target = request.args.get("target")
    if not source or not target:
        return jsonify({"error": "source and target query params required"}), 400
    if source not in engine.entities or target not in engine.entities:
        return jsonify({"error": "source and/or target is not a known entity_id in this case"}), 400
    result = engine.shortest_path(source, target)
    case_store.log_action(case_id, "path_query_run", {"source": source, "target": target})
    return jsonify(result)


@api_bp.get("/cases/<case_id>/timeline")
def get_timeline(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    entity_id = request.args.get("entity_id") or None
    if entity_id and entity_id not in engine.entities:
        return jsonify({"error": f"Unknown entity_id '{entity_id}'"}), 400
    limit = request.args.get("limit", default=500, type=int)
    limit = max(1, min(limit, 2000))
    case_store.log_action(case_id, "timeline_viewed", {"entity_id": entity_id})
    return jsonify(engine.timeline(entity_id=entity_id, limit=limit))


# ---------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------
@api_bp.get("/cases/<case_id>/export/report.pdf")
def export_report_pdf(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    try:
        pdf_bytes = report_generator.build_case_pdf(
            engine, case_id,
            engine.centrality_analysis(),
            engine.community_detection(),
            engine.anomaly_scores(),
            engine.link_prediction(),
        )
    except Exception:
        logger.exception("PDF generation failed")
        return jsonify({"error": "Failed to generate PDF report."}), 500
    case_store.log_action(case_id, "report_exported", {"format": "pdf"})
    return Response(pdf_bytes, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{case_id}-report.pdf"'
    })


@api_bp.get("/cases/<case_id>/export/entities.csv")
def export_entities_csv(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    csv_text = report_generator.build_entities_csv(engine)
    case_store.log_action(case_id, "csv_exported", {"type": "entities"})
    return Response(csv_text, mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{case_id}-entities.csv"'
    })


@api_bp.get("/cases/<case_id>/export/artifacts.csv")
def export_artifacts_csv(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    csv_text = report_generator.build_artifacts_csv(engine)
    case_store.log_action(case_id, "csv_exported", {"type": "artifacts"})
    return Response(csv_text, mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{case_id}-artifacts.csv"'
    })


@api_bp.get("/cases/<case_id>/export/analysis.csv")
def export_analysis_csv(case_id):
    engine, err = _get_engine_or_error(case_id)
    if err:
        return err
    csv_text = report_generator.build_analysis_csv(engine.centrality_analysis(), engine.anomaly_scores())
    case_store.log_action(case_id, "csv_exported", {"type": "analysis"})
    return Response(csv_text, mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{case_id}-analysis.csv"'
    })
