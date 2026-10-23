import tempfile
from pathlib import Path
from offtest.discovery.app_mapper import ApplicationMapper
from offtest.inventory.engine import InventoryEngine


def test_app_mapper_routes_and_features():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create FastAPI server
        api_file = tmp_path / "server.py"
        api_code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "hello"}

@app.get("/api/v1/users")
def get_users():
    return []

if is_feature_enabled("NEW_DASHBOARD"):
    print("New dashboard active")
"""
        api_file.write_text(api_code, encoding="utf-8")

        # Test file linking to feature
        test_file = tmp_path / "test_api.py"
        test_file.write_text('def test_feature():\n    assert "NEW_DASHBOARD" in "NEW_DASHBOARD"\n', encoding="utf-8")

        engine = InventoryEngine(str(tmp_path))
        files, _ = engine.scan()

        mapper = ApplicationMapper(tmp_path, files)
        routes, apis, features, workflows, integrations = mapper.map_application()

        assert len(routes) == 1
        assert routes[0].path == "/"
        assert len(apis) == 1
        assert apis[0].endpoint == "/api/v1/users"

        assert len(features) == 1
        assert features[0].flag_key == "NEW_DASHBOARD"
        assert len(features[0].linked_tests) == 1
