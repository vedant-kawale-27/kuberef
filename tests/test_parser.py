from kuberef.main import get_secret_refs, get_yaml_files

def test_recursive_discovery():
    """Test that secrets are found deep inside nested structures (like a Deployment)."""
    manifest = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "app",
                        "env": [{
                            "name": "DB_PASS",
                            "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}}
                        }]
                    }]
                }
            }
        }
    }
    refs = get_secret_refs(manifest)
    assert "db-secret" in refs
    assert "password" in refs["db-secret"]

def test_empty_manifest():
    """Ensure the tool doesn't crash on empty or non-k8s YAML."""
    manifest = {"random": "data"}
    refs = get_secret_refs(manifest)
    assert refs == {}

def test_multi_document_parsing():
    """Ensure secrets are discovered across multiple YAML documents."""

    import yaml

    multi_doc_yaml = """
---
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: DB_PASS
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password

---
kind: Pod
spec:
  containers:
  - name: worker
    env:
    - name: API_KEY
      valueFrom:
        secretKeyRef:
          name: api-secret
          key: token
"""

    docs = yaml.safe_load_all(multi_doc_yaml)

    combined_refs = {}

    for doc in docs:
        if not doc:
            continue

        for name, keys in get_secret_refs(doc).items():
            combined_refs.setdefault(name, set()).update(keys)

    assert "db-secret" in combined_refs
    assert "password" in combined_refs["db-secret"]

    assert "api-secret" in combined_refs
    assert "token" in combined_refs["api-secret"]

def test_invalid_yaml_handling():
    """Test that the audit command gracefully handles malformed YAML files without crashing."""
    import os
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Mock read_namespaced_secret to return correct Kubernetes secret objects
        def mock_read_secret(name, namespace=None):
            secret_data = {
                "registry-creds": {},
                "db-secret": {"password": "some-password-hash"},
                "api-keys": {},
                "ssl-certs": {},
                "controller-level-secret": {"api-token": "some-token"},
                "nested-app-secret": {"password": "some-password"}
            }
            if name in secret_data:
                secret = MagicMock()
                secret.data = secret_data[name]
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        # Resolve test-manifests to an absolute path
        test_manifests_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "test-manifests")
        )
        
        result = runner.invoke(app, [test_manifests_dir])
        
        # The tool should finish with exit code 0 or 1, and not crash with an exception.
        assert result.exit_code in (0, 1)
        # It should contain a clear error/warning message about malformed-pod.yaml.
        assert "Invalid YAML" in result.output
        assert "malformed-pod.yaml" in result.output


def test_quiet_mode():
    """Test that the audit command suppresses per-file tables when the quiet option is enabled."""
    import os
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Mock read_namespaced_secret
        def mock_read_secret(name, namespace=None):
            secret = MagicMock()
            secret.data = {}
            return secret
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        test_manifests_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "test-manifests")
        )
        
        # Test short option -q
        result_q = runner.invoke(app, [test_manifests_dir, "-q"])
        assert result_q.exit_code in (0, 1)
        assert "Security Audit:" not in result_q.output
        assert "AUDIT SUMMARY" in result_q.output
        
        # Test long option --quiet
        result_quiet = runner.invoke(app, [test_manifests_dir, "--quiet"])
        assert result_quiet.exit_code in (0, 1)
        assert "Security Audit:" not in result_quiet.output
        assert "AUDIT SUMMARY" in result_quiet.output


import os
import yaml
from kuberef.main import get_secret_refs  # Compiles the parser method

def test_complex_pod_secret_references():
    """
    Verifies that the parser extracts all 4 core Secret reference patterns
    (env, envFrom, volumes, and imagePullSecrets) from a real manifest file.
    """
    # 1. Safely locate the test-manifests directory relative to this file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    manifest_path = os.path.join(project_root, "test-manifests", "complex-pod.yaml")
    
    # 2. Read and parse the raw static YAML file from disk
    with open(manifest_path, "r") as file:
        manifest_data = yaml.safe_load(file)
        
    # 3. Pass the parsed dictionary data to the Kuberef discovery engine
    discovered_secrets = get_secret_refs(manifest_data)
    
    # 4. Assert that all 4 expected target secrets are extracted properly
    assert "registry-creds" in discovered_secrets, "Failed to extract secret from imagePullSecrets"
    assert "db-secret" in discovered_secrets, "Failed to extract secret from env.valueFrom"
    assert "api-keys" in discovered_secrets, "Failed to extract secret from envFrom"
    assert "ssl-certs" in discovered_secrets, "Failed to extract secret from volumes"


def test_get_yaml_files_excludes_directories(tmp_path):
    """Verify that get_yaml_files discovers valid YAMLs and filters out build/env/meta directories."""
    # Create valid manifest files
    valid_dir = tmp_path / "manifests"
    valid_dir.mkdir()
    valid_file = valid_dir / "pod.yaml"
    valid_file.write_text("kind: Pod")
    
    # Create files inside excluded directories
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    git_file = git_dir / "config.yaml"
    git_file.write_text("some-git-config")
    
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    venv_file = venv_dir / "lib.yml"
    venv_file.write_text("some-venv-config")
    
    node_modules_dir = tmp_path / "node_modules"
    node_modules_dir.mkdir()
    node_modules_file = node_modules_dir / "package.yaml"
    node_modules_file.write_text("npm-yaml")
    
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    build_file = build_dir / "build-config.yaml"
    build_file.write_text("some-build-config")
    
    # Run the get_yaml_files helper
    discovered = get_yaml_files(tmp_path)
    
    # Assertions: Only pod.yaml should be found
    discovered_names = [f.name for f in discovered]
    assert "pod.yaml" in discovered_names
    assert "config.yaml" not in discovered_names
    assert "lib.yml" not in discovered_names
    assert "package.yaml" not in discovered_names
    assert "build-config.yaml" not in discovered_names
    assert len(discovered) == 1


def test_get_yaml_files_with_excluded_name_in_parent_path(tmp_path):
    """Verify that get_yaml_files does not exclude files just because a parent directory contains an excluded name."""
    # Create a parent directory named 'venv'
    parent_dir = tmp_path / "venv"
    parent_dir.mkdir()
    
    # Create a target directory inside the 'venv' folder
    target_dir = parent_dir / "my-project"
    target_dir.mkdir()
    
    # Create a valid yaml manifest inside 'my-project'
    valid_file = target_dir / "deployment.yaml"
    valid_file.write_text("kind: Deployment")
    
    # Scan the target directory
    discovered = get_yaml_files(target_dir)
    
    # It should discover the valid deployment.yaml file!
    discovered_names = [f.name for f in discovered]
    assert "deployment.yaml" in discovered_names
    assert len(discovered) == 1


def test_find_line_number(tmp_path):
    """Test find_line_number helper handles finding matching secret and key names."""
    from kuberef.formatters import find_line_number
    yaml_content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  template:
    spec:
      containers:
      - name: web
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
"""
    manifest_file = tmp_path / "manifest.yaml"
    manifest_file.write_text(yaml_content)
    
    # Locate secret definition
    secret_line = find_line_number(manifest_file, "db-secret")
    assert secret_line == 14
    
    # Locate key definition (should return the closest line of the key)
    key_line = find_line_number(manifest_file, "db-secret", "password")
    assert key_line == 15


def test_github_formatter(capsys, tmp_path):
    """Test print_github_annotations outputs correct ::error and ::warning format lines."""
    from kuberef.formatters import print_github_annotations
    findings = [
        {
            "file_path": tmp_path / "deployment.yaml",
            "type": "error",
            "rule_id": "missing-secret",
            "res_name": "db-secret"
        },
        {
            "file_path": tmp_path / "pod.yaml",
            "type": "warning",
            "rule_id": "missing-key",
            "res_name": "api-secret",
            "res_key": "token"
        }
    ]
    # Create dummy files
    (tmp_path / "deployment.yaml").write_text("name: db-secret")
    (tmp_path / "pod.yaml").write_text("name: api-secret\nkey: token")
    
    print_github_annotations(findings)
    captured = capsys.readouterr()
    
    assert "::error file=" in captured.out
    assert "title=Missing Secret Reference::The secret 'db-secret' was not found in the cluster." in captured.out
    assert "::warning file=" in captured.out
    assert "title=Missing Secret Key::The key 'token' of secret 'api-secret' was not found in the cluster." in captured.out


def test_sarif_formatter(tmp_path):
    """Test generate_sarif_report formats a valid SARIF structure."""
    from kuberef.formatters import generate_sarif_report
    findings = [
        {
            "file_path": tmp_path / "deployment.yaml",
            "type": "error",
            "rule_id": "missing-secret",
            "res_name": "db-secret"
        }
    ]
    (tmp_path / "deployment.yaml").write_text("name: db-secret")
    
    sarif_data = generate_sarif_report(findings, 1)
    
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(sarif_data["runs"]) == 1
    run = sarif_data["runs"][0]
    assert run["tool"]["driver"]["name"] == "kuberef"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "missing-secret"
    assert result["level"] == "error"
    assert "db-secret" in result["message"]["text"]


def test_cli_audit_format_github(tmp_path):
    """Integration test: audit --format github prints standard logs and github annotations."""
    import os
    import json
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    yaml_content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  template:
    spec:
      containers:
      - name: main
        env:
        - name: SECRET_VAR
          valueFrom:
            secretKeyRef:
              name: missing-secret
              key: some-key
"""
    manifest_file = tmp_path / "deployment.yaml"
    manifest_file.write_text(yaml_content)

    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        from kubernetes.client.rest import ApiException
        mock_api.read_namespaced_secret.side_effect = ApiException(status=404, reason="Not Found")
        
        result = runner.invoke(app, [str(manifest_file), "--format", "github"])
        
        assert result.exit_code == 1
        assert "Security Audit:" in result.output
        assert "AUDIT SUMMARY" in result.output
        assert "::error file=" in result.output
        assert "title=Missing Secret Reference::The secret 'missing-secret' was not found in the cluster." in result.output


def test_cli_audit_format_sarif(tmp_path):
    """Integration test: audit --format sarif prints valid SARIF JSON to stdout or file."""
    import os
    import json
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    yaml_content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  template:
    spec:
      containers:
      - name: main
        env:
        - name: SECRET_VAR
          valueFrom:
            secretKeyRef:
              name: missing-secret
              key: some-key
"""
    manifest_file = tmp_path / "deployment.yaml"
    manifest_file.write_text(yaml_content)

    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        from kubernetes.client.rest import ApiException
        mock_api.read_namespaced_secret.side_effect = ApiException(status=404, reason="Not Found")
        
        # Test output to stdout
        result = runner.invoke(app, [str(manifest_file), "--format", "sarif"])
        assert result.exit_code == 1
        assert "Security Audit:" not in result.output
        assert "AUDIT SUMMARY" not in result.output
        
        sarif_out = json.loads(result.output)
        assert sarif_out["version"] == "2.1.0"
        assert len(sarif_out["runs"][0]["results"]) == 1
        
        # Test output to file
        sarif_file = tmp_path / "output.sarif"
        result_file = runner.invoke(app, [str(manifest_file), "--format", "sarif", "--output-file", str(sarif_file)])
        assert result_file.exit_code == 1
        assert result_file.output == ""
        
        assert sarif_file.is_file()
        with open(sarif_file, "r") as sf:
            file_sarif = json.load(sf)
        assert file_sarif["version"] == "2.1.0"
        assert file_sarif["runs"][0]["results"][0]["ruleId"] == "missing-secret"


def test_is_helm_chart(tmp_path):
    """Test that is_helm_chart correctly identifies directories with Chart.yaml or Chart.yml."""
    from kuberef.main import is_helm_chart
    
    # Not a directory/non-existent
    assert not is_helm_chart(tmp_path / "non-existent")
    
    # Empty directory
    dir_path = tmp_path / "chart-dir"
    dir_path.mkdir()
    assert not is_helm_chart(dir_path)
    
    # Directory with Chart.yaml
    chart_yaml = dir_path / "Chart.yaml"
    chart_yaml.write_text("apiVersion: v2")
    assert is_helm_chart(dir_path)
    
    # Directory with Chart.yml
    dir_path_yml = tmp_path / "chart-dir-yml"
    dir_path_yml.mkdir()
    chart_yml = dir_path_yml / "Chart.yml"
    chart_yml.write_text("apiVersion: v2")
    assert is_helm_chart(dir_path_yml)


def test_helm_rendering_success(tmp_path):
    """Test standard Helm chart rendering and integration with the audit engine."""
    import os
    import subprocess
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    # Set up dummy chart dir
    chart_dir = tmp_path / "my-chart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: my-chart")
    
    mock_rendered_yaml = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-name-deployment
spec:
  template:
    spec:
      containers:
      - name: web
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        - name: ANOTHER_SECRET
          valueFrom:
            secretKeyRef:
              name: missing-secret-ref
              key: token
"""

    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class, \
         patch("subprocess.run") as mock_run:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        # Mock read_namespaced_secret
        def mock_read_secret(name, namespace=None):
            if name == "db-secret":
                secret = MagicMock()
                secret.data = {"password": "pwd"}
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        # Mock subprocess.run for helm version and helm template
        def mock_subprocess_run(args, **kwargs):
            mock_res = MagicMock()
            mock_res.returncode = 0
            if args == ["helm", "version"]:
                mock_res.stdout = "version.BuildInfo{Version:\"v3.12.0\"}"
            elif args == ["helm", "template", str(chart_dir)]:
                mock_res.stdout = mock_rendered_yaml
            return mock_res
            
        mock_run.side_effect = mock_subprocess_run
        
        result = runner.invoke(app, [str(chart_dir)])
        
        assert result.exit_code == 1
        assert "Security Audit: Helm Template: my-chart" in result.output
        assert "db-secret" in result.output
        assert "PASS" in result.output
        assert "missing-secret-ref" in result.output
        assert "FAIL (Secret Missing)" in result.output


def test_helm_rendering_missing_helm(tmp_path):
    """Test that a clean error is raised if the Helm CLI is not found on the system."""
    import subprocess
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    chart_dir = tmp_path / "my-chart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2")
    
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = runner.invoke(app, [str(chart_dir)])
        assert result.exit_code == 1
        assert "Helm CLI not found. Please install Helm to audit Helm charts natively." in result.output


def test_helm_rendering_command_failure(tmp_path):
    """Test that helm template errors are printed to stdout and cause clean exit."""
    import subprocess
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    chart_dir = tmp_path / "my-chart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2")
    
    def mock_subprocess_run(args, **kwargs):
        if args == ["helm", "version"]:
            res = MagicMock()
            res.returncode = 0
            return res
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=args,
            stderr="Error: failed to parse Chart.yaml: unexpected end of file"
        )
        
    with patch("subprocess.run", side_effect=mock_subprocess_run):
        result = runner.invoke(app, [str(chart_dir)])
        assert result.exit_code == 1
        assert "Helm Template Error:" in result.output
        assert "failed to parse Chart.yaml" in result.output


def test_helm_rendering_github_format(tmp_path):
    """Test Helm chart rendering and integration with GitHub output format."""
    import os
    import subprocess
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    # Set up dummy chart dir
    chart_dir = tmp_path / "my-chart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: my-chart")
    
    mock_rendered_yaml = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-name-deployment
spec:
  template:
    spec:
      containers:
      - name: web
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        - name: ANOTHER_SECRET
          valueFrom:
            secretKeyRef:
              name: missing-secret-ref
              key: token
"""

    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class, \
         patch("subprocess.run") as mock_run:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        def mock_read_secret(name, namespace=None):
            if name == "db-secret":
                secret = MagicMock()
                secret.data = {"password": "pwd"}
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        def mock_subprocess_run(args, **kwargs):
            mock_res = MagicMock()
            mock_res.returncode = 0
            if args == ["helm", "version"]:
                mock_res.stdout = "version.BuildInfo{Version:\"v3.12.0\"}"
            elif args == ["helm", "template", str(chart_dir)]:
                mock_res.stdout = mock_rendered_yaml
            return mock_res
            
        mock_run.side_effect = mock_subprocess_run
        
        result = runner.invoke(app, [str(chart_dir), "--format", "github"])
        
        assert result.exit_code == 1
        assert "::error file=Helm Template: my-chart" in result.output
        assert "The secret 'missing-secret-ref' was not found in the cluster." in result.output


def test_helm_rendering_sarif_format(tmp_path):
    """Test Helm chart rendering and integration with SARIF output format."""
    import os
    import json
    import subprocess
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    # Set up dummy chart dir
    chart_dir = tmp_path / "my-chart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: my-chart")
    
    mock_rendered_yaml = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-name-deployment
spec:
  template:
    spec:
      containers:
      - name: web
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        - name: ANOTHER_SECRET
          valueFrom:
            secretKeyRef:
              name: missing-secret-ref
              key: token
"""

    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class, \
         patch("subprocess.run") as mock_run:
        
        mock_contexts.return_value = (None, {"name": "mock-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        def mock_read_secret(name, namespace=None):
            if name == "db-secret":
                secret = MagicMock()
                secret.data = {"password": "pwd"}
                return secret
            from kubernetes.client.rest import ApiException
            raise ApiException(status=404, reason="Not Found")
            
        mock_api.read_namespaced_secret.side_effect = mock_read_secret
        
        def mock_subprocess_run(args, **kwargs):
            mock_res = MagicMock()
            mock_res.returncode = 0
            if args == ["helm", "version"]:
                mock_res.stdout = "version.BuildInfo{Version:\"v3.12.0\"}"
            elif args == ["helm", "template", str(chart_dir)]:
                mock_res.stdout = mock_rendered_yaml
            return mock_res
            
        mock_run.side_effect = mock_subprocess_run
        
        result = runner.invoke(app, [str(chart_dir), "--format", "sarif"])
        
        assert result.exit_code == 1
        sarif_data = json.loads(result.output)
        assert sarif_data["version"] == "2.1.0"
        results = sarif_data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "missing-secret"
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "Helm Template: my-chart"


def test_context_and_kubeconfig_forwarding(tmp_path):
    """Test that the CLI options --context and --kubeconfig are correctly forwarded to config.load_kube_config."""
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    yaml_content = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: my-pod\n"
    manifest_file = tmp_path / "pod.yaml"
    manifest_file.write_text(yaml_content)

    with patch("kuberef.main.config.load_kube_config") as mock_load, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        mock_contexts.return_value = (None, {"name": "custom-cluster"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        result = runner.invoke(app, [
            str(manifest_file),
            "--context", "dev-cluster",
            "--kubeconfig", "/path/to/kubeconfig"
        ])
        
        import os
        expected_path = os.path.normpath("/path/to/kubeconfig")
        
        assert result.exit_code in (0, 1)
        mock_load.assert_called_once_with(
            config_file=expected_path,
            context="dev-cluster"
        )


def test_incluster_config_fallback(tmp_path):
    """Test that the audit command falls back to config.load_incluster_config if load_kube_config fails when no explicit config options are provided."""
    from unittest.mock import patch, MagicMock
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    
    yaml_content = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: my-pod\n"
    manifest_file = tmp_path / "pod.yaml"
    manifest_file.write_text(yaml_content)

    with patch("kuberef.main.config.load_kube_config") as mock_load_kube, \
         patch("kuberef.main.config.load_incluster_config") as mock_load_incluster, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:
        
        # Make load_kube_config raise an exception (simulating no kubeconfig file)
        mock_load_kube.side_effect = Exception("No kubeconfig file found")
        
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api
        
        result = runner.invoke(app, [str(manifest_file)])
        
        assert result.exit_code in (0, 1)
        mock_load_kube.assert_called_once()
        mock_load_incluster.assert_called_once()


def test_context_resolution_from_env_plugin(tmp_path):
    """Test that context is resolved from KUBECTL_PLUGINS_CURRENT_CONTEXT if not explicitly set."""
    from unittest.mock import patch, MagicMock
    import os
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    manifest_file = tmp_path / "pod.yaml"
    manifest_file.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: my-pod\n")

    with patch.dict(os.environ, {"KUBECTL_PLUGINS_CURRENT_CONTEXT": "my-plugin-context"}), \
         patch("kuberef.main.config.load_kube_config") as mock_load_kube, \
         patch("kuberef.main.config.list_kube_config_contexts") as mock_contexts, \
         patch("kuberef.main.client.CoreV1Api") as mock_api_class:

        mock_contexts.return_value = (None, {"name": "my-plugin-context"})
        mock_api = MagicMock()
        mock_api_class.return_value = mock_api

        result = runner.invoke(app, [str(manifest_file)])

        assert result.exit_code in (0, 1)
        mock_load_kube.assert_called_once_with(
            config_file=None,
            context="my-plugin-context"
        )


def test_no_incluster_fallback_for_plugin_env(tmp_path):
    """Test that we do not fallback to in-cluster config when KUBECTL_PLUGINS_CURRENT_CONTEXT or KUBECONFIG is set."""
    from unittest.mock import patch, MagicMock
    import os
    from typer.testing import CliRunner
    from kuberef.main import app

    runner = CliRunner()
    manifest_file = tmp_path / "pod.yaml"
    manifest_file.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: my-pod\n")

    # Scenario A: KUBECTL_PLUGINS_CURRENT_CONTEXT is set
    with patch.dict(os.environ, {"KUBECTL_PLUGINS_CURRENT_CONTEXT": "some-context"}), \
         patch("kuberef.main.config.load_kube_config") as mock_load_kube, \
         patch("kuberef.main.config.load_incluster_config") as mock_load_incluster:

        mock_load_kube.side_effect = Exception("Load config failed")

        result = runner.invoke(app, [str(manifest_file)])

        assert result.exit_code == 1
        mock_load_kube.assert_called_once()
        mock_load_incluster.assert_not_called()

    # Scenario B: KUBECONFIG is set
    with patch.dict(os.environ, {"KUBECONFIG": "/some/kubeconfig"}), \
         patch("kuberef.main.config.load_kube_config") as mock_load_kube, \
         patch("kuberef.main.config.load_incluster_config") as mock_load_incluster:

        mock_load_kube.side_effect = Exception("Load config failed")

        result = runner.invoke(app, [str(manifest_file)])

        assert result.exit_code == 1
        mock_load_kube.assert_called_once()
        mock_load_incluster.assert_not_called()