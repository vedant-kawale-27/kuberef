import json
import subprocess
import typer
import yaml
from pathlib import Path
from typing import List, Dict, Any, Set
from rich.console import Console
from rich.table import Table
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kuberef.formatters import print_github_annotations, generate_sarif_report, sanitize_string


app = typer.Typer()
console = Console()


class ScanTarget:
    def __init__(self, name: str, path: Path, content: str = None):
        self.name = name
        self.path = path
        self.content = content

    def __str__(self) -> str:
        return self.name


def is_helm_chart(path: Path) -> bool:
    """Checks if a directory is a Helm chart by looking for Chart.yaml or Chart.yml."""
    return path.is_dir() and ((path / "Chart.yaml").is_file() or (path / "Chart.yml").is_file())


def find_pod_specs(data: Any) -> List[Dict[str, Any]]:
    """Recursively finds all Pod 'spec' blocks (handles Deployments, Jobs, etc.)."""
    specs = []
    if isinstance(data, dict):
        if "containers" in data and isinstance(data["containers"], list):
            specs.append(data)
        for value in data.values():
            specs.extend(find_pod_specs(value))
    elif isinstance(data, list):
        for item in data:
            specs.extend(find_pod_specs(item))
    return specs


def get_secret_refs(data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Maps secret names to the specific keys they need to provide."""
    all_refs = {}

    def add_ref(name: str, key: str = None):
        if not name:
            return
        if name not in all_refs:
            all_refs[name] = set()
        if key:
            all_refs[name].add(key)

    for spec in find_pod_specs(data):
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for c in containers:
            for env in c.get("env", []):
                if "valueFrom" in env and "secretKeyRef" in env["valueFrom"]:
                    ref = env["valueFrom"]["secretKeyRef"]
                    add_ref(ref.get("name"), ref.get("key"))
            for ef in c.get("envFrom", []):
                if "secretRef" in ef:
                    add_ref(ef["secretRef"].get("name"))

        for vol in spec.get("volumes", []):
            if "secret" in vol:
                add_ref(vol.get("secret", {}).get("secretName"))

        for ps in spec.get("imagePullSecrets", []):
            add_ref(ps.get("name"))

    return all_refs

def build_summary(files_scanned: int, passed: int, failed: int, warnings: int, files: list):
    return {
        "files_scanned": files_scanned,
        "passes": passed,
        "failures": failed,
        "warnings": warnings,
        "files": files,
    }

def run_audit(
    files_to_scan: List[Any],
    namespace: str,
    v1: Any,
    quiet: bool = False,
    json_output: bool = False,
    output_format: str = "text",
    output_file: Path = None,
) -> int:
    """
    Core audit logic. Scans the given files against the live cluster.
    Returns exit code: 0 for clean, 1 for failures/warnings.
    """
    global_passed, global_failed, global_warnings = 0, 0, 0
    json_results = []
    findings = []

    is_sarif = output_format == "sarif"
    effective_quiet = quiet or is_sarif

    for yaml_file in files_to_scan:
        combined_refs: Dict[str, Set[str]] = {}
        
        has_content = hasattr(yaml_file, "content") and yaml_file.content is not None
        try:
            if has_content:
                docs = yaml.safe_load_all(yaml_file.content)
            else:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    content = f.read()
                docs = yaml.safe_load_all(content)
            for doc in docs:
                if not doc:
                    continue
                for name, keys in get_secret_refs(doc).items():
                    combined_refs.setdefault(name, set()).update(keys)
        except yaml.YAMLError:
                findings.append({
                    "file_path": yaml_file,
                    "type": "error",
                    "rule_id": "invalid-yaml",
                    "message": f"Invalid YAML format in {yaml_file.name}."
                })
                if json_output:
                    json_results.append({
                        "file": yaml_file.name,
                        "status": "INVALID_YAML"
                    })
                else:
                    if not effective_quiet:
                        console.print(
                            f"[bold red]Error:[/bold red] Invalid YAML format in {yaml_file.name}. Skipping..."
                        )
                continue

        if not combined_refs:
            continue
        file_results = []

        table = Table(title=f"Security Audit: {yaml_file.name}")
        table.add_column("Secret Name", style="cyan")
        table.add_column("Status", justify="left")

        for name, keys in combined_refs.items():
            try:
                secret = v1.read_namespaced_secret(name, namespace)
                if keys:
                    existing_keys = (secret.data or {}).keys()
                    missing = [k for k in keys if k not in existing_keys]
                    if missing:
                        table.add_row(
                            name,
                            f"[bold yellow]KEY MISSING: {', '.join(missing)}[/bold yellow]",
                        )
                        file_results.append({
                                "secret": name,
                                "status": "WARNING",
                                "missing_keys": missing
                        })
                        for key in missing:
                            findings.append({
                                "file_path": yaml_file,
                                "type": "warning",
                                "rule_id": "missing-key",
                                "res_name": name,
                                "res_key": key,
                            })
                        global_warnings += 1
                    else:
                        table.add_row(name, "[bold green]PASS[/bold green]")
                        file_results.append({
                             "secret": name,
                             "status": "PASS"
                        })
                        global_passed += 1
                else:
                    table.add_row(name, "[bold green]PASS (Found)[/bold green]")
                    file_results.append({
                        "secret": name,
                        "status": "PASS"
                    })
                    global_passed += 1
            except ApiException as e:
                if e.status == 404:
                    table.add_row(name, "[bold red]FAIL (Secret Missing)[/bold red]")
                    file_results.append({
                            "secret": name,
                            "status": "FAIL"
                    })
                    findings.append({
                        "file_path": yaml_file,
                        "type": "error",
                        "rule_id": "missing-secret",
                        "res_name": name,
                    })
                    global_failed += 1
                else:
                    table.add_row(name, f"[dim]Error {e.status}[/dim]")
                    findings.append({
                        "file_path": yaml_file,
                        "type": "error",
                        "rule_id": "missing-secret",
                        "res_name": name,
                    })
                    global_failed += 1

        json_results.append({
            "file": yaml_file.name,
            "results": file_results
        })

        if not effective_quiet and not json_output:
            console.print(table)

    summary = build_summary(len(files_to_scan), global_passed, global_failed, global_warnings, json_results)
    if json_output:
        if not is_sarif:
            print(json.dumps(summary, indent=2))        
    elif not is_sarif:
        console.print("\n" + "━" * 30)
        console.print("[bold underline]AUDIT SUMMARY[/bold underline]\n")
        console.print(f"📂 Files Scanned: {len(files_to_scan)}")
        console.print(f"✅ Total Passed:   [green]{global_passed}[/green]")
        console.print(f"❌ Total Failed:   [red]{global_failed}[/red]")
        console.print(f"⚠️  Total Warnings: [yellow]{global_warnings}[/yellow]")
        console.print("━" * 30 + "\n")

    if output_format == "github":
        print_github_annotations(findings)
    elif output_format == "sarif":
        import sys
        sarif_report = generate_sarif_report(findings, len(files_to_scan))
        if output_file:
            try:
                out_path = Path(output_file)
                with open(out_path, "w", encoding="utf-8") as out:
                    out.write(sanitize_string(json.dumps(sarif_report, indent=2)))
            except Exception as e:
                console.print(f"[bold red]Error writing SARIF to {output_file}:[/bold red] {str(e)}")
        else:
            sys.stdout.write(sanitize_string(json.dumps(sarif_report, indent=2) + "\n"))

    return 1 if (global_failed > 0 or global_warnings > 0) else 0


EXCLUDE_DIRS = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}


def get_yaml_files(target_path: Path) -> List[Path]:
    """Recursively gets all YAML files, filtering out standard excluded directories."""
    files = list(target_path.rglob("*.yaml")) + list(target_path.rglob("*.yml"))
    return [
        f for f in files
        if not any(part in EXCLUDE_DIRS for part in f.relative_to(target_path).parts)
    ]


@app.command()
def audit(
    path_str: str = typer.Argument(..., help="Path to K8s YAML file or directory"),
    namespace: str = typer.Option("default", "--namespace", "-n"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Silence per-file status tables and print only the summary"),
    watch: bool = typer.Option(False, "--watch", "-w", help="Stay running and re-audit on every .yaml/.yml file change."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output summary in JSON format"),
    output_format: str = typer.Option("text", "--format", help="Output format: text, github, or sarif"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: alias for --format github"),
    output_file: Path = typer.Option(None, "--output-file", "-o", help="Path to write the report (e.g. results.sarif)"),
    context: str = typer.Option(None, "--context", help="Kubeconfig context name to use"),
    kubeconfig: Path = typer.Option(None, "--kubeconfig", help="Path to the kubeconfig file to use"),
):
    """
Deep audit: Checks files or directories against Cluster, Namespace,
and Secret keys.

Examples:
  kuberef deployment.yaml             # Scan a single manifest file
  kuberef ./k8s-manifests/            # Scan an entire directory
  kuberef deployment.yaml --watch     # Re-audit automatically on file changes
  kuberef ./k8s-manifests/ -w         # Watch an entire directory

"""
    if ci:
        output_format = "github"

    if output_format not in ("text", "github", "sarif"):
        console.print(f"[bold red]Error:[/bold red] Invalid format '{output_format}'. Must be one of: text, github, sarif")
        raise typer.Exit(1)

    target_path = Path(path_str)

    files_to_scan: List[Any] = []
    if is_helm_chart(target_path):
        try:
            subprocess.run(["helm", "version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            console.print("[bold red]Error:[/bold red] Helm CLI not found. Please install Helm to audit Helm charts natively.")
            raise typer.Exit(1)

        try:
            result = subprocess.run(
                ["helm", "template", str(target_path)],
                capture_output=True,
                text=True,
                check=True
            )
            files_to_scan = [ScanTarget(
                name=f"Helm Template: {target_path.name}",
                path=target_path,
                content=result.stdout
            )]
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]Helm Template Error:[/bold red]\n{e.stderr}")
            raise typer.Exit(1)
    elif target_path.is_dir():
        files_to_scan = get_yaml_files(target_path)
    elif target_path.is_file():
        files_to_scan = [target_path]
    else:
        console.print(f"[bold red]Error:[/bold red] Path {path_str} not found!")
        raise typer.Exit(1)

    if not files_to_scan:
        console.print(f"[yellow]No YAML files found at {path_str}[/yellow]")
        return

    try:
        import os
        resolved_context = context if context else os.environ.get("KUBECTL_PLUGINS_CURRENT_CONTEXT")
        resolved_kubeconfig = kubeconfig

        is_plugin_or_external = (
            bool(resolved_kubeconfig)
            or bool(resolved_context)
            or "KUBECONFIG" in os.environ
            or "KUBECTL_PLUGINS_CURRENT_CONTEXT" in os.environ
        )

        is_incluster = False
        if is_plugin_or_external:
            config.load_kube_config(
                config_file=str(resolved_kubeconfig) if resolved_kubeconfig else None,
                context=resolved_context
            )
        else:
            try:
                config.load_kube_config()
            except Exception:
                config.load_incluster_config()
                is_incluster = True

        try:
            if is_incluster:
                cluster_name = "in-cluster"
            else:
                _, active_context = config.list_kube_config_contexts()
                cluster_name = active_context["name"] if active_context else "unknown"
        except Exception:
            cluster_name = "unknown"
        v1 = client.CoreV1Api()
        v1.read_namespace(name=namespace)
        if not json_output and not quiet and output_format != "sarif":
            console.print(f"[bold blue]Target Cluster:[/bold blue] {cluster_name}")
    except Exception as e:
        console.print(f"[bold red]Pre-flight Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

    exit_code = run_audit(
        files_to_scan,
        namespace,
        v1,
        quiet=quiet,
        json_output=json_output,
        output_format=output_format,
        output_file=output_file,
    )

    if watch:
        from kuberef.watcher import run_watch_mode

        def _on_change(changed_path: Path) -> None:
            if is_helm_chart(target_path):
                try:
                    result = subprocess.run(
                        ["helm", "template", str(target_path)],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    updated_files = [ScanTarget(
                        name=f"Helm Template: {target_path.name}",
                        path=target_path,
                        content=result.stdout
                    )]
                except (FileNotFoundError, subprocess.CalledProcessError) as e:
                    if isinstance(e, FileNotFoundError):
                        console.print("[bold red]Error:[/bold red] Helm CLI not found.")
                    else:
                        console.print(f"[bold red]Helm Template Error:[/bold red]\n{e.stderr}")
                    return
            elif target_path.is_dir():
                updated_files = get_yaml_files(target_path)
            else:
                updated_files = [changed_path]
            run_audit(
                updated_files,
                namespace,
                v1,
                quiet=quiet,
                json_output=json_output,
                output_format=output_format,
                output_file=output_file,
            )

        run_watch_mode(target_path, _on_change)
    else:
        raise typer.Exit(exit_code)


def start():
    app()


if __name__ == "__main__":
    start()
