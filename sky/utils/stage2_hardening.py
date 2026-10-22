"""Opt-in Stage 2 launch restrictions, independent of admin policies."""
import re
import subprocess
from typing import Optional

from sky import exceptions
from sky import skypilot_config

# The controller checks this marker before accepting the installed fork.
VERSION = 1


def project_id() -> Optional[str]:
    config = skypilot_config.get_nested(('stage2_hardening',), None)
    if config is None:
        return None
    if (not isinstance(config, dict) or set(config) != {'project_id'} or
            not isinstance(config['project_id'], str) or re.fullmatch(
                r'[a-z][a-z0-9-]{4,28}[a-z0-9]', config['project_id']) is None):
        raise exceptions.InvalidCloudConfigs(
            'Stage 2 hardening requires an explicit GCP project ID.')
    return config['project_id']


def enabled() -> bool:
    return project_id() is not None


def check_project_id(actual: Optional[str]) -> None:
    expected = project_id()
    if expected is not None and actual != expected:
        raise exceptions.InvalidCloudConfigs(
            'Stage 2 effective GCP project differs from the pinned project.')


def check_gcloud_project() -> None:
    if not enabled():
        return
    try:
        result = subprocess.run(
            ['gcloud', 'config', 'get-value', 'project', '--quiet'],
            check=True,
            capture_output=True,
            text=True,
            timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise exceptions.InvalidCloudConfigs(
            'Stage 2 cannot resolve the gcloud default project.') from exc
    check_project_id(result.stdout.strip())
