"""Opt-in Stage 2 launch restrictions, independent of admin policies."""
import re
import subprocess
from typing import Optional

from sky import exceptions
from sky import skypilot_config
from sky.utils import stage2_ownership

# The controller checks this marker before accepting the installed fork.
VERSION = 2


def settings():
    config = skypilot_config.get_nested(('stage2_hardening',), None)
    if config is None:
        return None
    keys = {
        'project_id', 'allowed_project_ids', 'control_bucket',
        'evidence_bucket', 'pool', 'guest_service_account'
    }
    try:
        if not isinstance(config, dict) or set(config) != keys:
            raise ValueError('Stage 2 hardening configuration is incomplete')
        stage2_ownership.require_allowed_project(config['project_id'],
                                                 config['allowed_project_ids'])
        if (re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,17}', config['pool']) is None or
                any(
                    re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', config[k])
                    is None for k in ('control_bucket', 'evidence_bucket')) or
                not config['guest_service_account'].endswith(
                    '@' + config['project_id'] + '.iam.gserviceaccount.com')):
            raise ValueError('Stage 2 hardening identity is malformed')
    except (ValueError, TypeError, AttributeError) as exc:
        raise exceptions.InvalidCloudConfigs(str(exc)) from exc
    return config


def project_id() -> Optional[str]:
    config = settings()
    return None if config is None else config['project_id']


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
