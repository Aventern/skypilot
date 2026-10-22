"""Offline regressions through controller handoff and launch boundaries.

Only transport, scheduling, cloud clients and the final key/upload boundary are
faked. Config serialization/reload, recovery dispatch, mount enumeration,
authentication and bootstrap are the production functions, not AST copies.
"""
import asyncio
from contextlib import asynccontextmanager
import copy
import importlib
from pathlib import Path
import shutil
from types import SimpleNamespace
from unittest import mock

import pytest

from sky import authentication
from sky import clouds
from sky import exceptions
from sky import skypilot_config
from sky.backends import backend_utils
from sky.jobs import recovery_strategy
from sky.provision import common
from sky.provision.gcp import config as gcp_config
from sky.server.requests import payloads
from sky.utils import auth_utils
from sky.utils import common_utils
from sky.utils import controller_utils
from sky.utils import stage2_hardening
from sky.utils import yaml_utils

sky_check = importlib.import_module('sky.check')
PROJECT = 'stage2-test-project'
SAFE = {'stage2_hardening': {'project_id': PROJECT}}


class BoundaryReached(BaseException):
    """Stop before keys, template uploads, or provisioning side effects."""


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.setattr(skypilot_config, '_global_config_context',
                        skypilot_config.ConfigContext())
    path = tmp_path / 'server.yaml'
    monkeypatch.setenv('SKYPILOT_CONFIG', str(path))

    def load(value):
        yaml_utils.dump_yaml(str(path), value)
        skypilot_config.reload_config()

    load(SAFE)
    return load


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    path = tmp_path / 'other-credentials'
    provider = mock.Mock()
    provider.get_credential_file_mounts.return_value = {
        '~/.other/credentials': str(path)
    }
    monkeypatch.setattr(sky_check.registry, 'CLOUD_REGISTRY',
                        {'other': provider})
    for name in ('cloudflare', 'coreweave', 'vastdata', 'huggingface'):
        monkeypatch.setattr(getattr(sky_check, name),
                            'check_storage_credentials', lambda: (False, None))
    return path


def controller_handoff(tmp_path, monkeypatch):
    remote = tmp_path / 'controller.yaml'
    # The unrelated plugin/image setup is outside the config handoff boundary.
    monkeypatch.setattr(controller_utils, 'controller_only_vars_to_fill',
                        lambda _: {'controller_envs': {}})
    value = copy.deepcopy(SAFE)
    value['admin_policy'] = 'not.installed.Policy'
    saved = controller_utils.shared_controller_vars_to_fill(
        controller_utils.Controllers.JOBS_CONTROLLER, str(remote), value)
    local = Path(saved['local_user_config_path'])
    shutil.copyfile(local, remote)
    local.unlink()
    assert 'admin_policy' not in yaml_utils.read_yaml(str(remote))
    monkeypatch.setenv('SKYPILOT_CONFIG',
                       saved['controller_envs']['SKYPILOT_CONFIG'])
    monkeypatch.setattr(payloads.common, 'is_api_server_local', lambda: True)
    # This is the request environment passed by the local SDK to the executor.
    env = payloads.request_body_env_vars()
    assert env['SKYPILOT_CONFIG'] == str(remote)
    monkeypatch.setenv('SKYPILOT_CONFIG', env['SKYPILOT_CONFIG'])
    skypilot_config.reload_config()
    assert stage2_hardening.project_id() == PROJECT


def write_config():
    resources = mock.Mock(cloud=clouds.GCP(), cluster_config_overrides={})
    resources.make_deploy_variables.return_value = {}
    return backend_utils.write_cluster_config(resources, 1, 'gcp-ray.yml.j2',
                                              'stage2-worker',
                                              Path('/fake/wheel'), 'fake-hash',
                                              clouds.Region('us-central1'))


@asynccontextmanager
async def scheduled(*_):
    yield


def managed_launch(monkeypatch, recovery, operation):
    # Keep the real StrategyExecutor._launch and Failover.recover dispatch.
    executor = recovery_strategy.FailoverStrategyExecutor.__new__(
        recovery_strategy.FailoverStrategyExecutor)
    executor.__dict__.update(job_id=1,
                             task_id=0,
                             starting=set(),
                             starting_lock=None,
                             starting_signal=None,
                             pool=None,
                             cluster_name='stage2-worker',
                             file_mounts_blob_id=None,
                             dag=SimpleNamespace(tasks=[]),
                             _launched_resources=None)
    executor._refresh_priority_from_persisted_dag = mock.AsyncMock()
    executor._try_cancel_jobs = mock.AsyncMock()
    executor._cleanup_cluster = mock.Mock()
    monkeypatch.setattr(recovery_strategy.scheduler, 'scheduled_launch',
                        scheduled)
    monkeypatch.setattr(recovery_strategy.sdk, 'api_start', mock.Mock())

    def local_sdk(*_, **kwargs):
        assert kwargs['_is_launched_by_jobs_controller'] is True
        env = payloads.request_body_env_vars()
        assert env['SKYPILOT_CONFIG']
        skypilot_config.reload_config()
        try:
            return operation()
        except Exception as exc:
            # Transport errors must fail this offline probe immediately, not
            # enter the production controller's unbounded retry/backoff loop.
            pytest.fail(f'Offline launch boundary failed: {exc}')

    monkeypatch.setattr(recovery_strategy.sdk, 'launch', local_sdk)
    coro = executor.recover() if recovery else executor.launch()
    asyncio.run(coro)


@pytest.mark.parametrize('route', ['initial', 'controller', 'recovery'])
def test_late_credentials_never_reach_mounts(config_file, credentials, tmp_path,
                                             monkeypatch, route):
    # Submit precedes the appearance of another provider's credentials.
    assert sky_check.get_cloud_credential_file_mounts(None) == {}
    if route != 'initial':
        controller_handoff(tmp_path, monkeypatch)
    credentials.write_text('FAKE-SECRET')
    seen = []
    original = sky_check.get_cloud_credential_file_mounts

    def enumerate_mounts(excluded):
        mounts = original(excluded)
        seen.append(mounts.copy())
        return mounts

    monkeypatch.setattr(sky_check, 'get_cloud_credential_file_mounts',
                        enumerate_mounts)
    monkeypatch.setattr(backend_utils.logs, 'get_logging_agent', lambda: None)
    monkeypatch.setattr(auth_utils, 'get_or_generate_keys',
                        mock.Mock(side_effect=BoundaryReached))
    with pytest.raises(BoundaryReached):
        if route == 'initial':
            write_config()
        else:
            managed_launch(monkeypatch, route == 'recovery', write_config)
    assert seen == [{}]


@pytest.mark.parametrize('source', ['cloud', 'logging'])
def test_backend_rejects_injected_mounts_before_keys(config_file, monkeypatch,
                                                     source):
    mounts = {'~/.other/credentials': '/fake/secret'}
    monkeypatch.setattr(sky_check, 'get_cloud_credential_file_mounts',
                        lambda _: mounts.copy() if source == 'cloud' else {})
    agent = mock.Mock()
    agent.get_credential_file_mounts.return_value = mounts
    monkeypatch.setattr(backend_utils.logs, 'get_logging_agent', lambda: agent
                        if source == 'logging' else None)
    keys = mock.Mock(side_effect=BoundaryReached)
    monkeypatch.setattr(auth_utils, 'get_or_generate_keys', keys)
    with pytest.raises(exceptions.InvalidCloudConfigs,
                       match='credential mounts'):
        write_config()
    keys.assert_not_called()


@pytest.fixture
def gcp_boundary(monkeypatch):
    monkeypatch.setattr(clouds.gcp, '_get_default', lambda: (None, PROJECT))
    monkeypatch.setattr(skypilot_config, 'get_workspace_cloud', lambda _: {})
    # Same subprocess module is used by authentication; record every invocation.
    commands = []

    def run(command, **_):
        commands.append(command)
        if isinstance(command, list):
            return SimpleNamespace(stdout=PROJECT + '\n', returncode=0)
        return SimpleNamespace(stdout=b'posixAccounts:\n- username: fake\n',
                               stderr=b'',
                               returncode=0)

    monkeypatch.setattr(stage2_hardening.subprocess, 'run', run)
    monkeypatch.setattr(common_utils.time, 'sleep', lambda _: None)
    keys = mock.Mock(return_value=('/fake/private', '/fake/public'))
    monkeypatch.setattr(auth_utils, 'get_or_generate_keys', keys)
    compute = mock.Mock()
    monkeypatch.setattr(authentication.gcp, 'build',
                        mock.Mock(return_value=compute))
    monkeypatch.setattr(authentication, 'configure_ssh_info',
                        lambda config: config)
    clients = mock.Mock(side_effect=BoundaryReached)
    monkeypatch.setattr(gcp_config, 'construct_clients_from_provider_config',
                        clients)
    return commands, keys, compute, clients


def auth_config(project=PROJECT):
    return {'provider': {'project_id': project}, 'auth': {'ssh_user': 'fake'}}


def bootstrap(project=PROJECT):
    config = common.ProvisionConfig(
        provider_config={'project_id': project},
        authentication_config={},
        docker_config={},
        node_config={'machineType': 'n1-standard-4'},
        count=1,
        tags={},
        resume_stopped_nodes=False,
        ports_to_open_on_launch=None)
    return gcp_config.bootstrap_instances('us-central1', 'stage2-worker',
                                          config)


@pytest.mark.parametrize('recovery', [False, True])
def test_oslogin_changed_after_preflight_never_creates_firewall(
        config_file, gcp_boundary, tmp_path, monkeypatch, recovery):
    commands, _, compute, _ = gcp_boundary
    metadata = {
        'commonInstanceMetadata': {
            'items': [{
                'key': 'enable-oslogin',
                'value': 'FALSE'
            }]
        }
    }
    # A complete earlier authentication sees FALSE, then the value changes.
    compute.projects.return_value.get.return_value.execute.return_value = metadata
    authentication.setup_gcp_authentication(auth_config())
    assert authentication.parse_gcp_project_oslogin(metadata) == 'FALSE'
    controller_handoff(tmp_path, monkeypatch)
    metadata['commonInstanceMetadata']['items'][0]['value'] = 'TRUE'
    compute.projects.return_value.get.return_value.execute.return_value = metadata

    def authenticate():
        with pytest.raises(exceptions.InvalidCloudConfigs, match='OS Login'):
            authentication.setup_gcp_authentication(auth_config())
        raise BoundaryReached

    with pytest.raises(BoundaryReached):
        managed_launch(monkeypatch, recovery, authenticate)
    assert commands
    assert all(
        isinstance(c, list) and c[:3] == ['gcloud', 'config', 'get-value']
        for c in commands)


@pytest.mark.parametrize(
    'entry,mismatch',
    [(entry, mismatch)
     for entry in ('resolve', 'auth', 'bootstrap')
     for mismatch in ('adc', 'gcloud', 'workspace', 'provider')
     if (entry, mismatch) != ('resolve', 'provider')])
def test_project_mismatch_precedes_side_effects(config_file, gcp_boundary,
                                                monkeypatch, entry, mismatch):
    commands, keys, compute, clients = gcp_boundary
    if mismatch == 'adc':
        monkeypatch.setattr(clouds.gcp, '_get_default', lambda:
                            (None, 'foreign-project'))
    elif mismatch == 'workspace':
        monkeypatch.setattr(skypilot_config, 'get_workspace_cloud',
                            lambda _: {'project_id': 'foreign-project'})
    elif mismatch == 'gcloud':
        monkeypatch.setattr(
            stage2_hardening.subprocess, 'run',
            lambda *a, **k: SimpleNamespace(stdout='foreign-project\n'))
    project = 'foreign-project' if mismatch == 'provider' else PROJECT
    with pytest.raises(exceptions.InvalidCloudConfigs, match='pinned project'):
        if entry == 'resolve':
            clouds.GCP.get_project_id()
        elif entry == 'auth':
            authentication.setup_gcp_authentication(auth_config(project))
        else:
            bootstrap(project)
    keys.assert_not_called()
    compute.assert_not_called()
    assert not compute.mock_calls
    clients.assert_not_called()
    assert not any(isinstance(c, str) for c in commands)


def test_matching_project_reaches_existing_boundaries(config_file,
                                                      gcp_boundary):
    _, _, compute, clients = gcp_boundary
    compute.projects.return_value.get.return_value.execute.return_value = {}
    assert clouds.GCP.get_project_id() == PROJECT
    authentication.setup_gcp_authentication(auth_config())
    with pytest.raises(BoundaryReached):
        bootstrap()
    clients.assert_called_once()


def test_disabled_preserves_upstream(config_file, credentials, gcp_boundary):
    config_file({})
    credentials.write_text('FAKE-SECRET')
    assert sky_check.get_cloud_credential_file_mounts(None) == {
        '~/.other/credentials': str(credentials)
    }
    commands, _, compute, _ = gcp_boundary
    assert clouds.GCP.get_project_id() == PROJECT
    assert commands == []
    compute.projects.return_value.get.return_value.execute.return_value = {
        'commonInstanceMetadata': {
            'items': [{
                'key': 'enable-oslogin',
                'value': 'TRUE'
            }]
        }
    }
    authentication.setup_gcp_authentication(auth_config())
    assert any('firewall-rules create' in c for c in commands)


@pytest.mark.parametrize('value', [{}, {
    'project_id': ''
}, {
    'project_id': 'UPPER'
}, {
    'project_id': PROJECT,
    'enabled': False
}])
def test_malformed_opt_in_is_rejected(config_file, value):
    with pytest.raises((ValueError, exceptions.InvalidCloudConfigs)):
        config_file({'stage2_hardening': value})
        stage2_hardening.enabled()


@pytest.mark.parametrize(
    'output', ['', '(unset)', 'stage2-test-project\nforeign-project'])
def test_unavailable_gcloud_project_fails_closed(config_file, gcp_boundary,
                                                 monkeypatch, output):
    monkeypatch.setattr(stage2_hardening.subprocess, 'run',
                        lambda *a, **k: SimpleNamespace(stdout=output))
    with pytest.raises(exceptions.InvalidCloudConfigs):
        authentication.setup_gcp_authentication(auth_config())
    gcp_boundary[1].assert_not_called()


def test_disabled_backend_keeps_existing_mount_behavior(config_file,
                                                        monkeypatch):
    config_file({})
    monkeypatch.setattr(sky_check, 'get_cloud_credential_file_mounts',
                        lambda _: {'~/.fake': '/fake'})
    monkeypatch.setattr(backend_utils.logs, 'get_logging_agent', lambda: None)
    keys = mock.Mock(side_effect=BoundaryReached)
    monkeypatch.setattr(auth_utils, 'get_or_generate_keys', keys)
    with pytest.raises(BoundaryReached):
        write_config()
    keys.assert_called_once()
