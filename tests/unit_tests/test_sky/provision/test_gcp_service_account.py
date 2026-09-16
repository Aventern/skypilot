"""Offline tests for GCP VM service account selection."""
import json
from unittest import mock

import pytest

from sky import skypilot_config
from sky.provision import common
from sky.provision.gcp import config as gcp_config
from sky.provision.gcp import constants
from sky.utils import common_utils
from sky.utils import config_utils
from sky.utils import schemas

_EMAIL = 'worker-sa@test-project.iam.gserviceaccount.com'
_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'


@pytest.fixture
def loaded_config(monkeypatch):
    config = config_utils.Config()
    monkeypatch.setattr(skypilot_config, '_get_loaded_config', lambda: config)
    return config


@pytest.fixture(params=[False, True], ids=['compute', 'tpu'])
def provision_config(request):
    is_tpu = request.param
    return common.ProvisionConfig(provider_config={
        'project_id': 'test-project',
        'region': 'us-central1',
        constants.HAS_TPU_PROVIDER_FIELD: is_tpu,
    },
                                  authentication_config={},
                                  docker_config={},
                                  node_config=({
                                      'acceleratorType': 'v2-8'
                                  } if is_tpu else {
                                      'machineType': 'n1-standard-4'
                                  }),
                                  count=1,
                                  tags={},
                                  resume_stopped_nodes=False,
                                  ports_to_open_on_launch=None)


@pytest.fixture
def iam_helpers(monkeypatch):
    helpers = {}
    for name in ('_get_service_account', '_create_service_account',
                 '_is_permission_satisfied', '_add_iam_policy_binding'):
        helper = mock.MagicMock(name=name)
        monkeypatch.setattr(gcp_config, name, helper)
        helpers[name] = helper
    return helpers


def _expected_role(config, email):
    if 'acceleratorType' in config.node_config:
        return {'serviceAccount': {'email': email, 'scope': [_SCOPE]}}
    return {'serviceAccounts': [{'email': email, 'scopes': [_SCOPE]}]}


@pytest.mark.parametrize('email', [
    _EMAIL,
    'abcde@abcdef.iam.gserviceaccount.com',
    f'{"a" * 30}@{"b" * 30}.iam.gserviceaccount.com',
])
def test_existing_service_account_skips_iam(loaded_config, provision_config,
                                            iam_helpers, email):
    loaded_config['gcp'] = {'service_account': email}
    crm, iam = mock.MagicMock(), mock.MagicMock()
    with mock.patch.object(
            skypilot_config,
            'get_effective_region_config',
            wraps=skypilot_config.get_effective_region_config) as resolve:
        result = gcp_config._configure_iam_role(provision_config, crm, iam)
    resolve.assert_called_once_with(cloud='gcp',
                                    region='us-central1',
                                    keys=('service_account',),
                                    default_value=None)
    assert result == _expected_role(provision_config, email)
    assert crm.mock_calls == []
    assert iam.mock_calls == []
    for helper in iam_helpers.values():
        helper.assert_not_called()


@pytest.mark.parametrize('email', [
    '',
    'worker-sa',
    'Worker-sa@test-project.iam.gserviceaccount.com',
    'work_er@test-project.iam.gserviceaccount.com',
    'abcd@test-project.iam.gserviceaccount.com',
    f'{"a" * 31}@test-project.iam.gserviceaccount.com',
    'worker-sa@abcde.iam.gserviceaccount.com',
    f'worker-sa@{"b" * 31}.iam.gserviceaccount.com',
    'worker-sa@1project.iam.gserviceaccount.com',
    'worker-sa@project-.iam.gserviceaccount.com',
    'worker-sa@test-project.example.com',
    _EMAIL + '\n',
    ' ' + _EMAIL,
    False,
    123,
])
def test_invalid_service_account_fails_closed(loaded_config, provision_config,
                                              iam_helpers, email):
    loaded_config['gcp'] = {'service_account': email}
    crm, iam = mock.MagicMock(), mock.MagicMock()
    with pytest.raises(ValueError, match='Invalid gcp.service_account email'):
        gcp_config._configure_iam_role(provision_config, crm, iam)
    assert crm.mock_calls == []
    assert iam.mock_calls == []
    for helper in iam_helpers.values():
        helper.assert_not_called()


@pytest.mark.parametrize('path', ['existing', 'legacy', 'create', 'bind'])
def test_unspecified_service_account_preserves_behavior(loaded_config,
                                                        provision_config,
                                                        iam_helpers,
                                                        monkeypatch, path):
    assert not loaded_config
    crm, iam = mock.MagicMock(), mock.MagicMock()
    managed = {
        'email': 'skypilot-v1@test-project.iam.gserviceaccount.com',
        'projectId': 'test-project',
    }
    legacy = {
        'email': 'ray-autoscaler-sa-v1@test-project.iam.gserviceaccount.com',
        'projectId': 'test-project',
    }
    policy = {'bindings': []}
    get_account = iam_helpers['_get_service_account']
    check_permissions = iam_helpers['_is_permission_satisfied']
    create_account = iam_helpers['_create_service_account']
    bind = iam_helpers['_add_iam_policy_binding']
    get_account.side_effect = ([None, None]
                               if path == 'create' else [managed, legacy])
    check_permissions.side_effect = {
        'existing': [(True, policy)],
        'legacy': [(False, policy), (True, policy)],
        'create': [(False, None), (False, None), (False, policy)],
        'bind': [(False, policy), (False, policy)],
    }[path]
    create_account.return_value = managed
    monkeypatch.setattr(gcp_config.gcp_utils, 'get_minimal_compute_permissions',
                        lambda: ['compute.instances.get'])

    result = gcp_config._configure_iam_role(provision_config, crm, iam)

    account = legacy if path == 'legacy' else managed
    # Preserve dictionary shape, key order and serialized output.
    assert json.dumps(result).encode() == json.dumps(
        _expected_role(provision_config, account['email'])).encode()
    expected_gets = [mock.call(managed['email'], 'test-project', iam)]
    if path != 'existing':
        expected_gets.append(mock.call(legacy['email'], 'test-project', iam))
    assert get_account.call_args_list == expected_gets
    if path == 'create':
        create_account.assert_called_once_with(
            constants.SKYPILOT_SERVICE_ACCOUNT_ID,
            constants.SKYPILOT_SERVICE_ACCOUNT_CONFIG, 'test-project', iam)
    else:
        create_account.assert_not_called()
    if path in ('create', 'bind'):
        bind.assert_called_once_with(managed, policy, crm, iam)
    else:
        bind.assert_not_called()


def test_service_account_schema():
    common_utils.validate_schema({'gcp': {
        'service_account': _EMAIL
    }},
                                 schemas.get_config_schema(),
                                 'Invalid config: ',
                                 skip_none=False)
    assert schemas.get_config_schema(
    )['properties']['gcp']['properties']['service_account'] == {
        'type': 'string'
    }
