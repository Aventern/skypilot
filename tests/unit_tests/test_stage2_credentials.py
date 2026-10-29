"""Generated deployment roles through the real fork check and SDK preflight."""
import json
from pathlib import Path
from types import SimpleNamespace

from google import auth
import pytest
import yaml

from sky import skypilot_config
from sky.clouds import gcp as gcp_cloud
from sky.clouds.gcp import GCP
from sky.clouds.gcp import GCPIdentityType
from sky.utils import stage2_credentials as check
from sky.utils import stage2_hardening
from tests.unit_tests.test_stage2_journal import CONFIG
from tests.unit_tests.test_stage2_journal import Request


@pytest.mark.parametrize('missing', [
    None, *check.PROJECT_PERMISSIONS, 'compute.subnetworks.use',
    'iam.serviceAccounts.actAs'
])
def test_generated_scoped_iam_reaches_real_gcp_check_and_preflight(
        monkeypatch, missing):
    from stage2.deploy.preflight import require_gcp_enabled
    roles = json.loads(Path('/app/stage2/deploy/iam/roles.yaml').read_text())
    extra = yaml.safe_load(
        Path('/app/stage2/deploy/iam/apiserver-check.yaml').read_text())
    # Conditional mutation and subnet grants are deliberately NOT returned by
    # project testIamPermissions, even though deployment generates both.
    project_permissions = set(
        roles['Stage2ComputeRead']['includedPermissions']) | set(
            extra['includedPermissions'])
    project_permissions.discard(missing)
    subnet_permissions = set(
        roles['Stage2NetworkUse']['includedPermissions']) - {missing}
    sa_permissions = {'iam.serviceAccounts.actAs'} - {missing}
    calls = []
    project = CONFIG['project_id']
    network = f'https://www.googleapis.com/compute/v1/projects/{project}/global/networks/stage2-vpc'

    class Api:

        def __init__(self, service, path=''):
            self.service, self.path = service, path

        def __getattr__(self, key):

            def invoke(**kwargs):
                path = self.path + '.' + key
                if not kwargs:
                    return Api(self.service, path)
                calls.append((self.service, path, kwargs))
                if key == 'testIamPermissions':
                    if self.service == 'cloudresourcemanager':
                        assert kwargs['resource'] == project
                        granted = project_permissions
                    elif self.service == 'compute':
                        assert (kwargs['project'], kwargs['region'],
                                kwargs['resource']) == (project, 'asia-east1',
                                                        'stage2-subnet')
                        granted = subnet_permissions
                    else:
                        assert kwargs[
                            'resource'] == f"projects/-/serviceAccounts/{CONFIG['guest_service_account']}"
                        granted = sa_permissions
                    return Request(
                        lambda: {
                            'permissions': sorted(granted & set(kwargs['body'][
                                'permissions']))
                        })
                if key == 'aggregatedList':
                    assert kwargs['filter'] == '(name = "stage2-subnet")'
                    return Request(
                        lambda: {
                            'items': {
                                'regions/asia-east1': {
                                    'subnetworks': [
                                        dict(name='stage2-subnet',
                                             network=network,
                                             region='regions/asia-east1')
                                    ]
                                }
                            }
                        })
                assert key == 'get' and path in {
                    '.projects.get', '.networks.get'
                }
                return Request(lambda: {})

            return invoke

    settings = dict(gcp=dict(vpc_name='stage2-vpc',
                             subnet_names=['stage2-subnet'],
                             use_internal_ips=True,
                             force_enable_external_ips=False))

    def get_nested(keys, default=None):
        value = settings
        for key in keys:
            if key not in value:
                return default
            value = value[key]
        return value

    monkeypatch.setattr(stage2_hardening, 'settings', lambda: CONFIG)
    monkeypatch.setattr(skypilot_config, 'get_nested', get_nested)
    monkeypatch.setattr(GCP, 'get_project_id', lambda: project)
    monkeypatch.setattr(GCP, '_get_identity_type',
                        lambda: GCPIdentityType.SERVICE_ACCOUNT)
    monkeypatch.setattr(GCP, 'get_active_user_identity',
                        lambda: ['stage2-api@example.iam.gserviceaccount.com'])
    monkeypatch.setattr(gcp_cloud.shutil, 'which', lambda _: '/usr/bin/gcloud')
    monkeypatch.setattr(gcp_cloud, '_get_default', lambda: (object(), project))
    monkeypatch.setattr(auth, 'default', lambda: (object(), project))
    monkeypatch.setattr(check.gcp, 'build',
                        lambda service, *a, **k: Api(service))
    enabled, message = GCP._check_compute_credentials()
    assert enabled is (missing is None), message
    sdk = SimpleNamespace(
        get_user_workspace=lambda: {'workspace': 'default'},
        check=lambda **kw: {'default': {
            'GCP': ['compute'] if enabled else []
        }},
        enabled_clouds=lambda **kw: ['GCP'] if enabled else [],
        get=lambda request: request)
    from sky.client import sdk as real_sdk
    for name, value in vars(sdk).items():
        monkeypatch.setattr(real_sdk, name, value)
    if missing is None:
        require_gcp_enabled()
    else:
        with pytest.raises(ValueError, match='preflight failed'):
            require_gcp_enabled()
    requested = {
        p for _, _, args in calls
        for p in args.get('body', {}).get('permissions', [])
    }
    assert not requested & set(
        roles['Stage2ComputeMutate']['includedPermissions'])
    assert 'compute.subnetworks.useExternalIp' not in requested
    assert 'serviceusage.services.enable' not in requested
