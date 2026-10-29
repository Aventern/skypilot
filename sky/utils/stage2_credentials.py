"""Read-only credential checks for a private, shared-project Stage 2 launcher.

Compute mutation grants are resource-conditional and cannot be tested against
its parent project. Deployment validates those bindings; the actual mutation
API evaluates their conditions. Never enable APIs or request external-IP use.
"""
from sky import skypilot_config
from sky.adaptors import gcp
from sky.utils import stage2_hardening
from sky.utils.stage2_journal import bounded
from sky.utils.stage2_journal import rpc

PROJECT_PERMISSIONS = (
    'compute.disks.list',
    'compute.instances.list',
    'compute.projects.get',
    'resourcemanager.projects.get',
    'compute.instances.get',
    'compute.disks.get',
    'compute.zoneOperations.get',
    'compute.zoneOperations.list',
    'compute.networks.get',
    'compute.networks.list',
    'compute.networks.getEffectiveFirewalls',
    'compute.subnetworks.get',
    'compute.subnetworks.list',
    'compute.zones.get',
    'compute.zones.list',
    'serviceusage.services.use',
)


def _require_permissions(request, permissions):
    granted = rpc(request).get('permissions', [])
    if not set(permissions) <= set(granted):
        raise ValueError('Stage 2 required resource permissions are missing')


@bounded
def check_credentials(cloud):
    try:
        config = stage2_hardening.settings()
        project = cloud.get_project_id()
        stage2_hardening.check_project_id(project)
        from google import auth
        credentials, _ = auth.default()

        def build(service):
            return gcp.build(service,
                             'v1',
                             credentials=credentials,
                             cache_discovery=False)

        crm, compute, iam = (
            build(s) for s in ('cloudresourcemanager', 'compute', 'iam'))
        _require_permissions(
            crm.projects().testIamPermissions(
                resource=project,
                body={'permissions': list(PROJECT_PERMISSIONS)}),
            PROJECT_PERMISSIONS)
        # This also checks Compute API enablement, without enabling anything.
        rpc(compute.projects().get(project=project))
        network = skypilot_config.get_nested(('gcp', 'vpc_name'), None)
        names = skypilot_config.get_nested(('gcp', 'subnet_names'), None)
        if (not network or not isinstance(names, list) or not names or
                len(names) > 32 or len(set(names)) != len(names) or
                skypilot_config.get_nested(
                    ('gcp', 'use_internal_ips'), False) is not True or
                skypilot_config.get_nested(
                    ('gcp', 'force_enable_external_ips'), False) is not False):
            raise ValueError('Stage 2 requires fixed private subnets')
        rpc(compute.networks().get(project=project, network=network))
        page = rpc(compute.subnetworks().aggregatedList(
            project=project,
            filter=' OR '.join(f'(name = "{n}")' for n in names),
            maxResults=128))
        subnets = [
            subnet for group in page.get('items', {}).values()
            for subnet in group.get('subnetworks', [])
        ]
        if (page.get('nextPageToken') or len(subnets) != len(names) or
            {s['name'] for s in subnets} != set(names)):
            raise ValueError(
                'Stage 2 configured subnets are missing or ambiguous')
        for subnet in subnets:
            if not subnet['network'].endswith(
                    f'/projects/{project}/global/networks/{network}'):
                raise ValueError('Stage 2 subnet belongs to another network')
            permissions = ['compute.subnetworks.use']
            _require_permissions(
                compute.subnetworks().testIamPermissions(
                    project=project,
                    region=subnet['region'].rsplit('/', 1)[-1],
                    resource=subnet['name'],
                    body={'permissions': permissions}), permissions)
        permissions = ['iam.serviceAccounts.actAs']
        _require_permissions(
            iam.projects().serviceAccounts().testIamPermissions(
                resource=
                f"projects/-/serviceAccounts/{config['guest_service_account']}",
                body={'permissions': permissions}), permissions)
        return True, None
    except Exception:
        return False, 'Stage 2 scoped GCP credential check failed; review deployment IAM and private subnets'
