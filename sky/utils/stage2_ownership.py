"""Pure ownership contract shared by the Stage 2 controller and provisioner.

Records MUST come from the configured immutable journal, never resource labels.
This module deliberately has no SkyPilot or cloud imports.
"""
import re
from urllib.parse import urlsplit

VERSION = 2
OWNED, SUSPECT, UNRELATED = 'OWNED', 'SUSPECT', 'UNRELATED'
# Reserved namespaces: workers use pull-, control-plane resources use stage2-.
PREFIXES = ('pull-', 'stage2-')
WORKER_PREFIXES = ('pull-',)
LABEL_KEYS = ('managed-by', 'dayseum-pool', 'dayseum-worker-slot',
              'dayseum-launch-request', 'dayseum-config-sha')
PROJECT = re.compile(r'[a-z][a-z0-9-]{4,28}[a-z0-9]')


def require_allowed_project(project_id, allowed_project_ids):
    if (not isinstance(allowed_project_ids,
                       (list, tuple)) or not allowed_project_ids or
            any(not isinstance(p, str) or PROJECT.fullmatch(p) is None
                for p in allowed_project_ids) or
            len(set(allowed_project_ids)) != len(allowed_project_ids) or
            project_id not in allowed_project_ids):
        raise ValueError('Stage 2 project is not explicitly allowed')
    return project_id


def worker_prefix(pool):
    """Return the IAM prefix retained by GCP's 23-character instance stem."""
    if (not isinstance(pool, str) or re.fullmatch(
            r'[a-z0-9](?:[a-z0-9-]{0,15}[a-z0-9])?', pool) is None):
        raise ValueError('Stage 2 pool cannot retain its worker name prefix')
    return f'pull-{pool}-'


def worker_metadata_valid(metadata):
    items = metadata.get('items') if isinstance(metadata, dict) else None
    return isinstance(items, list) and all(
        [
            item.get('value')
            for item in items
            if isinstance(item, dict) and item.get('key') == key
        ] == [expected]
        for key, expected in (('enable-oslogin', 'FALSE'),
                              ('block-project-ssh-keys', 'TRUE')))


def resource_path(value):
    if not isinstance(value, str):
        return ''
    if value.startswith('https://'):
        url = urlsplit(value)
        if (url.netloc not in ('www.googleapis.com', 'compute.googleapis.com')
                or url.query or url.fragment):
            return ''
        value = url.path.removeprefix('/compute/v1/')
    return value if value.startswith('projects/') else ''


def candidate_filters(kind):
    if kind not in ('instances', 'disks'):
        raise ValueError('unsupported Stage 2 resource kind')
    # GCE does not allow regex and AIP-160 expressions in the same filter.
    return ('name eq "pull-.*"',
            '(labels.managed-by = "dayseum-stage2-pool") OR ' +
            ' OR '.join(f'(labels.{key}:*)' for key in LABEL_KEYS[1:]))


def _valid_record(record, project_id):
    try:
        request, operation = record['request'], record['operation']
        name, zone, kind = (request[k] for k in ('name', 'zone', 'kind'))
        labels = request['labels']
        intent = request['intent']
        path = f'projects/{project_id}/zones/{zone}/{kind}/{name}'
        return (request['project_id'] == project_id and
                kind in ('instances', 'disks') and isinstance(name, str) and
                name.startswith(WORKER_PREFIXES) and
                re.fullmatch(r'[a-z]+-[a-z]+[0-9]-[a-z]', zone) is not None and
                isinstance(request['job_name'], str) and
                request['job_name'].startswith(WORKER_PREFIXES) and
                type(request['job_id']) is int and request['job_id'] > 0 and
                isinstance(request['cluster'], str) and
                request['cluster'].startswith(WORKER_PREFIXES) and
                isinstance(request['guest_service_account'], str) and
                request['guest_service_account'].endswith(
                    f'@{project_id}.iam.gserviceaccount.com') and
                labels['managed-by'] == 'dayseum-stage2-pool' and all(
                    isinstance(labels[k], str) and labels[k]
                    for k in LABEL_KEYS) and isinstance(intent['uri'], str) and
                intent['uri'].startswith('gs://') and
                re.fullmatch('[0-9a-f]{64}', intent['sha256']) is not None and
                type(intent['generation']) is int and
                intent['generation'] > 0 and
                operation['clientOperationId'] == request['request_id'] and
                operation['operationType'] == 'insert' and
                resource_path(operation['targetLink']) == path and
                isinstance(operation['targetId'], str) and
                operation['targetId'].isdigit() and
                int(operation['targetId']) > 0 and not operation.get('error'))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def classify_resource(resource, records, *, project_id, resources=None):
    if not isinstance(resource, dict):
        return UNRELATED
    name, labels = resource.get('name', ''), resource.get('labels', {})
    labels = labels if isinstance(labels, dict) else {}
    marked = ((isinstance(name, str) and name.startswith(WORKER_PREFIXES)) or
              labels.get('managed-by') == 'dayseum-stage2-pool' or
              any(k in labels for k in LABEL_KEYS[1:]))
    path = resource_path(resource.get('selfLink'))
    matches = []
    for record in records:
        if not _valid_record(record, project_id):
            continue
        request, operation = record['request'], record['operation']
        if (resource_path(operation['targetLink']) == path and
                str(resource.get('id', '')) == operation['targetId']):
            matches.append(request)
    if len(matches) != 1:
        return SUSPECT if marked or matches else UNRELATED
    request = matches[0]
    if (name != request['name'] or resource_path(resource.get('zone')) !=
            f"projects/{project_id}/zones/{request['zone']}"):
        return SUSPECT
    if request['kind'] == 'disks':
        # The independently inserted disk has its own operation targetId.
        # Disk labels/users are not required after detachment.
        return OWNED
    services = resource.get('serviceAccounts', [])
    disks = resource.get('disks', [])
    if (any(labels.get(k) != request['labels'][k] for k in LABEL_KEYS) or
            labels.get('ray-cluster-name') != request['cluster'] or
            labels.get('skypilot-cluster-name') != request['cluster'] or
            not isinstance(services, list) or len(services) != 1 or
            not isinstance(services[0], dict) or
            services[0].get('email') != request['guest_service_account'] or
            not worker_metadata_valid(resource.get('metadata')) or
            not isinstance(disks, list) or len(disks) != 1 or
            not isinstance(disks[0], dict) or
            disks[0].get('boot') is not True or
            resource_path(disks[0].get('source')) not in
        {
            f"projects/{project_id}/zones/{request['zone']}/disks/{request.get('disk_name')}",
            f"projects/{project_id}/zones/{request['zone']}/disks/{request.get('disk_id')}"
        } or not str(request.get('disk_id', '')).isdigit()):
        return SUSPECT
    if resources is None:
        return SUSPECT
    disk_matches = [
        disk for disk in resources
        if isinstance(disk, dict) and str(disk.get('id', '')) ==
        request['disk_id'] and resource_path(disk.get('selfLink')) ==
        f"projects/{project_id}/zones/{request['zone']}/disks/{request['disk_name']}"
        and classify_resource(disk, records, project_id=project_id) == OWNED
    ]
    return OWNED if len(disk_matches) == 1 else SUSPECT


def classify_job(resource, records, *, project_id):
    if not isinstance(resource, dict):
        return UNRELATED
    name = resource.get('job_name', '')
    marked = isinstance(name, str) and name.startswith(WORKER_PREFIXES)
    matches = []
    for record in records:
        try:
            if (record['project_id'] == project_id and
                    record['job_name'] == name and marked and
                    type(resource.get('job_id')) is int and
                    resource['job_id'] > 0 and
                    record['job_id'] == resource['job_id'] and
                    record['cluster'].startswith(WORKER_PREFIXES) and
                    record['guest_service_account'].endswith(
                        '@' + project_id + '.iam.gserviceaccount.com') and
                    record['labels']['managed-by'] == 'dayseum-stage2-pool' and
                    all(record['labels'][k] for k in LABEL_KEYS) and
                    record['intent']['uri'].startswith('gs://') and
                    re.fullmatch('[0-9a-f]{64}', record['intent']['sha256']) and
                    type(record['intent']['generation']) is int and
                    record['intent']['generation'] > 0):
                matches.append(record)
        except (KeyError, TypeError, AttributeError):
            continue
    return OWNED if len(matches) == 1 else SUSPECT if marked else UNRELATED
