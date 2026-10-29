"""Ownership identity permutations and durable provenance checks, without GCP."""
import copy
import itertools

from sky.utils import stage2_ownership as own

PROJECT = 'dayseum-training'
ZONE = 'asia-east1-b'
NAME = 'pull-main-test-head-abcd-compute'
ROOT = f'https://www.googleapis.com/compute/v1/projects/{PROJECT}/zones/{ZONE}'
LABELS = {
    'managed-by': 'dayseum-stage2-pool',
    'dayseum-pool': 'main-upscale-v1',
    'dayseum-worker-slot': '001',
    'dayseum-launch-request': 'a' * 32,
    'dayseum-config-sha': 'b' * 32
}


def fixture(kind='instances'):
    request = dict(
        kind=kind,
        name=NAME,
        project_id=PROJECT,
        zone=ZONE,
        request_id='r',
        job_name='pull-main-w001-i0001',
        job_id=42,
        cluster='pull-main-cluster',
        labels=LABELS,
        guest_service_account=f'stage2-guest@{PROJECT}.iam.gserviceaccount.com',
        intent=dict(uri='gs://evidence/intent', sha256='a' * 64, generation=1),
        disk_name=NAME,
        disk_id='456')
    record = dict(request=request,
                  operation=dict(clientOperationId='r',
                                 targetId='123',
                                 operationType='insert',
                                 targetLink=f'{ROOT}/{kind}/{NAME}'))
    vm = dict(name=NAME,
              id='123',
              selfLink=f'{ROOT}/{kind}/{NAME}',
              zone=ROOT,
              labels=dict(
                  LABELS, **{
                      'ray-cluster-name': 'pull-main-cluster',
                      'skypilot-cluster-name': 'pull-main-cluster'
                  }),
              serviceAccounts=[{
                  'email': request['guest_service_account']
              }],
              metadata={'items': [{
                  'key': 'enable-oslogin',
                  'value': 'FALSE'
              }]},
              disks=[{
                  'boot': True,
                  'source': f'{ROOT}/disks/{NAME}'
              }])
    return vm, record


def test_every_independent_mark_is_required():
    vm, record = fixture()
    assert classify(vm, [record], project_id=PROJECT) == own.OWNED
    for field in ('name', 'id', 'selfLink', 'zone', 'labels', 'serviceAccounts',
                  'metadata', 'disks'):
        for value in (None, {}, [], '', 'foreign'):
            changed = copy.deepcopy(vm)
            changed[field] = value
            assert classify(changed, [record],
                            project_id=PROJECT) != own.OWNED, field
    for key in LABELS:
        changed = copy.deepcopy(vm)
        changed['labels'].pop(key)
        assert classify(changed, [record], project_id=PROJECT) == own.SUSPECT


def test_production_names_and_labels_never_owned():
    names = [
        'dayseum-xl-v3-1-l4-full-s-001', 'dayseum-xl-v3-l4-t2i-001',
        'dayseum-xl-pull-prod-001', 'dayseum-xl-pull-prod-002',
        'dayseum-xl-character-coyote-001', 'illustrious-xl-l4-full-s-001',
        'dayseum-image2prompt-xl-001', 'dayseum-birefnet-server-001',
        'bastion-server'
    ]
    for name, mask in itertools.product(
            names, itertools.product((False, True), repeat=5)):
        vm, record = fixture()
        vm['name'] = name
        vm['selfLink'] = f'{ROOT}/instances/{name}'
        vm['labels'] = {
            k: LABELS[k] for k, present in zip(LABELS, mask) if present
        }
        assert classify(vm, [record], project_id=PROJECT) != own.OWNED
    for labels in ({}, {
            'pool': 'main-upscale-v1',
            'component': 'pull-inference'
    }, {
            'managed-by': 'production'
    }):
        assert classify(dict(name=names[2], labels=labels), [],
                        project_id=PROJECT) == own.UNRELATED


def test_disk_id_survives_detach_but_not_recreation():
    disk, record = fixture('disks')
    disk.pop('labels')
    disk['users'] = []
    assert classify(disk, [record], project_id=PROJECT) == own.OWNED
    disk['id'] = '124'
    assert classify(disk, [record], project_id=PROJECT) == own.SUSPECT


def test_project_allowlist_exact_match():
    import pytest
    own.require_allowed_project(PROJECT, [PROJECT])
    for values in ([], [PROJECT,
                        PROJECT], ['prefix-' + PROJECT], ['bad'], None):
        with pytest.raises(ValueError):
            own.require_allowed_project(PROJECT, values)


def classify(resource, records, *, project_id):
    disk, disk_record = fixture('disks')
    disk['id'] = '456'
    disk_record['operation']['targetId'] = '456'
    return own.classify_resource(resource,
                                 records + [disk_record],
                                 project_id=project_id,
                                 resources=[resource, disk])
