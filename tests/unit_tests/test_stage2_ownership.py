"""Ownership identity permutations and durable provenance checks, without GCP."""
import copy
import itertools

import pytest

from sky.jobs import utils as job_utils
from sky.utils import common_utils
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
        cluster='pull-main-upscale-v1-cluster',
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
                      'ray-cluster-name': 'pull-main-upscale-v1-cluster',
                      'skypilot-cluster-name': 'pull-main-upscale-v1-cluster'
                  }),
              serviceAccounts=[{
                  'email': request['guest_service_account']
              }],
              metadata={
                  'items': [{
                      'key': 'enable-oslogin',
                      'value': 'FALSE'
                  }, {
                      'key': 'block-project-ssh-keys',
                      'value': 'TRUE'
                  }]
              },
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


def test_vm_requires_observed_original_disk():
    vm, record = fixture()
    disk, disk_record = fixture('disks')
    disk['id'] = disk_record['operation']['targetId'] = '456'
    records = [record, disk_record]
    assert own.classify_resource(vm, records, project_id=PROJECT) == own.SUSPECT
    assert own.classify_resource(vm,
                                 records,
                                 project_id=PROJECT,
                                 resources=[vm, disk]) == own.OWNED
    disk['id'] = '789'
    assert own.classify_resource(vm,
                                 records,
                                 project_id=PROJECT,
                                 resources=[vm, disk]) == own.SUSPECT


def test_job_requires_immutable_numeric_binding():
    _, record = fixture()
    binding = {
        k: record['request'][k]
        for k in ('project_id', 'job_id', 'job_name', 'cluster', 'labels',
                  'guest_service_account', 'intent')
    }
    view = {'job_name': binding['job_name'], 'job_id': 42}
    assert own.classify_job(view, [binding], project_id=PROJECT) == own.OWNED
    for key in binding:
        broken = copy.deepcopy(binding)
        broken.pop(key)
        assert own.classify_job(view, [broken],
                                project_id=PROJECT) == own.SUSPECT
    assert own.classify_job(dict(view, job_id=43), [binding],
                            project_id=PROJECT) == own.SUSPECT


def test_control_plane_namespace_is_never_worker_owned():
    for kind in ('instances', 'disks'):
        for name in ('stage2-apiserver', 'stage2-apiserver-boot',
                     'stage2-owned'):
            resource, record = fixture(kind)
            resource.update(name=name, selfLink=f'{ROOT}/{kind}/{name}')
            record['request'].update(name=name, cluster=name, job_name=name)
            record['operation']['targetLink'] = resource['selfLink']
            for labels in ({}, {
                    'pool': 'main-upscale-v1',
                    'component': 'pull-inference'
            }):
                resource['labels'] = labels
                assert own.classify_resource(
                    resource, [record], project_id=PROJECT) == own.UNRELATED
            for mask in itertools.product((False, True), repeat=len(LABELS)):
                resource['labels'] = {
                    key: LABELS[key]
                    for key, include in zip(LABELS, mask)
                    if include
                }
                expected = own.SUSPECT if any(mask) else own.UNRELATED
                assert own.classify_resource(resource, [record],
                                             project_id=PROJECT) == expected
            binding = dict(record['request'])
            assert own.classify_job({
                'job_name': name,
                'job_id': 42
            }, [binding],
                                    project_id=PROJECT) == own.UNRELATED
    for kind in ('instances', 'disks'):
        assert own.candidate_filters(kind)[0] == 'name eq "pull-.*"'


def test_worker_requires_exact_ssh_metadata_before_ownership():
    vm, record = fixture()
    assert classify(vm, [record], project_id=PROJECT) == own.OWNED
    for key, expected in (('enable-oslogin', 'FALSE'),
                          ('block-project-ssh-keys', 'TRUE')):
        for values in ([], [None], [True], ['true'],
                       ['FALSE' if expected == 'TRUE' else 'TRUE'
                       ], [expected, expected]):
            changed = copy.deepcopy(vm)
            items = [m for m in changed['metadata']['items'] if m['key'] != key]
            items.extend({'key': key, 'value': value} for value in values)
            changed['metadata']['items'] = items
            assert classify(changed, [record],
                            project_id=PROJECT) == own.SUSPECT


def test_worker_pool_prefix_survives_actual_skypilot_name_generation(
        monkeypatch):
    monkeypatch.setattr(common_utils, 'get_user_hash', lambda: 'fb16a555')
    for pool in ('a', 'main-upscale-v1', 'a' * 17, 'a-b-c-d-e-f-g-h-i'):
        prefix = own.worker_prefix(pool)
        assert len(prefix) <= 23
        for slot, incarnation, job_id in itertools.product((1, 64), (1, 9999),
                                                           (1, 1000000)):
            task_name = f'{prefix}w{slot:03d}-i{incarnation:04d}'
            cluster = job_utils.generate_managed_job_cluster_name(
                task_name, job_id)
            cloud_name = common_utils.make_cluster_name_on_cloud(cluster, 35)
            instance = f'{cloud_name[:23]}-head-0123456789abcdef-compute'
            assert cloud_name.startswith(prefix)
            assert instance.startswith(prefix)
    for pool in ('a' * 18, 'main_upscale', '-main', 'main-', '', None):
        with pytest.raises(ValueError):
            own.worker_prefix(pool)
