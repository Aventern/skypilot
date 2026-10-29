"""Real fork create and mutation entries with in-memory GCS/Compute transports."""
import copy
import json
from types import SimpleNamespace

import pytest

from sky.provision.gcp import instance
from sky.provision.gcp import instance_utils
from sky.utils import stage2_hardening
from sky.utils import stage2_journal as journal
from sky.utils import stage2_ownership as own
from tests.unit_tests.test_stage2_ownership import LABELS
from tests.unit_tests.test_stage2_ownership import NAME
from tests.unit_tests.test_stage2_ownership import PROJECT
from tests.unit_tests.test_stage2_ownership import ROOT
from tests.unit_tests.test_stage2_ownership import ZONE

CONFIG = dict(
    project_id=PROJECT,
    allowed_project_ids=[PROJECT],
    control_bucket='stage2-control',
    evidence_bucket='stage2-evidence',
    pool='main-upscale-v1',
    guest_service_account=f'stage2-guest@{PROJECT}.iam.gserviceaccount.com')


class Missing(Exception):
    code = 404
    resp = SimpleNamespace(status=404)


class Conflict(Exception):
    code = 412


class Blob:

    def __init__(self, storage, name):
        self.storage, self.name, self.generation = storage, name, None

    def download_as_bytes(self, **_):
        if self.name not in self.storage.objects:
            raise Missing()
        self.generation, body = self.storage.objects[self.name]
        return body

    def upload_from_string(self, body, if_generation_match, **_):
        existing = self.storage.objects.get(self.name, (0, None))[0]
        if existing != if_generation_match:
            raise Conflict()
        self.generation = existing + 1
        self.storage.objects[self.name] = (self.generation, body)


class Storage:

    def __init__(self):
        self.objects = {}

    def bucket(self, _):
        return self

    def blob(self, name, **_):
        return Blob(self, name)

    def list_blobs(self, prefix, **_):
        return [
            self.blob(name) for name in self.objects if name.startswith(prefix)
        ]


class Request:

    def __init__(self, perform):
        self.perform = perform

    def execute(self, **_):
        return self.perform()


class Compute:

    def __init__(self):
        self.resources = {'instances': {}, 'disks': {}}
        self.operations = {}
        self.calls = []
        self.lost = None
        self.before = None

    def __getattr__(self, kind):
        return lambda: Collection(self, kind)


class Collection:

    def __init__(self, compute, kind):
        self.compute, self.kind = compute, kind

    def __getattr__(self, action):

        def call(**kwargs):
            return Request(lambda: self.perform(action, kwargs))

        return call

    def perform(self, action, args):
        c, kind = self.compute, self.kind
        c.calls.append((kind, action, copy.deepcopy(args)))
        if kind == 'zoneOperations':
            if action == 'list':
                request_id = args['filter'].split('"')[1]
                return {
                    'items': [
                        x for x in c.operations.values()
                        if x['clientOperationId'] == request_id
                    ]
                }
            return c.operations[args['operation']]
        values = c.resources[kind]
        if action == 'insert':
            if c.before == kind:
                c.before = None
                raise ConnectionError('crash after claim before RPC submission')
            name = args['body']['name']
            request_id = args['requestId']
            prior = next((v for v in c.operations.values()
                          if v['clientOperationId'] == request_id), None)
            if prior:
                return prior
            if name in values:
                raise Conflict()
            numeric = str(100 + sum(len(v) for v in c.resources.values()))
            body = copy.deepcopy(args['body'])
            body.update(id=numeric,
                        selfLink=f'{ROOT}/{kind}/{name}',
                        zone=ROOT,
                        status='RUNNING')
            if kind == 'instances':
                disk = next(iter(c.resources['disks'].values()))
                body['disks'][0]['source'] = disk['selfLink']
                disk['users'] = [body['selfLink']]
            values[name] = body
            op = dict(name='op-' + request_id,
                      clientOperationId=request_id,
                      targetId=numeric,
                      targetLink=body['selfLink'],
                      operationType='insert',
                      status='DONE')
            c.operations[op['name']] = op
            if c.lost == kind:
                c.lost = None
                raise ConnectionError('lost create response')
            return copy.deepcopy(op)
        if action == 'list':
            return {'items': list(values.values())}
        identity = args.get('instance', args.get('disk'))
        found = next(
            (v for v in values.values() if identity in (v['name'], v['id'])),
            None)
        if found is None:
            raise Missing()
        if action == 'get':
            return copy.deepcopy(found)
        if action == 'delete':
            del values[found['name']]
            if kind == 'instances':
                for disk in c.resources['disks'].values():
                    disk['users'] = []
            return {'name': 'deleted', 'status': 'DONE'}
        if action == 'stop':
            found['status'] = 'TERMINATED'
            return {'name': 'stopped', 'status': 'DONE'}
        if action == 'start':
            found['status'] = 'RUNNING'
            return {'name': 'started', 'status': 'DONE'}
        raise AssertionError((kind, action))


@pytest.fixture
def environment(monkeypatch):
    storage, compute = Storage(), Compute()
    monkeypatch.setattr(stage2_hardening, 'settings', lambda: CONFIG)
    monkeypatch.setattr(journal, '_storage', lambda: storage)
    monkeypatch.setattr(instance_utils.GCPComputeInstance, 'load_resource',
                        lambda: compute)
    j = journal.Journal(storage)
    binding = dict(job_name='pull-main-w001-i0001',
                   job_id=42,
                   cluster='pull-main-cluster',
                   labels=LABELS,
                   guest_service_account=CONFIG['guest_service_account'],
                   project_id=PROJECT,
                   intent=dict(uri='gs://stage2-evidence/intent',
                               sha256='a' * 64,
                               generation=1))
    journal._put(j.blob('jobs/' + binding['job_name'] + '.json'), binding)
    journal._put(j.blob('jobs-by-id/42.json'), binding)
    j.active_job_update(binding)
    config = dict(
        machineType='g2-standard-4',
        labels=LABELS,
        disks=[
            dict(boot=True,
                 autoDelete=True,
                 initializeParams=dict(
                     diskSizeGb=32,
                     diskType=f'zones/{ZONE}/diskTypes/pd-balanced',
                     sourceImage='projects/images/global/images/worker'))
        ],
        serviceAccounts=[{
            'email': CONFIG['guest_service_account']
        }],
        metadata={'items': [{
            'key': 'enable-oslogin',
            'value': 'FALSE'
        }]},
        _stage2_ownership=binding)
    return storage, compute, j, binding, config


def create(environment):
    _, _, _, binding, config = environment
    errors, names = instance_utils.GCPComputeInstance.create_instances(
        binding['cluster'], PROJECT, ZONE, config, {}, 1, 1, True)
    assert errors is None
    return names[0]


@pytest.mark.parametrize('lost', ['disks', 'instances'])
def test_lost_response_resumes_original_insert_and_records_ids(
        environment, lost):
    storage, compute, _, _, _ = environment
    compute.lost = lost
    with pytest.raises(ConnectionError):
        create(environment)
    name = create(environment)
    records = journal.read_records(storage, CONFIG['control_bucket'],
                                   CONFIG['pool'])
    resources = [
        r for group in compute.resources.values() for r in group.values()
    ]
    assert len(records) == 2
    assert len(resources) == 2
    assert own.classify_resource(compute.resources['instances'][name],
                                 records,
                                 project_id=PROJECT,
                                 resources=resources) == own.OWNED
    assert sum(action == 'insert' and kind == lost
               for kind, action, _ in compute.calls) == 1


def test_real_delete_boundary_rechecks_and_uses_numeric_id(environment):
    _, compute, _, _, _ = environment
    name = create(environment)
    numeric = compute.resources['instances'][name]['id']
    instance_utils.GCPComputeInstance.terminate(PROJECT, ZONE, name)
    assert [
        args['instance']
        for kind, action, args in compute.calls
        if kind == 'instances' and action == 'delete'
    ] == [numeric]


def test_foreign_cluster_label_never_reaches_delete(environment):
    _, compute, _, binding, _ = environment
    name = create(environment)
    compute.resources['instances'][name]['serviceAccounts'] = [{
        'email': 'foreign@example.com'
    }]
    with pytest.raises(ValueError):
        instance_utils.GCPComputeInstance.terminate(PROJECT, ZONE, name)
    assert not any(action == 'delete' for _, action, _ in compute.calls)
    assert instance_utils.GCPComputeInstance.filter(
        PROJECT, ZONE, {'ray-cluster-name': binding['cluster']}, None) == {}


@pytest.mark.parametrize('key', [
    'tpu_node', '_has_tpus', 'use_managed_instance_group', 'enable_gpu_direct'
])
def test_filter_bypass_cleanup_is_rejected(environment, key):
    _, compute, _, _, _ = environment
    with pytest.raises(ValueError):
        instance.terminate_instances(
            'pull-cluster',
            dict(project_id=PROJECT, availability_zone=ZONE, **{key: True}))
    assert compute.calls == []


def test_detached_disk_before_vm_request_is_recoverable(environment):
    storage, compute, j, binding, _ = environment
    compute.lost = 'disks'
    with pytest.raises(ConnectionError):
        create(environment)
    j.cleanup_disks(compute, binding['cluster'], PROJECT, ZONE)
    j.cleanup_disks(compute, binding['cluster'], PROJECT, ZONE)
    assert compute.resources['disks'] == {}
    assert journal.read_records(storage, CONFIG['control_bucket'],
                                CONFIG['pool']) == []


def test_terminal_cancel_retries_journal_without_cluster_handle(
        environment, monkeypatch):
    from sky.jobs import state
    from sky.jobs import utils as jobs_utils
    _, compute, _, _, _ = environment
    create(environment)
    monkeypatch.setattr(state, 'get_status',
                        lambda _: state.ManagedJobStatus.CANCELLED)
    monkeypatch.setattr(state, 'get_workspace', lambda _: 'default')
    for attempt in range(3):
        try:
            jobs_utils.cancel_jobs_by_id([42],
                                         current_workspace='default',
                                         cancel_launched_from=False)
            break
        except RuntimeError:
            if attempt == 2:
                raise
    assert all(not values for values in compute.resources.values())
    assert journal.read_records(environment[0], CONFIG['control_bucket'],
                                CONFIG['pool']) == []


def test_boot_disk_replacement_blocks_vm_delete(environment):
    _, compute, _, _, _ = environment
    name = create(environment)
    compute.resources['disks'][name]['id'] = '999999'
    with pytest.raises(Missing):
        instance_utils.GCPComputeInstance.terminate(PROJECT, ZONE, name)
    assert not any(action == 'delete' for _, action, _ in compute.calls)


def test_managed_binding_reads_exact_intent_and_rejects_changed_spec(
        environment):
    import hashlib

    from sky import Task
    storage, _, j, _, _ = environment
    spec = dict(name='pull-main-w001-i0001',
                num_nodes=1,
                setup='echo setup',
                run='echo run',
                resources={
                    'cloud': 'gcp',
                    'instance_type': 'g2-standard-4',
                    'use_spot': True,
                    'labels': LABELS
                },
                envs={
                    'STAGE2_EXPECTED_PROJECT': PROJECT,
                    'STAGE2_EXPECTED_GUEST_SA': CONFIG['guest_service_account'],
                    'STAGE2_POOL': CONFIG['pool']
                })
    record = dict(job_name=spec['name'], spec=spec)
    payload = journal.canonical(record)
    digest = hashlib.sha256(payload).hexdigest()
    key = f"stage2/{CONFIG['pool']}/evidence/launch-intent/{digest}.json"
    storage.objects[key] = (1, payload)
    receipt = dict(uri=f'gs://stage2-evidence/{key}',
                   sha256=digest,
                   generation=1)
    task = Task.from_yaml_config(copy.deepcopy(spec))
    task.update_envs({'STAGE2_INTENT_RECEIPT': json.dumps(receipt)})
    # Use a distinct binding name, because the fixture registered another intent.
    storage.objects.pop(j.prefix + 'jobs/' + spec['name'] + '.json')
    storage.objects.pop(j.prefix + 'jobs-by-id/42.json')
    binding = j.bind_job(task, 42, 'pull-main-cluster')
    assert own.classify_job({
        'job_name': task.name,
        'job_id': 42
    }, [binding],
                            project_id=PROJECT) == own.OWNED
    task.run = 'echo changed'
    with pytest.raises(ValueError):
        j.bind_job(task, 42, 'pull-main-cluster')
    task.run = spec['run']
    task.set_resources(
        {next(iter(task.resources)).copy(instance_type='g2-standard-8')})
    with pytest.raises(ValueError):
        j.bind_job(task, 42, 'pull-main-cluster')


def test_receipt_index_crash_repairs_without_reinserting(environment):
    storage, compute, j, _, _ = environment
    name = create(environment)
    index_key = j.prefix + 'active.json'
    generation, body = storage.objects[index_key]
    index = json.loads(body)
    for record in index['records'].values():
        record['operation'] = None
    storage.objects[index_key] = (generation + 1, journal.canonical(index))
    fresh = journal.Journal(storage)
    fresh.require_owned(compute, 'instances', PROJECT, ZONE, name)
    assert all(record['operation'] is not None
               for record in journal.read_records(
                   storage, CONFIG['control_bucket'], CONFIG['pool']))


def test_rpc_budget_and_deadline_do_not_reset_on_restart(
        environment, monkeypatch):
    _, _, j, _, _ = environment
    monkeypatch.setattr(journal.time, 'time', lambda: 1000)
    j.reclaim_started('instances', ZONE, NAME)
    monkeypatch.setattr(journal.time, 'time', lambda: 1300)
    assert j.reclaim_started('instances', ZONE, NAME)['started_at'] == 1000
    assert journal._read(j.blob(f'overdue/instances/{ZONE}/{NAME}.json')) == {
        'started_at': 1000
    }
    token = journal._SCOPE.set([30, journal.time.monotonic()])
    try:
        with pytest.raises(RuntimeError):
            journal.rpc(Request(lambda: pytest.fail('RPC must not run')))
    finally:
        journal._SCOPE.reset(token)


def test_crash_after_claim_before_rpc_cancel_replays_only_original_request(
        environment, monkeypatch):
    from sky.jobs import state
    from sky.jobs import utils as jobs_utils
    storage, compute, _, _, _ = environment
    compute.before = 'disks'
    with pytest.raises(ConnectionError):
        create(environment)
    original = [
        args for kind, action, args in compute.calls
        if kind == 'disks' and action == 'insert'
    ][0]
    assert compute.resources['disks'] == {}
    monkeypatch.setattr(state, 'get_status',
                        lambda _: state.ManagedJobStatus.CANCELLED)
    monkeypatch.setattr(state, 'get_workspace', lambda _: 'default')
    for attempt in range(3):
        try:
            jobs_utils.cancel_jobs_by_id([42],
                                         current_workspace='default',
                                         cancel_launched_from=False)
            break
        except RuntimeError:
            if attempt == 2:
                raise
    inserts = [
        args for kind, action, args in compute.calls if action == 'insert'
    ]
    assert len(inserts) == 2
    assert inserts[0] == inserts[1] == original
    assert not compute.resources['disks']
    assert not journal.read_records(storage, CONFIG['control_bucket'],
                                    CONFIG['pool'])
    with pytest.raises(ValueError, match='closing'):
        create(environment)


def test_pending_binding_precedes_visibility(environment, monkeypatch):
    from sky import Dag
    from sky import Task
    from sky.jobs import state
    from sky.jobs.server import core
    task = Task(name='pull-main-w001-i0001')
    with Dag() as dag:
        task
    dag.add(task)
    dag.name = task.name
    events = []
    monkeypatch.setattr(core.managed_job_utils, 'is_consolidation_mode',
                        lambda: True)
    monkeypatch.setattr(state, 'set_job_info_without_job_id',
                        lambda *a, **k: 42)
    monkeypatch.setattr(
        journal.Journal, 'bind_job',
        lambda self, task, job_id, cluster: events.append(('binding', job_id)))
    monkeypatch.setattr(
        state, 'set_pending', lambda job_id, *a, **k: events.append(
            ('pending', job_id)))
    monkeypatch.setattr(core.backend_utils, 'get_task_resources_str',
                        lambda *a, **k: 'test')
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        core._maybe_submit_job_locally(directory, dag, 1)
    assert events == [('binding', 42), ('pending', 42)]


def test_quota_narrowed_order_uses_same_immutable_intent(environment):
    import hashlib

    from sky import Task
    storage, _, j, _, _ = environment
    spec = dict(name='pull-narrow-w001-i0001',
                num_nodes=1,
                setup='true',
                run='true',
                resources={
                    'ordered': [{
                        'infra': 'gcp/asia-east1'
                    }, {
                        'infra': 'gcp/us-west1'
                    }],
                    'instance_type': 'g2-standard-4',
                    'use_spot': True,
                    'labels': LABELS
                },
                envs={
                    'STAGE2_EXPECTED_PROJECT': PROJECT,
                    'STAGE2_EXPECTED_GUEST_SA': CONFIG['guest_service_account'],
                    'STAGE2_POOL': CONFIG['pool'],
                    'STAGE2_REGION_ORDER': 'asia-east1,us-west1'
                })
    payload = journal.canonical(dict(job_name=spec['name'], spec=spec))
    digest = hashlib.sha256(payload).hexdigest()
    key = f"stage2/{CONFIG['pool']}/evidence/launch-intent/{digest}.json"
    storage.objects[key] = (1, payload)
    narrowed = copy.deepcopy(spec)
    narrowed['resources']['ordered'] = narrowed['resources']['ordered'][1:]
    narrowed['envs']['STAGE2_REGION_ORDER'] = 'us-west1'
    task = Task.from_yaml_config(narrowed)
    task.update_envs({
        'STAGE2_INTENT_RECEIPT': json.dumps(
            dict(uri=f'gs://stage2-evidence/{key}', sha256=digest,
                 generation=1))
    })
    assert j.bind_job(task, 43, 'pull-narrow-cluster')['job_id'] == 43
    task.update_envs({'STAGE2_REGION_ORDER': 'asia-east1'})
    with pytest.raises(ValueError, match='region subset'):
        j.bind_job(task, 43, 'pull-narrow-cluster')


def test_recovery_after_partial_cleanup_allocates_fresh_name(environment):
    storage, compute, j, binding, _ = environment
    compute.lost = 'disks'
    with pytest.raises(ConnectionError):
        create(environment)
    old_name = next(iter(compute.resources['disks']))
    # An ordinary recovery cleanup closes the old attempt, then permits a new
    # attempt for the same immutable job. Cancellation never reopens the gate.
    for attempt in range(3):
        try:
            journal.cleanup_job(cluster=binding['cluster'])
            break
        except RuntimeError:
            if attempt == 2:
                raise
    j.active_job_update(binding)
    new_name = create(environment)
    assert new_name != old_name
    assert list(compute.resources['instances']) == [new_name]
    assert len(
        journal.read_records(storage, CONFIG['control_bucket'],
                             CONFIG['pool'])) == 2


@pytest.mark.parametrize('kind', ['instances', 'disks'])
def test_pending_insert_is_never_retired_by_two_invisible_reads(
        environment, kind):
    storage, compute, j, binding, _ = environment
    name = create(environment)
    hidden = compute.resources[kind].pop(name)
    operation = next(op for op in compute.operations.values()
                     if op['targetLink'] == hidden['selfLink'])
    operation['status'] = 'PENDING'
    with pytest.raises(RuntimeError, match='insert operation'):
        j.cleanup_disks(compute, binding['cluster'], PROJECT, ZONE)
    active = journal.read_records(storage, CONFIG['control_bucket'],
                                  CONFIG['pool'])
    assert any(r['request']['kind'] == kind and r['request']['name'] == name
               for r in active)
    # The create eventually finishes after cancellation. Its original proof is
    # still present, so repeated cleanup must reclaim exactly this incarnation.
    operation['status'] = 'DONE'
    compute.resources[kind][name] = hidden
    for attempt in range(3):
        try:
            journal.cleanup_job(job_id=42)
            break
        except RuntimeError:
            if attempt == 2:
                raise
    assert not journal.read_records(storage, CONFIG['control_bucket'],
                                    CONFIG['pool'])
    assert all(not group for group in compute.resources.values())


def test_rpc_timeout_is_clamped_to_remaining_scope(environment, monkeypatch):
    request = SimpleNamespace(http=SimpleNamespace(timeout=None))
    request.execute = lambda **_: request.http.timeout
    monkeypatch.setattr(journal.time, 'monotonic', lambda: 129.0)
    token = journal._SCOPE.set([0, 100.0])
    try:
        assert journal.rpc(request) == 1.0
        monkeypatch.setattr(journal.time, 'monotonic', lambda: 130.0)
        with pytest.raises(RuntimeError):
            journal.rpc(request)
    finally:
        journal._SCOPE.reset(token)
