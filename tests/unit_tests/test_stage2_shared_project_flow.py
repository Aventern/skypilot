"""Cross-repository recovery tests through the deployed fork and pool controller."""
from types import SimpleNamespace

import pytest

from sky import Dag
from sky import Task
from sky.jobs import state
from sky.jobs import utils as jobs_utils
from sky.jobs.server import core
from sky.utils import stage2_hardening
from sky.utils import stage2_journal as journal
from tests.unit_tests.test_stage2_journal import environment  # noqa: F401


@pytest.mark.parametrize(
    'boundary', ['jobs-active.json', 'jobs/', 'jobs-by-id/', 'pending'])
def test_unpublished_binding_reaches_controller_release(environment,
                                                        monkeypatch, tmp_path,
                                                        boundary):
    from stage2.skypilot_pool.admission import MemoryAdmission
    from stage2.skypilot_pool.backend_skypilot import SkyPilotPoolBackend
    from stage2.skypilot_pool.ownership import OwnedJobsApi
    from test_stage2_controller import Stage2ControllerTest
    from test_stage2_controller import T0

    storage, compute, _, _, _ = environment
    storage.objects.clear()
    harness = Stage2ControllerTest()
    harness.setUp()
    config = harness.config
    settings = dict(project_id=config.project_id,
                    allowed_project_ids=list(config.allowed_project_ids),
                    pool=config.pool,
                    control_bucket=config.control_bucket,
                    evidence_bucket=config.evidence_bucket,
                    guest_service_account=config.guest_service_account)
    monkeypatch.setattr(stage2_hardening, 'settings', lambda: settings)
    gate = MemoryAdmission()
    harness.controller.admission = gate
    original_publish = harness.store.publish_evidence

    def publish(kind, record):
        receipt = original_publish(kind, record)
        key = f"stage2/{config.pool}/evidence/{kind}/{receipt['sha256']}.json"
        storage.objects[key] = (receipt['generation'],
                                journal.canonical(record))
        receipt['uri'] = f'gs://{config.evidence_bucket}/{key}'
        return receipt

    harness.store.publish_evidence = publish
    monkeypatch.setattr(core.managed_job_utils, 'is_consolidation_mode',
                        lambda: True)
    monkeypatch.setattr(state, 'set_job_info_without_job_id',
                        lambda *a, **k: 42)
    monkeypatch.setattr(state, 'get_status', lambda _: None)
    monkeypatch.setattr(state, 'get_workspace', lambda _: 'default')
    monkeypatch.setattr(core.backend_utils, 'get_task_resources_str',
                        lambda *a, **k: 'test')
    calls, published, captured = [], [], []
    original_put = journal._put
    crashed = [False]

    def put(blob, value, generation=0):
        result = original_put(blob, value, generation)
        if not crashed[0] and boundary in blob.name:
            crashed[0] = True
            raise SystemExit('API process stopped after durable binding write')
        return result

    monkeypatch.setattr(journal, '_put', put)

    def pending(*args, **kwargs):
        if boundary == 'pending' and not crashed[0]:
            crashed[0] = True
            raise SystemExit('API process stopped before queue publication')
        published.append(args)

    monkeypatch.setattr(state, 'set_pending', pending)

    def launch(yaml_text, name):
        import yaml
        task = Task.from_yaml_config(yaml.safe_load(yaml_text))
        captured.append(task)
        with Dag() as dag:
            task
        dag.add(task)
        dag.name = name
        try:
            core._maybe_submit_job_locally(str(tmp_path), dag, 1)
        except SystemExit as exc:
            raise ConnectionError('API response lost') from exc

    def cancel(job_id):
        calls.append(job_id)
        return jobs_utils.cancel_jobs_by_id([job_id],
                                            current_workspace='default',
                                            cancel_launched_from=False)

    api = OwnedJobsApi(
        SimpleNamespace(queue=lambda: [], launch=launch, cancel_id=cancel),
        config, lambda names: journal.read_job_records(
            storage, config.control_bucket, config.pool, names))
    markers = set()
    backend = SkyPilotPoolBackend(
        api=api,
        control_store=SimpleNamespace(write_marker=markers.add,
                                      delete_marker=markers.discard),
        server_config_reader=harness.backend.effective_server_config)
    harness.controller.backend = backend
    result = harness.controller.tick(T0)
    assert result.launch['status'] == 'outcome_unknown', result.launch
    assert crashed[0] and not published
    assert api.queue() == []  # binding alone is never counted as a running VM
    entry = harness.store.state['slots']['001']
    name, request = entry['job_name'], entry['request_id']
    harness.store.stopped = True
    for offset in [60, 120, 180, 1200, 1260, 1320, 1800, 1860, 3600]:
        harness.controller.tick(T0 + offset)
    assert harness.store.state['slots']['001'][
        'status'] == 'RELEASED', harness.store.state['slots']['001']
    assert request in gate.released and gate.headroom() == gate.cap
    assert calls and set(calls) == {42}
    assert not journal.read_job_records(storage, config.control_bucket,
                                        config.pool)
    assert not any(compute.resources.values())
    assert any(kind == 'release' for kind, _ in harness.store.evidence)
    # Neither a replay nor a different job ID can revive this intent after cancel.
    for job_id in [42, 43]:
        with pytest.raises(ValueError):
            journal.Journal(storage).bind_job(
                captured[0], job_id,
                core.managed_job_utils.generate_managed_job_cluster_name(
                    name, job_id))
    with pytest.raises(ValueError, match='closing'):
        journal.Journal(storage).gate(name, claim='late-create')
    gate.reserve('next-intent', T0 + 4000)
    harness.doCleanups()


@pytest.mark.parametrize('kind', ['instances', 'disks'])
def test_async_failure_releases_real_admission_via_runtime(
        environment, monkeypatch, kind):
    import uuid

    from stage1.project_admission import MemoryLedgerStore
    from stage1.project_admission import ProjectAdmissionAllocator
    from stage2.skypilot_pool.admission import _grant
    from stage2.skypilot_pool.admission import Stage2Admission
    from stage2.skypilot_pool.inventory import SharedProjectBoundary
    from stage2.skypilot_pool.ownership import OwnedJobsApi
    from stage2.skypilot_pool.runtime import _InventoryReader
    from test_stage2_shared_ownership import shared_config

    from tests.unit_tests.test_stage2_journal import CONFIG
    from tests.unit_tests.test_stage2_journal import create
    from tests.unit_tests.test_stage2_journal import ZONE

    storage, compute, j, binding, _ = environment
    config = shared_config()
    now = [1800000000]
    boundary = SharedProjectBoundary(
        config, '123456', '234567', lambda: journal.read_records(
            storage, config.control_bucket, config.pool))
    inventory = _InventoryReader({})
    inventory.boundary, inventory.pool = boundary, config.pool

    def capture(**_):
        boundary.refresh()
        return boundary.classify(
            [v for group in compute.resources.values() for v in group.values()],
            now[0])

    inventory.reader = SimpleNamespace(capture=capture)
    inventory.jobs_api = OwnedJobsApi(
        SimpleNamespace(
            queue=lambda: [],
            cancel_id=lambda job_id: journal.cleanup_job(job_id=job_id)),
        config, lambda names: journal.read_job_records(storage, CONFIG[
            'control_bucket'], config.pool, names))
    allocator = ProjectAdmissionAllocator(store=MemoryLedgerStore(),
                                          project_id=config.project_id,
                                          project_number='123456',
                                          compute_project_numeric_id='234567',
                                          inventory_boundary=boundary)
    admission = Stage2Admission(
        config,
        allocator,
        inventory,
        now=lambda: now[0],
        sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
    request = str(uuid.uuid4())
    binding['labels'] = dict(
        binding['labels'],
        **{'dayseum-launch-request': request.replace('-', '')})
    environment[4]['labels'].update(binding['labels'])
    storage.objects.clear()
    journal._put(j.blob(f"jobs/{binding['job_name']}.json"), binding)
    journal._put(j.blob('jobs-by-id/42.json'), binding)
    j.active_job_update(binding)
    grant = admission.reserve(request, now[0])
    name = create(environment)
    receipt = j.receipt(kind, ZONE, name)
    operation = compute.operations[receipt['operation']['name']]
    operation.update(
        status='DONE',
        error={'errors': [{
            'code': 'ZONE_RESOURCE_POOL_EXHAUSTED'
        }]})
    # Cloud has removed the failed resources. Durable active receipts still
    # require runtime.settle_absence to re-cancel before allocator.abandon.
    compute.resources['instances'].clear()
    compute.resources['disks'].clear()
    now[0] += 120
    for attempt in range(8):
        try:
            admission.release(grant, now[0])
            break
        except RuntimeError:
            if attempt == 7:
                raise
    allocator.assert_released(_grant(grant))
    assert now[0] >= 1800000125
    assert not journal.read_records(storage, CONFIG['control_bucket'],
                                    config.pool)
    assert admission.headroom() == 12
    admission.reserve(str(uuid.uuid4()), now[0])
    assert admission.headroom() == 11
