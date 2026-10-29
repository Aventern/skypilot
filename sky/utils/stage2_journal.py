"""Immutable Stage 2 creation provenance, shared by initial launch and cleanup.

Only the API-server credential may write this prefix. Guest credentials must not
have write access. Every cloud call is bounded and there is no label-only adopt.
"""
import contextvars
import copy
import functools
import hashlib
import json
import time
from urllib.parse import urlsplit
import uuid

from sky.utils import stage2_hardening
from sky.utils import stage2_ownership as ownership

_SCOPE = contextvars.ContextVar('stage2_rpc_budget', default=None)


def canonical(value):
    return json.dumps(value,
                      sort_keys=True,
                      separators=(',', ':'),
                      ensure_ascii=False,
                      allow_nan=False).encode()


def _charge():
    scope = _SCOPE.get()
    if scope is not None:
        if scope[0] >= 30 or time.monotonic() - scope[1] >= 30:
            raise RuntimeError('Stage 2 ownership RPC budget exhausted')
        scope[0] += 1


def bounded(function):

    @functools.wraps(function)
    def call(*args, **kwargs):
        if not stage2_hardening.enabled() or _SCOPE.get() is not None:
            return function(*args, **kwargs)
        token = _SCOPE.set([0, time.monotonic()])
        try:
            return function(*args, **kwargs)
        finally:
            _SCOPE.reset(token)

    return call


def rpc(request):
    if not getattr(request, '_stage2_bounded', False):
        _charge()
    # Discovery HttpRequest uses this httplib2 timeout for the actual request.
    if hasattr(request, 'http') and hasattr(request.http, 'timeout'):
        request.http.timeout = 10
    return request.execute(num_retries=0)


def _storage():
    # google-cloud-storage is an optional GCP dependency.
    from google.cloud import storage  # pylint: disable=import-outside-toplevel
    return storage.Client()


def _code(error):
    value = getattr(error, 'code', None)
    return value() if callable(value) else value


def _read(blob):
    _charge()
    try:
        body = blob.download_as_bytes(timeout=10, retry=None)
    except Exception as exc:
        if _code(exc) == 404:
            return None
        raise
    value = json.loads(body)
    if canonical(value) != body:
        raise ValueError('noncanonical ownership evidence')
    return value


def _put(blob, value, generation=0):
    _charge()
    body = canonical(value)
    try:
        blob.upload_from_string(body,
                                content_type='application/json',
                                if_generation_match=generation,
                                timeout=10,
                                retry=None)
    except Exception as exc:
        if _code(exc) != 412:
            raise
        current = _read(blob)
        if generation != 0 or current != value:
            raise ValueError('ownership journal conflict') from exc
    return value


def read_records(storage, bucket, pool):
    value = _read(
        storage.bucket(bucket).blob(f'stage2/{pool}/ownership/active.json'))
    return [] if value is None else list(value['records'].values())


def read_job_records(storage, bucket, pool, names=None):
    if names is not None:
        result = []
        for name in set(names):
            if not isinstance(name, str) or not name.startswith(
                    ownership.PREFIXES) or "/" in name:
                continue
            value = _read(
                storage.bucket(bucket).blob(
                    f"stage2/{pool}/ownership/jobs/{name}.json"))
            if value is not None:
                result.append(value)
        return result
    value = _read(
        storage.bucket(bucket).blob(
            f'stage2/{pool}/ownership/jobs-active.json'))
    return [] if value is None else list(value['records'].values())


class Journal:

    def __init__(self, storage=None):
        self.config = stage2_hardening.settings()
        if self.config is None:
            raise ValueError('Stage 2 journal requires hardening configuration')
        self.storage = storage or _storage()
        self.bucket = self.storage.bucket(self.config['control_bucket'])
        self.prefix = f"stage2/{self.config['pool']}/ownership/"
        self._repaired = set()

    def blob(self, suffix):
        if any(part in ('', '.', '..') for part in suffix.split('/')):
            raise ValueError('invalid ownership journal path')
        return self.bucket.blob(self.prefix + suffix)

    def intent(self, receipt):
        if (not isinstance(receipt, dict) or
                type(receipt.get('generation')) is not int or
                receipt['generation'] <= 0):
            raise ValueError('invalid intent receipt')
        uri = urlsplit(receipt['uri'])
        prefix = f"stage2/{self.config['pool']}/evidence/launch-intent/"
        if (uri.scheme != 'gs' or
                uri.netloc != self.config['evidence_bucket'] or
                not uri.path.removeprefix('/').startswith(prefix) or
                uri.query or uri.fragment):
            raise ValueError(
                'intent receipt outside configured evidence prefix')
        blob = self.storage.bucket(uri.netloc).blob(
            uri.path.removeprefix('/'), generation=receipt['generation'])
        _charge()
        body = blob.download_as_bytes(if_generation_match=receipt['generation'],
                                      timeout=10,
                                      retry=None)
        if hashlib.sha256(body).hexdigest() != receipt['sha256']:
            raise ValueError('intent digest differs')
        value = json.loads(body)
        if canonical(value) != body:
            raise ValueError('intent is not canonical')
        return value

    def bind_job(self, task, job_id, cluster):
        receipt = json.loads(task.envs['STAGE2_INTENT_RECEIPT'])
        record = self.intent(receipt)
        spec = record['spec']
        expected = spec['envs']
        # Task parsing normalizes ordered resource alternatives just as the
        # real submit path does. Local mount paths are rewritten by transport.
        from sky import Task  # pylint: disable=import-outside-toplevel
        expected_spec = copy.deepcopy(spec)
        expected_spec.pop('file_mounts', None)
        expected_task = Task.from_yaml_config(expected_spec)
        actual_resources = [
            canonical(r.to_yaml_config()) for r in task.resources
        ]
        expected_resources = {
            canonical(r.to_yaml_config()) for r in expected_task.resources
        }
        if (not actual_resources or
                len(set(actual_resources)) != len(actual_resources) or
                not set(actual_resources) <= expected_resources):
            raise ValueError('managed job resources differ from launch intent')
        if 'STAGE2_REGION_ORDER' in expected:
            allowed = expected['STAGE2_REGION_ORDER'].split(',')
            selected = task.envs.get('STAGE2_REGION_ORDER', '').split(',')
            if (not selected or len(set(selected)) != len(selected) or
                [region for region in allowed if region in selected] != selected
                    or {r.region for r in task.resources} != set(selected)):
                raise ValueError(
                    'managed job region subset differs from launch intent')

        if (task.name != record['job_name'] or task.name != spec['name'] or
                task.num_nodes != 1 or spec['num_nodes'] != 1 or
                task.run != spec['run'] or task.setup != spec['setup'] or
                type(job_id) is not int or job_id <= 0 or
                not cluster.startswith(ownership.PREFIXES) or
                expected['STAGE2_EXPECTED_PROJECT'] != self.config['project_id']
                or expected['STAGE2_EXPECTED_GUEST_SA'] !=
                self.config['guest_service_account'] or
                expected['STAGE2_POOL'] != self.config['pool'] or any(
                    task.envs.get(k) != v
                    for k, v in expected.items()
                    if k != 'STAGE2_REGION_ORDER') or not task.resources or
                any(r.labels != spec['resources']['labels'] or r.ports or
                    r.use_spot is not True for r in task.resources)):
            raise ValueError('managed job differs from immutable launch intent')
        value = dict(job_name=task.name,
                     job_id=job_id,
                     cluster=cluster,
                     intent=receipt,
                     labels=spec['resources']['labels'],
                     guest_service_account=self.config['guest_service_account'],
                     project_id=self.config['project_id'])
        _put(self.blob(f'jobs/{task.name}.json'), value)
        _put(self.blob(f'jobs-by-id/{job_id}.json'), value)
        self.active_job_update(value)
        return value

    def job(self, name):
        value = _read(self.blob(f'jobs/{name}.json'))
        if value is None:
            raise ValueError('managed job binding is missing')
        return value

    def receipt(self, kind, zone, name):
        return _read(self.blob(f'receipts/{kind}/{zone}/{name}.json'))

    def save_request(self, request):
        _put(
            self.blob(
                f"requests/{request['kind']}/{request['zone']}/{request['name']}.json"
            ), request)
        self.active_update(request, None)

    def request(self, kind, zone, name):
        return _read(self.blob(f'requests/{kind}/{zone}/{name}.json'))

    def observe_operation(self, request, operation):
        value = dict(request=request, operation=operation)
        if not ownership._valid_record(value, self.config['project_id']):
            raise ValueError('create operation differs from durable request')
        # The server-assigned targetId is immutable even before DONE.
        _put(
            self.blob(
                f"receipts/{request['kind']}/{request['zone']}/{request['name']}.json"
            ),
            dict(request=request,
                 operation={
                     k: operation[k]
                     for k in ('clientOperationId', 'targetId', 'targetLink',
                               'operationType', 'name')
                 }))
        receipt = self.receipt(request['kind'], request['zone'],
                               request['name'])
        self.active_update(request, receipt)
        return receipt

    def recover(self, compute, kind, zone, name):
        receipt = self.receipt(kind, zone, name)
        if receipt is not None:
            key = (kind, zone, name)
            if key not in self._repaired:
                self.active_update(receipt['request'], receipt)
                self._repaired.add(key)
            return receipt
        request = self.request(kind, zone, name)
        if request is None:
            return None
        page = rpc(compute.zoneOperations().list(
            project=request['project_id'],
            zone=zone,
            filter=f'clientOperationId = "{request["request_id"]}"',
            maxResults=2))
        operations = page.get('items', [])
        if page.get('nextPageToken') or len(operations) > 1:
            raise ValueError('ambiguous create operation')
        if not operations:
            return None
        operation = operations[0]
        if operation.get('error') and operation.get('status') == 'DONE':
            if (operation.get('clientOperationId') != request['request_id'] or
                    operation.get('operationType') != 'insert' or
                    ownership.resource_path(operation.get('targetLink')) !=
                    f"projects/{request['project_id']}/zones/{zone}/{kind}/{name}"
               ):
                raise ValueError('failed create operation identity differs')
            value = dict(request=request, operation=operation)
            _put(self.blob(f'failed/{kind}/{zone}/{name}.json'), value)
            return value
        return self.observe_operation(request, operation)

    def require_owned(self, compute, kind, project, zone, name):
        stage2_hardening.check_project_id(project)
        collection = getattr(compute, kind)()
        parameter = 'instance' if kind == 'instances' else 'disk'
        resource = rpc(
            collection.get(project=project, zone=zone, **{parameter: name}))
        receipt = self.recover(compute, kind, zone, resource['name'])
        records = [receipt] if receipt else []
        resources = [resource]
        if kind == 'instances' and receipt is not None:
            request = receipt['request']
            disk = rpc(compute.disks().get(project=project,
                                           zone=zone,
                                           disk=request['disk_id']))
            disk_receipt = self.recover(compute, 'disks', zone,
                                        request['disk_name'])
            resources.append(disk)
            if disk_receipt:
                records.append(disk_receipt)
        if ownership.classify_resource(
                resource, records, project_id=project,
                resources=resources) != ownership.OWNED:
            raise ValueError('Stage 2 mutation target is not owned')
        return resource, receipt

    def reclaim_started(self, kind, zone, name):
        blob = self.blob(f'reclaim/{kind}/{zone}/{name}.json')
        record = _read(blob)
        if record is None:
            record = dict(started_at=time.time())
            try:
                _put(blob, record)
            except ValueError:
                record = _read(blob)
        if time.time() >= record['started_at'] + 300:
            _put(self.blob(f'overdue/{kind}/{zone}/{name}.json'), record)
            # Continue known-owned recovery after recording the overdue state.
        return record

    def active_update(self, request, record, remove=False):
        key = f"{request['kind']}/{request['zone']}/{request['name']}"
        for _ in range(3):
            blob = self.blob('active.json')
            current = _read(blob)
            generation = int(blob.generation) if current is not None else 0
            current = current or {'records': {}}
            if not remove and record is not None and current['records'].get(
                    key) == record:
                return
            if remove:
                current['records'].pop(key, None)
            else:
                if key not in current['records'] and len(
                        current['records']) >= 128:
                    raise ValueError('active ownership bound exceeded')
                current['records'][key] = record or {
                    'request': request,
                    'operation': None
                }
            try:
                _put(blob, current, generation)
                return
            except ValueError:
                continue
        raise ValueError('active ownership CAS contention')

    def active_job_update(self, value, remove=False):
        for _ in range(3):
            blob = self.blob('jobs-active.json')
            current = _read(blob)
            generation = int(blob.generation) if current is not None else 0
            current = current or {'records': {}}
            name = value['job_name']
            if remove:
                current['records'].pop(name, None)
            else:
                if name not in current['records'] and len(
                        current['records']) >= 128:
                    raise ValueError('active job binding bound exceeded')
                current['records'][name] = value
            try:
                _put(blob, current, generation)
                return
            except ValueError:
                continue
        raise ValueError('active job CAS contention')

    def gate(self, job_name, *, claim=None, closing=None, cancelled=False):
        for _ in range(3):
            blob = self.blob(f'gates/{job_name}.json')
            value = _read(blob)
            generation = int(blob.generation) if value is not None else 0
            value = value or dict(requests=[], closing=False, cancelled=False)
            if claim is not None:
                if value['closing'] or value['cancelled']:
                    raise ValueError(
                        'Stage 2 job is closing; create is forbidden')
                if claim in value['requests']:
                    return value
                value['requests'].append(claim)
            if closing is not None:
                value['closing'] = closing
            value['cancelled'] = value['cancelled'] or cancelled
            try:
                _put(blob, value, generation)
                return value
            except ValueError:
                continue
        raise ValueError('Stage 2 create/cancel gate contention')

    def resolve_ambiguous(self, compute, request):
        gate = _read(self.blob(f"gates/{request['job_name']}.json"))
        self.reclaim_started(request['kind'], request['zone'], request['name'])
        if (gate is None or not (gate['closing'] or gate['cancelled']) or
                request['request_id'] not in gate['requests'] or
                time.time() >= request['created_at_epoch'] + 300):
            raise ValueError('ambiguous create cannot be safely replayed')
        # Resolve the already claimed original request, under its existing
        # reservation. Never allocate a new attempt/name while cancelling.
        operation = rpc(
            getattr(compute,
                    request['kind'])().insert(project=request['project_id'],
                                              zone=request['zone'],
                                              requestId=request['request_id'],
                                              body=request['body']))
        return self.observe_operation(request, operation)

    def close_unsent(self, compute, request):
        gate = _read(self.blob(f"gates/{request['job_name']}.json"))
        if (gate is None or not (gate['closing'] or gate['cancelled']) or
                request['request_id'] in gate['requests']):
            return False
        parameter = 'instance' if request['kind'] == 'instances' else 'disk'
        for _ in range(2):
            try:
                rpc(
                    getattr(compute, request['kind'])().get(
                        project=request['project_id'],
                        zone=request['zone'],
                        **{parameter: request['name']}))
            except Exception as exc:
                if getattr(getattr(exc, 'resp', None), 'status', None) != 404:
                    raise
            else:
                return False
        self.active_update(request, None, remove=True)
        return True

    def create_single(self, compute, cluster, project, zone, config, binding):
        """Resume the same request after a lost response; never reuse a name."""
        stage2_hardening.check_project_id(project)
        gate = _read(self.blob(f"gates/{binding['job_name']}.json"))
        if gate and (gate['closing'] or gate['cancelled']):
            raise ValueError('Stage 2 job is closing; new attempt is forbidden')
        if self.job(binding['job_name']) != binding:
            raise ValueError(
                'provider binding differs from managed job evidence')
        if not cluster.startswith(ownership.PREFIXES):
            raise ValueError('Stage 2 cloud name prefix differs')
        slot = self.blob(f'attempts/{cluster}/{zone}.json')
        attempt = _read(slot)
        generation = int(slot.generation) if attempt is not None else 0
        if attempt is not None:
            previous_disk = self.receipt('disks', zone, attempt['name'])
            active = read_records(self.storage, self.config['control_bucket'],
                                  self.config['pool'])
            if previous_disk is not None and not any(
                    r['request']['name'] == attempt['name'] for r in active):
                # Two confirmed absences retired this attempt. A subsequent
                # recovery gets a fresh name; the old name is never inserted.
                attempt = None
        if attempt is not None:
            if attempt['binding'] != binding:
                raise ValueError('active attempt belongs to another job')
            previous = self.recover(compute, 'instances', zone, attempt['name'])
            if previous is not None:
                try:
                    rpc(compute.instances().get(
                        project=project,
                        zone=zone,
                        instance=previous['operation']['targetId']))
                except Exception as exc:
                    if getattr(getattr(exc, 'resp', None), 'status',
                               None) != 404:
                        raise
                else:
                    self.require_owned(compute, 'instances', project, zone,
                                       previous['operation']['targetId'])
                    return attempt['name'], previous['operation']
                self.cleanup_disks(compute, cluster, project, zone)
                attempt = None
        if attempt is None:
            # This permanent attempt identity precedes both disk and VM insert.
            attempt = dict(
                name=f'{cluster[:23]}-head-{uuid.uuid4().hex[:16]}-compute',
                binding=binding,
                disk_request_id=str(uuid.uuid4()),
                vm_request_id=str(uuid.uuid4()),
                created_at_epoch=time.time())
            _put(slot, attempt, generation)
        name = attempt['name']
        vm_body = copy.deepcopy(config)
        boot = vm_body['disks'][0]
        initial = boot['initializeParams']
        disk_body = dict(name=name,
                         sizeGb=initial['diskSizeGb'],
                         type=initial['diskType'],
                         sourceImage=initial['sourceImage'])
        common = dict(created_at_epoch=attempt['created_at_epoch'],
                      project_id=project,
                      zone=zone,
                      name=name,
                      job_name=binding['job_name'],
                      job_id=binding['job_id'],
                      job_cluster=binding['cluster'],
                      cluster=cluster,
                      labels=binding['labels'],
                      guest_service_account=binding['guest_service_account'],
                      intent=binding['intent'])
        disk_request = dict(common,
                            kind='disks',
                            request_id=attempt['disk_request_id'],
                            body=disk_body)
        disk_receipt = self._insert(compute, disk_request)
        disk_id = disk_receipt['operation']['targetId']
        self._wait_insert(compute, disk_request)
        disk = rpc(compute.disks().get(project=project, zone=zone,
                                       disk=disk_id))
        if ownership.classify_resource(disk, [disk_receipt],
                                       project_id=project) != ownership.OWNED:
            raise ValueError('new boot disk differs from insert operation')
        vm_body['disks'] = [
            dict(boot=True,
                 autoDelete=True,
                 type='PERSISTENT',
                 source=f'projects/{project}/zones/{zone}/disks/{disk_id}')
        ]
        vm_body['name'] = name
        vm_request = dict(common,
                          kind='instances',
                          request_id=attempt['vm_request_id'],
                          body=vm_body,
                          disk_name=name,
                          disk_id=disk_id)
        receipt = self._insert(compute, vm_request)
        return name, receipt['operation']

    def _insert(self, compute, request):
        receipt = self.recover(compute, request['kind'], request['zone'],
                               request['name'])
        if receipt is not None:
            if receipt['request'] != request:
                raise ValueError('create retry body differs')
            return receipt
        self.save_request(request)
        self.gate(request['job_name'], claim=request['request_id'])
        operation = rpc(
            getattr(compute,
                    request['kind'])().insert(project=request['project_id'],
                                              zone=request['zone'],
                                              requestId=request['request_id'],
                                              body=request['body']))
        return self.observe_operation(request, operation)

    def _wait_insert(self, compute, request):
        # A disk insert normally completes quickly. A pending operation remains
        # in the journal and the next recovery resumes it with the same ID.
        for _ in range(3):
            page = rpc(compute.zoneOperations().list(
                project=request['project_id'],
                zone=request['zone'],
                filter=f'clientOperationId = "{request["request_id"]}"',
                maxResults=2))
            ops = page.get('items', [])
            if len(ops) != 1 or page.get('nextPageToken'):
                raise ValueError('create operation unavailable or ambiguous')
            if ops[0].get('error'):
                raise ValueError('create operation failed')
            if ops[0].get('status') == 'DONE':
                return
            time.sleep(1)
        raise RuntimeError(
            'create operation remains pending; resume durable attempt')

    def close_failed_insert(self, compute, receipt):
        if not receipt or not receipt['operation'].get('error'):
            return False
        request = receipt['request']
        parameter = 'instance' if request['kind'] == 'instances' else 'disk'
        for _ in range(2):
            try:
                rpc(
                    getattr(compute, request['kind'])().get(
                        project=request['project_id'],
                        zone=request['zone'],
                        **{parameter: request['name']}))
            except Exception as exc:
                if getattr(getattr(exc, 'resp', None), 'status', None) != 404:
                    raise
            else:
                raise ValueError('failed create left an unproven resource')
        self.active_update(request, receipt, remove=True)
        return True

    def cleanup_disks(self, compute, cluster, project, zone):
        """Recover detached disks too, including crashes before VM insertion."""
        records = read_records(self.storage, self.config['control_bucket'],
                               self.config['pool'])
        for record in records:
            request = record['request']
            if (request['kind'] == 'instances' and
                    request['cluster'] == cluster and
                    request['project_id'] == project and
                    request['zone'] == zone):
                receipt = self.recover(compute, 'instances', zone,
                                       request['name'])
                if receipt is not None:
                    if self.close_failed_insert(compute, receipt):
                        continue
                    absent = 0
                    for _ in range(2):
                        try:
                            rpc(compute.instances().get(
                                project=project,
                                zone=zone,
                                instance=receipt['operation']['targetId']))
                        except Exception as exc:
                            if getattr(getattr(exc, 'resp', None), 'status',
                                       None) != 404:
                                raise
                            absent += 1
                    if absent == 2:
                        self.active_update(request, receipt, remove=True)
            if (request['kind'] != 'disks' or request['cluster'] != cluster or
                    request['project_id'] != project or
                    request['zone'] != zone):
                continue
            receipt = self.recover(compute, 'disks', zone, request['name'])
            if receipt is None:
                if self.close_unsent(compute, request):
                    continue
                receipt = self.resolve_ambiguous(compute, request)
            if self.close_failed_insert(compute, receipt):
                continue
            disk_id = receipt['operation']['targetId']
            absent = 0
            for _ in range(3):
                try:
                    disk, _ = self.require_owned(compute, 'disks', project,
                                                 zone, disk_id)
                except Exception as exc:
                    if getattr(getattr(exc, 'resp', None), 'status',
                               None) != 404:
                        raise
                    absent += 1
                    if absent == 2:
                        break
                    continue
                if disk.get('users'):
                    break
                self.reclaim_started('disks', zone, request['name'])
                rpc(compute.disks().delete(
                    project=project,
                    zone=zone,
                    disk=disk_id,
                    requestId=str(
                        uuid.uuid5(uuid.NAMESPACE_URL,
                                   f'delete:{project}:{zone}:{disk_id}'))))
            if absent == 2:
                self.active_update(request, receipt, remove=True)


class _BoundedRequest:
    _stage2_bounded = True

    def __init__(self, request):
        self.request = request

    def execute(self, **_):
        _charge()
        http = getattr(self.request, 'http', None)
        if http is not None:
            http.timeout = 10
        return self.request.execute(num_retries=0)


class _BoundedCollection:

    def __init__(self, collection):
        self.collection = collection

    def __getattr__(self, method):
        return lambda *args, **kwargs: _BoundedRequest(
            getattr(self.collection, method)(*args, **kwargs))


class _BoundedCompute:

    def __init__(self, compute):
        self.compute = compute

    def __getattr__(self, collection):
        return lambda *args, **kwargs: _BoundedCollection(
            getattr(self.compute, collection)(*args, **kwargs))


def guard_compute(compute):
    return _BoundedCompute(compute) if stage2_hardening.enabled() else compute


@bounded
def cleanup_job(*, job_id=None, cluster=None):
    """API-server retry entry, also used for terminal jobs and missing handles."""
    # pylint: disable=import-outside-toplevel
    from sky.provision.gcp import instance_utils
    journal = Journal()
    bindings = [
        binding for binding in read_job_records(
            journal.storage, journal.config['control_bucket'],
            journal.config['pool'])
        if ((job_id is not None and binding['job_id'] == job_id) or
            (cluster is not None and binding['cluster'] == cluster))
    ]
    if not bindings and job_id is not None:
        archived = _read(journal.blob(f'jobs-by-id/{job_id}.json'))
        if archived is not None and archived['job_id'] == job_id:
            bindings = [archived]
    for binding in bindings:
        journal.gate(binding['job_name'],
                     closing=True,
                     cancelled=job_id is not None)
    records = read_records(journal.storage, journal.config['control_bucket'],
                           journal.config['pool'])
    selected = [
        r for r in records
        if (job_id is not None and r['request']['job_id'] == job_id) or
        (cluster is not None and r['request'].get('job_cluster') == cluster)
    ]
    compute = instance_utils.GCPComputeInstance.load_resource()
    failures = []
    groups = set()
    for record in selected:
        request = record['request']
        project, zone, name = request['project_id'], request['zone'], request[
            'name']
        groups.add((request['cluster'], project, zone))
        if request['kind'] != 'instances':
            continue
        try:
            receipt = journal.recover(compute, 'instances', zone, name)
            if receipt is None:
                if journal.close_unsent(compute, request):
                    continue
                receipt = journal.resolve_ambiguous(compute, request)
            if journal.close_failed_insert(compute, receipt):
                continue
            numeric = receipt['operation']['targetId']
            try:
                journal.require_owned(compute, 'instances', project, zone,
                                      numeric)
            except Exception as exc:
                if getattr(getattr(exc, 'resp', None), 'status', None) != 404:
                    raise
            else:
                journal.reclaim_started('instances', zone, name)
                rpc(compute.instances().delete(
                    project=project,
                    zone=zone,
                    instance=numeric,
                    requestId=str(
                        uuid.uuid5(uuid.NAMESPACE_URL,
                                   f'delete:{project}:{zone}:{numeric}'))))
        except Exception as exc:
            failures.append(exc)
    for cloud_cluster, project, zone in sorted(groups):
        try:
            journal.cleanup_disks(compute, cloud_cluster, project, zone)
        except Exception as exc:
            failures.append(exc)
    remaining = read_records(journal.storage, journal.config['control_bucket'],
                             journal.config['pool'])
    if failures or any(
            r['request']['name'] in {x['request']['name']
                                     for x in selected}
            for r in remaining):
        raise RuntimeError('Stage 2 cleanup unresolved; retry the same job ID'
                          ) from (failures[0] if failures else None)

    blob = journal.blob('jobs-active.json')
    current = _read(blob)
    if current is not None:
        changed = False
        for name, binding in list(current['records'].items()):
            if ((job_id is not None and binding['job_id'] == job_id) or
                (cluster is not None and binding['cluster'] == cluster)):
                current['records'].pop(name)
                changed = True
        if changed:
            _put(blob, current, int(blob.generation))

    if job_id is None:
        for binding in bindings:
            journal.gate(binding['job_name'], closing=False)
