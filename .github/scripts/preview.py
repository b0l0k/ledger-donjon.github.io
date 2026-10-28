"""Trusted preview publisher. No subprocesses, archive extraction, or PR imports.

All remote site bytes are data passed to the Git data API as non-executable blobs.
Only this file from the triggering default-branch context may run with a token.
"""

import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SOURCE = 'Ledger-Donjon/ledger-donjon.github.io'
SOURCE_ID = 191391592
DEFAULT_BRANCH = 'master'
TARGET = 'Ledger-Donjon/ledger-donjon-preview.github.io'
WORKFLOW = '.github/workflows/pr-preview.yml'
BRANCH = 'gh-pages'
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_ENTRIES = 1500
EXTENSIONS = set('html css js mjs json map txt xml svg png jpg jpeg gif webp avif ico woff woff2 ttf otf pdf wasm webmanifest'.split())


class Rejected(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def positive(value):
    require(type(value) is int and 0 < value < 2 ** 53, 'Invalid numeric identity')
    return value


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'Invalid source revision')
    return value


def source_repository(repo):
    require(repo['id'] == SOURCE_ID and repo['full_name'] == SOURCE, 'Wrong source repository')


def pr_identity(pr, number, state):
    require(pr['number'] == positive(number) and pr['state'] == state, 'PR state or identity changed')
    source_repository(pr['base']['repo'])
    require(pr['base']['ref'] == DEFAULT_BRANCH, 'Unexpected PR base branch')


def binding(event, run, workflow, pr, now):
    """Bind only server-provided identities; no artifact-supplied manifest."""
    source_repository(event['repository'])
    incoming = event['workflow_run']
    source_repository(incoming['repository'])
    source_repository(run['repository'])
    require(run['id'] == positive(incoming['id']), 'Wrong build run')
    require(run['run_attempt'] == positive(incoming['run_attempt']), 'Superseded run attempt')
    require(run['workflow_id'] == workflow['id'] == incoming['workflow_id'], 'Wrong build workflow')
    require(workflow['path'] == run['path'] == WORKFLOW, 'Wrong workflow path')
    require(workflow['state'] == 'active' and run['name'] == 'PR Preview Build', 'Unexpected build workflow')
    require(run['event'] == incoming['event'] == 'pull_request', 'Wrong build event')
    require(run['status'] == 'completed' and run['conclusion'] == 'success', 'Build did not succeed')
    require(incoming['conclusion'] == 'success', 'Unsuccessful triggering build')
    require(len(run['pull_requests']) == len(incoming['pull_requests']) == 1, 'Ambiguous PR association')
    linked = run['pull_requests'][0]
    number = positive(linked['number'])
    require(incoming['pull_requests'][0]['number'] == number, 'Wrong triggering PR')
    pr_identity(pr, number, 'open')
    revision = sha(pr['head']['sha'])
    require(run['head_sha'] == incoming['head_sha'] == linked['head']['sha'] == revision, 'Stale or mismatched source')
    require(linked['base']['repo']['id'] == SOURCE_ID and linked['base']['ref'] == DEFAULT_BRANCH, 'Wrong associated base')
    require(linked['head']['repo']['id'] == pr['head']['repo']['id'] == run['head_repository']['id'], 'Wrong source repository association')
    require(run['head_branch'] == pr['head']['ref'], 'Wrong source branch')
    created = dt.datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
    require(dt.timedelta(0) <= now - created <= dt.timedelta(days=1), 'Build is too old')
    return {'number': number, 'sha': revision, 'run': run['id'], 'attempt': run['run_attempt'],
            'head_repository_id': pr['head']['repo']['id'], 'head_branch': pr['head']['ref']}


def artifact_identity(artifacts, bound):
    require(artifacts['total_count'] <= 100, 'Artifact listing is incomplete')
    name = f"pr-preview-{bound['number']}-{bound['sha']}-{bound['run']}-{bound['attempt']}"
    matches = [item for item in artifacts['artifacts'] if item['name'] == name]
    require(len(matches) == 1, 'Expected exactly one bound artifact')
    item = matches[0]
    positive(item['id'])
    require(item['expired'] is False and 0 < item['size_in_bytes'] <= MAX_ARCHIVE, 'Expired or oversized artifact')
    origin = item['workflow_run']
    require(origin['id'] == bound['run'] and origin['repository_id'] == SOURCE_ID, 'Artifact belongs to another run')
    require(origin['head_sha'] == bound['sha'] and origin['head_repository_id'] == bound['head_repository_id'] and origin['head_branch'] == bound['head_branch'], 'Artifact source mismatch')
    require(re.fullmatch('sha256:[0-9a-f]{64}', item.get('digest') or ''), 'Missing artifact digest')
    return item


def safe_path(name, directory=False):
    require(isinstance(name, str) and 0 < len(name) <= 240, 'Invalid artifact path')
    parts = name.split('/')
    require(len(parts) <= 16 and all(re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,127}', part) for part in parts), 'Unsafe artifact path')
    require(all(not part.endswith('.') for part in parts), 'Ambiguous artifact path')
    if not directory:
        require('.' in parts[-1] and parts[-1].rsplit('.', 1)[1].lower() in EXTENSIONS, 'Unsupported artifact file type')
    return name


def site_files(data, digest):
    require(len(data) <= MAX_ARCHIVE, 'Oversized archive')
    require('sha256:' + hashlib.sha256(data).hexdigest() == digest, 'Artifact digest mismatch')
    files, seen, total = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= MAX_ENTRIES, 'Invalid archive entry count')
        for item in entries:
            require(item.orig_filename == item.filename, 'Truncated archive path')
            directory = item.is_dir()
            name = safe_path(item.filename[:-1] if directory else item.filename, directory)
            require(name.lower() not in seen, 'Duplicate or case-colliding archive path')
            seen.add(name.lower())
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            require(kind in (0, stat.S_IFDIR if directory else stat.S_IFREG), 'Non-regular archive entry')
            require(not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX), 'Unsafe file mode')
            require(directory or not mode & 0o111, 'Executable archive entry')
            require(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'Unsupported archive encoding')
            require(0 <= item.file_size <= MAX_FILE, 'Oversized archive entry')
            total += item.file_size
            require(total <= MAX_TOTAL, 'Expanded archive is too large')
            if directory:
                require(item.file_size == 0, 'Directory contains data')
            else:
                # ZipFile.read checks CRC. Nothing is extracted to the runner.
                content = archive.read(item)
                require(len(content) == item.file_size, 'Incorrect entry size')
                files[name] = content
    require('index.html' in files, 'Missing site entry point')
    lowered = {name.lower() for name in files}
    for name in files:
        parts = name.lower().split('/')
        require(all('/'.join(parts[:i]) not in lowered for i in range(1, len(parts))), 'File/directory collision')
    return files


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, token):
        require(bool(token), 'Missing runtime token')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, method='GET', body=None, redirect=False):
        require(path.startswith('/') and not path.startswith('//'), 'Invalid API path')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'preview-publisher'}
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request('https://api.github.com' + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as response:
                payload = response.read(16 * 1024 * 1024 + 1)
                require(len(payload) <= 16 * 1024 * 1024, 'API response is too large')
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            if redirect and error.code == 302:
                return error.headers['Location']
            # Never print response bodies, request headers, or signed URLs.
            raise Rejected(f'GitHub API request failed ({error.code})') from None

    def download(self, artifact_id):
        location = self.request(f'/repos/{SOURCE}/actions/artifacts/{positive(artifact_id)}/zip', redirect=True)
        url = urllib.parse.urlsplit(location)
        require(url.scheme == 'https' and url.hostname and not url.username and not url.password and url.port in (None, 443), 'Invalid artifact download origin')
        require(url.hostname.endswith('.blob.core.windows.net') or url.hostname.endswith('.actions.githubusercontent.com'), 'Unexpected artifact storage host')
        # A new unauthenticated request: NEVER forward the GitHub bearer token.
        with self.opener.open(urllib.request.Request(location), timeout=30) as response:
            data = response.read(MAX_ARCHIVE + 1)
        require(len(data) <= MAX_ARCHIVE, 'Oversized download')
        return data


def inspect_build(api, event):
    incoming = event['workflow_run']
    run = api.request(f"/repos/{SOURCE}/actions/runs/{positive(incoming['id'])}")
    workflow = api.request(f'/repos/{SOURCE}/actions/workflows/pr-preview.yml')
    require(len(run['pull_requests']) == 1, 'No unique server PR association')
    number = positive(run['pull_requests'][0]['number'])
    pr = api.request(f'/repos/{SOURCE}/pulls/{number}')
    bound = binding(event, run, workflow, pr, dt.datetime.now(dt.timezone.utc))
    # A later build of this revision supersedes this one, even if still running.
    runs = api.request(f"/repos/{SOURCE}/actions/workflows/{positive(workflow['id'])}/runs?event=pull_request&head_sha={bound['sha']}&per_page=100")
    require(runs['total_count'] <= 100 and all(item['id'] <= bound['run'] for item in runs['workflow_runs']), 'Superseded build or incomplete run listing')
    return bound


def inspect_cleanup(api, event):
    source_repository(event['repository'])
    require(event['action'] == 'closed', 'Not a close event')
    number = positive(event['number'])
    pr_identity(event['pull_request'], number, 'closed')
    pr = api.request(f'/repos/{SOURCE}/pulls/{number}')
    pr_identity(pr, number, 'closed')
    return number


def tree_child(api, tree_sha, name):
    tree = api.request(f'/repos/{TARGET}/git/trees/{sha(tree_sha)}')
    require(not tree.get('truncated'), 'Incomplete target tree')
    matches = [entry for entry in tree['tree'] if entry['path'] == name]
    require(len(matches) <= 1, 'Ambiguous target tree')
    if not matches:
        return None
    entry = matches[0]
    require(entry['type'] == 'tree' and entry['mode'] == '040000', 'Target path is not a directory')
    return sha(entry['sha'])


def replacement_tree(api, parent, name, child):
    entry = {'path': name, 'mode': '040000', 'type': 'tree', 'sha': child}
    body = {'tree': [entry]}
    if parent is not None:
        body['base_tree'] = parent
    return api.request(f'/repos/{TARGET}/git/trees', 'POST', body)['sha']


def publish(api, number, files, recheck):
    """Replace/delete exactly one PR subtree, without a working tree or staging."""
    name = f'pr-{positive(number)}'
    installation = api.request('/installation/repositories?per_page=100')
    require(installation['total_count'] == 1 and len(installation['repositories']) == 1 and installation['repositories'][0]['full_name'] == TARGET, 'Token is not target-repository-only')
    ref = api.request(f'/repos/{TARGET}/git/ref/heads/{BRANCH}')
    parent = sha(ref['object']['sha'])
    commit = api.request(f'/repos/{TARGET}/git/commits/{parent}')
    root = sha(commit['tree']['sha'])
    previews = tree_child(api, root, 'pr-preview')
    old = tree_child(api, previews, name) if previews else None
    if files is None and old is None:
        return
    child = None
    if files is not None:
        entries = []
        for path, content in sorted(files.items()):
            safe_path(path)
            blob = api.request(f'/repos/{TARGET}/git/blobs', 'POST', {'encoding': 'base64', 'content': base64.b64encode(content).decode('ascii')})
            entries.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': sha(blob['sha'])})
        child = api.request(f'/repos/{TARGET}/git/trees', 'POST', {'tree': entries})['sha']
    if child == old:
        return
    preview_tree = replacement_tree(api, previews, name, child)
    root_tree = replacement_tree(api, root, 'pr-preview', preview_tree)
    message = f"{'Remove' if files is None else 'Deploy'} preview for PR #{number}"
    new = api.request(f'/repos/{TARGET}/git/commits', 'POST', {'message': message, 'tree': root_tree, 'parents': [parent]})
    recheck()  # Repeat live PR/run checks immediately before making anything visible.
    # Never force: concurrent updates fail instead of overwriting another preview.
    api.request(f'/repos/{TARGET}/git/refs/heads/{BRANCH}', 'PATCH', {'sha': sha(new['sha']), 'force': False})


def main():
    command = sys.argv[1]
    if command == 'revoke':
        API(os.environ['PREVIEW_TOKEN']).request('/installation/token', 'DELETE')
        print('Preview token revoked')
        return
    event = json.load(open(os.environ['GITHUB_EVENT_PATH'], encoding='utf-8'))
    require(os.environ['GITHUB_REPOSITORY'] == SOURCE and event['repository']['default_branch'] == DEFAULT_BRANCH, 'Unexpected workflow repository')
    require(os.environ['GITHUB_REF'] == 'refs/heads/' + DEFAULT_BRANCH, 'Publisher must run in default-branch context')
    source = API(os.environ['GH_TOKEN'])
    if os.environ['GITHUB_EVENT_NAME'] == 'workflow_run':
        require(event['action'] == 'completed', 'Not a completed build')
        bound = inspect_build(source, event)
        if command == 'check':
            return
        artifacts = source.request(f"/repos/{SOURCE}/actions/runs/{bound['run']}/artifacts?per_page=100")
        artifact = artifact_identity(artifacts, bound)
        files = site_files(source.download(artifact['id']), artifact['digest'])
        def recheck():
            require(inspect_build(source, event) == bound, 'Build binding changed')
        number = bound['number']
    else:
        require(os.environ['GITHUB_EVENT_NAME'] == 'pull_request_target', 'Unexpected publisher event')
        number = inspect_cleanup(source, event)
        if command == 'check':
            return
        files = None
        def recheck():
            require(inspect_cleanup(source, event) == number, 'Cleanup binding changed')
    require(command == 'publish', 'Unexpected command')
    publish(API(os.environ['PREVIEW_TOKEN']), number, files, recheck)
    print('Preview update finished')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Remote filenames, site bytes, API errors, tokens and signed URLs must
        # never become workflow commands, log messages, or shell input.
        print('Preview operation rejected or failed; no unsafe fallback', file=sys.stderr)
        sys.exit(1)
