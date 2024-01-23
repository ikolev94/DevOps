#!/usr/bin/env python3

import base64
import json
import os
import re
import ssl
import sys
import urllib.parse
from urllib import request
from urllib.error import HTTPError

GITLAB_URL = 'gitlab.com'
GLCM_PROJECT_ID = '1'
GITLAB_MR_URL = f'https://{GITLAB_URL}/api/v4/projects/{GLCM_PROJECT_ID}/merge_requests/%s'
CHANGES_URL = f'{GITLAB_MR_URL}/changes'
DISCUSSIONS_URL = f'{GITLAB_MR_URL}/discussions'
GITLAB_TOKEN = ''
GITLAB_HEADERS = {"PRIVATE-TOKEN": GITLAB_TOKEN, "Content-Type": "application/json"}

SONAR_URL = 'https://sonrar.com'
SONAR_PROJECT_NAME = 'project-name'
SONAR_TOKEN = os.environ.get("SONAR_TOKEN")
IGNORE_RULES = ['java:S125', 'java:S1133', 'java:S1874', 'java:S112', 'java:S1135', 'java:S1075', 'java:S1192']


def send_request(url: str, headers: dict, method='GET', data=None) -> dict:
    try:
        context = ssl.create_default_context()
        context.set_ciphers('ALL:@SECLEVEL=1')
        req = request.Request(url, method=method, data=json.dumps(data).encode('utf-8') if data else None,
                              headers=headers)
        res = request.urlopen(req, timeout=60, context=context)
        print(f"{method}: {res.url} -> {res.status}")
        return json.loads(res.read().decode('utf-8'))
    except HTTPError as err:
        print(f'A HTTPError was thrown: {err.code} {err.fp.read()}')
        return {}


def get_glcm_mr_by_id(mr_id: str) -> dict:
    return send_request(CHANGES_URL % mr_id, headers=GITLAB_HEADERS)


def get_all_inline_comments(mr_id: str) -> list:
    return [
        {
            "body": note.get("body", ""),
            "new_path": note.get("position", {}).get("new_path", ""),
            "new_line": note.get("position", {}).get("new_line", 0)
        }
        for item in send_request(DISCUSSIONS_URL % mr_id, headers=GITLAB_HEADERS)
        for note in item.get("notes", [])
    ]


def create_inline_comment(mr_id: str, comment: dict):
    return send_request(DISCUSSIONS_URL % mr_id, method='POST', headers=GITLAB_HEADERS, data=comment)


def extract_changes(merge_request: dict) -> list:
    return merge_request["changes"]


def extract_diff_refs(merge_request: dict) -> dict:
    return merge_request['diff_refs']


def extract_path(change: dict) -> str:
    return change["new_path"]


def extract_diff_file_paths(changes: list) -> list:
    return [extract_path(change) for change in changes]


def is_number_in_ranges(n: int, ranges: list) -> bool:
    return any(range_start <= n <= range_end for range_start, range_end in ranges)


def update_mr(merge_request: dict, issues: list):
    mr_id = merge_request['iid']
    position = {'position_type': 'text'}
    position.update(extract_diff_refs(merge_request))
    existing_comments = get_all_inline_comments(mr_id)
    if len(existing_comments) > 30:
        print("This may be something unexpected. For now aborting the comment creation to prevent the spam.")
        return
    for issue in issues:
        comment_body = format_message(issue)
        print(comment_body)
        if any(
                issue['message'] in existing_comment["body"]
                and existing_comment["new_path"] == extract_full_path_from_issue(issue)
                and existing_comment["new_line"] == issue['line']
                for existing_comment in existing_comments
        ):
            print("The comment already exists")
            continue

        position['new_path'] = extract_full_path_from_issue(issue)
        position['new_line'] = issue['line']
        if create_inline_comment(mr_id, {'position': position, 'body': comment_body}):
            print("Successful comment creation on a new file")
            continue
        position['old_path'] = extract_full_path_from_issue(issue)
        if create_inline_comment(mr_id, {'position': position, 'body': comment_body}):
            print("Successful comment creation")
            continue
        # TODO: find how can this be eliminated and calculate old_line
        # https://docs.gitlab.com/ee/api/discussions.html#create-a-new-thread-in-the-merge-request-diff
        position['old_line'] = issue['line']
        create_inline_comment(mr_id, {'position': position, 'body': comment_body})


def find_changed_code_ranges(changes: list) -> dict:
    ranges_per_file = {}
    for change in changes:
        if not extract_path(change).endswith('.java'):
            continue
        file_diffs = change['diff']
        code_changes_start = [
            int(digit) for digit in re.findall("\\+\\d+", file_diffs)
        ]
        code_changes_length = [
            d.count('\n') for d in file_diffs.split("@@") if d.count('\n') > 0
        ]
        ranges_per_file[extract_path(change)] = [
            (x, x + y) for x, y in zip(code_changes_start, code_changes_length)]
    return ranges_per_file


def get_sonar_issues_by_mr_id(mr_id: str, sonar_proj_key: str) -> list:
    sonar_url = f'{SONAR_URL}/api/issues/search?'
    headers = {
        'Authorization': 'Basic ' + base64.b64encode((SONAR_TOKEN + ':').encode()).decode()
    }
    all_issues = []
    page = 1
    page_size = 250
    while True:
        params = {
            "statuses": "OPEN",
            "p": page,
            "ps": page_size,
            "pullRequest": mr_id,
            "componentKeys": sonar_proj_key
        }
        data = send_request(sonar_url + urllib.parse.urlencode(params), headers=headers)
        current_page_issues = data.get('issues', [])
        all_issues.extend(current_page_issues)
        if not current_page_issues or page > data.get('total', 0) // page_size:
            break
        page += 1
    print(f"Found {len(all_issues)} sonar issues")
    return all_issues


def format_message(issue: dict) -> str:
    return (
        f"- **{issue['message']}**\n"
        f"- [Why is this an issue?](https://rules.sonarsource.com/java/RSPEC-{issue['rule'].strip('java:S')})\n"
        f"- Type: `{issue['type']}`\n"
        f"- Severity: {issue['severity']}\n\n"
        f":robot: _This note is automatically generated by a pipeline performing static code analysis, which has identified an issue in your merge request._ :rotating_light:"
    )


def extract_path_from_issue(sonar_issue: dict) -> str:
    return sonar_issue['component'].split(':')[1]


def extract_full_path_from_issue(sonar_issue: dict) -> str:
    return sonar_issue['full_path']


def find_all_issues_introduced_by_merge_request(all_issues: list, changes: list) -> list:
    code_ranges = find_changed_code_ranges(changes)
    file_paths = extract_diff_file_paths(changes)
    print('file paths = ' + str(file_paths))
    issues_per_files = []
    for path in file_paths:
        issues_per_file = list(filter(lambda issue: extract_path_from_issue(issue) in path, all_issues))
        print(f"Found {len(issues_per_file)} in file {path}")
        for i in issues_per_file:
            i['full_path'] = path
        if issues_per_file:
            issues_per_files.extend(issues_per_file)
    relevant_issues = [i for i in issues_per_files if
                       is_number_in_ranges(i['line'], code_ranges[extract_full_path_from_issue(i)])]
    print(f"After filtering, the number of errors is {len(relevant_issues)}")
    return relevant_issues


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sonarqube_gitlab_bridge.py <merge_request_id> <sonar_project_key>")
        sys.exit(1)
    merge_request_id = sys.argv[1]
    sonar_project_key = sys.argv[2]
    mr = get_glcm_mr_by_id(merge_request_id)
    if not mr:
        print(f"Cannot find merge request with ID: {merge_request_id}")
        sys.exit(1)

    mr_changes = extract_changes(mr)
    sonar_issues = get_sonar_issues_by_mr_id(merge_request_id, sonar_project_key)
    mr_issues = find_all_issues_introduced_by_merge_request(sonar_issues, mr_changes)
    # TODO: Ignore rules from SonarQube UI (per project)
    final_issues = [i for i in mr_issues if i['rule'] not in IGNORE_RULES]
    update_mr(mr, final_issues)
