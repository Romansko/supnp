#!/usr/bin/env python3
#
# https://gist.github.com/magnetikonline/2242eb18bf8890e9fc72b3c3ef41bd93
# Usage:
# export GITHUB_TOKEN="GITHUB_PERSONAL_ACCESS_TOKEN"
# ./rm_workflow.py --repository-name <repo_name> --workflow-id <build/fuzz/lint/codeql>
#

import argparse
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Generator

API_BASE_URL = "https://api.github.com"
REQUEST_ACCEPT = "application/vnd.github+json"
REQUEST_USER_AGENT = "magnetikonline/remove-workflow-run"

WORKFLOW_RUN_LIST_PAGE_MAX = 10
WORKFLOW_RUN_LIST_PAGE_SIZE = 100

# Repo name
REPO_NAME = "romansko/supnp"

# Workflow Mapping
MAPPING = {
    "build": "ccpp.yml",
    "fuzz": "cifuzz.yml",
    "lint": "clang-format.yml",
    "codeql": "codeql-analysis.yml"
}

def mapping(workflow_name: str) -> str:
    if workflow_name not in MAPPING.keys():
        return workflow_name
    return MAPPING[workflow_name]

def github_request(
    auth_token: str,
    path: str,
    method: str | None = None,
    parameter_collection: dict[str, str] | None = None,
    parse_response=True,
) -> dict[str, Any]:
    # build base request URL/headers
    request_url = f"{API_BASE_URL}/{path}"
    header_collection = {
        "Accept": REQUEST_ACCEPT,
        "Authorization": f"token {auth_token}",
        "User-Agent": REQUEST_USER_AGENT,
    }

    if method is None:
        # GET method
        if parameter_collection is not None:
            request_url = (
                f"{request_url}?{urllib.parse.urlencode(parameter_collection)}"
            )

        request = urllib.request.Request(headers=header_collection, url=request_url)
    else:
        # POST/PATCH/PUT/DELETE method
        request = urllib.request.Request(
            headers=header_collection, method=method, url=request_url
        )

    response = urllib.request.urlopen(request)
    response_data = {}
    if parse_response:
        response_data = json.load(response)

    response.close()
    return response_data


def workflow_run_list(
    auth_token: str, owner_repo_name: str, workflow_id: str
) -> Generator[str, None, None]:
    # note: return at most (WORKFLOW_RUN_LIST_PAGE_MAX * WORKFLOW_RUN_LIST_PAGE_SIZE) results
    request_page = 1
    while request_page <= WORKFLOW_RUN_LIST_PAGE_MAX:
        data = github_request(
            auth_token,
            f"repos/{owner_repo_name}/actions/workflows/{urllib.parse.quote(workflow_id)}/runs",
            parameter_collection={
                "page": str(request_page),
                "per_page": str(WORKFLOW_RUN_LIST_PAGE_SIZE),
            },
        )

        run_list = data["workflow_runs"]
        if len(run_list) < 1:
            # no more items
            break

        for item in run_list:
            yield item["id"]

        # move to next page
        request_page += 1


def workflow_run_delete(auth_token: str, owner_repo_name: str, run_id: str):
    github_request(
        auth_token,
        f"repos/{owner_repo_name}/actions/runs/{run_id}",
        method="DELETE",
        parse_response=False,
    )


def main():
    # fetch requested repository and workflow ID to remove prior runs from
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-name", default=REPO_NAME, required=False)
    parser.add_argument("--workflow-id", required=True)
    arg_list = parser.parse_args()

    # fetch GitHub access token
    auth_token = os.environ["GITHUB_TOKEN"]

    while True:
        # fetch run id list chunk from repository workflow
        run_id_list = list(
            workflow_run_list(
                auth_token, arg_list.repository_name, mapping(arg_list.workflow_id)
            )
        )

        if not run_id_list:
            # no further workflow runs
            break

        for run_id in run_id_list:
            print(f"Deleting run ID: {run_id}")
            workflow_run_delete(auth_token, arg_list.repository_name, run_id)


if __name__ == "__main__":
    main()
