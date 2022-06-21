import concurrent.futures
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import interfaces
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


class Tester(interfaces.TesterInterface):
    def __init__(self) -> None:
        self.credentials = GoogleCredentials.get_application_default()
        # self.account_arn = self.credentials.service_account_email
        self.cloudresourcemanager_client = discovery.build('cloudresourcemanager', 'v1',
                                                           credentials=self.credentials)
        self.iam_client = discovery.build("iam", "v1", credentials=self.credentials)
        self.all_projects, self.project_id_li = self._get_all_project_details()
        self.api_key_li = self._get_all_api_keys(self.all_projects)
        self.iam_policy = self._get_iam_policy_in_projects()

    def declare_tested_service(self) -> str:
        return 'iam'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        executor_list = []
        return_value = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor_list.append(executor.submit(
                self.detect_gcp_iam_user_assigned_service_account_user_or_service_account_token_creator_roles_at_project_level))
            executor_list.append(executor.submit(
                self.detect_gcp_iam_user_managed_and_external_keys_for_service_accounts_are_rotated_every_90_days_or_less))
            executor_list.append(executor.submit(self.detect_user_managed_service_accounts_not_have_user_managed_keys))
            executor_list.append(executor.submit(self.detect_gcp_iam_service_account_with_admin_privileges))
            executor_list.append(executor.submit(self.detect_gcp_iam_default_service_account_is_used_at_project_level))

            for future in executor_list:
                return_value += future.result()
        return return_value

    def _append_gcp_iam_test_result(self, iam_user, test_name, issue_status):
        return {
            # "user": self.user_id,
            # "account_arn": self.account_arn,
            # "account": self.account_id,
            "timestamp": time.time(),
            "item": iam_user,
            "item_type": "iam",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _get_all_project_details(self) -> Tuple:
        request = self.cloudresourcemanager_client.projects().list()
        project_detail_list = []
        project_id_li = []
        while request is not None:
            response = request.execute()
            for project in response.get('projects', []):
                project_detail_dict = {
                    'project_id': project['projectId'],
                    'project_name': project['name'],
                    'project_number': project['projectNumber']
                }
                project_id_li.append(project['projectId'])
                project_detail_list.append(project_detail_dict)
            request = self.cloudresourcemanager_client.projects().list_next(previous_request=request,
                                                                            previous_response=response)
        return project_detail_list, project_id_li

    def _get_iam_policy_in_projects(self) -> List[Dict]:
        policy_result = []
        for project_detail_dict in self.all_projects:
            response = self.cloudresourcemanager_client.projects().getIamPolicy(
                resource=project_detail_dict['project_id'],
                body={}).execute()

            if 'bindings' in response and response['bindings']:
                policy_result.extend(response['bindings'])

        return policy_result

    def _get_all_api_keys(self, all_projects) -> List[Dict]:
        api_keys = []
        for project in all_projects:
            project_id = project["project_id"]
            name = "projects/{project_id}".format(project_id=project_id)
            sa_list_rqst = self.iam_client.projects().serviceAccounts().list(name=name)
            while sa_list_rqst is not None:
                sa_list_resp = sa_list_rqst.execute()
                accounts = sa_list_resp.get("accounts", [])
                for account in accounts:
                    name = account["name"]
                    keys_list_rqst = self.iam_client.projects().serviceAccounts().keys().list(
                        name=name)
                    keys_list_resp = keys_list_rqst.execute()
                    api_keys.extend(keys_list_resp.get("keys", []))
                sa_list_rqst = self.iam_client.projects().serviceAccounts().list_next(previous_request=sa_list_rqst,
                                                                                      previous_response=sa_list_resp)

        return api_keys

    def detect_gcp_iam_default_service_account_is_used_at_project_level(self):
        result = []
        test_name = 'gcp_iam_default_service_account_is_used_at_project_level'
        compute_account = 'compute@developer.gserviceaccount.com'
        app_engine_account = 'appspot.gserviceaccount.com'
        service_account_with_issue = set()
        service_account_with_no_issue = set()
        for policy in self.iam_policy:
            for member in policy['members']:
                if bool(re.search(compute_account, member)):
                    account = member.split(':')
                    if account[-1].split('-')[0].isdecimal():
                        service_account_with_issue.add(member)
                    else:
                        service_account_with_no_issue.add(member)
                elif bool(re.search(app_engine_account, member)):
                    account = member.split(':')
                    if account[-1].split('@')[0] in self.project_id_li:
                        service_account_with_issue.add(member)
                    else:
                        service_account_with_no_issue.add(member)
                else:
                    service_account_with_no_issue.add(member)
        for service_account in service_account_with_issue:
            result.append(self._append_gcp_iam_test_result(service_account, test_name, 'issue_found'))
        for service_account in list(service_account_with_no_issue - service_account_with_issue):
            result.append(self._append_gcp_iam_test_result(service_account, test_name, 'no_issue_found'))

        return result

    def detect_gcp_iam_user_assigned_service_account_user_or_service_account_token_creator_roles_at_project_level(self):
        result = []
        roles_to_check = ['roles/iam.serviceAccountTokenCreator', 'oles/firestore.serviceAgent']
        user_with_issue = []
        user_with_no_issue = []
        test_name = 'gcp_iam_user_assigned_service_account_user_or_service_account_token_creator_roles_at_project_level'
        for bindings in self.iam_policy:
            if bindings['role'] in roles_to_check:
                user_with_issue.extend(bindings['members'])
            else:
                user_with_no_issue.extend(bindings['members'])
        user_with_issue = set(user_with_issue)
        for user in user_with_issue:
            result.append(self._append_gcp_iam_test_result(user, test_name, 'issue_found'))
        for user in list(set(user_with_no_issue) - user_with_issue):
            result.append(self._append_gcp_iam_test_result(user, test_name, 'no_issue_found'))
        return result

    def detect_gcp_iam_user_managed_and_external_keys_for_service_accounts_are_rotated_every_90_days_or_less(self):
        result = []
        test_name = 'gcp_iam_user_managed_and_external_keys_for_service_accounts_are_rotated_every_90_days_or_less'
        rotation_day_limit = 90
        for api_key_dict in self.api_key_li:
            day = (datetime.now(timezone.utc) - datetime.fromisoformat(
                api_key_dict['validAfterTime'][0:-1] + '+00:00')).days
            if day >= rotation_day_limit:
                result.append(self._append_gcp_iam_test_result(api_key_dict['name'], test_name, 'issue_found'))
            else:
                result.append(self._append_gcp_iam_test_result(api_key_dict['name'], test_name, 'no_issue_found'))
        return result

    def detect_user_managed_service_accounts_not_have_user_managed_keys(self):
        result = []
        test_name = 'gcp_iam_gcp_managed_service_account_keys_for_each_service_account'
        key_type = 'USER_MANAGED'
        for api_key_dict in self.api_key_li:
            if api_key_dict['keyType'].upper() == key_type:
                result.append(self._append_gcp_iam_test_result(api_key_dict['name'], test_name, 'issue_found'))
            else:
                result.append(self._append_gcp_iam_test_result(api_key_dict['name'], test_name, 'no_issue_found'))
        return result

    def detect_gcp_iam_service_account_with_admin_privileges(self):
        result = []
        admin_privileges = ['roles/actions.Admin', 'roles/editor', 'roles/owner']
        account_with_issue = []
        account_without_issue = []
        test_name = 'gcp_iam_service_account_with_admin_privileges'
        for policy in self.iam_policy:
            if policy['role'] in admin_privileges:
                for member in policy['members']:
                    if member.startswith('serviceAccount'):
                        account_with_issue.append(member)
                    else:
                        account_without_issue.append(member)
            else:
                account_without_issue.extend(policy['members'])
        account_with_issue = set(account_with_issue)
        for account in account_with_issue:
            result.append(self._append_gcp_iam_test_result(account, test_name, 'issue_found'))
        for account in list(set(account_without_issue) - account_with_issue):
            result.append(self._append_gcp_iam_test_result(account, test_name, 'no_issue_found'))

        return result

