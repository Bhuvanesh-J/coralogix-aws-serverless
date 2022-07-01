import time
from concurrent.futures import ThreadPoolExecutor

import interfaces
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


class Tester(interfaces.TesterInterface):
    def __init__(self, region_name='global'):
        self.credentials = GoogleCredentials.get_application_default()
        self.cloudresourcemanager_client = discovery.build('cloudresourcemanager', 'v1',
                                                           credentials=self.credentials)
        self.account_arn = self.credentials.service_account_email
        self.account_id = None
        self.dns_client = discovery.build('dns', 'v1', credentials=self.credentials)
        self.region_name = region_name
        self.projects = None
        self.managed_zones = []

    def declare_tested_service(self) -> str:
        return 'dns'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        if self.region_name != 'global':
            return None

        self.projects = self._get_all_project_details()
        self.account_id = self.projects[0]['project_id']
        self.managed_zones = self._get_all_managed_zones()
        if not self.managed_zones:
            return []
        return_values = []
        with ThreadPoolExecutor() as executor:
            executor_list = [
                executor.submit(self.detect_gcp_dns_rsasha1_is_not_used_for_the_key_signing_key_in_cloud_dns_dnssec)]
            for future in executor_list:
                return_values.extend(future.result())

        return return_values

    def _get_all_project_details(self):
        request = self.cloudresourcemanager_client.projects().list()
        project_detail_list = []
        while request is not None:
            response = request.execute()
            for project in response.get('projects', []):
                project_detail_dict = {
                    'project_id': project['projectId'],
                    'project_name': project['name'],
                    'project_number': project['projectNumber']
                }
                project_detail_list.append(project_detail_dict)
            request = self.cloudresourcemanager_client.projects().list_next(previous_request=request,
                                                                            previous_response=response)
        return project_detail_list

    def _append_gcp_test_result(self, dns, test_name, issue_status):
        return {
            "user": self.account_arn,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": dns,
            "item_type": "dns",
            "test_name": test_name,
            "test_result": issue_status,
            "region": self.region_name
        }

    def _get_all_managed_zones(self):
        zones = []
        for project_detail in self.projects:
            request = self.dns_client.managedZones().list(project=project_detail['project_id'])
            while request is not None:
                response = request.execute()
                zones.extend(response['managedZones'])
                request = self.dns_client.managedZones().list_next(previous_request=request, previous_response=response)
        return zones

    def detect_gcp_dns_rsasha1_is_not_used_for_the_key_signing_key_in_cloud_dns_dnssec(self):
        check_key_signing = lambda managed_zone_dict: 'issue_found' if managed_zone_dict['visibility'] == 'public' and (
                'dnssecConfig' not in managed_zone_dict or not managed_zone_dict[
            'dnssecConfig']) else 'no_issue_found'
        return [self._append_gcp_test_result(managed_zone_dict['name'],
                                             'gcp_dns_rsasha1_is_not_used_for_the_key_signing_key_in_cloud_dns_dnssec',
                                             check_key_signing(managed_zone_dict)) for managed_zone_dict in
                self.managed_zones]

