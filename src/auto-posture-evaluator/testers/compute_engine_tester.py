import time
from typing import Dict, List

import interfaces
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.credentials = GoogleCredentials.get_application_default()
        self.cloudresourcemanager_client = discovery.build('cloudresourcemanager', 'v1',
                                                           credentials=self.credentials)
        self.compute_engine_client = discovery.build('compute', 'v1', credentials=self.credentials)
        self.all_projects = self._get_all_project_details()
        self.compute_engine = self._get_all_vm_instances()

    def declare_tested_service(self) -> str:
        return 'compute_engine'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        return self.detect_gcp_vm_instance_virtual_machine_with_full_access_scope() + \
               self.detect_gcp_vm_instance_virtual_machine_uses_the_project_wide_ssh_keys() + \
               self.detect_gcp_vm_instance_virtual_machine_connection_through_serial_ports_enabled() + \
               self.detect_gcp_vm_instance_virtual_machine_using_the_default_compute_engine_service_account_with_full_access_to_cloud_apis_scope() + \
               self.detect_gcp_vm_instance_virtual_machine_using_the_default_compute_engine_service_account() + \
               self.detect_gcp_shielded_vm_security_feature() + \
               self.detect_gcp_vm_instance_virtual_machine_has_public_ip_address() + \
               self.detect_gcp_shielded_vm_security_feature_fully_enabled()

    def _append_gcp_compute_engine_test_result(self, vm_instance, test_name, issue_status) -> dict:
        return {
            # "user": self.user_id,
            # "account_arn": self.account_arn,
            # "account": self.account_id,
            "timestamp": time.time(),
            "item": vm_instance['name'],
            "item_type": "compute_engine",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _get_all_project_details(self) -> List[Dict]:
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

    def _get_all_vm_instances(self) -> List[Dict]:
        vm_instances = []
        for project_dict in self.all_projects:
            request = self.compute_engine_client.instances().aggregatedList(project=project_dict['project_id'])
            while request is not None:
                response = request.execute()
                for name, instances_scoped_list in response['items'].items():
                    if 'warning' not in instances_scoped_list:
                        vm_instances.extend(instances_scoped_list['instances'])
                request = self.compute_engine_client.instances().aggregatedList_next(previous_request=request,
                                                                                     previous_response=response)
        return vm_instances

    def _find_vulnerability_based_on_metadata_items(self, test_name, default_issue_status, key_name, value) -> List[
        Dict]:
        metadata_item_result = []
        for vm_instance_dict in self.compute_engine:
            issue_found = default_issue_status
            if 'items' in vm_instance_dict['metadata']:
                metadata_items_li = vm_instance_dict['metadata']['items']
                for item_dict in metadata_items_li:
                    if item_dict['key'] == key_name:
                        issue_found = False if item_dict['value'] == value else True
                        break
            if issue_found:
                metadata_item_result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))
            else:
                metadata_item_result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))

        return metadata_item_result

    def detect_gcp_vm_instance_virtual_machine_with_full_access_scope(self):
        """This functions checks whether the VM has full access to cloud apis or not."""
        result = []
        scope = 'https://www.googleapis.com/auth/cloud-platform'
        test_name = 'gcp_compute_engine_vm_instance_virtual_machine_with_full_access_scope'
        for vm_instance_dict in self.compute_engine:
            service_account_li = vm_instance_dict['serviceAccounts']
            issue_found = False
            for service_account_dict in service_account_li:
                if scope in service_account_dict['scopes']:
                    issue_found = True
                    break
            if issue_found:
                result.append(self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))
            else:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))

        return result

    def detect_gcp_vm_instance_virtual_machine_uses_the_project_wide_ssh_keys(self):
        test_name = 'gcp_vm_instance_virtual_machine_uses_the_project_wide_ssh_keys'
        default_issue_status = True
        key_name = 'block-project-ssh-keys'
        value = 'true'
        return self._find_vulnerability_based_on_metadata_items(test_name, default_issue_status, key_name, value)

    def detect_gcp_vm_instance_virtual_machine_connection_through_serial_ports_enabled(self):
        test_name = 'gcp_vm_instance_virtual_machine_connection_through_serial_ports_enabled'
        default_issue_status = False
        key_name = 'serial-port-enable'
        value = 'false'
        return self._find_vulnerability_based_on_metadata_items(test_name, default_issue_status, key_name, value)

    def detect_gcp_vm_instance_virtual_machine_using_the_default_compute_engine_service_account_with_full_access_to_cloud_apis_scope(
            self):
        """This functions checks whether the VM has DEFAULT SERVICE ACCOUNT or not.
         If it has DEFAULT SERVICE ACCOUNT then, It will check whether the scope has full access to cloud apis or not."""
        result = []
        scope = 'https://www.googleapis.com/auth/cloud-platform'
        test_name = 'gcp_compute_engine_vm_instance_virtual_machine_using_the_default_compute_engine_service_account_with_full_access_to_cloud_apis_scope'
        for vm_instance_dict in self.compute_engine:
            service_account_li = vm_instance_dict['serviceAccounts']
            issue_found = False
            for service_account_dict in service_account_li:
                '''This if checks whether the service account is default or not.'''
                if service_account_dict["email"].split('-')[0].isdecimal():
                    if scope in service_account_dict['scopes']:
                        issue_found = True
                        break
            if issue_found:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))
            else:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))

        return result

    def detect_gcp_vm_instance_virtual_machine_using_the_default_compute_engine_service_account(self):
        """This functions checks whether the VM has DEFAULT SERVICE ACCOUNT or not."""
        result = []
        test_name = 'gcp_compute_engine_vm_instance_virtual_machine_using_the_default_compute_engine_service_account'
        for vm_instance_dict in self.compute_engine:
            service_account_li = vm_instance_dict['serviceAccounts']
            issue_found = False
            for service_account_dict in service_account_li:
                '''This if checks whether the service account is default or not.'''
                if service_account_dict["email"].split('-')[0].isdecimal():
                    issue_found = True
            if issue_found:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))
            else:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))

        return result

    def detect_gcp_shielded_vm_security_feature(self):
        result = []
        test_name = 'gcp_compute_engine_vm_instance_are_launched_with_shielded_vm_enabled'
        for vm_instance_dict in self.compute_engine:
            if vm_instance_dict['shieldedInstanceConfig']['enableVtpm'] and vm_instance_dict['shieldedInstanceConfig'][
                'enableIntegrityMonitoring']:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))
            else:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))

        return result

    def detect_gcp_vm_instance_virtual_machine_has_public_ip_address(self):
        result = []
        test_name = 'gcp_compute_engine_vm_instance_virtual_machine_has_public_ip_address'
        for vm_instance_dict in self.compute_engine:
            network_interfaces_li = vm_instance_dict['networkInterfaces']
            issue_found = False
            for network_interfaces_dict in network_interfaces_li:
                if 'accessConfigs' in network_interfaces_dict and network_interfaces_dict['accessConfigs']:
                    access_configs_li = network_interfaces_dict['accessConfigs']
                    for access_configs_dict in access_configs_li:
                        if access_configs_dict['name'].lower() == 'external nat':
                            issue_found = True
                            break
                    if issue_found:
                        break
            if issue_found:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))
            else:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))

        return result

    def detect_gcp_shielded_vm_security_feature_fully_enabled(self):
        result = []
        test_name = 'gcp_compute_engine_vm_instance_shielded_vm_is_fully_enabled'
        for vm_instance_dict in self.compute_engine:
            if vm_instance_dict['shieldedInstanceConfig']['enableVtpm'] and vm_instance_dict['shieldedInstanceConfig'][
                'enableIntegrityMonitoring'] and vm_instance_dict['shieldedInstanceConfig']['enableSecureBoot']:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'no_issue_found'))
            else:
                result.append(
                    self._append_gcp_compute_engine_test_result(vm_instance_dict, test_name, 'issue_found'))

        return result

