import time
from concurrent.futures import ThreadPoolExecutor

import interfaces
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


def get_all_regions():
    return ["asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1",
            "asia-southeast1", "asia-southeast2", "australia-southeast1", "europe-central2", "europe-west1",
            "europe-west2", "europe-west3", "europe-west6", "northamerica-northeast1", "southamerica-east1",
            "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
            "northamerica-northeast2", "southamerica-west1", "us-east5", "us-south1", "europe-west4",
            "europe-north1",
            "europe-west8", "europe-southwest1", "europe-west9", "asia-south2", "australia-southeast2"]


class Tester(interfaces.TesterInterface):
    def __init__(self, region_name):
        self.credentials = GoogleCredentials.get_application_default()
        self.cloudresourcemanager_client = discovery.build('cloudresourcemanager', 'v1',
                                                           credentials=self.credentials)
        self.account_arn = self.credentials.service_account_email
        self.account_id = None
        self.container_client = discovery.build('container', 'v1', credentials=self.credentials)
        self.compute = discovery.build('compute', 'v1', credentials=self.credentials)
        self.region_name = region_name
        self.projects = None
        self.region_with_zone = None
        self.containers = []

    def declare_tested_service(self) -> str:
        return 'gke'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        if self.region_name == 'global' or self.region_name not in get_all_regions():
            return None

        self.projects = self._get_all_project_details()
        self.region_with_zone = self._find_region(self.region_name)
        self.containers = self._get_all_conatiners()
        self.account_id = self.projects[0]['project_id']
        if not self.containers:
            return []
        return_values = []
        with ThreadPoolExecutor() as executor:
            executor_list = [executor.submit(self.detect_gcp_gke_integrity_monitoring_disabled),
                             executor.submit(self.detect_gcp_gke_auto_upgrade_disabled),
                             executor.submit(self.detect_gcp_gke_network_policy_disable),
                             executor.submit(self.detect_gcp_gke_container_optimized_os_unused),
                             executor.submit(self.detect_gcp_gke_shielded_nodes_disabled),
                             executor.submit(self.detect_gcp_gke_legacy_authorization_enabled),
                             executor.submit(self.detect_gcp_gke_workload_identity_disabled),
                             executor.submit(self.detect_gcp_gke_auto_repair_disabled),
                             executor.submit(self.detect_gcp_gke_system_logging_disabled),
                             executor.submit(self.detect_gcp_gke_system_monitoring_disabled),
                             executor.submit(self.detect_gcp_gke_client_certificate_authentication_enabled),
                             executor.submit(self.detect_gcp_gke_vpc_native_traffic_disabled),
                             executor.submit(self.detect_gcp_gke_secure_boot_disabled)]
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

    def _append_gcp_gke_test_result(self, gke, test_name, issue_status):
        return {
            "user": self.account_arn,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": gke,
            "item_type": "gke",
            "test_name": test_name,
            "test_result": issue_status,
            "region": self.region_name
        }

    def _find_region(self, region_name):
        for project_detail in self.projects:
            request = self.compute.regions().get(project=project_detail['project_id'], region=self.region_name)
            region = request.execute()
            return {"region_name": region_name, "zone": [z.split('/')[-1] for z in region['zones']]}
        return {"region_name": region_name, "zone": []}

    def _get_all_conatiners(self):
        clusters = []
        for project_detail in self.projects:
            request = self.container_client.projects().zones().clusters().list(
                projectId=project_detail['project_id'], zone='-')
            response = request.execute()
            if 'clusters' not in response or not response['clusters']:
                return []
            for cluster in response['clusters']:
                if cluster['location'] == self.region_name or cluster['location'] in self.region_with_zone['zone']:
                    clusters.append(cluster)
        return clusters

    def detect_gcp_gke_integrity_monitoring_disabled(self):
        test_name = 'gcp_gke_integrity_monitoring_disabled'
        node_pool = []
        for i, container in self.containers:
            for node in container['nodePools']:
                config = node['config']
                if 'shieldedInstanceConfig' in config and 'enableIntegrityMonitoring' in config[
                    'shieldedInstanceConfig'] and config['shieldedInstanceConfig']['enableIntegrityMonitoring']:
                    node_pool.append(
                        self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'], test_name,
                                                         "no_issue_found"))

                else:
                    node_pool.append(
                        self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'], test_name,
                                                         "issue_found"))
        return node_pool

    def detect_gcp_gke_auto_upgrade_disabled(self):
        test_name = 'gcp_gke_integrity_monitoring_disabled'
        node_pool_auto_upgrade = []
        for container in self.containers:
            for node in container['nodePools']:
                management = node['management']
                if 'autoUpgrade' in management and management['autoUpgrade']:
                    node_pool_auto_upgrade.append(
                        self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'], test_name,
                                                         "issue_found"))
                else:
                    node_pool_auto_upgrade.append(
                        self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'], test_name,
                                                         "no_issue_found"))

        return node_pool_auto_upgrade

    def detect_gcp_gke_network_policy_disable(self):
        test_name = 'gcp_gke_integrity_monitoring_disabled'
        network_policy_res = []
        for container in self.containers:
            addons_config = container['addonsConfig']
            if 'networkPolicyConfig' in addons_config and 'disabled' in addons_config['networkPolicyConfig'] and not \
                    addons_config['networkPolicyConfig']['disabled']:
                network_policy_res.append(
                    self._append_gcp_gke_test_result(container['name'], test_name, "no_issue_found"))
            else:
                network_policy_res.append(
                    self._append_gcp_gke_test_result(container['name'], test_name, "issue_found"))
        return network_policy_res

    def detect_gcp_gke_container_optimized_os_unused(self):
        test_name = 'gcp_gke_integrity_monitoring_disabled'
        container_optimized_os_res = []
        container_optimized_os = ['COS_CONTAINERD', 'UBUNTU_CONTAINERD']
        for container in self.containers:
            for node in container['nodePools']:
                if node['config']['imageType'].upper() in container_optimized_os:
                    container_optimized_os_res.append(
                        self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'], test_name,
                                                         "no_issue_found"))
                else:
                    container_optimized_os_res.append(
                        self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'], test_name,
                                                         "issue_found"))
        return container_optimized_os_res

    def detect_gcp_gke_legacy_authorization_enabled(self):
        check = lambda container: 'legacyAbac' in container and 'enabled' in container['legacyAbac'] and \
                                  container['legacyAbac']['enabled'] and 'no_issue_found' or 'issue_found'
        return [self._append_gcp_gke_test_result(container['name'], 'gcp_gke_legacy_authorization_enabled',
                                                 check(container)) for container in self.containers]

    def detect_gcp_gke_workload_identity_disabled(self):
        find_issue = lambda container_dict: 'workloadIdentityConfig' in container_dict and 'workloadPool' in \
                                            container_dict['workloadIdentityConfig'] and \
                                            container_dict['workloadIdentityConfig'][
                                                'workloadPool'] and 'no_issue_found' or 'issue_found'
        return [self._append_gcp_gke_test_result(container['name'], 'gcp_gke_workload_identity_disabled',
                                                 find_issue(container)) for container in self.containers]

    def detect_gcp_gke_shielded_nodes_disabled(self):
        return [self._append_gcp_gke_test_result(container['name'], 'gcp_gke_shielded_nodes_disabled',
                                                 'shieldedNodes' in container and container[
                                                     'shieldedNodes'] and 'no_issue_found' or 'issue_found') for
                container in self.containers]

    def detect_gcp_gke_application_layer_secrets_encryption_disabled(self):
        encryption_check = lambda container_dict: 'databaseEncryption' in container_dict and 'keyName' in \
                                                  container_dict['databaseEncryption'] and \
                                                  container_dict['databaseEncryption'][
                                                      'keyName'] and 'no_issue_found' or 'issue_found'
        return [
            self._append_gcp_gke_test_result(container['name'], 'gcp_gke_application_layer_secrets_encryption_disabled',
                                             encryption_check(container)) for container in self.containers]

    def detect_gcp_gke_auto_repair_disabled(self):
        auto_repair = lambda container_dict: 'autoRepair' in container_dict and container_dict[
            'autoRepair'] and 'no_issue_found' or 'issue_found'
        test_name = 'gcp_gke_auto_repair_disabled'
        auto_repair_result_li = []
        for container in self.containers:
            auto_repair_result_li.extend([self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'],
                                                                           test_name, auto_repair(node['management']))
                                          for node in container['nodePools']])
        return auto_repair_result_li

    def detect_gcp_gke_secure_boot_disabled(self):
        secure_boot = lambda container_dict: 'shieldedInstanceConfig' in container_dict and 'enableSecureBoot' in \
                                             container_dict['shieldedInstanceConfig'] and \
                                             container_dict['shieldedInstanceConfig'][
                                                 'enableSecureBoot'] and 'no_issue_found' or 'issue_found'
        test_name = 'gcp_gke_secure_boot_disabled'
        secure_boot_result_li = []
        for container in self.containers:
            secure_boot_result_li.extend([self._append_gcp_gke_test_result(container['name'] + '@@' + node['name'],
                                                                           test_name, secure_boot(node['config'])) for
                                          node in container['nodePools']])
        return secure_boot_result_li

    def detect_gcp_gke_system_logging_disabled(self):
        test_name = 'gcp_gke_system_logging_disabled'
        logging_res = []
        for container in self.containers:
            logging_config = container['loggingConfig']
            if 'componentConfig' in logging_config and logging_config['componentConfig'] and \
                    'enableComponents' in logging_config['componentConfig'] and logging_config['componentConfig'][
                'enableComponents']:
                logging_res.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                    "no_issue_found"))
            else:
                logging_res.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                    "issue_found"))

        return logging_res

    def detect_gcp_gke_system_monitoring_disabled(self):
        test_name = 'gcp_gke_system_monitoring_disabled'
        monitoring_config_res_li = []
        for container in self.containers:
            monitoring_config = container['monitoringConfig']
            if 'componentConfig' in monitoring_config and monitoring_config['componentConfig'] and \
                    'enableComponents' in monitoring_config['componentConfig'] and monitoring_config['componentConfig'][
                'enableComponents']:
                monitoring_config_res_li.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                                 "no_issue_found"))
            else:
                monitoring_config_res_li.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                                 "issue_found"))

        return monitoring_config_res_li

    def detect_gcp_gke_client_certificate_authentication_enabled(self):
        client_certificate = []
        test_name = 'gcp_gke_client_certificate_authentication_enabled'
        for container in self.containers:
            master_auth = container['masterAuth']
            if 'clientCertificate' in master_auth and master_auth['clientCertificate']:
                client_certificate.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                           "issue_found"))
            else:
                client_certificate.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                           "no_issue_found"))

        return client_certificate

    def detect_gcp_gke_vpc_native_traffic_disabled(self):
        vpc_native_res_li = []
        test_name = 'gcp_gke_vpc_native_traffic_disabled'
        for container in self.containers:
            is_vpc_native = any(bool(
                'networkConfig' in node and node['networkConfig'] and 'podRange' in node['networkConfig'] and
                node['networkConfig']['podRange'] and 'podIpv4CidrBlock' in node['networkConfig'] and
                node['networkConfig']['podIpv4CidrBlock']) for node in container['nodePools'])
            if is_vpc_native:
                vpc_native_res_li.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                          "no_issue_found"))
            else:
                vpc_native_res_li.append(self._append_gcp_gke_test_result(container['name'], test_name,
                                                                          "issue_found"))

        return vpc_native_res_li

