import time
import interfaces
from google.cloud import kms
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


def get_all_locations():
    return ["asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1",
            "asia-southeast1", "asia-southeast2", "australia-southeast1", "europe-central2", "europe-west1",
            "europe-west2", "europe-west3", "europe-west6", "northamerica-northeast1", "southamerica-east1",
            "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4", "global",
            "northamerica-northeast2", "southamerica-west1", "us-east5", "us-south1", "europe-west4", "europe-north1",
            "europe-west8", "europe-southwest1", "europe-west9", "asia-south2", "australia-southeast2"]


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.credentials = GoogleCredentials.get_application_default()
        self.cloudresourcemanager_client = discovery.build('cloudresourcemanager', 'v1',
                                                           credentials=self.credentials)

        self.all_projects = self._get_all_project_details()
        self.kms_client = kms.KeyManagementServiceClient()
        self.key_rings = self._get_kms_keyrings()

    def declare_tested_service(self) -> str:
        return 'gcp_kms'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        return self.detect_gcp_kms_cloud_cryptokeys_are_not_anonymously_or_publicly_accessible()

    def _append_gcp_kms_test_result(self, kms, test_name, issue_status):
        return {
            # "user": self.user_id,
            # "account_arn": self.account_arn,
            # "account": self.account_id,
            "timestamp": time.time(),
            "item": kms,
            "item_type": "kms",
            "test_name": test_name,
            "test_result": issue_status
        }

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

    def _get_kms_keyrings(self):
        kms_keyrings = []
        locations = get_all_locations()
        for project_details_dict in self.all_projects:
            project_id_api = 'projects/{project_id}/locations/'.format(project_id=project_details_dict['project_id'])
            for location_id in locations:
                location_name = project_id_api + location_id
                key_rings = self.kms_client.list_key_rings(request={'parent': location_name})
                for key_ring in key_rings:
                    key_ring_details = {
                        'key_ring_id': key_ring.name.split('/')[-1],
                        'location_id': location_id,
                        'project_id': project_details_dict['project_id']

                    }
                    kms_keyrings.append(key_ring_details)
        return kms_keyrings

    def _iam_get_policy_vulnerabilities(self, test_name, kms_detail):
        iam_result = []
        for kms_detail_dict in kms_detail:
            resource_name = self.kms_client.key_ring_path(kms_detail_dict['project_id'], kms_detail_dict['location_id'],
                                                          kms_detail_dict['key_ring_id'])

            policy = self.kms_client.get_iam_policy(request={'resource': resource_name})
            issue_found = False
            for binding in policy.bindings:
                for member in binding.members:
                    if member in ['allUsers', 'allAuthenticatedUsers']:
                        issue_found = True
                        break
                if issue_found:
                    break
            if issue_found:
                iam_result.append(
                    self._append_gcp_kms_test_result(kms_detail_dict['key_ring_id'], test_name, 'issue_found'))
            else:
                iam_result.append(
                    self._append_gcp_kms_test_result(kms_detail_dict['key_ring_id'], test_name, 'no_issue_found'))
        return iam_result

    def detect_gcp_kms_cloud_cryptokeys_are_not_anonymously_or_publicly_accessible(self):
        result = []
        test_name = 'gcp_kms_cloud_cryptokeys_are_not_anonymously_or_publicly_accessible'
        result.extend(self._iam_get_policy_vulnerabilities(test_name, self.key_rings))
        return result

