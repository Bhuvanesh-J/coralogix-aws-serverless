import time
from concurrent.futures import ThreadPoolExecutor

import interfaces
from google.cloud import storage
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
        self.storage_client = storage.Client()
        self.projects = None
        self.buckets = list()
        self.region_name = region_name

    def declare_tested_service(self) -> str:
        return 'cloudstorage'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        if self.region_name == 'global' or self.region_name not in get_all_regions():
            return None
        self.projects = self._get_all_project_details()
        self.account_id = self.projects[0]['project_id']
        self.buckets = self._get_buck_based_on_region()
        if not self.buckets:
            return []
        bucket_with_acl_policy, bucket_with_iam_policy = self._find_access_control_policy_types()
        return_values = []
        with ThreadPoolExecutor() as executor:
            executor_list = [
                executor.submit(self.detect_gcp_bucket_uniform_bucket_level_access_on_cloud_storage_bucket_not_enabled,
                                bucket_with_acl_policy, bucket_with_iam_policy),
                executor.submit(self.detect_gcp_bucket_storage_is_anonymously_or_publicly_accessible_through_bucket_acl,
                                bucket_with_acl_policy),
                executor.submit(
                    self.detect_gcp_bucket_cloud_storage_is_anonymously_or_publicly_accessible_through_iam_policy,
                    bucket_with_iam_policy),
                executor.submit(self.detect_gcp_bucket_google_storage_bucket_not_encrypted_with_customer_key),
                executor.submit(self.detect_gcp_cloud_storage_bucket_versioning_should_be_enabled)
            ]
            for future in executor_list:
                return_values.extend(future.result())

        return return_values

    def _get_buck_based_on_region(self):
        bucket_li = []
        for buck_obj in list(self.storage_client.list_buckets()):
            if buck_obj.location.lower() == self.region_name:
                bucket_li.append(buck_obj)
        return bucket_li

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

    def _append_gcp_cloudstorage_test_result(self, bucket_name, test_name, issue_status):
        return {
            "user": self.account_arn,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": bucket_name,
            "item_type": "cloudstorage",
            "test_name": test_name,
            "test_result": issue_status,
            "region": self.region_name
        }

    def _find_access_control_policy_types(self):
        bucket_with_fine_grained_or_acl_policy = []
        bucket_with_uniform_or_iam_policy = []
        for bucket in self.buckets:
            buck_property = bucket._properties
            if buck_property['iamConfiguration']['uniformBucketLevelAccess']['enabled']:
                bucket_with_uniform_or_iam_policy.append(bucket)
            else:
                bucket_with_fine_grained_or_acl_policy.append(bucket)

        return bucket_with_fine_grained_or_acl_policy, bucket_with_uniform_or_iam_policy

    def _find_acl_or_iam_policies(self, buckets, test_name):
        policy_result = []
        for bucket in buckets:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            issue_found = False
            for binding in policy.bindings:
                if binding['role'] == 'roles/storage.objectViewer' and (
                        'allAuthenticatedUsers' in binding['members'] or 'allUsers' in binding['members']):
                    issue_found = True
                    break
            if issue_found:
                policy_result.append(self._append_gcp_cloudstorage_test_result(bucket.name, test_name, 'issue_found'))
            else:
                policy_result.append(
                    self._append_gcp_cloudstorage_test_result(bucket.name, test_name, 'no_issue_found'))
        return policy_result

    def detect_gcp_bucket_uniform_bucket_level_access_on_cloud_storage_bucket_not_enabled(self, bucket_with_acl_policy,
                                                                                          bucket_with_iam_policy):
        result = []
        test_name = 'gcp_cloudstorage_bucket_uniform_bucket_level_access_on_cloud_storage_bucket_not_enabled'
        for bucket in bucket_with_iam_policy:
            result.append(self._append_gcp_cloudstorage_test_result(bucket.name, test_name, 'no_issue_found'))
        for bucket in bucket_with_acl_policy:
            result.append(self._append_gcp_cloudstorage_test_result(bucket.name, test_name, 'issue_found'))

        return result

    def detect_gcp_bucket_storage_is_anonymously_or_publicly_accessible_through_bucket_acl(self,
                                                                                           bucket_with_acl_policy):
        result = []
        test_name = 'gcp_cloudstorage_is_anonymously_or_publicly_accessible_through_bucket_acl'
        result.extend(self._find_acl_or_iam_policies(bucket_with_acl_policy, test_name))
        return result

    def detect_gcp_bucket_cloud_storage_is_anonymously_or_publicly_accessible_through_iam_policy(self,
                                                                                                 bucket_with_iam_policy):
        result = []
        test_name = 'gcp_cloudstorage_bucket_is_anonymously_or_publicly_accessible_through_iam_policy'
        result.extend(self._find_acl_or_iam_policies(bucket_with_iam_policy, test_name))
        return result

    def detect_gcp_bucket_google_storage_bucket_not_encrypted_with_customer_key(self):
        result = []
        test_name = 'gcp_cloudstorage_bucket_not_encrypted_with_customer_key'
        for bucket in self.buckets:
            if bucket.default_kms_key_name:
                result.append(self._append_gcp_cloudstorage_test_result(bucket.name, test_name, 'no_issue_found'))
            else:
                result.append(self._append_gcp_cloudstorage_test_result(bucket.name, test_name, 'issue_found'))
        return result

    def detect_gcp_cloud_storage_bucket_versioning_should_be_enabled(self):
        test_name = 'gcp_cloud_storage_bucket_versioning_should_be_enabled'
        check_versioning = lambda status: "no_issue_found" if status else "issue_found"
        return [self._append_gcp_cloudstorage_test_result(
            bucket_obj.name,
            test_name,
            check_versioning(bucket_obj.versioning_enabled)) for bucket_obj in self.buckets]

