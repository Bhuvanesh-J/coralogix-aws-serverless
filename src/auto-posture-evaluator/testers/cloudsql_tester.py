import time

import interfaces
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.cloudresourcemanager_client = discovery.build('cloudresourcemanager', 'v1',
                                                           credentials=GoogleCredentials.get_application_default())
        self.cloud_sql_client = discovery.build('sqladmin', 'v1beta4')
        self.projects = self._get_all_project_details()
        self.cloud_sql_instances = self._get_all_cloud_sql()

    def declare_tested_service(self) -> str:
        return 'cloudsql'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:

        return self.detect_gcp_cloud_sql_instance_automated_backups_disabled() + \
               self.detect_gcp_cloud_sql_instance_log_checkpoints_database_flag_for_cloudsql_postgresql_instance_is_set_to_on() + \
               self.detect_gcp_cloud_sql_instance_log_lock_waits_database_flag_for_cloudsql_postgresql_instance_is_set_to_on() + \
               self.detect_gcp_cloud_sql_instance_log_min_error_statement_database_flag_for_cloudsql_postgresql_instance_is_set_to_error() + \
               self.detect_gcp_cloud_sql_instance_local_infile_database_flag_for_cloudsql_mysql_instance_is_set_to_off() + \
               self.detect_gcp_cloud_sql_instance_cross_db_ownership_chaining_database_flag_for_cloudsql_sql_server_instance_is_set_to_off() + \
               self.detect_gcp_cloud_sql_instance_transport_encryption_disabled()

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
                #
                resource = project['projectId']
                response = self.cloudresourcemanager_client.projects().getIamPolicy(resource=resource,
                                                                                    body={}).execute()
            request = self.cloudresourcemanager_client.projects().list_next(previous_request=request,
                                                                            previous_response=response)
        return project_detail_list

    def _get_all_cloud_sql(self):
        sql_instances = []
        for project_dict in self.projects:
            request = self.cloud_sql_client.instances().list(project=project_dict['project_id'])
            while request is not None:
                response = request.execute()
                if 'items' in response and response['items']:
                    for database_instance in response['items']:
                        sql_instances.append(database_instance)
                request = self.cloud_sql_client.instances().list_next(previous_request=request,
                                                                      previous_response=response)
        return sql_instances

    def _append_gcp_cloudsql_test_result(self, cloudsql, test_name, issue_status):
        return {
            # "user": self.user_id,
            # "account_arn": self.account_arn,
            # "account": self.account_id,
            "timestamp": time.time(),
            "item": cloudsql,
            "item_type": "cloudsql",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _find_vulnerability_based_on_db_flags(self, flag_name, flag_value, test_name, sql_instances_dict) -> list:
        flag_result = []
        issue_found = True
        if 'databaseFlags' in sql_instances_dict['settings'] and sql_instances_dict['settings']['databaseFlags']:
            database_flags = sql_instances_dict['settings']['databaseFlags']
            for database_flags_dict in database_flags:
                if database_flags_dict['name'].lower() == flag_name:
                    if database_flags_dict[
                        'value'].lower() == flag_value:
                        issue_found = False
                    break
        if issue_found:
            flag_result.append(
                self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'issue_found'))
        else:
            flag_result.append(
                self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'no_issue_found'))
        return flag_result

    def _find_vulnerability_based_on_db_flags_for_mysql_or_sql_server(self, flag_name, flag_value, test_name,
                                                                      sql_instances_dict) -> list:
        flag_result = []
        issue_found = False
        if 'databaseFlags' in sql_instances_dict['settings'] and sql_instances_dict['settings'][
            'databaseFlags']:
            database_flags = sql_instances_dict['settings']['databaseFlags']
            for database_flags_dict in database_flags:
                if database_flags_dict['name'].lower() == flag_name:
                    if not database_flags_dict['value'].lower() == flag_value:
                        issue_found = True
                    break
        if issue_found:
            flag_result.append(
                self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'issue_found'))
        else:
            flag_result.append(
                self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'no_issue_found'))
        return flag_result

    def detect_gcp_cloud_sql_instance_automated_backups_disabled(self):
        result = []
        test_name = 'gcp_cloud_sql_instance_automated_backups_disabled'
        for sql_instances_dict in self.cloud_sql_instances:
            if sql_instances_dict['settings']['backupConfiguration']['enabled']:
                result.append(
                    self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'no_issue_found'))
            else:
                result.append(
                    self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'issue_found'))

        return result

    def detect_gcp_cloud_sql_instance_log_lock_waits_database_flag_for_cloudsql_postgresql_instance_is_set_to_on(self):
        result = []
        test_name = 'gcp_cloud_sql_instance_log_lock_waits_database_flag_for_cloudsql_postgresql_instance_is_set_to_on'
        flag_name = 'log_lock_waits'
        flag_value = 'on'
        for sql_instances_dict in self.cloud_sql_instances:

            if sql_instances_dict['databaseVersion'][:8].upper() == 'POSTGRES':
                result.extend(
                    self._find_vulnerability_based_on_db_flags(flag_name, flag_value, test_name, sql_instances_dict))

        return result

    def detect_gcp_cloud_sql_instance_log_checkpoints_database_flag_for_cloudsql_postgresql_instance_is_set_to_on(self):
        result = []
        test_name = 'gcp_cloud_sql_instance_log_checkpoints_database_flag_for_cloudsql_postgresql_instance_is_set_to_on'
        flag_name = 'log_checkpoints'
        flag_value = 'on'
        for sql_instances_dict in self.cloud_sql_instances:
            if sql_instances_dict['databaseVersion'][:8].upper() == 'POSTGRES':
                result.extend(
                    self._find_vulnerability_based_on_db_flags(flag_name, flag_value, test_name, sql_instances_dict))

        return result

    def detect_gcp_cloud_sql_instance_local_infile_database_flag_for_cloudsql_mysql_instance_is_set_to_off(self):
        result = []
        test_name = 'gcp_cloud_sql_instance_local_infile_database_flag_for_cloudsql_mysql_instance_is_set_to_off'
        flag_name = 'local_infile'
        flag_value = 'off'
        for sql_instances_dict in self.cloud_sql_instances:
            if sql_instances_dict['databaseVersion'][:5].upper() == 'MYSQL':
                result.extend(
                    self._find_vulnerability_based_on_db_flags_for_mysql_or_sql_server(flag_name, flag_value, test_name,
                                                                                       sql_instances_dict))
        return result

    def detect_gcp_cloud_sql_instance_cross_db_ownership_chaining_database_flag_for_cloudsql_sql_server_instance_is_set_to_off(
            self):
        result = []
        test_name = 'gcp_cloud_sql_instance_cross_db_ownership_chaining_database_flag_for_cloudsql_sql_server_instance_is_set_to_off'
        flag_name = 'cross db ownership chaining'
        flag_value = 'off'
        for sql_instances_dict in self.cloud_sql_instances:
            if sql_instances_dict['databaseVersion'][:9].upper() == 'SQLSERVER':
                result.extend(
                    self._find_vulnerability_based_on_db_flags_for_mysql_or_sql_server(flag_name, flag_value, test_name,
                                                                                       sql_instances_dict))

        return result

    def detect_gcp_cloud_sql_instance_log_min_error_statement_database_flag_for_cloudsql_postgresql_instance_is_set_to_error(
            self):
        result = []
        test_name = 'gcp_cloud_sql_instance_log_min_error_statement_database_flag_for_cloudsql_postgresql_instance_is_set_to_error'
        flag_name = 'log_min_error_statement'
        flag_value = 'error'
        for sql_instances_dict in self.cloud_sql_instances:
            if sql_instances_dict['databaseVersion'][:8].upper() == 'POSTGRES':
                result.extend(
                    self._find_vulnerability_based_on_db_flags(flag_name, flag_value, test_name, sql_instances_dict))

        return result

    def detect_gcp_cloud_sql_instance_transport_encryption_disabled(self):
        result = []
        test_name = 'gcp_cloud_sql_instance_transport_encryption_disabled'
        for sql_instances_dict in self.cloud_sql_instances:
            if 'requireSsl' in sql_instances_dict['settings']['ipConfiguration'] and \
                    sql_instances_dict['settings']['ipConfiguration']['requireSsl']:
                result.append(
                    self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'no_issue_found'))
            else:
                result.append(
                    self._append_gcp_cloudsql_test_result(sql_instances_dict['name'], test_name, 'issue_found'))
        return result

