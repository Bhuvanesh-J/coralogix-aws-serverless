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
        self.firewalls_li = self._get_all_firewalls()
        self.subnets_li = self._get_all_subnets()

    def declare_tested_service(self) -> str:
        return 'vpc'

    def declare_tested_provider(self) -> str:
        return 'gcp'

    def run_tests(self) -> list:
        ingress_firewall_li = self._return_ingress_firewall(self.firewalls_li)
        return self.detect_gcp_vpc_firewall_should_restrict_postgresql_access(ingress_firewall_li) + \
               self.detect_gcp_vpc_firewall_should_restrict_ftp_access(ingress_firewall_li) + \
               self.detect_gcp_vpc_firewall_should_restrict_access_over_uncommon_ports(ingress_firewall_li) + \
               self.detect_gcp_vpc_subnet_should_have_private_google_access_enabled()

    def _append_gcp_vpc_test_result(self, vpc, test_name, issue_status) -> dict:
        return {
            # "user": self.user_id,
            # "account_arn": self.account_arn,
            # "account": self.account_id,
            "timestamp": time.time(),
            "item": vpc,
            "item_type": "vpc",
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

    def _get_all_firewalls(self) -> List[Dict]:
        firewall_resp = []
        for project_detail_dict in self.all_projects:
            request = self.compute_engine_client.firewalls().list(project=project_detail_dict['project_id'])
            while request is not None:
                response = request.execute()
                firewall_resp.extend('items' in response and response['items'] or [])
                request = self.compute_engine_client.firewalls().list_next(previous_request=request,
                                                                           previous_response=response)
        return firewall_resp

    def _get_all_subnets(self) -> List[Dict]:
        subnet_result = []
        for project_detail_dict in self.all_projects:

            region_request = self.compute_engine_client.regions().list(project=project_detail_dict['project_id'])
            region_li = []
            while region_request is not None:
                region_response = region_request.execute()
                for region in region_response['items']:
                    region_li.append(region['name'])
                region_request = self.compute_engine_client.regions().list_next(previous_request=region_request,
                                                                                previous_response=region_response)

            for region in region_li:
                subnet_request = self.compute_engine_client.subnetworks().list(
                    project=project_detail_dict['project_id'],
                    region=region)
                while subnet_request is not None:
                    subnet_response = subnet_request.execute()
                    for subnetwork in subnet_response['items']:
                        subnet_result.append(subnetwork)
                    subnet_request = self.compute_engine_client.subnetworks().list_next(previous_request=subnet_request,
                                                                                        previous_response=subnet_response)

        return subnet_result

    def _return_ingress_firewall(self, firewall_li) -> List[Dict]:
        ingress_firewall_li = []
        for firewall_dict in firewall_li:
            if firewall_dict['direction'].upper() == 'INGRESS':
                ingress_firewall_li.append(firewall_dict)
        return ingress_firewall_li

    def _find_firewall_vulnerability(self, ingress_firewall_li, anywhere_ip, ports_li, protocol, test_name) -> List[
        Dict]:
        result = []
        for firewall_dict in ingress_firewall_li:
            issue_found = False
            if 'sourceRanges' in firewall_dict and firewall_dict['sourceRanges'] and 'allowed' in firewall_dict:
                ip_exits = any(ip in anywhere_ip for ip in firewall_dict['sourceRanges'])
                if ip_exits:
                    for port_and_protocol_detail in firewall_dict['allowed']:
                        for port in ports_li:
                            if (port_and_protocol_detail['IPProtocol'].lower() == 'all') or (
                                    port_and_protocol_detail['IPProtocol'].lower() in protocol and (
                                    'ports' not in port_and_protocol_detail or port in port_and_protocol_detail[
                                'ports'])):
                                issue_found = True
                                break
                        if issue_found:
                            break
            if issue_found:
                result.append(self._append_gcp_vpc_test_result(
                    firewall_dict['network'].split('/')[-1] + "@@" + firewall_dict['name'], test_name, "issue_found"))
            else:
                result.append(self._append_gcp_vpc_test_result(
                    firewall_dict['network'].split('/')[-1] + "@@" + firewall_dict['name'], test_name,
                    "no_issue_found"))
        return result

    def detect_gcp_vpc_firewall_should_restrict_postgresql_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_firewall_should_restrict_postgresql_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        rds_psql_port = ["5432", "5431"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, rds_psql_port, protocol, test_name)

    def detect_gcp_vpc_firewall_should_restrict_ftp_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_firewall_should_restrict_ftp_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        rds_psql_port = ["20", "21"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, rds_psql_port, protocol, test_name)

    def detect_gcp_vpc_firewall_should_restrict_access_over_uncommon_ports(self, ingress_firewall_li):
        result = []
        test_name = 'gcp_vpc_firewall_should_restrict_access_over_uncommon_ports'
        common_ports = ["20", "21", "22", "23", "25", "53", "80", "135",
                        "137", "138", "139", "443", "445", "465",
                        "587", "1433", "1521", "3306", "3389", "5432"]

        anywhere_ip = ["::/0", "0.0.0.0/0"]
        protocol_li = ['tcp', 'udp']
        for firewall_dict in ingress_firewall_li:
            issue_found = False
            if 'sourceRanges' in firewall_dict and firewall_dict['sourceRanges'] and 'allowed' in firewall_dict:
                ip_exits = any(ip in anywhere_ip for ip in firewall_dict['sourceRanges'])
                if ip_exits:
                    for port_and_protocol_detail in firewall_dict['allowed']:
                        if (port_and_protocol_detail['IPProtocol'].lower() == 'all') or (
                                port_and_protocol_detail['IPProtocol'].lower() in protocol_li and (
                                'ports' not in port_and_protocol_detail or port_and_protocol_detail[
                            'ports'][0] not in common_ports)):
                            issue_found = True
                            break
            if issue_found:
                result.append(self._append_gcp_vpc_test_result(
                    firewall_dict['network'].split('/')[-1] + "@@" + firewall_dict['name'], test_name, "issue_found"))
            else:
                result.append(self._append_gcp_vpc_test_result(
                    firewall_dict['network'].split('/')[-1] + "@@" + firewall_dict['name'], test_name,
                    "no_issue_found"))

        return result

    def detect_gcp_vpc_subnet_should_have_private_google_access_enabled(self):
        result = []
        test_name = 'gcp_vpc_subnet_should_have_private_google_access_enabled'
        for subnet_dict in self.subnets_li:
            if subnet_dict['privateIpGoogleAccess']:
                result.append(self._append_gcp_vpc_test_result(
                    subnet_dict['name'] + "@@" + subnet_dict['region'].split('/')[-1], test_name,
                    "no_issue_found"))
            else:
                result.append(self._append_gcp_vpc_test_result(
                    subnet_dict['name'] + "@@" + subnet_dict['region'].split('/')[-1], test_name,
                    "issue_found"))

        return result

    def detect_gcp_security_vpc_firewall_should_restrict_dns_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_dns_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        dns_port = ["53"]
        protocol = ['tcp', 'udp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, dns_port, protocol, test_name)

    def detect_gcp_security_vpc_firewall_should_restrict_netbios_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_netbios_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        netbios_port = ["137", "139"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, netbios_port, protocol, test_name)

    def detect_gcp_vpc_security_firewall_should_restrict_vnc_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_vnc_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["5500", "5900"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gcp_vpc_security_firewall_should_restrict_mssql_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_mssql_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["1433", "1434"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gcp_vpc_security_firewall_should_restrict_mysql_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_mysql_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["3306"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gcp_vpc_security_firewall_should_restrict_oracle_database_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_oracle_database_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["1521"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gpc_vpc_security_firewall_should_restrict_icmp_access(self, ingress_firewall_li):
        test_name = 'gpc_vpc_security_firewall_should_restrict_icmp_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        protocol = ['tcp']
        result = []
        for firewall_dict in ingress_firewall_li:
            issue_found = False
            if 'sourceRanges' in firewall_dict and firewall_dict['sourceRanges'] and 'allowed' in firewall_dict:
                ip_exits = any(ip in anywhere_ip for ip in firewall_dict['sourceRanges'])
                if ip_exits:
                    for port_and_protocol_detail in firewall_dict['allowed']:
                        if (port_and_protocol_detail['IPProtocol'].lower() == 'all') or (
                                port_and_protocol_detail['IPProtocol'].lower() in protocol):
                            issue_found = True
            if issue_found:
                result.append(self._append_gcp_vpc_test_result(
                    firewall_dict['network'].split('/')[-1] + "@@" + firewall_dict['name'], test_name, "issue_found"))
            else:
                result.append(self._append_gcp_vpc_test_result(
                    firewall_dict['network'].split('/')[-1] + "@@" + firewall_dict['name'], test_name,
                    "no_issue_found"))
        return result

    def detect_gcp_vpc_security_firewall_should_restrict_http_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_http_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["80"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gcp_vpc_security_firewall_should_restrict_https_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_https_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["443"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gcp_vpc_security_firewall_should_restrict_cifs_access(self, ingress_firewall_li):
        test_name = 'gcp_vpc_security_firewall_should_restrict_cifs_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["445"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

    def detect_gpc_vpc_security_firewall_should_restrict_smtp_access(self, ingress_firewall_li):
        test_name = 'gpc_vpc_security_firewall_should_restrict_smtp_access'
        anywhere_ip = ["::/0", "0.0.0.0/0"]
        port_li = ["25"]
        protocol = ['tcp']
        return self._find_firewall_vulnerability(ingress_firewall_li, anywhere_ip, port_li, protocol, test_name)

