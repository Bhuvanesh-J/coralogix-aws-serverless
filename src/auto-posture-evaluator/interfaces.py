import boto3


class TesterInterface:
    def __init__(self, region_name, is_global=False):
        self.region_name = region_name
        self.is_global = is_global
        self.ssm = None

    def declare_tested_service(self) -> str:
        pass

    def declare_tested_provider(self) -> str:
        pass

    def run_tests(self) -> bool:
        if self.is_global and self.region_name != 'global':
            return False
        self.ssm = boto3.client('ssm')
        if self.region_name == 'global' or self.region_name not in self._get_regions():
            return False
        return True

    def _get_regions(self):
        region_list = []
        for page in self.ssm.get_paginator('get_parameters_by_path').paginate(
                Path='/aws/service/global-infrastructure/regions'
        ):
            region_list.append(p['Value'] for p in page['Parameters'])
        return region_list
