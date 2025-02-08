# -----------------------------------------------------------------------------
# Copyright (c) 2025 Patrick Sattler
#
# This file is part of ECSplorer for Ark.
#
# This code is licensed under the Mozilla Public License, version 2.0 (MPL 2.0).
# You may not use this file except in compliance with the License.
# You can obtain a copy of the License at:
#
#    https://www.mozilla.org/en-US/MPL/2.0/
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

import ipaddress
import datetime
from root_element import Root
from typing import List


class DomainState:
    def __init__(self, domain: str, nameserver_ip: str, identifier: int):
        self.domain = domain
        self.nameserver_ip = ipaddress.ip_address(nameserver_ip)
        self.identifier = identifier
        self.temp_errors = 0
        self.perm_error = False
        self.state = None


class QueryRequest:
    def __init__(self, ip_address_client: str, source_prefix_length: int, family: int, domain_state: DomainState):
        self.ip_address_client = ipaddress.ip_address(ip_address_client)
        self.source_prefix_length = source_prefix_length
        self.family = family
        self.domain_state = domain_state

    def is_nil(self) -> bool:
        return self.ip_address_client is None

    def print_new_request(self):
        print(f"ECS REQUEST Parameters (domain: '{self.domain_state.domain}', "
              f"subnet: '{self.ip_address_client}/{self.source_prefix_length}')")


class VantagePoint:
    def __init__(self, vp_ins):
        self.name = vp_ins.shortname
        self.ipv4_addr = vp_ins.ipv4
        # self.ipv6_addr = vp_ins.ipv6
        self.asn4 = vp_ins.asn4
        # self.asn6 = vp_ins.asn6
        self.location = vp_ins.loc


class InstQueryResponse:
    def __init__(self, answers, scope_prefix_length, error, vp: VantagePoint, cnames: List[str], nsid: str):
        self.answers = answers
        self.scope_prefix_length = scope_prefix_length
        self.error = error
        self.vp = vp
        self.scan_timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        self.cnames = cnames
        self.nsid = nsid


class QueryResponse:
    def __init__(self, request: QueryRequest, ins_responses: List[InstQueryResponse]):
        self.request = request
        self.ins_responses = ins_responses

    def print_request_and_response(self):
        print(f"        Scan Result (domain: '{self.request.domain_state.domain}', "
              f"client subnet: '{self.request.ip_address_client}/{self.request.source_prefix_length}', "
              f"\n  VPS: \n" +
              '\n'.join(f"vp {res.vp.name}, scope prefix length: '{res.scope_prefix_length}', error: '{res.error}'" for res in self.ins_responses) +
              ")")


class IPGeneratorRequest:
    def __init__(self, domain_state: DomainState, last_scan: QueryResponse):
        self.domain_state = domain_state
        self.last_scan = last_scan


# Define an empty base class to represent the interface
class IPGeneratorResult:
    pass


class DomainScanFinished(IPGeneratorResult):
    def __init__(self, domain_state: DomainState):
        self.domain_state = domain_state


class WaitingForMoreResults(IPGeneratorResult):
    def __init__(self, domain_state: DomainState):
        self.domain_state = domain_state
