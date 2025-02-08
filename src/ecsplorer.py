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

import sys
from scamper import ScamperCtrl
from helpers import *
from typing import List

class ECSplorer:

    def __init__(self, mux: str, vps: List[str]):
        self.ctrl = ScamperCtrl(mux=mux)
        self.ctrl.add_vps([vp for vp in self.ctrl.vps() if vp.name in vps])
        self.num_vps = len(self.ctrl.instances())

    def initiate_scan(self, query_request: QueryRequest):
        self.ctrl.do_dns(
            query_request.domain_state.domain,
            query_request.domain_state.nameserver_ip,
            ecs=f'{query_request.ip_address_client}/{query_request.source_prefix_length}',
            userid=query_request.domain_state.identifier,
            nsid=True,
            inst=self.ctrl.instances())

def handle_response(scamper_resp):
    userid = scamper_resp.userid
    answers = [str(addr) for addr in scamper_resp.ans_addrs()]
    cnames = [rr.cname for rr in scamper_resp.ans(rrtypes=['cname']) if rr.cname]
    scope_prefix_length = 0
    nsid = ''
    for rr in scamper_resp.ars(rrtypes=['opt']):
        if rr.opt is None:
            continue
        for elem in rr.opt:
            # see DNS EDNS0 Option Codes (OPT) https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
            # 8 is edns-client-subnet
            if elem.code_num == 8:
                # parse ecs extension
                sourcepl = elem.data[2]
                scope_prefix_length = elem.data[3]
            elif elem.code_num == 3:
                # 3 is nsid
                nsid = f'0x{elem.data.hex()}'

    query_resp = InstQueryResponse(answers, scope_prefix_length, None, VantagePoint(scamper_resp.inst), cnames, nsid)
    return userid, query_resp
