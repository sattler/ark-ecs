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

import csv
import os

from helpers import InstQueryResponse, QueryRequest

class ECSResultWriter:

    def __init__(self, outputpath):
        self.outfile = open(os.path.join(outputpath, 'ecsresults.csv'), 'w')
        self.writer = csv.writer(self.outfile)
        self.writer.writerow(['domain', 'nameserver_ip', 'vp_name', 'client_subnet', 'source_pl', 'scope_pl', 'error', 'nsid', 'answers', 'cnames', 'scan_timestamp'])

    def add_result(self, query_request: QueryRequest, inst_query_response: InstQueryResponse):
        self.writer.writerow([query_request.domain_state.domain, query_request.domain_state.nameserver_ip, inst_query_response.vp.name, query_request.ip_address_client, query_request.source_prefix_length, inst_query_response.scope_prefix_length, inst_query_response.error is not None, inst_query_response.nsid, sorted(inst_query_response.answers), sorted(inst_query_response.cnames), inst_query_response.scan_timestamp])

    def close(self):
        self.outfile.close()

class VantagePointWriter:

    def __init__(self, outputpath):
        self.outfile = open(os.path.join(outputpath, 'vps.csv'), 'w')
        self.writer = csv.writer(self.outfile)
        self.writer.writerow(['shortname', 'cc', 'state', 'city', 'lat', 'lon', 'ipv4', 'asn4']) #, 'ipv6', 'asn6'])

    # Takes a list of ScamperInst objects
    def add_vps(self, vps):
        for vp in vps:
            self.writer.writerow([vp.shortname, vp.cc, vp.st, vp.place, vp.loc[0], vp.loc[1], vp.ipv4, vp.asn4]) # , vp.ipv6, vp.asn6])

    def close(self):
        self.outfile.close()