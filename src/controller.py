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

import datetime
import sys

from helpers import *
from utils import *
from root_element import *
from ecsplorer import ECSplorer, handle_response
from ecsresult_writer import ECSResultWriter, VantagePointWriter
from ecsplorerconfigurator import ECSplorerConfigurator


class Controller:
    def __init__(self, domain_ns_pairs, mux, vps, args, config, logger):
        self.no_more_domains = False
        self.currently_scanned_domains = {}
        self.currently_cached_responses = {}
        self.vps = vps
        self.ecsplorer = ECSplorer(mux, vps)
        vpwriter = VantagePointWriter(args.output_basedir)
        vpwriter.add_vps(self.ecsplorer.ctrl.instances())
        vpwriter.close()
        self.ecswriter = ECSResultWriter(args.output_basedir)
        self.domain_ns_pairs = []
        domains = set()
        for domain, _, ns in domain_ns_pairs:
            if domain not in domains:
                domains.add(domain)
                self.domain_ns_pairs.append((domain, ns))
        logger.debug(f'using the follwoing domain ns pairs: {self.domain_ns_pairs}')
        self.domain_index = 0
        self.config = config
        self.logger = logger

    def next_domain_state(self):
        if self.domain_index >= len(self.domain_ns_pairs):
            return None
        domain, nameserver_ip = self.domain_ns_pairs[self.domain_index]
        self.logger.debug(f'next domain: {domain} {nameserver_ip}')
        domain_state = DomainState(domain, nameserver_ip, self.domain_index)
        self.domain_index += 1
        return domain_state

    def initiate_next_domain(self):
        if self.no_more_domains:
            return
        domain_state = self.next_domain_state()
        if domain_state is None:
            self.logger.debug("Controller: no more domains available to scan")
            self.no_more_domains = True
        else:
            self.logger.debug('scanning next domain')
            self.currently_scanned_domains[domain_state.identifier] = domain_state
            ip_generator_result = self.trie_request(domain_state, None)
            self.handle_new_ecs_request(ip_generator_result)

    def trie_request(self, domain_state, last_scan: QueryResponse):
        new_request = IPGeneratorRequest(domain_state, last_scan)
        self.logger.debug("CONTROLLER: Request to IP Generator will be sent for %s", domain_state.domain)

        return get_next_trie_request(new_request, self.config, self.logger)

    def start(self):
        # Add new requests to the queue
        while len(self.currently_scanned_domains) < self.config.get_config_max_parallel_domains() and not self.no_more_domains:
            self.initiate_next_domain()

        # scamper controller
        while self.currently_scanned_domains:
            for response in self.ecsplorer.ctrl.responses(timeout=datetime.timedelta(seconds=10)):
                self.handle_new_response(response)
            exceptions = list(self.ecsplorer.ctrl.exceptions())
            for exc in exceptions:
                self.logger.exception('logging exception: %s', exc)
            if exceptions:
                self.logger.debug(f'exiting due to exceptions {len(exceptions)}')
                sys.exit(1)

    def handle_new_ecs_request(self, new_request: IPGeneratorRequest):
        if isinstance(new_request, DomainScanFinished):
            self.logger.debug("CONTROLLER: We have finished scanning for Domain %s", new_request.domain_state.domain)
            # print_domain_result(new_request.domain_state)
            del self.currently_scanned_domains[new_request.domain_state.identifier]
            self.initiate_next_domain()
        elif isinstance(new_request, WaitingForMoreResults):
            self.logger.debug("CONTROLLER: Waiting for more results for %s", new_request.domain_state.domain)
        elif isinstance(new_request, QueryRequest):
            self.logger.debug("CONTROLLER: IPGen sent us: Domain = %s, IP = %s / %s",
                        new_request.domain_state.domain,
                        new_request.ip_address_client,
                        new_request.source_prefix_length)
            self.logger.debug("CONTROLLER: We now send the new Request to the scannerHandler")
            self.currently_cached_responses[new_request.domain_state.identifier] = {
                'query_request': new_request,
                'responses': []
            }
            self.ecsplorer.initiate_scan(new_request)

    def handle_new_response(self, response):
        identifier, inst_query_response = handle_response(response)
        self.currently_cached_responses[identifier]['responses'].append(inst_query_response)

        # Check if all responses are here
        if len(self.currently_cached_responses[identifier]['responses']) == self.ecsplorer.num_vps:
            domain_state = self.currently_scanned_domains[identifier]
            query_request = self.currently_cached_responses[identifier]['query_request']
            for response in self.currently_cached_responses[identifier]['responses']:
                self.ecswriter.add_result(query_request, response)
            query_response = QueryResponse(query_request, self.currently_cached_responses[identifier]['responses'])
            del self.currently_cached_responses[identifier]
            ip_generator_result = self.trie_request(domain_state, query_response)
            self.handle_new_ecs_request(ip_generator_result)


def get_next_trie_request(received_request: IPGeneratorRequest, config, logger):
    logger.debug("IPGenerator: Received request for %s.", received_request.domain_state)

    last_scan_client_ip = None
    last_scan_scope = 0
    new_result = None

    if received_request.last_scan is None:
        logger.debug("IPGenerator: Received request for new domain initializing new trie")
        new_root = Root(config)
        received_request.domain_state.state = new_root
    else:
        last_scan = received_request.last_scan
        has_error = sum([1 for resp in last_scan.ins_responses if resp.error is not None]) > 0
        if not has_error and not config.ignore_response_scope:
            #TODO implement logic for multi vp
            last_scan_client_ip = last_scan.request.ip_address_client
            last_scan_scope = max(inst_resp.scope_prefix_length for inst_resp in last_scan.ins_responses)

            if last_scan.request.source_prefix_length < last_scan_scope:
                last_scan_scope = last_scan.request.source_prefix_length

            last_scan_client_ip_shortened = first_bits_of_ip_as_field(
                last_scan_scope, convert_ip_from_net_ip_to_field(last_scan_client_ip)
            )

            if received_request.domain_state.state.root_handle_response(last_scan_client_ip_shortened) == ScanningMode.FINISHED_SCANNING:
                new_result = DomainScanFinished(domain_state=received_request.domain_state)

    if new_result is None:
        if received_request.domain_state.perm_error or received_request.domain_state.temp_errors > 0:
            logger.debug("IPGENERATOR: Too many errors on domain %s, finishing scanning", received_request.domain_state.domain)
            new_result = DomainScanFinished(domain_state=received_request.domain_state)
        else:
            logger.debug("IPGENERATOR: Calculating new ECS parameters")
            new_ip_for_new_scope, new_source_prefix, finished = calculate_next_parameters(received_request.domain_state.state, config, logger)

            logger.debug(f'IPGenerator: next param {new_ip_for_new_scope} - finished {finished}')
            if finished:
                new_result = DomainScanFinished(domain_state=received_request.domain_state)
            else:
                family = 1 if not config.get_config_address_family() == 6 else 2
                new_result = QueryRequest(
                    ip_address_client=new_ip_for_new_scope,
                    source_prefix_length=new_source_prefix,
                    family=family,
                    domain_state=received_request.domain_state,
                )

    return new_result


def calculate_next_parameters(trie, config, logger):
    new_net = get_new_parameters(trie, [], config, logger)

    if new_net is None:
        return None, 0, True
    else:
        new_source = len(new_net)
        new_ip_help = convert_ip_from_field_to_net_ip(new_net, config.get_config_address_family() == 6)
        return ensure_concatenating_with_zeros(new_ip_help, new_source, config.get_config_address_family() == 6), new_source, False
