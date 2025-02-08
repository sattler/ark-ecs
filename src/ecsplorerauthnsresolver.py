# -----------------------------------------------------------------------------
# Copyright (c) 2025 Mattijs Jonker
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
import os
import pprint
import publicsuffixlist
import random
import scamper
import sys

class ECSplorerAuthNSResolver:

    def __init__(self, logger, domains_list, configured_vps_list, mux, output_basedir):

        self.logger = logger
        self.domains_list = domains_list
        self.configured_vps_list = configured_vps_list
        self.output_basedir = output_basedir
        self.mux = mux
        
        # https://raw.githubusercontent.com/publicsuffix/list/refs/heads/main/public_suffix_list.dat 
        with open("public_suffix_list.dat", "rb") as f:
            self.psl = publicsuffixlist.PublicSuffixList(f)     

    def resolve_authoritative_nameservers(self):

        ## State dicts for selected VPs
        # { vpid : list<string> of registered domains to resolve NS RR for }
        selected_vps_state_ns = {}
        # { vpid : list<string> of FQDN to resolve A RR for }
        selected_vps_state_a = {}

        ### PHASE 1: Get NS RRs for domains list -----------------------------------------------------------------------

        # Create Scamper Controller
        ctrl = scamper.ScamperCtrl(morecb=self._ctrl_callback_do_dns_ns, param=selected_vps_state_ns, mux=self.mux)
        # List the currently available VPs from mux
        active_vps = ctrl.vps()

        # Add configured VPs to controller
        active_vps_nmap = { i.name : i for i in active_vps }
        for i_configured_vp_name in self.configured_vps_list:
            if i_configured_vp_name in active_vps_nmap:

                self.logger.debug("Adding VP {} to controller for auth NS resolution.".format(i_configured_vp_name))
                ctrl.add_vps(active_vps_nmap[i_configured_vp_name])
            else:
                self.logger.error("Configured VP '{}' is not active.".format(i_configured_vp_name))
                sys.exit(os.EX_SOFTWARE)

        self.logger.info("Using {} VP(s) for auth NS resolution.".format(len(ctrl.instances())))

        # Populate state dict in (near-)equal slices from the domains list
        avg_slice_size = len(self.domains_list) // len(ctrl.instances()) # avg size of a slize
        remainder = len(self.domains_list) % len(ctrl.instances()) # no. slices with an extra entry
        slice_start = 0
        slices_done = 0
        for i_vp_inst in ctrl.instances():
            slice_end = slice_start + avg_slice_size + (1 if slices_done < remainder else 0)
            selected_vps_state_ns[i_vp_inst] = {
                # The list of input domains, of arbitrary depth
                "domains_list" : self.domains_list[slice_start:slice_end],
                # The mapping between the name targeted with an NS query and domain names
                # For, e.g., www.foo.bar.org, the name targeted may be foo.bar.org
                "queried_name_to_domains_mapping" : {}
            }

            slice_start = slice_end # move slice window
            slices_done += 1        # incr. no. slices done

        ## Issue NS RR measurements
        results_domains_to_ns = {} # { 'registered_domain' : set<string> of NS names }
        while not ctrl.is_done():
            scamperHost = None
            try:
                scamperHost = ctrl.poll(timeout=datetime.timedelta(seconds=60))

                # If ctrl.poll() returned None, either all measurements are completed or the call timed out
                if scamperHost is None:
                    if ctrl.is_done():
                        self.logger.info("Measurements are done.")
                    else:
                        self.logger.warning("Poll timed out.")
                    break

            except Exception as e:
                self.logger.error("Got exception from ScamperCtrl: {}.".format(e))
                continue

            # Iterate NS resource records in ANSWER section
            if scamperHost.ancount > 0:
                self.logger.debug("Got ({}) and RCODE {} for {} from VP {}.".format(
                    ",".join(["'{}'".format(i_ns) for i_ns in scamperHost.ans_nses()]),
                        scamperHost.rcode, scamperHost.qname, scamperHost.inst.name))

                for i_domain in selected_vps_state_ns[scamperHost.inst]["queried_name_to_domains_mapping"][scamperHost.qname]:
                    if i_domain not in results_domains_to_ns:
                        results_domains_to_ns[i_domain] = set(scamperHost.ans_nses())
            else:
                self.logger.debug("Got 0 answer records and RCODE {} for {} from VP {}.".format(scamperHost.rcode, scamperHost.qname, scamperHost.inst.name))

        # Create set of (distinct) NS names to resolve
        results_distinct_ns = set()
        for i_d_ns in results_domains_to_ns.values():
            results_distinct_ns = results_distinct_ns.union(i_d_ns)

        # Destroy the Controller
        ctrl.done()
        ctrl = None

        ### PHASE 2: Get A RRs for NS names ----------------------------------------------------------------------------

        ## We recreate a Scamper Controller, with a new CB and state param, and new set of VPs
        ## In the future, we may be able to reuse the controller (and VP selection) by setting a new morecb and param

        # Create new Controller
        ctrl = scamper.ScamperCtrl(morecb=self._ctrl_callback_do_dns_a, param=selected_vps_state_a, mux=self.mux)
        # List the currently available VPs from mux
        active_vps = ctrl.vps()

        # Add configured VPs to controller
        active_vps_nmap = { i.name : i for i in active_vps }
        for i_configured_vp_name in self.configured_vps_list:
            if i_configured_vp_name in active_vps_nmap:

                self.logger.debug("Adding VP {} to controller for A resolution.".format(i_configured_vp_name))
                ctrl.add_vps(active_vps_nmap[i_configured_vp_name])
            else:
                self.logger.error("Configured VP '{}' is not active.".format(i_configured_vp_name))
                sys.exit(os.EX_SOFTWARE)

        self.logger.info("Using {} VP(s) for A resolution.".format(len(ctrl.instances())))

        # Populate state dict in (near-)equal slices from the nameservers list
        avg_slice_size = len(results_distinct_ns) // len(ctrl.instances()) # avg size of a slize
        remainder = len(results_distinct_ns) % len(ctrl.instances()) # no. slices with an extra entry
        slice_start = 0
        slices_done = 0
        for i_vp_inst in ctrl.instances():
            slice_end = slice_start + avg_slice_size + (1 if slices_done < remainder else 0)
            selected_vps_state_a[i_vp_inst] = list(results_distinct_ns)[slice_start:slice_end]

            slice_start = slice_end # move slice window
            slices_done += 1        # incr. no. slices done

        ## Issue A RR measurements
        results_domains_to_a = {} # { 'fqdn' : set<string> of A addresses }
        while not ctrl.is_done():
            scamperHost = None
            try:
                scamperHost = ctrl.poll(timeout=datetime.timedelta(seconds=60))

                # If ctrl.poll() returned None, either all measurements are completed or the call timed out
                if scamperHost is None:
                    if ctrl.is_done():
                        self.logger.info("Measurements are done.")
                    else:
                        self.logger.warning("Poll timed out.")
                    break

            except Exception as e:
                self.logger.error("Got exception from ScamperCtrl: {}.".format(e))
                continue

            # Iterate NS resource records in ANSWER section
            if scamperHost.ancount > 0:
                self.logger.debug("Got ({}) and RCODE {} for {} from VP {}.".format(
                    ",".join(["'{}'".format(i_a) for i_a in scamperHost.ans_addrs()]),
                        scamperHost.rcode, scamperHost.qname, scamperHost.inst.name))

                results_domains_to_a[scamperHost.qname] = set(scamperHost.ans_addrs())
            else:
                self.logger.debug("Got 0 answer records and RCODE {} for {} from VP {}.".format(scamperHost.rcode, scamperHost.qname, scamperHost.inst.name))


        # Construct registered_domain -> NS IPv4 address
        self.results_domains_to_ns_a = set()
        for i_domain in results_domains_to_ns.keys():
            for i_ns in results_domains_to_ns[i_domain]:
                if i_ns in results_domains_to_a:
                    for i_a in results_domains_to_a[i_ns]:
                        if not i_a.is_linklocal() and not i_a.is_reserved() and not i_a.is_rfc1918():
                            self.results_domains_to_ns_a.add((i_domain, i_ns, str(i_a)))
                else:
                    self.logger.warning("Could not find '{}' in address resolution results.".format(i_ns))

    # Callback handler to do_ns query
    def _ctrl_callback_do_dns_ns(self, ctrl, vp_inst, state):
        # If there are no registered domains left in the VP's state
        if len(state[vp_inst]["domains_list"]) == 0:
            self.logger.debug("Marking VP '{}' as done.".format(vp_inst.name))
            vp_inst.done()
        else:
            _domain_name = state[vp_inst]["domains_list"].pop(0)
            # We consider the NS of the registered domain name, which may in fact be a parent NS that resolves to a subdomain authoritative
            _target_name = self.psl.privateparts(_domain_name)[-1] 

            if _target_name not in state[vp_inst]["queried_name_to_domains_mapping"]:
                state[vp_inst]["queried_name_to_domains_mapping"][_target_name] = []
            state[vp_inst]["queried_name_to_domains_mapping"][_target_name].append(_domain_name)

            self.logger.debug("Issuing NS query for {}".format(_target_name))
            ctrl.do_dns(_target_name, qtype="NS", rd=True, wait_timeout=3, inst=vp_inst, sync=False)

    # Callback handler to do_a query
    def _ctrl_callback_do_dns_a(self, ctrl, vp_inst, state):
        # If there are no registered domains left in the VP's state
        if len(state[vp_inst]) == 0:
            self.logger.debug("Marking VP '{}' as done.".format(vp_inst.name))
            vp_inst.done()
        else:
            _target_name = state[vp_inst].pop(0)
            self.logger.debug("Issuing A query for {}".format(_target_name))
            ctrl.do_dns(_target_name, qtype="A", rd=True, wait_timeout=3, inst=vp_inst, sync=False)

    def get_resolution_results(self):
        return self.results_domains_to_ns_a
