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

import ipaddress
import collections
import logging
import math
import os
import re
import sys
import yaml

MIN_SOURCE_PREFIX_LENGTH = {
    1: 8,  # IPv4
    2: 12, # IPv6
}
MAX_SOURCE_PREFIX_LENGTH = {
    1: 32,  # IPv4
    2: 64,  # IPv6
}

class ECSplorerConfigurator:

    def __init__(self, logger, config_fpath, domains_fpath, prefixes_fpath, output_basedir, ignore_response_scope):

        # Logger
        self.logger = logger
        # Path to YAML configuration file
        self.config_fpath = config_fpath
        # Path to file with domains list
        self.domains_fpath = domains_fpath
        # Path fo tile with prefixes
        self.prefixes_fpath = prefixes_fpath
        # Path to base directory of measurement output
        self.output_basedir = output_basedir
        self.source_prefix_list = []
        self.source_prefixes = collections.defaultdict(list)
        self.ignore_response_scope = ignore_response_scope

    def load_domains_list_file(self):
        """Loads domain names from the domains list file."""
        try:
            with open(self.domains_fpath, "r") as file:
                self._fqdns = file.read().splitlines()
        except FileNotFoundError:
            self.logger.error("The domains list file '{}' was not found.".format(self.domains_fpath))
            sys.exit(os.EX_CONFIG)

        ## Validate names
        # Regular expression for validating domain name
        domain_name_pattern = r"^(?!-)(?:[A-Za-z0-9-]{1,63})(?:(?:[.][A-Za-z0-9-]{1,63})+)[.]?$"
        self.domains_list = []
        for i_fqdn in self._fqdns:
            # Do re-based validity check
            if re.match(domain_name_pattern, i_fqdn) is None:
                self.logger.error("Domains list entry '{}' is not a valid domain name.".format(i_fqdn))
                sys.exit(os.EX_CONFIG)

            self.domains_list.append(i_fqdn)

        self.logger.info("Read {} domains from file '{}'.".format(len(self.domains_list), self.domains_fpath))

    def load_config_file(self):
        """Loads and parses the YAML configuration file."""
        self.config_data = None
        try:
            with open(self.config_fpath, "r") as file:
                self.config_data = yaml.safe_load(file)
        except FileNotFoundError:
            print("ERROR: The config file '{}' was not found.".format(self.config_fpath))
        except yaml.YAMLError as e:
            print("ERROR loading YAML config file: {}".format(e))

        self.process_and_validate_config_file()

    def process_and_validate_config_file(self):
        """Process the parsed config file along with the command-line parameters."""
        if self.config_data:
            self.logger.debug("Processing configuration...")

            # Check if address family is configured and a recognized value
            if "address_family_number" not in self.config_data:
                self.logger.error("'address_family_number' not present in config.")
                sys.exit(os.EX_CONFIG)
            else:

                if type(self.config_data["address_family_number"]) != int or self.config_data["address_family_number"] not in [1, 2]:
                    self.logger.error("Invalid 'address_family_number' in config.")
                    sys.exit(os.EX_CONFIG)

                self.logger.info("Using 'address_family_number' {}.".format(self.config_data["address_family_number"]))

            # Check if the source prefix length is configured and within the address-specific limits (hardcoded)
            if "source_prefix_length" not in self.config_data:
                self.logger.error("'source_prefix_length' not present in config.")
                sys.exit(os.EX_CONFIG)
            else:
                if type(self.config_data["source_prefix_length"]) != int or self.config_data["source_prefix_length"] < MIN_SOURCE_PREFIX_LENGTH[self.config_data["address_family_number"]] or self.config_data["source_prefix_length"] > MAX_SOURCE_PREFIX_LENGTH[self.config_data["address_family_number"]]:
                    self.logger.error("Invalid 'source_prefix_length'. Needs to be between {} and {}.".format(
                        MIN_SOURCE_PREFIX_LENGTH[self.config_data["address_family_number"]],
                        MAX_SOURCE_PREFIX_LENGTH[self.config_data["address_family_number"]]
                    ))
                    sys.exit(os.EX_CONFIG)


                self.logger.info("Using 'source_prefix_length' {}.".format(self.config_data["source_prefix_length"]))

            # Check if the source address space is configured and valid w.r.t. the given address family
            _process_prefixes = []
            if "source_address_space" not in self.config_data and self.prefixes_fpath is None:
                self.logger.error("'source_address_space' not present in config and '--prefixes_list' not specified.")
                sys.exit(os.EX_CONFIG)
            elif self.prefixes_fpath is None:

                if type(self.config_data["source_address_space"]) != list or len(self.config_data["source_address_space"]) == 0:
                    self.logger.error("Invalid 'source_address_space'. Needs to be non-empty list.")
                    sys.exit(os.EX_CONFIG)
                else:
                    _process_prefixes = self.config_data["source_address_space"]
            else:

                try:
                    with open(self.prefixes_fpath, "r") as file:
                        _process_prefixes = file.read().splitlines()
                except FileNotFoundError:
                    self.logger.error("The prefixes list file '{}' was not found.".format(self.prefixes_fpath))
                    sys.exit(os.EX_CONFIG)

            for i_prefix in _process_prefixes:

                try:
                    # parse the prefix, strict (so no host bits allowed)
                    _ipX_network = ipaddress.ip_network(i_prefix, strict=True)
                    # Check if family matches IP version
                    if (_ipX_network.version == 4 and self.config_data["address_family_number"] != 1) or (_ipX_network.version == 6 and self.config_data["address_family_number"] != 2):
                        self.logger.error("Invalid prefix in 'source_address_space': {} is not of configured address family.".format(i_prefix))
                        sys.exit(os.EX_CONFIG)
                    self.source_prefixes[int(_ipX_network.network_address)].append(_ipX_network.prefixlen)
                except Exception as e:
                    self.logger.error("Invalid prefix '{}' configured: {}.".format(i_prefix, e))
                    sys.exit(os.EX_CONFIG)


                # self.logger.debug("Configured prefix {}.".format(i_prefix))

                # self.logger.info("Configured source prefixes consisting of {} prefixes.".format(len(self.source_prefix_list)))
            self.source_prefix_list = sorted(self.source_prefixes.keys())

            # Check per-prefix probe limit configuration
            if "per_prefix_probe_limit" not in self.config_data:
                self.logger.error("'per_prefix_probe_limit' not present in config.")
                sys.exit(os.EX_CONFIG)
            else:

                if type(self.config_data["per_prefix_probe_limit"]) != dict or len(self.config_data["per_prefix_probe_limit"]) == 0:
                    self.logger.error("Invalid 'per_prefix_probe_limit'. Needs to be non-empty dict with 'length: limit' items.")
                    sys.exit(os.EX_CONFIG)
                else:
                    for i_prefix_len, i_probe_limit in self.config_data["per_prefix_probe_limit"].items():
                        if type(i_prefix_len) != int or type(i_probe_limit) != int:
                            self.logger.error("Invalid limit in 'per_prefix_probe_limit': '{}: {}' has non-integer.".format(i_prefix_len, i_probe_limit))
                            sys.exit(os.EX_CONFIG)
                        else:
                            # Calculate max number of probes possible for the configured address family and source prefix length, for the iterated
                            # prefix length to which to apply a limit
                            # e.g., a prefix of /20 to which to apply a limit can have at most 2^(24 - 20) = 16 queries of SPL /24
                            i_scope_and_spl_limit = int(math.pow(2, (self.config_data["source_prefix_length"] - i_prefix_len)))

                            if i_probe_limit < 1 or i_probe_limit > i_scope_and_spl_limit:
                                self.logger.error("Invalid limit in 'per_prefix_probe_limit': a limit of {} probes with /{} SPL per /{} is not within the sensible boundaries of [1, {}].".format(i_probe_limit, self.config_data["source_prefix_length"], i_prefix_len, i_scope_and_spl_limit))
                                sys.exit(os.EX_CONFIG)

            # Check if the Ark vantage point selection is configured
            if "use_ark_vantage_points" not in self.config_data:
                self.logger.error("'use_ark_vantage_points' not present in config.")
                sys.exit(os.EX_CONFIG)
            else:

                if type(self.config_data["use_ark_vantage_points"]) != list or len(self.config_data["use_ark_vantage_points"]) == 0:
                    self.logger.error("Invalid 'use_ark_vantage_points'. Needs to be non-empty list.")
                    sys.exit(os.EX_CONFIG)

                for i_config_vp_name in self.config_data["use_ark_vantage_points"]:
                    self.logger.info("Configured Ark VP '{}'.".format(i_config_vp_name))

            # Check if max parallel domains is configured and valid
            if "max_parallel_domains" not in self.config_data:
                self.logger.error("'max_parallel_domains' not present in config.")
                sys.exit(os.EX_CONFIG)
            else:

                if type(self.config_data["max_parallel_domains"]) != int or self.config_data["max_parallel_domains"] < 1:
                    self.logger.error("Invalid 'max_parallel_domains' in config.")
                    sys.exit(os.EX_CONFIG)

                self.logger.info("Using 'max_parallel_domains' {}.".format(self.config_data["max_parallel_domains"]))


        else:
            self.logger.error("No configuration data to process.")
            sys.exit(os.EX_CONFIG)

    def get_domains_list(self):
        return self.domains_list

    def get_config_ark_vps(self) -> list:
        return self.config_data["use_ark_vantage_points"]

    def get_config_address_family(self) -> int:
        return self.config_data["address_family_number"]

    def get_config_spl(self) -> int:
        return self.config_data["source_prefix_length"]

    def get_config_max_parallel_domains(self) -> int:
        return self.config_data["max_parallel_domains"]

    def get_config_source_address_space(self) -> list:
        return self.config_data["source_address_space"]

    def get_source_prefix_list(self) -> list:
        return self.source_prefix_list

    def get_source_prefixes(self) -> list:
        return self.source_prefixes

    def get_config_prefix_limits(self) -> dict:
        return self.config_data["per_prefix_probe_limit"]
