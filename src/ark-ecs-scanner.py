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

import argparse
import datetime
import importlib
import logging
import os
import pprint
import uuid

from ecsplorerconfigurator import ECSplorerConfigurator
from ecsplorerauthnsresolver import ECSplorerAuthNSResolver
from controller import Controller


def init_logger(logs_basedir):

	# Setup logging
	importlib.reload(logging)
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.DEBUG)

	# Make logs dir on disk, if necessary
	if not os.path.exists(logs_basedir):
		os.makedirs(logs_basedir)

	# File path for logger output to disk
	fhandler_path = os.path.join(logs_basedir, "{}-{}.log".format(datetime.datetime.now().date().isoformat(), uuid.uuid4()))

	# File handler
	fhandler_dbg = logging.FileHandler(filename=fhandler_path, mode="a")
	fhandler_dbg.setLevel(logging.DEBUG)

	# Console handler
	chandler = logging.StreamHandler()
	chandler.setLevel(logging.DEBUG)

	# Create formatter and add it to handlers
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	fhandler_dbg.setFormatter(formatter)
	chandler.setFormatter(formatter)

	# Add handlers
	logger.addHandler(fhandler_dbg)
	logger.addHandler(chandler)

	logger.debug("Logger initialized")
	return logger

def main():

    # Create ArgumentParser and parse
    parser = argparse.ArgumentParser(description="Response Aware EDNS Client Subnet Scanner.")
    parser.add_argument("--config", type=str, required=True, help="Path to the YAML config file.")
    parser.add_argument("--domains_list", type=str, required=True, help="File that contains list of input domain names.")
    parser.add_argument("--prefixes_list", type=str, required=False, help="File that contains list of prefixes. If set the config file entries are ignored.")
    parser.add_argument("--output_basedir", type=str, required=True, help="Base directory for output data")
    parser.add_argument("--mux", type=str, required=True, help="The multiplexing socket for Scamper Control.")
    parser.add_argument('--ignore-response-scope', action='store_true', help='if set code will ignore the scope prefix lengt when scheduling measurements')
    args = parser.parse_args()

	# Init logging
    logger = init_logger(args.output_basedir)

    # Create ECSplorer Configurator and load (and process/validate) config file
    ecs_c = ECSplorerConfigurator(logger, args.config, args.domains_list, args.prefixes_list, args.output_basedir, args.ignore_response_scope)
    ecs_c.load_config_file()
    ecs_c.load_domains_list_file()

    # Create ECSplorer Auth NS resolver
    ecs_nsa = ECSplorerAuthNSResolver(logger, ecs_c.get_domains_list(), ecs_c.get_config_ark_vps(), args.mux, args.output_basedir)
    ecs_nsa.resolve_authoritative_nameservers()

    ## DEBUG
    #pprint.pprint(ecs_nsa.get_resolution_results())
    print(ecs_c.get_config_ark_vps()) # list of strings (full name, incl. ark.caida.org)
    #print(ecs_c.get_config_address_family()) # 1 (ipv4) or 2 (ipv6)
    #print(ecs_c.get_config_spl()) # int
    # print(ecs_c.get_source_prefix_list()) # list of strings
    print(ecs_c.get_config_prefix_limits()) # { length : limit }
    #print(ecs_c.get_config_max_parallel_domains()) # int

    # TODO
    # Create ECSplorer Scanner
    controller = Controller(ecs_nsa.get_resolution_results(), args.mux, ecs_c.get_config_ark_vps(), args, ecs_c, logger)
    controller.start()
    # ecsps = ECSplorerScanner(ecspa.get_resolution_results(), args.mux, args.output_basedir, args.config)

if __name__ == "__main__":
    main()
