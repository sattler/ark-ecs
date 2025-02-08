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

from utils import ScanningMode, convert_ip_from_field_to_net_ip
from node_element import Node
from leaf_element import Leaf
from typing import List

import random


class Root:
    def __init__(self, config):
        self.scope_zero_observed = 0
        self.root_is_scanned = False
        self.childs = [None, None]
        self.config = config

    def get_value(self):
        raise NotImplementedError("Root has no value")

    def was_scanned(self):
        return False

    def finish_this_trie_element(self):
        return None

    def finish_child_element(self, index):
        if self.childs[index]:
            self.childs[index] = self.childs[index].finish_this_trie_element()

    def has_bgp_subnet(self):
        return len(self.config.get_source_prefix_list()) > 0

    def get_child(self, prefix_up_to_parent, index):
        if self.childs[index] is None:
            self.childs[index] = Node([], index, ScanningMode.SAMPLE_MODE, False, self.config)
        return self.childs[index]

    def get_scanning_mode(self, current_prefix_up_to_this):
        return ScanningMode.SAMPLE_MODE

    def is_in_announced_space(self):
        return False

    def is_bgp_prefix(self):
        return False

    def any_not_finished_bgp_subnets_left(self, prefix_up_to_this):
        for child in self.childs:
            if child is not None:
                if child.any_not_finished_bgp_subnets_left(prefix_up_to_this):
                    return True
        return False

    def set_child_scanned(self, _):
        pass

    def root_handle_response(self, shortened_last_client_ip: List[int]) -> bool:
        if len(shortened_last_client_ip) > 0:
            return handle_response(self, shortened_last_client_ip, 0)
        else:
            self.scope_zero_observed += 1
            max_num_scope_zeros = 0
            return max_num_scope_zeros > 0 and self.scope_zero_observed >= max_num_scope_zeros


def handle_response(current_node, shortened_last_client_ip, depth):
    if current_node is None:
        # found leaf node -> we do not care anymore about results there
        return False
    if len(shortened_last_client_ip) == depth:
        return current_node.mark_as_in_response()
    else:  # we have not reached the responsible node that represents the received lastClientIP/scopePrefixLength
        child_node = current_node.get_child(shortened_last_client_ip[:depth], shortened_last_client_ip[depth])
        if handle_response(child_node, shortened_last_client_ip, depth + 1):
            return current_node.get_scanning_mode(shortened_last_client_ip[:depth]) == ScanningMode.FINISHED_SCANNING
        else:
            return False


def get_new_parameters(node_element, prefix_up_to_parent, config, logger):
    prefix, _ = get_new_parameters_with_mode(node_element, prefix_up_to_parent, ScanningMode.BGP_MODE, config, logger)
    return prefix


def get_new_parameters_with_mode(node_element, prefix_up_to_parent, scanning_mode, config, logger):
    current_prefix_slice = list(prefix_up_to_parent)  # Copy the prefix
    if isinstance(node_element, Node):
        current_prefix_slice.append(node_element.get_value())
    elif isinstance(node_element, Leaf):
        logger.debug('Hit Leaf')
        return None, False

    length_of_current_prefix = len(current_prefix_slice)
    node_scanning_mode = node_element.get_scanning_mode(current_prefix_slice)

    if node_scanning_mode == ScanningMode.FINISHED_SCANNING:
        logger.debug('finished scanning mode')
        return None, False

    if node_scanning_mode.value > scanning_mode.value:
        scanning_mode = node_scanning_mode

    # if (scanning_mode == ScanningMode.BGP_MODE or scanning_mode == ScanningMode.BGP_PREFIX_MODE) and not node_element.has_bgp_subnet() and not node_element.is_in_announced_space():
    if scanning_mode == ScanningMode.BGP_PREFIX_MODE:
        logger.debug('BGP prefix mode')
        return None, False

    if scanning_mode == ScanningMode.BGP_MODE and not node_element.has_bgp_subnet() and not node_element.is_in_announced_space():
        logger.debug('BGP Mode without bgp prefixes left')
        return None, False

    # Depth to scan with is reached
    if length_of_current_prefix == node_element.config.get_config_spl():
        if node_element.was_scanned():
            logger.debug('was scanned')
            return None, False
        # elif (scanning_mode == ScanningMode.SAMPLE_MODE or
        #       (scanning_mode == ScanningMode.BGP_PREFIX_MODE and node_element.is_bgp_prefix()) or
        #       (scanning_mode == ScanningMode.BGP_MODE and node_element.is_in_announced_space())):
        elif scanning_mode == ScanningMode.SAMPLE_MODE or (scanning_mode == ScanningMode.BGP_MODE and node_element.is_in_announced_space()):
            node_element.set_scanned()
            return current_prefix_slice, node_element.is_bgp_prefix()
        else:
            return None, False

    first_child_index = 0
    if length_of_current_prefix >= 0: # randomize depth
        first_child_index = random.randint(0, 1)

    second_child_index = 1 if first_child_index == 0 else 0
    search_order = [None, None]
    child_available = False
    only_second_child_has_bgp = True

    for slice_index, child_index in enumerate([first_child_index, second_child_index]):
        search_order[slice_index] = node_element.get_child(current_prefix_slice, child_index)
        if isinstance(search_order[slice_index], Leaf):
            search_order[slice_index] = None
        else:
            if scanning_mode == ScanningMode.BGP_PREFIX_MODE and not search_order[slice_index].is_bgp_prefix() and not search_order[slice_index].has_bgp_subnet():
                logger.debug('finishing child as it has no BGP')
                node_element.finish_child_element(child_index)
                search_order[slice_index] = None
            elif search_order[slice_index].was_scanned():
                logger.debug('finishing after child has been scanned')
                node_element.finish_child_element(child_index)
                search_order[slice_index] = None
            else:
                first_element_check = slice_index == 0 and (search_order[slice_index].has_bgp_subnet() or search_order[slice_index].is_in_announced_space())
                secend_element_check = slice_index == 1 and not search_order[slice_index].has_bgp_subnet() and not search_order[slice_index].is_in_announced_space()
                if first_element_check or secend_element_check:
                    only_second_child_has_bgp = False
                child_available = True

    if child_available:
        if only_second_child_has_bgp:
            search_order = [search_order[1], search_order[0]]

        for index, child in enumerate(search_order):
            if child is None:
                continue
            child_prefix, isannounced = get_new_parameters_with_mode(child, current_prefix_slice, scanning_mode, config, logger)
            if child_prefix is not None:
                node_element.set_child_scanned(isannounced)
                return child_prefix, isannounced or node_element.is_bgp_prefix()
            else:
                logger.debug(f"trie: finish child because it told us no more scans to do {convert_ip_from_field_to_net_ip(current_prefix_slice + [child.get_value()], config.get_config_address_family() == 6)}/{length_of_current_prefix+1} scanning mode {scanning_mode}")
                if index == 0:
                    node_element.finish_child_element(first_child_index)
                else:
                    node_element.finish_child_element(second_child_index)

    if node_element.is_bgp_prefix():
        node_element.set_scanned()
        return current_prefix_slice, True

    return None, False
