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

from trie_element import TrieElement
from leaf_element import Leaf
from utils import *
from typing import List
from bisect import bisect_left

import logging

class Node(TrieElement):
    def __init__(self, prefix_up_to_parent: list[int], this_value: int, kind_of_net_parent: int, is_announced: bool, config):
        prefix_including_value = prefix_up_to_parent + [this_value]

        if is_bgp_announced(prefix_including_value, config.get_config_address_family() == 6, config):
            kind_of_prefix = PrefixType.BGPANNOUNCED
        else:
            kind_of_prefix = PrefixType.UNANNOUNCED

        self.which_kind_of_prefix = kind_of_prefix
        self.value = this_value
        self._has_bgp_subnet = has_bgp_subnet(prefix_including_value, config)
        self.children = [None, None]  # Represents the two possible children
        self.is_announced = is_announced or kind_of_prefix == PrefixType.BGPANNOUNCED
        self.config = config
        self.node_scans = 0
        self.scans_announced = 0
        self.scans_unannounced = 0
        self.counter_returned_as_scope = 0

    def get_value(self) -> int:
        return self.value

    def was_scanned(self) -> bool:
        return self.node_scans >= 1

    def set_scanned(self):
        self.node_scans += 1
        if self.which_kind_of_prefix == PrefixType.BGPANNOUNCED:
            self.scans_announced += 1
        else:
            self.scans_unannounced += 1

    def set_child_scanned(self, is_bgp_announced: bool):
        if is_bgp_announced or self.which_kind_of_prefix == PrefixType.BGPANNOUNCED:
            self.scans_announced += 1
        else:
            self.scans_unannounced += 1

    def has_bgp_subnet(self) -> bool:
        return self._has_bgp_subnet

    def is_bgp_prefix(self) -> bool:
        return self.which_kind_of_prefix == PrefixType.BGPANNOUNCED

    def is_in_announced_space(self) -> bool:
        return self.is_announced

    def finish_this_trie_element(self) -> Leaf:
        return Leaf(
            scans_announced=self.scans_announced,
            scans_unannounced=self.scans_unannounced,
            value=self.value,
            has_bgp_subnet=self.has_bgp_subnet,
            which_kind_of_prefix=self.which_kind_of_prefix,
            is_announced=self.is_announced,
            leaf_scanned=self.node_scans
        )

    def finish_child_element(self, index: int):
        if self.children[index]:
            self.children[index] = self.children[index].finish_this_trie_element()

    def mark_as_in_response(self) -> bool:
        self.counter_returned_as_scope += 1
        return self.counter_returned_as_scope >= 1

    def is_marked_in_response(self) -> bool:
        return self.counter_returned_as_scope >= 1

    def any_not_finished_bgp_subnets_left(self, prefix_up_to_this: List[int]) -> bool:
        if self.which_kind_of_prefix == PrefixType.BGPANNOUNCED and not self.was_scanned():
            return True
        elif not self.has_bgp_subnet:
            return False
        if len(prefix_up_to_this) == self.config.get_config_spl():
            return False
        for index in range(len(self.children)):
            if self.children[index]:
                new_prefix = prefix_up_to_this + [index]
                if self.children[index].any_not_finished_bgp_subnets_left(new_prefix):
                    return True
        return False

    def get_child(self, current_prefix: List[int], index_value: int) -> 'Node':
        if self.children[index_value] is None:
            self.children[index_value] = Node(current_prefix, index_value, self.which_kind_of_prefix, self.is_announced, self.config)
        return self.children[index_value]

    def get_scanning_mode(self, current_prefix_up_to_this: List[int]) -> int:
        depth = len(current_prefix_up_to_this)
        # if self.which_kind_of_prefix == PrefixType.SPECIAL and max_special_prefix_scans <= self.scans_unannounced:
        #     logging.debug(f"trie: finish scanning special prefix {convert_ip_from_field_to_net_ip(current_prefix_up_to_this, ipv6_scan)}/{depth}")
        #     return FINISHED_SCANNING

        # total_unannounced_limit_hit = self.scans_unannounced + self.scans_announced >= total_notrouted_limit
        default_mode = ScanningMode.SAMPLE_MODE # if not total_unannounced_limit_hit else BGP_MODE

        # no_limits = (self.config.get_config_prefix_limits()[PrefixType.BGPANNOUNCED][depth] == 0 and
        #              self.config.get_config_prefix_limits()[PrefixType.UNANNOUNCED][depth] == 0 and
        #              self.config.get_config_prefix_limits()[PrefixType.TOTAL][depth] == 0)

        no_limits = self.config.get_config_prefix_limits().get(depth, 0) == 0
        if no_limits:
            return default_mode

        if self.is_marked_in_response():
            # if self.any_not_finished_bgp_subnets_left(current_prefix_up_to_this):
            #     return BGP_PREFIX_MODE
            # else:
            #     debuglog(f"trie: finish scanning as marked in response {convert_ip_from_field_to_net_ip(current_prefix_up_to_this, ipv6_scan)}/{depth}")
            #     return FINISHED_SCANNING
            logging.getLogger(__name__).debug(f"trie: finish scanning as marked in response {convert_ip_from_field_to_net_ip(current_prefix_up_to_this, self.config.get_config_address_family() == 6)}/{depth}")
            return ScanningMode.FINISHED_SCANNING

        # total_limit_hit = self.config.get_config_prefix_limits()[TOTAL][depth] and self.config.get_config_prefix_limits()[TOTAL][depth] <= self.scans_unannounced + self.scans_announced
        # announced_limit_hit = self.config.get_config_prefix_limits()[BGPANNOUNCED][depth] and self.config.get_config_prefix_limits()[BGPANNOUNCED][depth] <= self.scans_announced
        # unannounced_limit_hit = self.config.get_config_prefix_limits()[UNANNOUNCED][depth] and self.config.get_config_prefix_limits()[UNANNOUNCED][depth] <= self.scans_unannounced
        announced_limit_hit = self.config.get_config_prefix_limits().get(depth, 0) and self.config.get_config_prefix_limits().get(depth, 0) <= self.scans_announced

        # if total_limit_hit or announced_limit_hit or unannounced_limit_hit:
        if announced_limit_hit:
            bgp_left = self.any_not_finished_bgp_subnets_left(current_prefix_up_to_this)
            # if total_limit_hit or announced_limit_hit:
            if bgp_left:
                return ScanningMode.BGP_PREFIX_MODE
            else:
                logging.getLogger(__name__).debug(f"trie: finish scanning - limit hit {announced_limit_hit} --- {convert_ip_from_field_to_net_ip(current_prefix_up_to_this, self.config.get_config_address_family() == 6)}/{depth}")
                return ScanningMode.FINISHED_SCANNING
            # else:
            #     return BGP_MODE
        else:
            return default_mode


def is_bgp_announced(prefix: List[int], is_ipv6: bool, config) -> bool:
    prefix_lengths = config.get_source_prefixes().get(convert_ip_from_short_field_to_key_int(prefix, is_ipv6), [])
    return len(prefix) in prefix_lengths


def has_bgp_subnet(prefix: List[int], config) -> bool:
    start_key = convert_ip_from_short_field_to_key_int(prefix, config.get_config_address_family() == 6)
    end_key = calculate_biggest_key_in_subnet(prefix, config.get_config_address_family() == 6)

    index = bisect_left(config.get_source_prefix_list(), start_key)
    if index == len(config.get_source_prefix_list()):
        return False

    return start_key <= config.get_source_prefix_list()[index] <= end_key