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
from utils import ScanningMode, PrefixType

class Leaf(TrieElement):
    def __init__(self, scans_announced, scans_unannounced, which_kind_of_prefix: int, has_bgp_subnet: bool, value: int, is_announced: bool, leaf_scanned):
        self.leaf_scanned = 0
        self.scans_announced = scans_announced
        self.scans_unannounced = scans_unannounced
        self.which_kind_of_prefix = which_kind_of_prefix
        self.has_bgp_subnet = has_bgp_subnet
        self.value = value  # 0 or 1
        self.is_announced = is_announced

    def get_value(self) -> int:
        return self.value

    def was_scanned(self) -> bool:
        return self.leaf_scanned >= 1

    def set_scanned(self):
        self.leaf_scanned += 1
        if self.which_kind_of_prefix == PrefixType.BGPANNOUNCED:
            self.scans_announced += 1
        else:
            self.scans_unannounced += 1

    def set_child_scanned(self, is_bgp_announced: bool):
        if is_bgp_announced or self.which_kind_of_prefix == PrefixType.BGPANNOUNCED:
            self.scans_announced += 1
        else:
            self.scans_unannounced += 1

    def get_scanning_mode(self, _: list[int]) -> int:
        return ScanningMode.FINISHED_SCANNING

    def has_bgp_subnet(self) -> bool:
        return self.has_bgp_subnet

    def is_bgp_prefix(self) -> bool:
        return self.which_kind_of_prefix == PrefixType.BGPANNOUNCED

    def is_in_announced_space(self) -> bool:
        return self.is_announced

    def handle_response(self, _: list[int], __: int):
        return self

    def finish_this_trie_element(self):
        return self

    def finish_child_element(self, _: int):
        raise RuntimeError("Leaf cannot finish child element")

    def how_many_scans_and_bgp_scans_inside_this_prefix(self) -> tuple[int, int]:
        return self.scans_unannounced, self.scans_announced

    def get_new_parameters(self, _: list[int]) -> tuple[list[int] | None, bool]:
        return None, False

    def any_not_finished_bgp_subnets_left(self, _: list[int]) -> bool:
        return False

    def get_child(self, _: list[int], __: int):
        return None

    def mark_as_in_response(self) -> bool:
        return True

    def is_marked_in_response(self) -> bool:
        return True
