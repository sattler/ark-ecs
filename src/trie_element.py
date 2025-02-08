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

class TrieElement:
    def finish_this_trie_element(self):
        pass
    def finish_child_element(self, index):
        pass
    def any_not_finished_bgp_subnets_left(self, prefix_up_to_this):
        pass
    def has_bgp_subnet(self):
        pass
    def get_child(self, prefix_up_to_parent, index):
        pass
    def mark_as_in_response(self):
        pass
    def get_value(self):
        pass
    def was_scanned(self):
        pass
    def set_scanned(self):
        pass
    def set_child_scanned(self, is_bgp_announced):
        pass
    def get_scanning_mode(self, current_prefix_up_to_this):
        pass
    def is_bgp_prefix(self):
        pass
    def is_in_announced_space(self):
        pass
    def is_marked_in_response(self):
        pass
