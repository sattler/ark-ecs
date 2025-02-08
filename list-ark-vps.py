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

import sys
import argparse
from scamper import ScamperCtrl

class ScamperCtrlVPLister:

    def __init__(self, mux):
        self.mux = mux

    def list_vps(self):

        ctrl = ScamperCtrl(mux = self.mux)
        for vp in ctrl.vps():
            # print Ark VP name and country code
            print(vp.name, vp.cc)

def main():

    parser = argparse.ArgumentParser(description="Scamper Vantage Point Lister.")
    parser.add_argument("--mux", type=str, required=True, help="The multiplexing socket for Scamper Control.")
    args = parser.parse_args()

    scvpl = ScamperCtrlVPLister(args.mux)
    scvpl.list_vps()

if __name__ == "__main__":
    main()
