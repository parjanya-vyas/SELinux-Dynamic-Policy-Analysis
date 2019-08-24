#!/usr/bin/env python
#
# Written by Radhika BS, Filippo Bonazzi
# Copyright (C) 2017 Radhika BS, Filippo Bonazzi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import sys
import argparse
import os
import os.path

from sets import Set
import setools
import setools.policyrep
import logging
import pandas as pd
import csv
from itertools import repeat
import subprocess
import time


EXPAND_ATTRIBUTES = True

class Label:
    """Label class containing reader set and writer set"""

    def __init__(self, name):
        self.name = name
        self.readers = Set()
        self.writers = Set()

    def __iter__(self):
        return self

    def __next__(self):
        if self.index == 0:
            raise StopIteration
        self.index = self.index - 1
        return self.data[self.index]

# Pass the policy as a command line parameter
parser = argparse.ArgumentParser(
    description="Run on a SELinux policy in single-file source or binary format")
parser.add_argument("policy", help="The policy file")

# Set the verbosity level
parser.add_argument(u"-v", u"--verbose", action=u"store_true",
                    help=u"Be verbose [Default: False]")
args = parser.parse_args()

# Open the policy file
policy_file = setools.policyrep.SELinuxPolicy(args.policy)

# Dictionary of the form (type: Label)
type_dict = {}

attributes = {}

def parse_policy(policy):
    for attr in policy.typeattributes():
        attributes[str(attr)] = set(str(x) for x in attr.expand())

    for r in policy.terules():
        if (isinstance(r, setools.policyrep.terule.AVRule)):
            sources = []
            targets = []

            if (r.ruletype == "allow"):
                # Expand source
                if EXPAND_ATTRIBUTES and str(r.source) in attributes:
                    sources = sorted(attributes[str(r.source)])
                else:
                    sources = [str(r.source)]
                # Expand target
                if EXPAND_ATTRIBUTES and str(r.target) in attributes:
                    targets = sorted(attributes[str(r.target)])
                else:
                    targets = [str(r.target)]

                for s in sources:
                    for t in targets:
                        # If the type/domain already doesn't exist in the dictionary,
                        # create a new entry
                        t += ":" + str(r.tclass)
                        if not t in type_dict:
                            type_dict[t] = Label(t)

                        # Compute the readers and writers sets for the type
                        if "read" in r.perms:
                            type_dict[t].readers.add(s)

                        if "write" in r.perms:
                            type_dict[t].writers.add(s)

    if (args.verbose):
        for key,value in type_dict.items():
            print key
            print ("Readers:", value.readers)
            print ("Writers:", value.writers)
        print("Number of types:", len(type_dict))

parse_policy(policy_file)







