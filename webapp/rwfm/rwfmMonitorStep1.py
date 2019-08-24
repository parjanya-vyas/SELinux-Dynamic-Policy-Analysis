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

def parse_policy():
    policy = setools.policyrep.SELinuxPolicy("/etc/selinux/ubuntu/policy/policy.30")

    # Dictionary of the form (type: Label)
    type_dict = {}
    attributes = {}

    alltypes = sorted(policy.types())
    print type(alltypes)
    print len(alltypes)

    #Parsing starts
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

                            #Add the newley discovered type in TypeList
                            #typeList = TypeList(selinux_type=t)
                            #typeList.save()
                            #typeObject = TypeObject(type_obj_id=typeList)
                            #typeObject.save()

                        if not s in type_dict:
                            type_dict[s] = Label(s)

                            #Add the newley discovered type in TypeList
                            #typeList = TypeList(selinux_type=s)
                            #typeList.save()
                            #typeObject = TypeObject(type_obj_id=typeList)
                            #typeObject.save()

                        # Compute the readers and writers sets for the type
                        if "read" in r.perms:
                            #typeObject = TypeObject.objects.get(type_obj_id=TypeList.objects.get(selinux_type=t))
                            #typeObject.type_readers.add(TypeList.objects.get(selinux_type=s))
                            type_dict[t].readers.add(s)

                        if "write" in r.perms:
                            #typeObject = TypeObject.objects.get(type_obj_id=TypeList.objects.get(selinux_type=t))
                            #typeObject.type_writers.add(TypeList.objects.get(selinux_type=s))
                            type_dict[t].writers.add(s)

    #return Response(request.data, status=status.HTTP_201_CREATED)

    for key,value in type_dict.items():
        print key
        print ("Readers:", value.readers)
        print ("Writers:", value.writers)
    print("Number of types:", len(type_dict))

parse_policy()
