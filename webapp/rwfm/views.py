from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from rwfm.models import Id, SubId, ObjId, UserId, GroupId, SockId, KeyId, Subject, Object, Socket, Addr, Connection, Key, ShmMap, TypeList, TypeObject, TypeSubject
from rwfm.serializers import SubIdSerializer, ObjIdSerializer, UserIdSerializer, GroupIdSerializer, KeyIdSerializer, AddrSerializer, SockIdSerializer, TypeListSerializer
import sets, json, ast

# Imports for parsing SELinux policies
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

type_dict = {}

class JSONResponse(HttpResponse):
    """
    An HttpResponse that renders its content into JSON.
    """
    def __init__(self, data, **kwargs):
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)

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

#@api_view(['GET'])
@csrf_exempt
def home(request):
    """
    Display welcome message.
    """
    data = "Readers Writers Flow Model demo."
    return JSONResponse(data)

@csrf_exempt
def reset(request):
    """
    Reset DB to null.
    """
    data = "DB set to NULL."
    for s in Subject.objects.all():
        s.delete()

    for sid in SubId.objects.all():
        sid.delete()

    for o in Object.objects.all():
        o.delete()

    for oid in ObjId.objects.all():
        oid.delete()

    for kid in KeyId.objects.all():
        kid.delete()

    return JSONResponse(data)

@api_view(['POST'])
def initialize_type_labels(request):
    """
    Initialize types and their labels
    Example post parameters -
        {
        }
    """
    if request.method == 'POST':
        # Open the policy file if error occurs check if the path of policy file is correct
        policy = setools.policyrep.SELinuxPolicy("/etc/selinux/default/policy/policy.30")

        # Dictionary of the form (type: Label)
        #type_dict = {}
        attributes = {}

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
                            t += ":" + str(r.tclass)
                            #typeListTarget = TypeList(selinux_type=t)
                            #typeListSource = TypeList(selinux_type=s)
                            #typeListTarget.save()
                            #typeListSource.save()
                            #typeObjectTarget = TypeObject(type_obj_id=typeListTarget)
                            #typeObjectTarget.save()
                            
                            # If the type/domain already doesn't exist in the dictionary,
                            # create a new entry
                            if not t in type_dict:
                                type_dict[t] = Label(t)

                                #Add the newley discovered type in TypeList
                                #typeList = TypeList(selinux_type=t)
                                #typeList.save()
                                #typeObject = TypeObject(type_obj_id=typeList)
                                #typeObject.save()

                            #if not s in type_dict:
                                #type_dict[s] = Label(s)

                                #Add the newley discovered type in TypeList
                                #typeList = TypeList(selinux_type=s)
                                #typeList.save()
                                #typeObject = TypeObject(type_obj_id=typeList)
                                #typeObject.save()

                            # Compute the readers and writers sets for the type
                            if "read" in r.perms:
                                type_dict[t].readers.add(s)
                                #typeObjectTarget.type_readers.add(typeListSource)
                                #typeObject = TypeObject.objects.get(type_obj_id=TypeList.objects.get(selinux_type=t))
                                #typeObject.type_readers.add(TypeList.objects.get(selinux_type=s))

                            if "write" in r.perms:
                                type_dict[t].writers.add(s)
                                #typeObjectTarget.type_writers.add(typeListSource)
                                #typeObject = TypeObject.objects.get(type_obj_id=TypeList.objects.get(selinux_type=t))
                                #typeObject.type_writers.add(TypeList.objects.get(selinux_type=s))

                            #typeObjectTarget.save()

        print("Number of object types:", len(type_dict))
        response = {}
        return Response(response, status=status.HTTP_201_CREATED)

#        for key,value in type_dict.items():
#            print key
#            print ("Readers:", value.readers)
#            print ("Writers:", value.writers)

@api_view(['POST'])
def type_detail(request):
    """
    View type label details.

    Example POST parameters -

        {
        "selinux_type": "type"
        }

    """
    if request.method == 'POST':
        response={}
        #typeid = TypeList.objects.get(selinux_type=request.data['selinux_type'])
        #try:
        #    type_obj = TypeObject.objects.get(type_obj_id=typeid)
        #except:
        #    pass

        #serializer = TypeListSerializer(type_obj.type_obj_id)
        response["type_obj_id"] = JSONRenderer().render(request.data['selinux_type'])

        #readers = type_obj.type_readers.all()
        #serializer = TypeListSerializer(readers, many=True)
        response["type_readers"] = JSONRenderer().render(type_dict[request.data['selinux_type']].readers)

        #writers = type_obj.type_writers.all()
        #serializer = TypeListSerializer(writers, many=True)
        response["type_writers"] = JSONRenderer().render(type_dict[request.data['selinux_type']].writers)

        return Response(response, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def add_user(request):
    """
    Add a user
    Example post parameters -
        {
         "hostid": "localhost", "uid": "ataware"
        }
    """
    if request.method == 'POST':
        #create user ID
        serializer = UserIdSerializer(data=request.data)
        if serializer.is_valid():
            subjectid = serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(request.data, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def add_group(request):
    """
    Add a user
    Example post parameters -
        {
            "hostid": "localhost",
            "gid": "0",
            "members" : "0,1,2,55,100"
        }
    """
    if request.method == 'POST':
        #create user ID
        mydata =  request.data.copy()
        members = mydata.pop("members")
        serializer = GroupIdSerializer(data=mydata)
        if serializer.is_valid():
            group = serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        #create and add member of this group
        user = {}
        for u in members.split(','):
            user["hostid"] = group.hostid
            user["uid"] = u.strip()

            serializer = UserIdSerializer(data=user)
            if serializer.is_valid():
                user_object = serializer.save()
                group.members.add(user_object)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(request.data, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def subject_detail(request):
    """
    View subject details.

    Example POST parameters -

        {
        "hostid": "localhost", "uid": "ataware", "pid":111
        }

    """
    if request.method == 'POST':
        response={}
        subid = SubId.objects.get(hostid=request.data['hostid'], uid=request.data['uid'], pid=request.data['pid'])
        try:
            subject = Subject.objects.get(sub_id=subid)
        except:
            pass

        serializer = SubIdSerializer(subject.sub_id)
        response["sub_id"] = JSONRenderer().render(serializer.data)

        serializer = UserIdSerializer(subject.admin)
        response["admin"] = JSONRenderer().render(serializer.data)

        readers = subject.readers.all()
        serializer = UserIdSerializer(readers, many=True)
        response["readers"] = JSONRenderer().render(serializer.data)

        writers = subject.writers.all()
        serializer = UserIdSerializer(writers, many=True)
        response["writers"] = JSONRenderer().render(serializer.data)

        return Response(response, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def delete_subject(request):
    """
    Create subject.
    Example POST parameters -

        {
        "hostid": "localhost", "uid": "ataware", "pid":111
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 0
        ret["errors"] = "None"
        try:
            subid = SubId.objects.get(hostid=request.data['hostid'], uid=request.data['uid'], pid=request.data['pid'])
        except:
            ret["errors"] = "SubID does not exist."
            return Response(ret, status=status.HTTP_200_OK)

        try:
            ret["errors"] = "Failed to find mapping."
            mapList = ShmMap.objects.filter(subid=subid)
            ret["errors"] = "Failed to delete mapping."
            for m in mapList:
                keyid = m.keyid
                key = Key.objects.get(keyid=keyid)
                m.delete()
                key.refcount -= 1
                key.save()
                key = Key.objects.get(keyid=keyid)
                if key.refcount==0:
                    key.delete()
                    keyid.delete()
        except:
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        subject = Subject.objects.get(sub_id=subid)
        subject.delete()
        subid.delete()
        ret["status"] = 1
        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def subject_present(request):
    """
    Verify whether a subject is present.

    Example post parameters -

        { "hostid": "8323329", "uid": "1003", "pid":111}

    """
    if request.method == 'POST':
        ret={}
        ret["status"] = 0
        mydata =  request.data.copy()
        try:
            subid = SubId.objects.get(hostid=mydata['hostid'], uid=mydata['uid'], pid=mydata['pid'])
        except:
            ret["errors"] = "Subject ID not found."
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        ret["status"] = 1
        ret["errors"] = "None."
        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def add_subject(request):
    """
    Add a subject entry for a process trying to open file for the first time.

    Example post parameters -

        {
        "sub_id": { "hostid": "8323329", "uid": "1003", "pid":111},
        "admin": { "hostid": "8323329",  "uid": "1003"}
        }

    """
    if request.method == 'POST':
        ret = {}
        ret['status'] = 0
        sub_id = {}
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        #print mydata

        #create subject ID
        if(type(mydata)==dict):
            sub_id = mydata["sub_id"]
        else:
            sub_id = ast.literal_eval(mydata.get("sub_id"))

        serializer = SubIdSerializer(data=sub_id)
        if serializer.is_valid():
            subjectid = serializer.save()
        else:
            ret['errors'] = serializer.errors
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        #create admin user
        if(type(mydata)==dict):
            admin = mydata["admin"]
        else:
            admin = ast.literal_eval(mydata.get("admin"))

        serializer = UserIdSerializer(data=admin)
        if serializer.is_valid():
            adminuser = serializer.save()
        else:
            ret['errors'] = serializer.errors
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        subject = Subject(sub_id=subjectid, admin=adminuser)
        subject.save()

        #add all the users on this host as readers.
        subject.readers = UserId.objects.all()

        #add admin as writer for this subject.
        subject.writers.add(adminuser)

        ret['status'] = 1
        ret['errors'] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['GET'])
def user_list(request):
    """
    List all subjects.
    """
    if request.method == 'GET':
        uids = UserId.objects.all()
        serializer = UserIdSerializer(uids, many=True)
        return Response(serializer.data)

@api_view(['GET'])
def group_list(request):
    """
    List all subjects.
    """
    if request.method == 'GET':
        gids = GroupId.objects.all()
        serializer = GroupIdSerializer(gids, many=True)
        return Response(serializer.data)

@api_view(['GET'])
def subject_list(request):
    """
    List all subjects.
    """
    if request.method == 'GET':
        sub_ids = SubId.objects.all()
        serializer = SubIdSerializer(sub_ids, many=True)
        return Response(serializer.data)

@api_view(['GET'])
def key_list(request):
    """
    List all subjects.
    """
    if request.method == 'GET':
        keys = KeyId.objects.all()
        serializer = KeyIdSerializer(keys, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def create_key(request):
    """
    Create a new key on behalf of a subject.

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "key_id": { "hostid": "localhost", "key_id": 3},
        "shm_id": 1234
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata = request.data.copy()

        if(type(mydata)==dict):
            s = mydata["sub_id"]
            k = mydata["key_id"]
            shmid = mydata["shm_id"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            k = ast.literal_eval(mydata.get("key_id"))
            shmid = ast.literal_eval(mydata.get("shm_id"))

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            subject = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #create KeyID
        serializer = KeyIdSerializer(data=k)
        if serializer.is_valid():
            keyid, created = serializer.save()
        else:
            ret["errors"] = serializer.errors;
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        if created:
            key = Key(keyid=keyid, admin=subject.admin, refcount=1)
            key.save()

            #add readers
            for r in subject.readers.all():
                key.readers.add(r)

            #add writers
            for w in subject.writers.all():
                key.writers.add(w)
            key.writers.add(subject.admin)
            key.save()
        else:
            key = Key.objects.get(keyid=keyid)
            key.refcount += 1
            key.save()

        shmMapping = ShmMap(subid=sub_id, keyid=keyid, shmid=shmid, shmaddr="NULL")
        shmMapping.save()

        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def shmat(request):
    """
    Create a new key on behalf of a subject.

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "shmid": 1234,
        "shmaddr": "0xFF4321",
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            s = mydata["sub_id"]
            shmid = mydata["shmid"]
            shmaddr = mydata["shmaddr"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            shmid = ast.literal_eval(mydata.get("shmid"))
            shmaddr = ast.literal_eval(mydata.get("shmaddr"))

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            currentsubject = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        subjects = set()
        keys = set()
        smap = ShmMap.objects.get(subid=sub_id, shmid=shmid)
        currentkey = Key.objects.get(keyid=smap.keyid)
        subjects.add(sub_id)
        keys.add(smap.keyid)

        #
        #compute all reachable subjects and keys.
        #

        while True:
            klen = len(keys)
            slen = len(subjects)

            keys = keys | get_keys(subjects) #union
            klen_ = len(keys)

            subjects = subjects | get_subjects(keys) #union
            slen_ = len(subjects)

            if slen==slen_:
                break

        cadmin = set()
        for sub_id in subjects:
            s = Subject.objects.get(sub_id=sub_id)
            cadmin.add(s.admin)

        readers = set(currentsubject.readers.all()) & set(currentkey.readers.all())
        writers = set(currentsubject.writers.all()) | set(currentkey.writers.all())

        if cadmin.issubset(readers):
            for sub_id in subjects:
                s = Subject.objects.get(sub_id=sub_id)
                s.readers = list(set(s.readers.all()) & readers)
                s.writers = list(set(s.writers.all()) | writers)

            for keyid in keys:
                k = Key.objects.get(keyid=keyid)
                k.readers = list(set(k.readers.all()) & readers)
                k.writers = list(set(k.writers.all()) | writers)

            smap.shmaddr = shmaddr
            smap.save()
            ret["status"] = 1
            ret["errors"] = "None"
            print "Allow", "\n"
        else:
            ret["status"] = 0
            ret["errors"] = "shared memory attach not allowed by rwfm."
            print "Don't Allow", "\n"

        return Response(ret, status=status.HTTP_201_CREATED)


def get_subjects(keys):
    sset = set()
    for k in keys:
        for m in ShmMap.objects.exclude(shmaddr='NULL').filter(keyid=k):
            sset.add(m.subid)
    return sset

def get_keys(subjects):
    kset = set()
    for s in subjects:
        for m in ShmMap.objects.exclude(shmaddr='NULL').filter(subid=s):
            kset.add(m.keyid)
    return kset

@api_view(['POST'])
def shmdt(request):
    """
    Create a new key on behalf of a subject.

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "shmaddr": "0xFF4321"
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            s = mydata["sub_id"]
            shmaddr = mydata["shmaddr"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            shmaddr = ast.literal_eval(mydata.get("shmaddr"))

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            subject = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        try:
            ret["errors"] = "Failed to find mapping."
            smap = ShmMap.objects.get(subid=sub_id, shmaddr=shmaddr)
            ret["errors"] = "Failed to delete mapping."
            smap.shmaddr = "NULL"
            smap.save()
        except:
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def shmctl(request):
    """
    Create a new key on behalf of a subject.

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "shmid": 1234,
        "cmd" : "IPC_RMID"
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            s = mydata["sub_id"]
            shmid = mydata["shmid"]
            cmd = mydata["cmd"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            shmid = ast.literal_eval(mydata.get("shmid"))
            cmd = ast.literal_eval(mydata.get("cmd"))

        #fetch subject ID
        try:
            subid = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            subject = Subject.objects.get(sub_id=subid)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #cmd=0 is IPC_RMID
        if cmd in ['0', 0]:
            try:
                ret["errors"] = "Failed to find mapping."
                smap = ShmMap.objects.get(subid=subid, shmid=shmid)
                keyid = smap.keyid
                ret["errors"] = "Failed to delete mapping."
                smap.delete()
                key = Key.objects.get(keyid=keyid)
                key.refcount -= 1
                key.save()
                key = Key.objects.get(keyid=keyid)
                if key.refcount==0:
                    keyid = key.keyid
                    key.delete()
                    keyid.delete()
                #keyid.delete()
            except:
                return Response(ret, status=status.HTTP_404_NOT_FOUND)

        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def delete_key(request):
    """
    Delete a key.

    Example post parameters -
        {
        "hostid": "localhost", "key_id": 1
        }
    """
    if request.method == 'POST':
        ret = {}
        ret['status'] = 0
        try:
            ret['errors'] = "KeyID not found"
            keyid = KeyId.objects.get(hostid=request.data['hostid'], key_id=request.data['key_id'])
            ret['errors'] = "Key not found"
            key = Key.objects.get(keyid=keyid)
            ret['errors'] = "Failed to delete key."
            key.delete()
            ret['errors'] = "Failed to delete keyid."
            keyid.delete()
        except:
            return Response(ret, status=status.HTTP_404_NOT_FOUND)
        ret['status'] = 1
        ret['errors'] = "None"
        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def key_detail(request):
    """
    View subject details.

    Example POST parameters -

        {
        "hostid": "localhost", "key_id": 1
        }

    """
    if request.method == 'POST':
        response={}
        response["keyid"] = request.data.copy()
        keyid = KeyId.objects.get(hostid=request.data['hostid'], key_id=request.data['key_id'])
        try:
            key = Key.objects.get(keyid=keyid)
        except:
            pass

        serializer = UserIdSerializer(key.admin)
        response["admin"] = JSONRenderer().render(serializer.data)

        readers = key.readers.all()
        serializer = UserIdSerializer(readers, many=True)
        response["readers"] = JSONRenderer().render(serializer.data)

        writers = key.writers.all()
        serializer = UserIdSerializer(writers, many=True)
        response["writers"] = JSONRenderer().render(serializer.data)

        return Response(response, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def delete_object(request):
    """
    Delete an object.

    Example post parameters -
        {
        "hostid": "localhost", "devid": "2", "inum": 222
        }
    """
    if request.method == 'POST':
        ret = {}
        ret['status'] = 0
        try:
            ret['errors'] = "ObjectID not found"
            objid = ObjId.objects.get(hostid=request.data['hostid'], devid=request.data['devid'], inum=request.data['inum'])
            ret['errors'] = "Object not found"
            obj = Object.objects.get(obj_id=objid)
            ret['errors'] = "Failed to delete object."
            obj.delete()
            ret['errors'] = "Failed to delete objectID."
            objid.delete()
        except:
            return Response(ret, status=status.HTTP_404_NOT_FOUND)
        ret['status'] = 1
        ret['errors'] = "None"
        print "delete_object", ret, "\n"
        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def create_object(request):
    """
    Create a new object on behalf of a subject.

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "obj_id": { "hostid": "localhost", "devid": "3", "inum": 333 }
        }

    """
    if request.method == 'POST':

        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            o = mydata["obj_id"]
            s = mydata["sub_id"]
        else:
            o = ast.literal_eval(mydata.get("obj_id"))
            s = ast.literal_eval(mydata.get("sub_id"))

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            subject = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #create object ID
        serializer = ObjIdSerializer(data=o)
        if serializer.is_valid():
            objectid, created = serializer.save()
        else:
            ret["errors"] = serializer.errors;
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        obj = Object(obj_id=objectid, admin=subject.admin)
        obj.save()

        #add readers
        for r in subject.readers.all():
            obj.readers.add(r)

        #add writers
        for w in subject.writers.all():
            obj.writers.add(w)
        obj.writers.add(subject.admin)

        obj.save()
        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['GET'])
def object_list(request):
    """
    List all objects.
    """
    if request.method == 'GET':
        obj_ids = ObjId.objects.all()
        serializer = ObjIdSerializer(obj_ids, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def object_detail(request):
    """
    View subject details.

    Example POST parameters -

        {
        "hostid": "localhost", "devid": "2", "inum":111
        }

    """
    if request.method == 'POST':
        response={}
        response["obj_id"] = request.data.copy()
        obj_id = ObjId.objects.get(hostid=request.data['hostid'], devid=request.data['devid'], inum=request.data['inum'])
        try:
            obj = Object.objects.get(obj_id=obj_id)
        except:
            pass

        serializer = UserIdSerializer(obj.admin)
        response["admin"] = JSONRenderer().render(serializer.data)

        readers = obj.readers.all()
        serializer = UserIdSerializer(readers, many=True)
        response["readers"] = JSONRenderer().render(serializer.data)

        writers = obj.writers.all()
        serializer = UserIdSerializer(writers, many=True)
        response["writers"] = JSONRenderer().render(serializer.data)

        return Response(response, status=status.HTTP_201_CREATED)


@api_view(['POST'])
def add_object(request):
    """
    Create an object entry for an existing file to be opened.

    Example post parameters -

        {
        "obj_id": { "hostid": "8323329", "devid": "2067", "inum": 21374 },
        "uid"   : "1003",
        "gid"   : "1005",
        "mode"  : "100644"
        }

    """
    if request.method == 'POST':

        ret={}
        ret["status"] = 0
        ret["errors"] = ""
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            obj_id = mydata["obj_id"]
        else:
            obj_id = ast.literal_eval(mydata.get("obj_id"))

        hostid = obj_id["hostid"]
        uid  = mydata["uid"]
        gid  = mydata["gid"]
        mode = mydata["mode"]

        objectadmin = UserId.objects.get(hostid=hostid, uid=uid.split(':')[0])

        #print uid
        #print hostid
        print type_dict[uid]

        readers=UserId.objects.filter(uid__in=list(type_dict[uid].readers))
        writers=UserId.objects.filter(uid__in=list(type_dict[uid].writers))
        
        #create object ID
        #obj_id = mydata.pop("obj_id")

        serializer = ObjIdSerializer(data=obj_id)
        if serializer.is_valid():
            objectid, created = serializer.save()
        else:
            ret["errors"] = serializer.errors
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        if created:
            obj = Object(obj_id=objectid, admin=objectadmin)
            obj.save()

        obj.readers = readers
        obj.writers = writers

        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def write_auth(request):
    """
    Authenticate whether subject 's' can write to object 'o'

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "obj_id": { "hostid": "localhost", "devid": "2", "inum": 222 }
        }

    """

    if request.method == 'POST':

        ret={}
        ret["status"] = 0
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            o = mydata["obj_id"]
            s = mydata["sub_id"]
        else:
            o = ast.literal_eval(mydata.get("obj_id"))
            s = ast.literal_eval(mydata.get("sub_id"))

        #fetch object
        try:
            obj_id = ObjId.objects.get(hostid=o["hostid"], devid=o["devid"], inum=o["inum"])
            o = Object.objects.get(obj_id=obj_id)
        except:
            ret["errors"] = "Object not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch subject
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            s = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        sub_readers_set = set(s.readers.all())
        obj_readers_set = set(o.readers.all())

        sub_writers_set = set(s.writers.all())
        obj_writers_set = set(o.writers.all())

        if (s.admin in o.writers.all()) and sub_readers_set.issuperset(obj_readers_set) and sub_writers_set.issubset(obj_writers_set):
            ret["status"] = 1
            ret["errors"] = "None."
        else:
            ret["errors"] = "Denied by RWFM write rule."

        return Response(ret, status=status.HTTP_200_OK)


@api_view(['POST'])
def read_auth(request):
    """
    Authenticate whether subject 's' can read object 'o'

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "obj_id": { "hostid": "localhost", "devid": "2", "inum": 222 }
        }

    """

    if request.method == 'POST':

        ret={}
        ret["status"] = 0
        ret["errors"] = "None."
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            o = mydata["obj_id"]
            s = mydata["sub_id"]
        else:
            o = ast.literal_eval(mydata.get("obj_id"))
            s = ast.literal_eval(mydata.get("sub_id"))

        try:
            obj_id = ObjId.objects.get(hostid=o["hostid"], devid=o["devid"], inum=o["inum"])
            o = Object.objects.get(obj_id=obj_id)
        except:
            ret["errors"] = "Object not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            s = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        s_changed = 0

        if(s.admin in o.readers.all()):
            if set(s.readers.all()) != ( set(s.readers.all()) & set(o.readers.all()) ):
                s.readers = list( set(s.readers.all()) & set(o.readers.all()) )
                s_changed = 1
            if set(s.writers.all()) != ( set(s.writers.all()) | set(o.writers.all()) ):
                s.writers = list( set(s.writers.all()) | set(o.writers.all()) )
                s_changed = 1
            ret["status"] = 1
        else:
            ret["errors"] = "Denied by RWFM read rule."
            return Response(ret, status=status.HTTP_200_OK)
        if s_changed != 0:
            s.save()

        return Response(ret, status=status.HTTP_200_OK)


@api_view(['POST'])
def rdwr_auth(request):
    """
    Authenticate whether subject 's' can read and write object 'o'

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "obj_id": { "hostid": "localhost", "devid": "2", "inum": 222 }
        }

    """

    if request.method == 'POST':

        ret={}
        ret["status"] = 0
        ret["errors"] = "None."
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            o = mydata["obj_id"]
            s = mydata["sub_id"]
        else:
            o = ast.literal_eval(mydata.get("obj_id"))
            s = ast.literal_eval(mydata.get("sub_id"))

        try:
            obj_id = ObjId.objects.get(hostid=o["hostid"], devid=o["devid"], inum=o["inum"])
            o = Object.objects.get(obj_id=obj_id)
        except:
            ret["errors"] = "Object not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            s = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        sub_readers_set = set(s.readers.all())
        obj_readers_set = set(o.readers.all())

        sub_writers_set = set(s.writers.all())
        obj_writers_set = set(o.writers.all())

        s_changed = 0
        if s.admin in o.readers.all() and s.admin in o.writers.all() and sub_readers_set.issuperset(obj_readers_set) and sub_writers_set.issubset(obj_writers_set):
            ret["status"] = 1
            if set(s.readers.all()) != set(o.readers.all()):
                s.readers = o.readers.all()
                s_changed = 1
            if set(s.writers.all()) != set(o.writers.all()):
                s.writers = o.writers.all()
                s_changed = 1
        else:
            ret["errors"] = "Denied by RWFM read rule."
            return Response(ret, status=status.HTTP_200_OK)

        if s_changed != 0:
            s.save()

        return Response(ret, status=status.HTTP_200_OK)


@api_view(['POST'])
def downgrade_object(request):
    """
    Downgrade: Subject with label (s1,R1,W1) requests to downgrade an object with label (s2,R2,W2) to label (s3,R3,W3).

    IF 
    (s1=s2=s3) and (s1 is-in R2) and (R1=R2) and (W1=W2=W3) and (R3 superset-of R2) and [ (w2={s1}) OR (R3-R2 subset-of W2) ]
    THEN
        change the label of the object in the database
        ALLOW
    ELSE
        DENY


    Example post parameters -

    {
    "sub_id": { "hostid": "8323329", "uid": "1003", "pid":111},
    "obj_id": { "hostid": "8323329", "devid": "2067", "inum": 21374 },
    "new_label" : {
                        "admin" :  { "hostid": "8323329", "uid": "1003"},
                        "readers"  : [{"hostid":"ragnar","uid":"0"},{"hostid":"ragnar","uid":"1"},.......}],
                        "writers" : {}
              }
    }
    """
    if request.method == 'POST':
        ret={}
        ret["status"] = 0
        ret["errors"] = "None."
        mydata = request.data.copy()

        if(type(mydata)==dict):
            s  = mydata["sub_id"]
            o = mydata["obj_id"]
            l = mydata["new_label"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            o = ast.literal_eval(mydata.get("obj_id"))
            l = ast.literal_eval(mydata.get("new_label"))

        #fetch obejct ID
        try:
            obj_id = ObjId.objects.get(hostid=o["hostid"], devid=o["devid"], inum=o["inum"])
            o = Object.objects.get(obj_id=obj_id)
        except:
            ret["errors"] = "Object not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            s = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch admin object from new label.
        try:
            l_admin = UserId.objects.get(hostid=l["admin"]["hostid"], uid=l["admin"]["uid"])
        except:
            ret["errors"] = "Admin incorrect in label part."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch reader objects from new label.
        l_readers = []
        for u in l["readers"]:
            try:
                uobject = UserId.objects.get(hostid=u["hostid"], uid=u["uid"])
                l_readers.append(uobject)
            except:
                ret["errors"] = "Reader incorrect in label readers part."
                return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch writers objects from new label.
        l_writers = []
        for w in l["writers"]:
            try:
                wobject = UserId.objects.get(hostid=w["hostid"], uid=w["uid"])
                l_writers.append(wobject)
            except:
                ret["errors"] = "Writer incorrect in label writer part."
                return Response(ret, status=status.HTTP_404_NOT_FOUND)

        new_readers = set(l_readers)-set(o.readers.all())
        if s.admin==o.admin==l_admin and \
            s.admin in o.readers.all() and \
            set(s.readers.all())==set(o.readers.all()) and \
            set(s.writers.all())==set(o.writers.all())==set(l_writers) \
            and set(l_readers).issuperset(set(o.readers.all())) \
            and ( set(o.writers.all())==set([s.admin]) or new_readers.issubset(set(o.writers.all())) ) :
            print "\n Allow"
            o.admin = l_admin
            o.readers = l_readers
            o.writers = l_writers
            o.save()
            ret['status'] = 1
        else:
            ret['status'] = 0
            print "\n Deny"

        ret['errors'] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['POST'])
def upgrade_object(request):
    """
    Upgrade: Subject with label (s1,R1,W1) requests to upgrade an object with label (s2,R2,W2) to label (s3,R3,W3).

    Example post parameters -

    {
    "sub_id": { "hostid": "8323329", "uid": "1003", "pid":111},
    "obj_id": { "hostid": "8323329", "devid": "2067", "inum": 21374 },
    "new_label" : {
                        "admin" :  { "hostid": "8323329", "uid": "1003"},
                        "readers"  : [{"hostid":"ragnar","uid":"0"},{"hostid":"ragnar","uid":"1"},.......}],
                        "writers" : {}
              }
    }
    """
    if request.method == 'POST':
        ret={}
        ret["status"] = 0
        ret["errors"] = "None."
        mydata = request.data.copy()

        if(type(mydata)==dict):
            s  = mydata["sub_id"]
            o = mydata["obj_id"]
            l = mydata["new_label"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            o = ast.literal_eval(mydata.get("obj_id"))
            l = ast.literal_eval(mydata.get("new_label"))

        #fetch obejct ID
        try:
            obj_id = ObjId.objects.get(hostid=o["hostid"], devid=o["devid"], inum=o["inum"])
            o = Object.objects.get(obj_id=obj_id)
        except:
            ret["errors"] = "Object not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            s = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch admin object from new label.
        try:
            l_admin = UserId.objects.get(hostid=l["admin"]["hostid"], uid=l["admin"]["uid"])
        except:
            ret["errors"] = "Admin incorrect in label part."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch reader objects from new label.
        l_readers = []
        for u in l["readers"]:
            try:
                uobject = UserId.objects.get(hostid=u["hostid"], uid=u["uid"])
                l_readers.append(uobject)
            except:
                ret["errors"] = "Reader incorrect in label readers part."
                return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #fetch writers objects from new label.
        l_writers = []
        for w in l["writers"]:
            try:
                wobject = UserId.objects.get(hostid=w["hostid"], uid=w["uid"])
                l_writers.append(wobject)
            except:
                ret["errors"] = "Writer incorrect in label writer part."
                return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #(s1=s2=s3) and (s1 is-in R2) and (R1=R2) and (W1=W2=W3) and (R3 subset-of R2)
        if s.admin==o.admin==l_admin and \
            s.admin in o.readers.all() and \
            set(s.readers.all())==set(o.readers.all()) and \
            set(s.writers.all())==set(o.writers.all())==set(l_writers) and \
            set(l_readers).issubset(set(o.readers.all())) :
            print "\n Allow"
            o.admin = l_admin
            o.readers = l_readers
            o.writers = l_writers
            o.save()
            ret['status'] = 1
        else:
            ret['status'] = 0
            print "\n Deny"

        ret['errors'] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

#===================================== Socket specific APIs ===============================================
@api_view(['POST'])
def delete_socket(request):
    """
    Delete a socket.

    Example post parameters -
        {
        "hostid": "localhost", "uid": "2", "pid": 222, "fd" : 10
        }
    """
    if request.method == 'POST':
        ret = {}
        ret['status'] = 0
        try:
            ret['errors'] = "SocketID not found"
            sockid = SockId.objects.get(hostid=request.data['hostid'], 
                    uid=request.data['uid'], pid=request.data['pid'], fd=request.data['fd'])
            ret['errors'] = "Socket not found"
            sock = Socket.objects.get(sock_id=sockid)
            ret['errors'] = "Failed to delete socket."
            sock.delete()
            ret['errors'] = "Failed to delete socketID."
            sockid.delete()
        except:
            return Response(ret, status=status.HTTP_404_NOT_FOUND)
        ret['status'] = 1
        ret['errors'] = "None"
        print "delete_socket", ret, "\n"
        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def create_socket(request):
    """
    Create a new socket on behalf of a subject.

    Example post parameters -

        {
        "sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "fd" : 10 ,
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            s = mydata["sub_id"]
            fd = mydata["fd"]
        else:
            s = ast.literal_eval(mydata.get("sub_id"))
            fd = ast.literal_eval(mydata.get("fd"))

        #fetch subject ID
        try:
            sub_id = SubId.objects.get(hostid=s["hostid"], uid=s["uid"], pid=s["pid"])
            subject = Subject.objects.get(sub_id=sub_id)
        except:
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #create socket ID
        sock_data = s
        sock_data["fd"] = fd
        serializer = SockIdSerializer(data=sock_data)
        if serializer.is_valid():
            socketid = serializer.save()
        else:
            ret["errors"] = serializer.errors;
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        sock = Socket(sock_id=socketid, admin=subject.admin)
        sock.save()

        #add readers
        for r in subject.readers.all():
            sock.readers.add(r)

        #add writers
        for w in subject.writers.all():
            sock.writers.add(w)
        sock.writers.add(subject.admin)

        sock.save()
        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['GET'])
def socket_list(request):
    """
    List all sockets.
    """
    if request.method == 'GET':
        sock_ids = SockId.objects.all()
        serializer = SockIdSerializer(sock_ids, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def socket_detail(request):
    """
    View socket details.

    Example POST parameters -

        {
        "hostid": "localhost", "uid": "2", "pid":111, "fd" : 10
        }

    """
    if request.method == 'POST':
        response={}
        response["sock_id"] = request.data.copy()
        sock_id = SockId.objects.get(hostid=request.data['hostid'],
                uid=request.data['uid'], pid=request.data['pid'], fd=request.data['fd'])
        try:
            sock = Socket.objects.get(sock_id=sock_id)
        except:
            pass

        serializer = UserIdSerializer(sock.admin)
        response["admin"] = JSONRenderer().render(serializer.data)

        readers = sock.readers.all()
        serializer = UserIdSerializer(readers, many=True)
        response["readers"] = JSONRenderer().render(serializer.data)

        writers = sock.writers.all()
        serializer = UserIdSerializer(writers, many=True)
        response["writers"] = JSONRenderer().render(serializer.data)

        return Response(response, status=status.HTTP_201_CREATED)

def downgrade_socket(s, sc, new_reader):
    "subject, socket, reader"
    subid_of_socket = SubId.objects.get(hostid=sc.sock_id.hostid, uid=sc.sock_id.uid, pid=sc.sock_id.pid)

    print "Using downgrade!"

    if subid_of_socket != s.sub_id:
        print "\ndowngrade_socket : Subject Id is not related to socket."
        return False

    if set(s.readers.all())!=set(sc.readers.all()) or set(s.writers.all())!=set(sc.writers.all()):
        print "\ndowngrade_socket : Downgrade not allowed."
        return False

    if set([s.admin]) == set(sc.writers.all()) or new_reader in sc.writers.all():
        sc.readers.add(new_reader)
        sc.save()
        return True

    print "\ndowngrade_socket : Downgrade not allowed."
    return False


@api_view(['POST'])
def delete_address(request):
    """
    Delete an address.

    Example post parameters -
        {
        "sock_id" : { "hostid": "localhost", "uid": "1002", "pid": 101, "fd": 22 },
        "ip": "127.0.0.1",
        "port": 2001
        }
    """
    if request.method == 'POST':
        ret = {}
        ret['status'] = 0
        s = request.data.pop('sock_id')
        ip = request.data.pop('ip')
        port = request.data.pop('port')
        try:
            ret['errors'] = "SockID not found"
            sock_id = SockId.objects.get(hostid=s['hostid'], uid=s['uid'], pid=s['pid'], fd=s['fd'])
            ret['errors'] = "Address not found"
            addr = Addr.objects.get(sock_id=sock_id, ip=ip, port=port)
            ret['errors'] = "Failed to delete Address."
            addr.delete()
        except:
            return Response(ret, status=status.HTTP_404_NOT_FOUND)
        ret['status'] = 1
        ret['errors'] = "None"
        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def create_address(request):
    """
    Create a new address.

    Example post parameters -
        {
        "sock_id" : { "hostid": "localhost", "uid": "1002", "pid": 101, "fd": 22 },
        "ip": "127.0.0.1",
        "port": 2001
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #create socket ID
        serializer = AddrSerializer(data=request.data)
        if serializer.is_valid():
            address = serializer.save()
        else:
            ret["errors"] = serializer.errors;
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

@api_view(['GET'])
def address_list(request):
    """
    List all addresses.
    """
    if request.method == 'GET':
        addresses = Addr.objects.all()
        serializer = AddrSerializer(addresses, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def bind(request):
    """
        {
           "sock_id" : { "hostid": "localhost", "uid": "2", "pid": 222, "fd" : 10},
           "ip" : "127.0.0.1",
           "port" : 1001
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            s = mydata["sock_id"]
            ip = mydata["ip"]
            port = mydata["port"]
        else:
            s = ast.literal_eval(mydata.get("sock_id"))
            ip = mydata.get("ip")
            port = ast.literal_eval(mydata.get("port"))

        #fetch Socket
        try:
            ret['errors'] = "SockID not found"
            sock_id = SockId.objects.get(hostid=s['hostid'], uid=s['uid'], pid=s['pid'], fd=s['fd'])
            ret["errors"] = "Socket not found."
            socket = Socket.objects.get(sock_id=sock_id)
            ret["errors"] = "Subject ID for server not found."
            serverid = SubId.objects.get(hostid=s['hostid'], uid=s['uid'], pid=s['pid'])
            ret["errors"] = "Server not found."
            server = Subject.objects.get(sub_id=serverid)
            ret["errors"] = "None."
        except:
            ret["status"] = 0
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #create address
        addr_data = {}

        addr_data["sock_id"] = s
        addr_data["ip"] = ip
        addr_data["port"] = port

        serializer = AddrSerializer(data=addr_data)
        if serializer.is_valid():
            addr = serializer.save()
        else:
            ret["errors"] = serializer.errors;
            ret["status"] = 0
            return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        socket.readers = list( set(socket.readers.all()) & set(server.readers.all()) )
        socket.writers = list( set(socket.writers.all()) | set(server.writers.all()) )

        socket.save()

        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def connect(request):
    """
        Specify socketid of client and (ip, port) of server.
        {
           "sock_id" : { "hostid": "localhost", "uid": "2", "pid": 222, "fd" : 20},
           "server_ip" : "127.0.0.1",
           "port" : 1001
        }
    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        #data = JSONParser().parse(request)
        mydata =  request.data.copy()

        if(type(mydata)==dict):
            c = mydata["sock_id"]
            server_ip = mydata["server_ip"]
            port = mydata["port"]
        else:
            c = ast.literal_eval(mydata.get("sock_id"))
            server_ip = mydata.get("server_ip")
            port = ast.literal_eval(mydata.get("port"))

        #fetch Socket
        try:
            ret['errors'] = "client not found"
            c_subid = SubId.objects.get(hostid=c['hostid'], uid=c['uid'], pid=c['pid'])
            m = Subject.objects.get(sub_id=c_subid)

            ret['errors'] = "SockID not found"
            c_sock_id = SockId.objects.get(hostid=c['hostid'], uid=c['uid'], pid=c['pid'], fd=c['fd'])

            ret["errors"] = "Socket not found."
            client_sock = Socket.objects.get(sock_id=c_sock_id)

            ret["errors"] = "None."
        except:
            ret["status"] = 0
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        try:
            server_address = Addr.objects.get(ip=server_ip, port=port)
            server_sock = Socket.objects.get(sock_id=server_address.sock_id)
            s_subid = SubId.objects.get(hostid=server_sock.sock_id.hostid, 
                        uid=server_sock.sock_id.uid, pid=server_sock.sock_id.pid)
            server = Subject.objects.get(sub_id=s_subid)
        except:
            ret["status"] = 0
            ret["errors"] = "No server information found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        client_sock.readers = list( set(client_sock.readers.all()) & set(client.readers.all()) )
        client_sock.writers = list( set(client_sock.writers.all()) | set(client.writers.all()) )
        client_sock.save()

        if client.admin in server_sock.readers.all():
            client.readers = list(set(client.readers.all()) & set(server_sock.readers.all()))
            client.writers = list(set(client.writers.all()) | set(server_sock.writers.all()))
            client.save()
            client_sock.readers = list( set(client_sock.readers.all()) & set(client.readers.all()) )
            client_sock.writers = list( set(client_sock.writers.all()) | set(client.writers.all()) )
            client_sock.save()
        else:
            ret["status"] = 0
            ret["errors"] = "Client admin missing from server socket readers."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        if server.admin in client_sock.readers.all() or downgrade_socket(client, client_sock, server_sock.admin):
            connection = Connection(server=server_sock.sock_id, client=c_sock_id)
            connection.save()
            for r in client.readers.all():
                connection.readers.add(r)
            for w in client.writers.all():
                connection.writers.add(w)
            connection.save()
        else:
            ret["status"] = 0
            ret["errors"] = "Server admin missing from client socket reader or downgrade failed."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def accept(request):
    """
        Specify old and new socket ids.

        {
           "old_sockid" : { "hostid": "localhost", "uid": "1000", "pid": 7525, "fd" : 10},
           "new_sockfd" : 11
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        mydata = request.data.copy()
        o = ast.literal_eval(mydata.get("old_sockid"))
        new_sockfd = mydata.get("new_sockfd")

        #fetch Socket
        try:
            ret['errors'] = "Old Socket not found"
            old_sockid = SockId.objects.get(hostid=o['hostid'], uid=o['uid'], pid=o['pid'], fd=o['fd'])
            old_sock = Socket.objects.get(sock_id=old_sockid)

            ret['errors'] = "Server not found"
            s_subid = SubId.objects.get(hostid=o['hostid'], uid=o['uid'], pid=o['pid'])
            server = Subject.objects.get(sub_id=s_subid)

            ret["errors"] = "Connection not found."
            connection = Connection.objects.get(server=old_sockid)

            ret['errors'] = "New SockID not found"
            new_sockdata = {}
            new_sockdata['hostid'] = o['hostid']
            new_sockdata['uid'] = o['uid']
            new_sockdata['pid'] = o['pid']
            new_sockdata['fd'] = new_sockfd

            serializer = SockIdSerializer(data=new_sockdata)
            if serializer.is_valid():
                new_sockid = serializer.save()
            else:
                ret["errors"] = serializer.errors;
                return Response(ret, status=status.HTTP_400_BAD_REQUEST)
            ret["errors"] = "None"
        except:
            ret["status"] = 0
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        server.readers = list( set(server.readers.all()) & set(connection.readers.all()) )
        server.writers = list( set(server.writers.all()) | set(connection.writers.all()) )
        server.save()

        old_sock.readers = list( set(old_sock.readers.all()) & set(server.readers.all()) )
        old_sock.writers = list( set(old_sock.writers.all()) | set(server.writers.all()) )
        old_sock.save()

        #create new socket.
        new_sock = Socket(sock_id=new_sockid, admin=old_sock.admin)
        new_sock.save()
        for r in old_sock.readers.all():
            new_sock.readers.add(r)

        for w in old_sock.writers.all():
            new_sock.writers.add(w)
        new_sock.save()

        client_sock = Socket.objects.get(sock_id=connection.client)

        if client_sock.admin in new_sock.readers.all() or downgrade_socket(server, new_sock, client_sock.admin):
            connection.server = new_sockid
            connection.readers = list( set(connection.readers.all()) & set(server.readers.all()) )
            connection.writers = list( set(connection.writers.all()) | set(server.writers.all()) )
            connection.save()
        else:
            ret["status"] = 0
            ret["errors"] = "Client admin missing from new server socket reader or downgrade failed."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def send(request):
    """
        { 
        "hostid": "localhost",
        "uid": "1000",
        "pid": 7525,
        "fd" : 10
        }
    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        s =  request.data.copy()

        print s

        #fetch Socket
        try:
            ret['errors'] = "Socket not found"
            s_sockid = SockId.objects.get(hostid=s['hostid'], uid=s['uid'], pid=s['pid'], fd=s['fd'])
            s_socket = Socket.objects.get(sock_id=s_sockid)

            ret['errors'] = "Sender not found"
            s_subid = SubId.objects.get(hostid=s['hostid'], uid=s['uid'], pid=s['pid'])
            sender = Subject.objects.get(sub_id=s_subid)

            ret["errors"] = "None"
        except:
            ret["status"] = 0
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        connection = None
        try:
            connection = Connection.objects.get(server=s_sockid)
            r_sockid = connection.client
        except:
            pass

        try:
            connection = Connection.objects.get(client=s_sockid)
            r_sockid = connection.server
        except:
            pass

        if connection:
            try:
                r_socket = Socket.objects.get(sock_id=r_sockid)
                r_subid = SubId.objects.get(hostid=r_sockid.hostid, uid=r_sockid.uid, pid=r_sockid.pid)
                receiver = Subject.objects.get(sub_id=r_subid)
            except:
                ret["errors"] = "Receiver not found."
                ret["status"] = 0
                return Response(ret, status=status.HTTP_404_NOT_FOUND)
        else:
            ret["errors"] = "Connection not found."
            ret["status"] = 0
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #update readers, writers of sender socket.
        s_socket.readers = list( set(s_socket.readers.all()) & set(sender.readers.all()) )
        s_socket.writers = list( set(s_socket.writers.all()) | set(sender.writers.all()) )
        s_socket.save()

        if r_socket.admin in s_socket.readers.all() or downgrade_socket(sender, s_socket, r_socket.admin):
            connection.readers = list( set(connection.readers.all()) & set(s_socket.readers.all()) )
            connection.writers = list( set(connection.writers.all()) | set(s_socket.writers.all()) )
            connection.save()
            r_socket.readers = list( set(r_socket.readers.all()) & set(connection.readers.all()) )
            r_socket.writers = list( set(r_socket.writers.all()) | set(connection.writers.all()) )
            r_socket.save()
        else:
            ret["status"] = 0
            ret["errors"] = "Receiver's admin missing from sender socket reader or downgrade failed."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        return Response(ret, status=status.HTTP_200_OK)

@api_view(['POST'])
def receive(request):
    """
        {
        "hostid": "localhost",
        "uid": "1000",
        "pid": 7530,
        "fd" : 20
        }
    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        r =  request.data.copy()

        print r

        #fetch Socket
        try:
            ret['errors'] = "Receiver socket not found"
            r_sockid = SockId.objects.get(hostid=r['hostid'], uid=r['uid'], pid=r['pid'], fd=r['fd'])
            r_socket = Socket.objects.get(sock_id=r_sockid)

            ret['errors'] = "Receiver not found."
            r_subid = SubId.objects.get(hostid=r['hostid'], uid=r['uid'], pid=r['pid'])
            receiver = Subject.objects.get(sub_id=r_subid)

            ret["errors"] = "None"
        except:
            ret["status"] = 0
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        #update readers, writers of receiver and receiver socket.
        receiver.readers = list( set(receiver.readers.all()) & set(r_socket.readers.all()) )
        receiver.writers = list( set(receiver.writers.all()) | set(r_socket.writers.all()) )
        receiver.save()

        r_socket.readers = list( set(r_socket.readers.all()) & set(receiver.readers.all()) )
        r_socket.writers = list( set(r_socket.writers.all()) | set(receiver.writers.all()) )
        r_socket.save()

        return Response(ret, status=status.HTTP_200_OK)


@api_view(['GET'])
def connection_list(request):
    """
    List all connections.
    """
    if request.method == 'GET':
        connections = Connection.objects.all()
        print connections, "\n"
        #serializer = ObjIdSerializer(obj_ids, many=True)
        return Response(serializer.data)

#===================================== Signal specific APIs ===============================================

@api_view(['POST'])
def kill(request):
    """
    Send a signal to "recvr_sub_id" on behalf of "sendr_sub_id"

    Example post parameters -

        {
        "sendr_sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "recvr_sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        }

    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        mydata = request.data.copy()

        if(type(mydata)==dict):
            sendr_sub_id_param = mydata["sendr_sub_id"]
            recvr_sub_id_param = mydata["recvr_sub_id"]
        else:
            sendr_sub_id_param = ast.literal_eval(mydata.get("sendr_sub_id"))
            recvr_sub_id_param = ast.literal_eval(mydata.get("recvr_sub_id"))

        #fetch subject IDs and subjects
        try:
            sendr_sub_id = SubId.objects.get(hostid=sendr_sub_id_param["hostid"], uid=sendr_sub_id_param["uid"], pid=sendr_sub_id_param["pid"])
            sendr_subject = Subject.objects.get(sub_id=sendr_sub_id)

            recvr_sub_id = SubId.objects.get(hostid=recvr_sub_id_param["hostid"], uid=recvr_sub_id_param["uid"], pid=recvr_sub_id_param["pid"])
            recvr_subject = Subject.objects.get(sub_id=recvr_sub_id)
        except:
            ret["status"] = 0
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        if recvr_subject.admin in sendr_subject.readers.all():
            recvr_subject.readers = list(set(recvr_subject.readers.all()) & set(sendr_subject.readers.all()))
            recvr_subject.writers = list(set(recvr_subject.writers.all()) | set(sendr_subject.writers.all()))
            recvr_subject.save()

            ret["status"] = 1
            ret["errors"] = "None"
            return Response(ret, status=status.HTTP_201_CREATED)
        else:            
            ret["status"] = 0
            ret["errors"] = "Receiver process admin missing from sender process readers."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def kill_many(request):
    """
    Send a signal to all "recvr_sub_id"s on behalf of "sendr_sub_id"

    Example post parameters -

        {
        "sendr_sub_id": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "number_of_recvrs": {5}
        "recvr_sub_id_0": { "hostid": "localhost",  "uid": "ataware", "pid": 111 }, 
        "recvr_sub_id_1": { "hostid": "localhost",  "uid": "ataware", "pid": 112 }, 
        "recvr_sub_id_2": { "hostid": "localhost",  "uid": "ataware", "pid": 113 }, 
        "recvr_sub_id_3": { "hostid": "localhost",  "uid": "ataware", "pid": 114 }, 
        "recvr_sub_id_4": { "hostid": "localhost",  "uid": "ataware", "pid": 115 }, 
        }
    """
    if request.method == 'POST':
        ret = {}
        ret["status"] = 1
        mydata = request.data.copy()

        ret = {}
        ret["status"] = 1
        mydata = request.data.copy()
        recvr_sub_id_params = []
        recvr_sub_ids = []
        recvr_subjects = []

        if(type(mydata)==dict):
            sendr_sub_id_param = mydata["sendr_sub_id"]
            number_of_recvrs_param = mydata["number_of_recvrs"]
            for i in range(0,int(number_of_recvrs_param)):
                id = "recvr_sub_id_"+str(i)
                recvr_sub_id_params.append(mydata[id])
        else:
            sendr_sub_id_param = ast.literal_eval(mydata.get("sendr_sub_id"))
            number_of_recvrs_param = ast.literal_eval(mydata.get("number_of_recvrs"))
            for i in range(0,int(number_of_recvrs_param)):
                id = "recvr_sub_id_"+str(i)
                recvr_sub_id_params.append(ast.literal_eval(mydata.get(id)))

        try:
            sendr_sub_id = SubId.objects.get(hostid=sendr_sub_id_param["hostid"], uid=sendr_sub_id_param["uid"], pid=sendr_sub_id_param["pid"])
            sendr_subject = Subject.objects.get(sub_id=sendr_sub_id)
            for rcv_sub_id_param in recvr_sub_id_params:
                rcv_sub_id = SubId.objects.get(hostid=rcv_sub_id_param["hostid"], uid=rcv_sub_id_param["uid"], pid=rcv_sub_id_param["pid"])
                rcv_subject = Subject.objects.get(sub_id=rcv_sub_id)
                recvr_sub_ids.append(rcv_sub_id)
                recvr_subjects.append(rcv_subject)
        except:
            ret["status"] = 0
            ret["errors"] = "Subject not found."
            return Response(ret, status=status.HTTP_404_NOT_FOUND)

        for rcv_sub in recvr_subjects:
            if rcv_sub.admin not in sendr_subject.readers.all():
                ret["status"] = 0
                ret["errors"] = "Receiver process admin missing from sender process readers."
                return Response(ret, status=status.HTTP_404_NOT_FOUND)

        for rcv_sub in recvr_subjects:
            rcv_sub.readers = list(set(rcv_sub.readers.all()) & set(sendr_subject.readers.all()))
            rcv_sub.writers = list(set(rcv_sub.writers.all()) | set(sendr_subject.writers.all()))
            rcv_sub.save()

        ret["status"] = 1
        ret["errors"] = "None"
        return Response(ret, status=status.HTTP_201_CREATED)

