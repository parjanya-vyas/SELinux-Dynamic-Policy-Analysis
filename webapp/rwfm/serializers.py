#from django.forms import widgets
from rest_framework import serializers
from rwfm.models import Id, SubId, ObjId, UserId, GroupId, SockId, KeyId, Addr, Connection

class SubIdSerializer(serializers.Serializer):
    hostid = serializers.CharField()
    uid = serializers.CharField()
    pid = serializers.IntegerField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        subid, created =  SubId.objects.get_or_create(**validated_data)
        return subid

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.uid = validated_data.get('uid', instance.uid)
        instance.pid = validated_data.get('pid', instance.pid)

        instance.save()
        return instance

class UserIdSerializer(serializers.Serializer):
    hostid = serializers.CharField()
    uid = serializers.CharField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        userid, created =  UserId.objects.get_or_create(**validated_data)
        return userid

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.uid = validated_data.get('uid', instance.uid)

        instance.save()
        return instance

class ObjIdSerializer(serializers.Serializer):
    hostid = serializers.CharField()
    devid = serializers.CharField()
    inum = serializers.IntegerField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        objid, created =  ObjId.objects.get_or_create(**validated_data)
        return objid, created

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.devid = validated_data.get('devid', instance.uid)
        instance.inum = validated_data.get('inum', instance.pid)

        instance.save()
        return instance

class TypeListSerializer(serializers.Serializer):
    selinux_type = serializers.CharField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        typeid, created =  TypeList.objects.get_or_create(**validated_data)
        return typeid, created

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.selinux_type = validated_data.get('selinux_type', instance.selinux_type)

        instance.save()
        return instance

class KeyIdSerializer(serializers.Serializer):
    hostid = serializers.CharField()
    key_id = serializers.IntegerField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        print validated_data, "\n"
        key_id, created = KeyId.objects.get_or_create(**validated_data)
        return key_id, created

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.keyid = validated_data.get('keyid', instance.keyid)

        instance.save()
        return instance

class GroupIdSerializer(serializers.Serializer):
    hostid = serializers.CharField()
    gid = serializers.CharField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        gid, created =  GroupId.objects.get_or_create(**validated_data)
        return gid

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.uid = validated_data.get('gid', instance.gid)

        instance.save()
        return instance

#class SubjectSerializer(serializers.Serializer):
#    sub_id = SubIdSerializer()
#    admin = SubIdSerializer()
#    readers = SubIdSerializer(many=True)
#    writers = SubIdSerializer(many=True)
#
#    def create(self, validated_data):
#        """
#        Create and return a new `Snippet` instance, given the validated data.
#        """
#        subject =  Subject.objects.create(**validated_data)
#        return subject
#
#    def update(self, instance, validated_data):
#        """
#        Update and return an existing `Snippet` instance, given the validated data.
#        """
        #instance.hostid = validated_data.get('hostid', instance.hostid)
        #instance.uid = validated_data.get('uid', instance.uid)
        #instance.pid = validated_data.get('pid', instance.pid)

#        instance.save()
#        return instance

class SockIdSerializer(serializers.Serializer):
    hostid = serializers.CharField()
    uid = serializers.CharField()
    pid = serializers.IntegerField()
    fd = serializers.IntegerField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        sockid, created =  SockId.objects.get_or_create(**validated_data)
        return sockid

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """
        instance.hostid = validated_data.get('hostid', instance.hostid)
        instance.uid = validated_data.get('uid', instance.uid)
        instance.pid = validated_data.get('pid', instance.pid)
        instance.fd = validated_data.get('pid', instance.fd)

        instance.save()
        return instance

class AddrSerializer(serializers.Serializer):
    sock_id = SockIdSerializer()
    ip = serializers.CharField()
    port = serializers.IntegerField()

    def create(self, validated_data):
        """
        Create and return a new `Snippet` instance, given the validated data.
        """
        s = validated_data.pop('sock_id')
        sock_id =  SockId.objects.get(**s)
        addr, created =  Addr.objects.get_or_create(sock_id=sock_id, **validated_data)
        return addr

    def update(self, instance, validated_data):
        """
        Update and return an existing `Snippet` instance, given the validated data.
        """

        instance.save()
        return instance

class ConnectionSerializer(serializers.Serializer):
    server = SockIdSerializer()
    client = SockIdSerializer()

    def create(self, validated_data):
        """
        Create and return a new `Connection` instance, given the validated data.
        """
        s = validated_data.pop('server')
        c = validated_data.pop('client')
        server_sock, created =  SockId.objects.get_or_create(**s)
        client_sock, created =  SockId.objects.get_or_create(**c)
        connection, created =  Connection.objects.get_or_create(server=server_sock, client=client_sock)
        return connection

    def update(self, instance, validated_data):
        """
        Update and return an existing `Connection` instance, given the validated data.
        Need to find when this gets called. Though it is not stopping the work currently.
        Also needs to be implemented when only client or server are passed.
        """
        instance.save()
        return instance

