from django.db import models
from polymorphic import PolymorphicModel

# Create your models here.

class Id(PolymorphicModel):
    hostid = models.TextField()

class KeyId(Id):
    key_id = models.IntegerField()

    #class Meta:
    #    unique_together = ('hostid', 'keyid',)

    def __unicode__(self):
        return '%s %s' % (self.hostid, self.key_id)

class ObjId(Id):
    devid = models.TextField()
    inum = models.IntegerField()

    #class Meta:
    #    unique_together = ('hostid', 'devid', 'inum',)

    def __unicode__(self):
        return '%s %s %s' % (self.hostid, self.devid, self.inum)

class UserId(Id):
    uid = models.TextField()

    #class Meta:
    #    unique_together = ('hostid', 'uid', 'pid',)

    def __unicode__(self):
        return '%s %s' % (self.hostid, self.uid)

class SubId(Id):
    uid = models.TextField()
    pid = models.IntegerField()

    #class Meta:
    #    unique_together = ('hostid', 'uid', 'pid',)

    def __unicode__(self):
        return '%s %s %s' % (self.hostid, self.uid, self.pid)

class GroupId(Id):
    gid = models.TextField()
    members = models.ManyToManyField(UserId, related_name='user_groups', blank=True, null=True)

    #class Meta:
    #    unique_together = ('hostid', 'gid')

    def __unicode__(self):
        return '%s %s' % (self.hostid, self.gid)

class Key(models.Model):
    keyid = models.ForeignKey(KeyId, related_name='+')
    admin = models.ForeignKey(UserId, related_name='+')
    readers = models.ManyToManyField(UserId, related_name='key_readers', blank=True, null=True)
    writers = models.ManyToManyField(UserId, related_name='key_writers', blank=True, null=True)
    refcount = models.IntegerField()

    class Meta:
        ordering = ('keyid',)

class ShmMap(models.Model):
    subid = models.ForeignKey(SubId, related_name='subject')
    keyid = models.ForeignKey(KeyId, related_name='key')
    shmid = models.IntegerField()
    shmaddr = models.TextField()

class TypeList(models.Model):
    selinux_type = models.TextField()

class TypeObject(models.Model):
    type_obj_id = models.ForeignKey(TypeList, related_name='+')
    type_readers = models.ManyToManyField(TypeList, related_name='type_object_readers', blank=True, null=True)
    type_writers = models.ManyToManyField(TypeList, related_name='type_object_writers', blank=True, null=True)

class TypeSubject(models.Model):
    type_sub_id = models.ForeignKey(TypeList, related_name='+')
    type_readers = models.ManyToManyField(TypeList, related_name='type_subject_readers', blank=True, null=True)
    type_writers = models.ManyToManyField(TypeList, related_name='type_subject_writers', blank=True, null=True)

class Object(models.Model):
    obj_id = models.ForeignKey(ObjId, related_name='+')
    admin = models.ForeignKey(UserId, related_name='+')
    readers = models.ManyToManyField(UserId, related_name='object_readers', blank=True, null=True)
    writers = models.ManyToManyField(UserId, related_name='object_writers', blank=True, null=True)

    class Meta:
        ordering = ('obj_id',)

class Subject(models.Model):
    sub_id = models.ForeignKey(SubId, related_name='+')
    admin = models.ForeignKey(UserId, related_name='+')
    readers = models.ManyToManyField(UserId, related_name='subject_readers', blank=True, null=True)
    writers = models.ManyToManyField(UserId, related_name='subject_writers', blank=True, null=True)

    class Meta:
        ordering = ('sub_id',)

class SockId(Id):
    uid = models.TextField()
    pid = models.IntegerField()
    fd = models.IntegerField()

    def __unicode__(self):
        return '%s %s %s %s' % (self.hostid, self.uid, self.pid, self.fd)

class Socket(models.Model):
    sock_id = models.ForeignKey(SockId, related_name='+')
    admin = models.ForeignKey(UserId, related_name='+')
    readers = models.ManyToManyField(UserId, related_name='socket_readers', blank=True, null=True)
    writers = models.ManyToManyField(UserId, related_name='socket_writers', blank=True, null=True)

    class Meta:
        ordering = ('sock_id',)

class Addr(models.Model):
    sock_id = models.ForeignKey(SockId, related_name='sock_id')
    ip = models.TextField()
    port = models.IntegerField()

    def __unicode__(self):
        return '%s %s' % (self.ip, self.port)

class Connection(models.Model):
    server = models.ForeignKey(SockId, related_name='server')
    client = models.ForeignKey(SockId, related_name='client')
    readers = models.ManyToManyField(UserId, related_name='connection_readers', blank=True, null=True)
    writers = models.ManyToManyField(UserId, related_name='connection_writers', blank=True, null=True)

