from django.conf.urls import patterns, include, url
from rwfm import views

urlpatterns = patterns('',
    url(r'^rwfm/$', views.home),
    url(r'^rwfm/reset/$', views.reset),

    url(r'^rwfm/users/$', views.user_list),
    url(r'^rwfm/groups/$', views.group_list),
    url(r'^rwfm/add/user/$', views.add_user),
    url(r'^rwfm/add/group/$', views.add_group),

    url(r'^rwfm/add/types/$', views.initialize_type_labels),

    url(r'^rwfm/subject_present/$', views.subject_present),
    url(r'^rwfm/subjects/$', views.subject_list),
    #url(r'^rwfm/sub_details/$', views.subject_details),
    url(r'^rwfm/add/s/$', views.add_subject),
    url(r'^rwfm/delete/s/$', views.delete_subject),
    url(r'^rwfm/subject_detail/$', views.subject_detail),

    url(r'^rwfm/type_detail/$', views.type_detail),

    url(r'^rwfm/create/o/$', views.create_object),
    url(r'^rwfm/objects/$', views.object_list),
    #url(r'^rwfm/obj_details/$', views.object_details),
    url(r'^rwfm/add/o/$', views.add_object),
    url(r'^rwfm/delete/o/$', views.delete_object),
    url(r'^rwfm/object_detail/$', views.object_detail),

    url(r'^rwfm/create/k/$', views.create_key),
    url(r'^rwfm/shmat/$', views.shmat),
    url(r'^rwfm/shmdt/$', views.shmdt),
    url(r'^rwfm/shmctl/$', views.shmctl),
    url(r'^rwfm/keys/$', views.key_list),
    #url(r'^rwfm/add/k/$', views.add_key),
    url(r'^rwfm/delete/k/$', views.delete_key),
    url(r'^rwfm/key_detail/$', views.key_detail),

    url(r'^rwfm/write/$', views.write_auth),
    url(r'^rwfm/read/$', views.read_auth),
    url(r'^rwfm/rdwr/$', views.rdwr_auth),
    url(r'^rwfm/downgrade/$', views.downgrade_object),
    url(r'^rwfm/upgrade/$', views.upgrade_object),
    #url(r'^rwfm/read/(?P<sub_id>\w+)/(?P<obj_id>\w+)/$', views.read_auth),
    #url(r'^rwfm/write/(?P<sub_id>\w+)/(?P<obj_id>\w+)/$', views.write_auth),

    url(r'^rwfm/create/sock/$', views.create_socket),
    url(r'^rwfm/sockets/$', views.socket_list),
    url(r'^rwfm/delete/sock/$', views.delete_socket),
    url(r'^rwfm/socket_detail/$', views.socket_detail),

    url(r'^rwfm/create/address/$', views.create_address),
    url(r'^rwfm/delete/address/$', views.delete_address),
    url(r'^rwfm/addresses/$', views.address_list),

    url(r'^rwfm/bind/$', views.bind),
    url(r'^rwfm/connect/$', views.connect),
    url(r'^rwfm/accept/$', views.accept),
    url(r'^rwfm/send/$', views.send),
    url(r'^rwfm/receive/$', views.receive),
    url(r'^rwfm/connections/$', views.connection_list),

    url(r'^rwfm/kill/$', views.kill),
    url(r'^rwfm/kill_many/$', views.kill_many),
)
