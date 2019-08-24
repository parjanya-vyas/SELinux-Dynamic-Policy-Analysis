#!/bin/bash
export USE_RWFM=0
export hexNum=`hostid`
export HOSTID=`printf "%d" 0x${hexNum}`
export HOSTNAME=`hostname`

update_users(){
    for i in `seinfo -t | tail -n+3`
    do
        data="{ \"hostid\" : \"${HOSTNAME}\", \"uid\" : \"${i}\" }"
        #echo $data
        curl -H "Content-type: application/json" -X POST -d "$data" "$user_url" && echo "${i} : user added" || echo "${i} : user add failed"
    done
}

update_groups(){
    for g in `cat /etc/group | awk -F: '{print $3}'`
    do
        members=
        for u in `grep -w $g /etc/group | awk -F: '{print $4}'|sed -e 's/,/ /g'`
        do
            if [[ $members ]]
            then
                members="$members, "`id -u $u`
            else
                members=`id -u $u`
            fi
        done

        if [[ ! $members ]]
        then
            members=`grep -w $g /etc/passwd | awk -F: '{print $3}'`
        fi

        data="{ \"hostid\" : \"${HOSTNAME}\", \"gid\" : \"${g}\", \"members\" : \"${members}\" }"
        #echo $data
        curl -H "Content-type: application/json" -X POST -d "$data" "$group_url" && echo "${i} : group added" || echo "${i} : group add failed"
    done
}

init_types(){
        curl -H "Content-type: application/json" -X POST -d " " "$type_url"
}

#
# Main starts here..
#

config_file="rwfmd.cfg"
if [[ ! -f $config_file ]];then
    echo "$config_file missing!"
    exit 1
fi

webhost=`cat $config_file | grep -w webhost | awk -F: '{print $2}' | sed -e 's/[", ]//g'`
webport=`cat $config_file | grep -w webport | awk -F: '{print $2}' | sed -e 's/[", ]//g'`
rwfmd_port=`cat $config_file | grep rwfmd_port | awk -F: '{print $2}' | sed -e 's/[",]//g' | awk '{print $1}'`
baseurl="http://$webhost:$webport/rwfm"
group_url="$baseurl/add/group/"
user_url="$baseurl/add/user/"
type_url="$baseurl/add/types/"
echo $group_url
echo $user_url

rm -f preload.so preload.h
make || {
        echo "failed to build preload library."
        exit 1
}
echo "library built"

mkdir -p /lib/secos/
cp preload.so /lib/secos/
echo "library copied"

mkdir -p /opt/secos/bin/
cp daemon.py rwfmd.py rwfm secure_shell /opt/secos/bin/
chmod +x /opt/secos/bin/*
cp rwfmd.cfg /etc/

export PATH=$PATH:/opt/secos/bin/

python /opt/secos/bin/rwfmd.py restart || {
        echo "failed to start daemon."
        exit 1
}
echo "daemon started"

update_users || {
        echo "failed to update users in webapp."
        exit 1
}

echo
echo "users added"
echo

#update_groups || {
#        echo "failed to update groups in webapp."
#        exit 1
#}

#echo
#echo "groups added"
#echo

init_types || {
        echo "failed to initialize types in webapp."
        exit 1
}

echo
echo "types initialized"
echo

exit 0

