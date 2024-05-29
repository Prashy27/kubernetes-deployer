#!/bin/bash

sudo mkdir -p /root/.aws

cat <<EOT > /root/.aws/config
    [profile etcdscript]
    role_arn = arn:aws:iam::380349541627:role/avn-s3-etcd-autoscaling-access
    credential_source = Ec2InstanceMetadata
EOT

if [ $(dpkg -l jq | wc -l) -eq 0 ]; then
  sudo apt-get update -y
  sudo apt-get install jq -y
fi

if [ -f /usr/local/bin/cfssl ] && [ -f /usr/local/bin/cfssljson ]; then
        echo "cfssl already exist"
else
        curl -L https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -o /tmp/cfssl
        chmod +x /tmp/cfssl
        sudo mv /tmp/cfssl /usr/local/bin/cfssl
        curl -L https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -o /tmp/cfssljson
        chmod +x /tmp/cfssljson
        sudo mv /tmp/cfssljson /usr/local/bin/cfssljson
fi

if [ -f /usr/local/bin/etcd ] && [ -f /usr/local/bin/etcdctl ]; then
        echo "etcd already installed"
else
        wget https://github.com/coreos/etcd/releases/download/v3.4.7/etcd-v3.4.7-linux-amd64.tar.gz
        tar -xf ./etcd-v3.4.7-linux-amd64.tar.gz
        mv ./etcd-v3.4.7-linux-amd64/etcd /usr/local/bin
        mv ././etcd-v3.4.7-linux-amd64/etcdctl /usr/local/bin
fi
#until here

#etcd auto-scaling starts by collecting required infos
export GET_INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
export GET_HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/local-hostname)
export HOST_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq --raw-output .region)
export SSL_DIR=/etc/ssl/etcd
export KEY_PATH=/etc/ssl/etcd/$GET_HOSTNAME-key.pem
export CERT_PATH=/etc/ssl/etcd/$GET_HOSTNAME.pem
export ETCD_URL=$(aws elb describe-load-balancers --load-balancer-name etcd-av-0001-tst-tst-cluster --region eu-west-1 | jq -c '.[][].DNSName' | sed -e 's/^"//' -e 's/"$//')
export NEW_ETCD_NAME=etcd$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
sleep 1
export GET_INSTANCE_LAUNCHTIME=$(aws ec2 describe-instances --filters Name=instance-id,Values=$GET_INSTANCE_ID --region ${AWS_DEFAULT_REGION} --query Reservations[].Instances[].LaunchTime[] --output text)
sleep 1
export GET_ALL_MASTERS=$(aws ec2 describe-instances --query 'Reservations[].Instances[].{instanceID: InstanceId, ip: NetworkInterfaces[0].PrivateIpAddress, hostName: PrivateDnsName}' --region ${AWS_DEFAULT_REGION} --filters Name=tag-value,Values=etcd Name=instance-state-name,Values=running --output json)
sleep 1
sudo mkdir -p /etc/ssl/etcd/
echo $GET_ALL_MASTERS | jq -c '.[]' | while read i; do
  instance=$(echo $i | jq -c .instanceID)
  instance_ip=$(echo $i | jq -c .ip)
  instance_hostname=$(echo $i | jq -c .hostName | sed -e 's/^"//' -e 's/"$//')
  if [ "\"$GET_INSTANCE_ID\"" != $instance ]; then
    if [ -f /etc/ssl/etcd/etcd-root-ca.pem ] && [ -f /etc/ssl/etcd/etcd-root-ca-key.pem ] && [ -f /etc/ssl/etcd/etcd-gencert.json ]; then
            etcd_root_ca_file=$(cat /etc/ssl/etcd/etcd-root-ca.pem | grep "BEGIN" | wc -l)
            etcd_root_ca_key_file=$(cat /etc/ssl/etcd/etcd-root-ca-key.pem | grep "BEGIN" | wc -l)
            etcd_config=$(cat /etc/ssl/etcd/etcd-gencert.json | grep "ERROR" | wc -l)
            if [ $etcd_root_ca_file -eq 1 ] && [ $etcd_root_ca_key_file -eq 1 ] && [ $etcd_config -ne 1 ]; then
                    echo "breaking loop"
                    break
            fi
    fi
    ETCD_ROOT_CA=$(aws ssm send-command  --targets Key=InstanceIds,Values=$instance  --document-name "AWS-RunShellScript"  --parameters "commands=sudo cat /etc/ssl/etcd/etcd-root-ca.pem" --region ${AWS_DEFAULT_REGION} --query "Command.CommandId" --output text)
    sleep 1
    ETCD_ROOT_CA_KEY=$(aws ssm send-command  --targets Key=InstanceIds,Values=$instance  --document-name "AWS-RunShellScript"  --parameters "commands=sudo cat /etc/ssl/etcd/etcd-root-ca-key.pem" --region ${AWS_DEFAULT_REGION} --query "Command.CommandId" --output text)
    ETCD_CONFIG=$(aws ssm send-command  --targets Key=InstanceIds,Values=$instance  --document-name "AWS-RunShellScript"  --parameters "commands=sudo cat /etc/ssl/etcd/etcd-gencert.json" --region ${AWS_DEFAULT_REGION} --query "Command.CommandId" --output text)
    sleep 1
    ETCD_INSTANCE_JSON=$(aws ssm send-command  --targets Key=InstanceIds,Values=$instance  --document-name "AWS-RunShellScript"  --parameters "commands=sudo cat /etc/ssl/etcd/${instance_hostname}.json" --region ${AWS_DEFAULT_REGION} --query "Command.CommandId" --output text)
    sleep 1
    CP_ETCD_ROOT_CA=$(aws ssm list-command-invocations --command-id "$ETCD_ROOT_CA" --details --query "CommandInvocations[*].CommandPlugins[*].Output[]" --region ${AWS_DEFAULT_REGION} --output text > $SSL_DIR/etcd-root-ca.pem)
    CP_ETCD_ROOT_CA_KEY=$(aws ssm list-command-invocations --command-id "$ETCD_ROOT_CA_KEY" --details --query "CommandInvocations[*].CommandPlugins[*].Output[]" --region ${AWS_DEFAULT_REGION} --output text > $SSL_DIR/etcd-root-ca-key.pem)
    CP_ETCD_CONFIG=$(aws ssm list-command-invocations --command-id "$ETCD_CONFIG" --details --query "CommandInvocations[*].CommandPlugins[*].Output[]" --region ${AWS_DEFAULT_REGION} --output text > $SSL_DIR/etcd-gencert.json)
    CP_ETCD_INSTANCE_JSON=$(aws ssm list-command-invocations --command-id "$ETCD_INSTANCE_JSON" --details --query "CommandInvocations[*].CommandPlugins[*].Output[]" --region ${AWS_DEFAULT_REGION} --output text > $SSL_DIR/$GET_HOSTNAME.json)
    sudo sed -i '${/^$/d;}' $SSL_DIR/etcd-gencert.json
    sudo sed -i '${/^$/d;}' $SSL_DIR/etcd-root-ca.pem
    sudo sed -i '${/^$/d;}' $SSL_DIR/etcd-root-ca-key.pem
    sudo sed -i '${/^$/d;}' $SSL_DIR/$GET_HOSTNAME.json
    sudo sed -i -E "s/ip-.*.compute.internal/${GET_HOSTNAME}/" $SSL_DIR/$GET_HOSTNAME.json
  fi
done

#generate a cert with existing root-ca and host IPs
cfssl gencert --ca $SSL_DIR/etcd-root-ca.pem --ca-key $SSL_DIR/etcd-root-ca-key.pem --config $SSL_DIR/etcd-gencert.json $SSL_DIR/$GET_HOSTNAME.json | cfssljson --bare $SSL_DIR/$GET_HOSTNAME

#get the list of etcd cluster members
member_list=$(ETCDCTL_API=3 etcdctl --endpoints https://${ETCD_URL}:2379 --cacert ${SSL_DIR}/etcd-root-ca.pem --cert ${SSL_DIR}/$GET_HOSTNAME.pem --key ${SSL_DIR}/$GET_HOSTNAME-key.pem member list -w json)

#identify existing good and bad members
bad_members=""
existing_peer_urls="$NEW_ETCD_NAME=https://${HOST_IP}:2380"
existing_peer_names=""
existing_peer_ips="\"$HOST_IP\""

while read i; do
          peer_url=$(echo $i | jq -c '.peerURLs[]' | sed -e 's/^"//' -e 's/"$//')
          client_url=$(echo $i | jq -c '.clientURLs[]' | sed -e 's/^"//' -e 's/"$//')
          name=$(echo $i | jq -c '.name' | sed -e 's/^"//' -e 's/"$//')
          #check health of each node in the etcd cluster
          health_check=$(ETCDCTL_API=3 etcdctl --endpoints $client_url --cacert ${SSL_DIR}/etcd-root-ca.pem --cert ${SSL_DIR}/$GET_HOSTNAME.pem --key ${SSL_DIR}/$GET_HOSTNAME-key.pem endpoint health 2>&1)
          peer_ip=$(echo $client_url | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}')
          existing_peer_ips="${existing_peer_ips}${existing_peer_ips:+,\"}${peer_ip}\""
          status=$(echo $health_check | grep -iw "is healthy:" | wc -l )
          if [ $status -ne 1 ]; then
                #if a node health is returned unhealthy then that node will be removed from the cluster.
                  member_id=$(ETCDCTL_API=3 etcdctl --endpoints https://${ETCD_URL}:2379 --cacert ${SSL_DIR}/etcd-root-ca.pem --cert ${SSL_DIR}/$GET_HOSTNAME.pem --key ${SSL_DIR}/$GET_HOSTNAME-key.pem member list | grep "${client_url}" | awk -F"," '{print $1}')
                  echo "Bad Member ID: $member_id"
                  res=$(ETCDCTL_API=3 etcdctl --endpoints https://${ETCD_URL}:2379 --cacert ${SSL_DIR}/etcd-root-ca.pem --cert ${SSL_DIR}/$GET_HOSTNAME.pem --key ${SSL_DIR}/$GET_HOSTNAME-key.pem member remove $member_id 2>&1)
                  bad_members="${bad_members}${bad_members:+,}${client_url}"
                  sudo sed -i -E "s/${peer_ip}/\"${HOST_IP}\"/" $SSL_DIR/$GET_HOSTNAME.json
                  echo "$res (${client_url})"
          fi
          if [[ $client_url != *$bad_members* || -z $bad_members ]]; then
                #after bad members are removed, remaining nodes are added to existing peer urls variable
                  existing_peer_urls=${existing_peer_urls}${existing_peer_urls:+,}${name}=${peer_url}
                  existing_peer_names=${existing_peer_names}${existing_peer_names:+,}${name}
          fi
done < <(echo $member_list | jq -c '.members[]')

export existing_peer_ips=$existing_peer_ips
#add new node to the existing cluster
if [[ $existing_peer_urls && $HOST_IP != *$existing_peer_urls* ]]; then
        aws s3 cp s3://avn-appcloud-etcd-script/host-cert-template.json /tmp/host-cert-template.json --profile etcdscript
        rm $SSL_DIR/$GET_HOSTNAME.json
        /usr/bin/envsubst < /tmp/host-cert-template.json > $SSL_DIR/$GET_HOSTNAME.json
        echo "joining existing cluster"
        cfssl gencert --ca $SSL_DIR/etcd-root-ca.pem --ca-key $SSL_DIR/etcd-root-ca-key.pem --config $SSL_DIR/etcd-gencert.json $SSL_DIR/$GET_HOSTNAME.json | cfssljson --bare $SSL_DIR/$GET_HOSTNAME
      #first add the member to the cluster
        add=$(ETCDCTL_API=3 etcdctl --endpoints https://${ETCD_URL}:2379 --cacert ${SSL_DIR}/etcd-root-ca.pem --cert ${SSL_DIR}/$GET_HOSTNAME.pem --key ${SSL_DIR}/$GET_HOSTNAME-key.pem member add ${NEW_ETCD_NAME} --peer-urls=https://${HOST_IP}:2380)
        echo "$add (${HOST_IP})"
        export ETCD_NAME=$NEW_ETCD_NAME
        export ETCD_INITIAL_CLUSTER=$existing_peer_urls
        export ETCD_INITIAL_CLUSTER_STATE=existing

      #start etcd process in the background
        nohup etcd --listen-client-urls https://${HOST_IP}:2379,https://127.0.0.1:2379 --advertise-client-urls https://${HOST_IP}:2379 --listen-peer-urls https://${HOST_IP}:2380 --initial-advertise-peer-urls https://${HOST_IP}:2380 --client-cert-auth --trusted-ca-file ${SSL_DIR}/etcd-root-ca.pem --cert-file ${SSL_DIR}/$GET_HOSTNAME.pem --key-file ${SSL_DIR}/$GET_HOSTNAME-key.pem --peer-client-cert-auth --peer-trusted-ca-file ${SSL_DIR}/etcd-root-ca.pem --peer-cert-file ${SSL_DIR}/$GET_HOSTNAME.pem --peer-key-file ${SSL_DIR}/$GET_HOSTNAME-key.pem &
        echo "Added member: $HOST_IP"
fi