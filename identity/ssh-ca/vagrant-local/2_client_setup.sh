#!/usr/bin/env bash

# Create ssh key pair
ssh-keygen -f /home/vagrant/.ssh/id_rsa -t rsa -N ''

# Authenticate to Vault
vault login -method=userpass username=johnsmith password=test

sudo rm /home/vagrant/.ssh/id_rsa-cert.pub
cat /home/vagrant/.ssh/id_rsa.pub | \
  vault write -format=json ssh-client-signer/sign/clientrole valid_principals=johnsmith public_key=- \
  | jq -r '.data.signed_key' > /home/vagrant/.ssh/id_rsa-cert.pub

sudo chmod 0400 /home/vagrant/.ssh/id_rsa-cert.pub

echo "To use the new cert you can use the following command"
echo "ssh vault"
#ssh -i /home/vagrant/.ssh/id_rsa -i /home/vagrant/.ssh/id_rsa-cert.pub johnsmith@vault
