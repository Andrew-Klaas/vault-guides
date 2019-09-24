#!/usr/bin/env bash

# Authenticate to Vault
vault login password

vault audit enable file file_path=/vagrant/vault_audit.log

# Mount a backend's instance for signing host keys
vault secrets enable -path ssh-host-signer ssh

# Mount a backend's instance for signing client keys
vault secrets enable -path ssh-client-signer ssh

# Configure the client CA certificate
vault write -f -format=json ssh-client-signer/config/ca | jq -r '.data.public_key' >>  /home/vagrant/trusted-user-ca-keys.pem

sudo mv /home/vagrant/trusted-user-ca-keys.pem /etc/ssh/trusted-user-ca-keys.pem
echo "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem" | sudo tee --append /etc/ssh/sshd_config

# Allow host certificate to have longer TTLs
vault secrets tune -max-lease-ttl=87600h ssh-host-signer

# Create a role to sign host keys
vault write ssh-host-signer/roles/hostrole ttl=87600h \
  allow_host_certificates=true \
  key_type=ca \
  allowed_domains="localdomain,example.com" \
  allow_subdomains=true

 
echo '
{
    "allow_user_certificates": true,
    "allowed_users": "*",
    "default_user": "",
    "default_extensions": [
      {
        "permit-pty": ""
      }
    ],
    "key_type": "ca",
    "key_id_format": "vault-{{role_name}}-{{token_display_name}}-{{public_key_hash}}",
    "allow_user_key_ids": true,
    "ttl": "30m0s"
}' >> /home/vagrant/clientrole.json

# Create a role to sign client keys
vault write ssh-client-signer/roles/clientrole @/home/vagrant/clientrole.json

# Restart sshd
sudo systemctl restart sshd

echo '
path "sys/mounts" {
  capabilities = ["list","read"]
}
path "ssh-client-signer/sign/clientrole" {
  capabilities = ["create", "update"]
}' | vault policy write user -

vault auth enable userpass
vault write auth/userpass/users/johnsmith password=test policies=user

#Sentinel
cat <<EOF>> ssh-username-restrict.sentinel
import "strings"
username_match = func() {
    # Make sure there is request data
    if length(request.data else 0) is 0 {
        return false
    }
    # Make sure request data includes username
    if length(request.data.valid_principals else 0) is 0 {
        return false
    }
    # Make sure the supplied username matches the user's name
    if request.data.valid_principals != identity.entity.aliases[0].name {
       return false
    }
    return true
}
main = rule {
    strings.has_prefix(request.path, "ssh-client-signer/sign/clientrole") and username_match()
}
EOF


POLICY=$(base64 ssh-username-restrict.sentinel); vault write sys/policies/egp/ssh-username-restrict \
        policy="${POLICY}" \
        paths="ssh-client-signer/sign/clientrole" \
        enforcement_level="hard-mandatory"

sudo adduser johnsmith
sudo mkdir /home/johnsmith/.ssh
sudo chown -R johnsmith:johnsmith /home/johnsmith/.ssh
sudo chmod 0700 /home/johnsmith/.ssh
sudo touch /home/johnsmith/.ssh/authorized_keys
sudo chmod 0600 /home/johnsmith/.ssh/authorized_keys
