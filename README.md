
# Deploy Wazuh Server over Tailscale with Ansible

This doc guides through provisioning a VM for the Wazuh server, enrolling it in a Tailscale Mesh network, then using a remote ansible node to install Docker and deploy the latest Wazuh-Docker repository over the Tailscale VPN.

## Step 1 - Provision VM for Wazuh Server

First, provision a VM for the Wazuh server. These are the recommended specifications:

- 8 vCPUs
- 8 GB RAM
- 1 TB Free Disk Space

## Step 2 - Install Tailscale on target VM and enroll VM in network

Once your VM is initialized, use the following command to install Tailscale:

`curl -fsSL https://tailscale.com/install.sh | sh`

Then use the generated link to enroll the VM in your Tailnet.

***Once enrolled in the Tailnet, make sure to add the VM's tailscale IP to your Ansible Hosts file***

## Step 3 - Create a Service account for Ansible Script

Create an additional user that can perform nopassword sudo actions. This user will be used for the ansible script and can be disabled after a successful installation.

Add the user:

```
useradd -m <user name>
```

Set User password:

```
passwd <user>
```

Set up user in Sudoers.d with NOPASSWORD for Ansible automation:

```
echo "<USER> ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/<USER>
```

Once you have established SSH access to the VM for both our administrative and service account, for maximum security it is recommended to enable SSH via keys in a secure vault and disable password authentication in the SSH config.

You can generate an ssh key using `ssh-keygen` and copy it to the VM using `ssh-copy-id`

on systems that do not support `ssh-copy-id`, or if you are working with a vault that leverages `ssh-add -L` this command will work as well (althought you might want to run `ssh-add -L` on its own to get the key name first):

```
ssh <VM USER>@<VM IP> "echo $(ssh-add -L | grep <KEY NAME>) >> ~/.ssh/authorized_keys"
```

After adding the SSH to the VM, test SSH with the key instead of the password to ensure that adding the key was successful.

***To Disable Password Authentication for SSH on Ubuntu Server, uncomment the following lines and make the edits below to the ssh_config, sshd_config, and 50-init-cloud files in /etc/ssh***

**ssh_config**

```
   ...
   PasswordAuthentication no
   ...
   GSSAPIAuthentication no
```

**sshd_config**

```
   ...
   PermitRootLogin no
   ...
   PasswordAuthentication no
   PermitEmptyPasswords no
   ...
   UsePAM no
```

**sshd_config.d/50-cloud-init.conf**  *this one is easy to miss*

```
PasswordAuthentication no
```

Now you can restart the ssh service or reboot, and test that you have successfully disabled password authentication. 

***Once you have set up SSH keys for the service account, make sure they are accessible to the Hosts file, either by path or vault injection***
## Step 4 - Define Wazuh Version to be deployed

*Note that this playbook is to be run from this repo located on the Ansible Control Node in `/etc/ansible/wazuh-docker-ansible/`, if you want to run them elsewhere change the paths in the provided ansible playbook*

The playbook will clone the Wazuh-Docker repo to the target VM for installation. 

Consult Wazuh's Docker Documentation to get the latest release: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html

The latest wazuh-docker release is v4.7.0 at time of writing.

If necessary, update the recommended branch from Wazuh's documentation in the "version" argument in this section of the playbook:

```
# clone latest git repository from wazuh github
    - name: clone remote wazuh-docker repository
      ansible.builtin.git:
        repo: https://github.com/wazuh/wazuh-docker.git
        dest: /etc/wazuh/wazuh-docker
        single_branch: yes
        version: v4.7.0
```
## Step 5 - If possible, Snapshot Target VM 

If your environment supports snapshots, it is a good idea at this point to snapshot the VM to roll back to a known good state in the event the installation fails in Step 6.

Consult your hypervisor or system documentation for how to snapshot.
## Step 6 - Test Ansible Connection to Target VM and run Playbook

To test the connection to the target VM from the ansible control node run:

*in this care the group name is "Siem"*

```
ansible -m ping <group name from hosts file>
```

If the connection is successful, run the docker installation playbook with:

*Note that this playbook requires the `install-docker.sh` script at the root of the repo directory*

To run the playbook to install docker, docker-compose, and copy the wazuh-docker repo to the remote machine for deployment run:

```
ansible-playbook -vvv git-build-install-docker-wazuh.yml
```

***Note, if you are not building the images locally and experience 404 errors double check that you set the branch to stable before zip and deployment***

## Step 6 - Change default passwords

Refer to the Wazuh documentation to harden the password of the admin, kibana, and api user:

https://documentation.wazuh.com/4.4/deployment-options/docker/wazuh-container.html#change-pwd-existing-usr
## Step 7 - Disable the service account created for Wazuh Deployment

to disable the nopassword account created for ansible until needed later, run:

```
sudo usermod <USER> -s /sbin/nologin
```



