---
tags: [T1613, atomic_test]
filename: "[[T1613 - Container and Resource Discovery]]"
---
# T1613 - Container and Resource Discovery

## Atomic Test #1 - Container and ResourceDiscovery
Adversaries may attempt to discover containers and other resources that are available within a containers environment.

**Supported Platforms:** Containers


**auto_generated_guid:** 8a895923-f99f-4668-acf2-6cc59a44f05e






#### Attack Commands: Run with `sh`! 


```sh
docker build -t t1613  $PathtoAtomicsFolder/T1613/src/
docker run --name t1613_container  -d -t t1613
docker ps
docker stats --no-stream
docker inspect $(docker ps -l -q --filter ancestor=t1613)
```

#### Cleanup Commands:
```sh
docker stop t1613_container
docker rmi -f t1613_container
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
sudo systemctl status docker  --no-pager
```
##### Get Prereq Commands:
```sh
sudo systemctl start docker
```




<br/>
