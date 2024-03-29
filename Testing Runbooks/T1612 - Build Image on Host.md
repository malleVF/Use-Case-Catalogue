---
tags: [T1612, atomic_test]
filename: "[[T1612 - Build Image on Host]]"
---
# T1612 - Build Image on Host

## Atomic Test #1 - Build Image On Host
Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. An adversary may take advantage of that build API to build a custom image on the host that includes malware downloaded from their C2 server, and then they then may utilize Deploy Container using that custom image.

**Supported Platforms:** Containers


**auto_generated_guid:** 2db30061-589d-409b-b125-7b473944f9b3






#### Attack Commands: Run with `sh`! 


```sh
docker build -t t1612  $PathtoAtomicsFolder/T1612/src/
docker run --name t1612_container  -d -t t1612
docker exec t1612_container ./test.sh
```

#### Cleanup Commands:
```sh
docker stop t1612_container
docker rmi -f t1612
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
