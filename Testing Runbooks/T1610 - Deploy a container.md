---
tags: [T1610, atomic_test]
filename: "[[T1610 - Deploy a container]]"
---
# T1610 - Deploy a container

## Atomic Test #1 - Deploy Docker container
Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime. They can do this using docker create and docker start commands. Kinsing & Doki was exploited using this technique.

**Supported Platforms:** Containers


**auto_generated_guid:** 59aa6f26-7620-417e-9318-589e0fb7a372






#### Attack Commands: Run with `bash`! 


```bash
docker build -t t1610 $PathtoAtomicsFolder/T1610/src/
docker run --name t1610_container --rm -itd t1610 bash /tmp/script.sh
```

#### Cleanup Commands:
```bash
docker stop t1610_container
docker rmi -f t1610:latest
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
