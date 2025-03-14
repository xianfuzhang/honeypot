
## Docker build
```sh
cd honeypot

sudo docker build -t honeypot:0.1.0 .
```

## Kubernetes deploy
```sh
cd honeypot/examples

kubectl apply -f vnet.yaml
kubectl apply -f attack-subnet.yaml
kubectl apply -f defence-subnet.yaml
kubectl apply -f sniff-deployment.yaml
kubectl apply -f spoof-deployment.yaml
```
### Logical Switch Port promisc mode
在OVN网络中，pod开启混杂模式后，才能发送ARP、ICMP响应报文。开启混杂方式可通过YAML方法或者直接在OVN数据库中修改

YAML开启
```sh
apiVersion: v1
Kind: Pod
metadata:
  name: promisc-pod
  annotations:
    k8s.ovn.org/pod-networks: '{"default":{"promisc":true}}'
```
修改OVN数据库
```sh
// addresses栏位设置unknow
ovn-nbctl set Logical_Switch_Port port_name addresses='"unknown"'
// port_security栏位设置[]
ovn-nbctl set Logical_Switch_Port port_name port_security=[]
```
