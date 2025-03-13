
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
