include .env
.PHONY: pre_build base_build mk-config mk-start mk-stop mk-delete mk-restart mk-registry mk-up mk-build mk-setup

# define some variables
IMG_PREFIX=bgds-k8s
CONTAINER_NAMES=elastic logstash kibana
VOLUME_NAMES=elasticsearch-data postgres-data redis_data
IMAGE_NAMES=${IMG_PREFIX}-redis:latest ${IMG_PREFIX}-rediscommander:latest ${IMG_PREFIX}-elastic:${ELK_VERSION} ${IMG_PREFIX}-logstash:${ELK_VERSION} ${IMG_PREFIX}-kibana:${ELK_VERSION}

# generate and verify all necessary certificates
pre_build:
	KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD} ELASTIC_PASSWORD=${ELASTIC_PASSWORD} ELASTIC_INTERNAL=${ELASTIC_INTERNAL} ELASTICSEARCH_HOST=${ELASTICSEARCH_HOST} bash docker/scripts/gen_certs.sh


base_build:
	@echo "----------------- Kill any existing port-forward processes -------------------"
	@ps aux | grep "kubectl port-forward.*registry" | grep -v grep | awk '{print $$2}' | xargs -r kill || true

	@echo "----------------- Starting fresh port-forward -------------------"
	@kubectl port-forward -n default svc/registry 5000:5000 &
	@echo "Waiting for port-forward to establish..."
	@sleep 5

	@echo "----------------- Testing registry connection -------------------"
	@curl -s http://localhost:5000/v2/ || { echo "Registry connection failed! Check port-forward."; exit 1; }

	@echo "----------------- Creating and pushing base images to local registry -------------------"
	# Elasticsearch
	docker pull docker.elastic.co/elasticsearch/elasticsearch:${ELK_VERSION}
	echo "FROM docker.elastic.co/elasticsearch/elasticsearch:${ELK_VERSION}" | docker build -t elk/elastic-elk:${ELK_VERSION} -f - .
	docker tag elk/elastic-elk:${ELK_VERSION} localhost:5000/elk/elastic-elk:${ELK_VERSION}
	docker push localhost:5000/elk/elastic-elk:${ELK_VERSION}

	# Logstash
	docker pull docker.elastic.co/logstash/logstash:${ELK_VERSION}
	echo "FROM docker.elastic.co/logstash/logstash:${ELK_VERSION}" | docker build -t elk/logstash-elk:${ELK_VERSION} -f - .
	docker tag elk/logstash-elk:${ELK_VERSION} localhost:5000/elk/logstash-elk:${ELK_VERSION}
	docker push localhost:5000/elk/logstash-elk:${ELK_VERSION}

	# Kibana
	docker pull docker.elastic.co/kibana/kibana:${ELK_VERSION}
	echo "FROM docker.elastic.co/kibana/kibana:${ELK_VERSION}" | docker build -t elk/kibana-elk:${ELK_VERSION} -f - .
	docker tag elk/kibana-elk:${ELK_VERSION} localhost:5000/elk/kibana-elk:${ELK_VERSION}
	docker push localhost:5000/elk/kibana-elk:${ELK_VERSION}

	# Redis
	docker pull redis:latest
	echo "FROM redis:latest" | docker build -t elk/redis-elk:latest -f - .
	docker tag elk/redis-elk:latest localhost:5000/elk/redis-elk:latest
	docker push localhost:5000/elk/redis-elk:latest

	# Redis Commander
	docker pull rediscommander/redis-commander:latest
	echo "FROM rediscommander/redis-commander:latest" | docker build -t elk/redis-commander-elk:latest -f - .
	docker tag elk/redis-commander-elk:latest localhost:5000/elk/redis-commander-elk:latest
	docker push localhost:5000/elk/redis-commander-elk:latest

	@echo "----------------- Killing port-forward process -------------------"
	$(shell pkill -f "kubectl port-forward.*registry" || true)

	@echo "All base images created and pushed to registry successfully."

# Minikube Management
mk-config:
	@echo "----------------- Configuring Minikube -------------------"
	minikube config unset insecure-registry || true
	minikube config set insecure-registry "registry.default.svc.cluster.local:5000"
	minikube config set insecure-registry "localhost:5000"
	minikube config set memory 6144
	minikube config set cpus 2

mk-start: mk-config
	@echo "----------------- Starting Minikube -------------------"
	minikube start --insecure-registry="192.168.0.0/16"

mk-stop:
	@echo "----------------- Stopping Minikube -------------------"
	-minikube stop

mk-delete:
	@echo "----------------- Deleting Minikube cluster -------------------"
	minikube delete

mk-restart: mk-stop mk-start
	@echo "----------------- Restarting Minikube -------------------"


mk-up: mk-start
mk-build: mk-stop mk-delete mk-up mk-setup apply-config base_build


# Kubernetes Build
build-k8s:apply-instance-config build-k8s-redis build-k8s-redis-commander build-k8s-elasticsearch config-elasticsearch build-k8s-logstash build-k8s-kibana

mk-setup:
	@echo "----------------- Mounting working directory into Minikube -------------------"
	docker cp . minikube:/workspace

apply-config:
	@echo "----------------- Applying Kubernetes Registry -------------------"
	kubectl apply -f docker/registry.yaml
	kubectl rollout status deployment registry -n default --timeout=180s
	@echo "----------------- Ensuring registry is ready -------------------"
	@echo "Waiting for registry pod to be ready..."
	@kubectl wait --for=condition=ready pod -l app=registry -n default --timeout=90s
	@echo "Registry pod is ready!"
	@sleep 2

	@echo "----------------- Applying Kubernetes Namespace Limits -------------------"
	kubectl apply -f docker/limits.yaml

apply-instance-config:
	@echo "----------------- Applying Redis Persistent Volume -------------------"
	kubectl apply -f docker/redis/volume/redis-pv.yaml

	@echo "----------------- Setting Redis Persistent Volume permissions -------------------"
	minikube ssh -- 'sudo mkdir -p /mnt/data/redis && sudo chown -R 1000:1000 /mnt/data/redis && sudo chmod -R 775 /mnt/data/redis'

	@echo "----------------- Applying Redis Persistent Volume Claim -------------------"
	kubectl apply -f docker/redis/volume/redis-pvc.yaml

	@echo "----------------- Applying Elasticsearch Persistent Volume -------------------"
	kubectl apply -f docker/elasticsearch/volume/elasticsearch-pv.yaml

	@echo "----------------- Setting Elasticsearch Persistent Volume permissions -------------------"
	minikube ssh -- 'sudo mkdir -p /mnt/data/elasticsearch && sudo chown -R 1000:1000 /mnt/data/elasticsearch && sudo chmod -R 775 /mnt/data/elasticsearch'

	@echo "----------------- Applying Elasticsearch Persistent Volume Claim -------------------"
	kubectl apply -f docker/elasticsearch/volume/elasticsearch-pvc.yaml

	@echo "----------------- Applying Redis and Elasticsearch ConfigMaps -------------------"
	kubectl apply -f docker/redis/config/redis-config.yaml
	kubectl apply -f docker/redis-commander/config/redis-commander-config.yaml
	kubectl apply -f docker/elasticsearch/config/elasticsearch-config.yaml
	kubectl apply -f docker/elasticsearch/config/elasticsearch-secret.yaml
	kubectl apply -f docker/logstash/config/logstash-config.yaml
	kubectl apply -f docker/logstash/config/logstash-secret.yaml
	kubectl apply -f docker/kibana/config/kibana-config.yaml
	kubectl apply -f docker/kibana/config/kibana-secret.yaml

build-k8s-redis:
	@echo "----------------- Building Redis for Kubernetes -------------------"
	kubectl delete job redis-build --ignore-not-found=true
	kubectl apply -f docker/redis/redis-build-job.yaml
	kubectl wait --for=condition=complete job/redis-build --timeout=90s
	@echo "----------------- Logs for Redis build job -------------------"
	kubectl logs job/redis-build

build-k8s-redis-commander:
	@echo "----------------- Building Redis Commander for Kubernetes -------------------"
	kubectl delete job redis-commander-build --ignore-not-found=true
	kubectl apply -f docker/redis-commander/redis-commander-build-job.yaml
	kubectl wait --for=condition=complete job/redis-commander-build --timeout=60s
	@echo "----------------- Logs for Redis Commander build job -------------------"
	kubectl logs job/redis-commander-build

build-k8s-elasticsearch:
	@echo "----------------- Building Elasticsearch for Kubernetes -------------------"
	kubectl delete job elasticsearch-build --ignore-not-found=true
	kubectl apply -f docker/elasticsearch/elasticsearch-build-job.yaml
	kubectl wait --for=condition=complete job/elasticsearch-build --timeout=120s
	@echo "----------------- Logs for Elasticsearch build job -------------------"
	kubectl logs job/elasticsearch-build
	@echo "----------------- Creating Elasticsearch Service -------------------"
	kubectl apply -f docker/elasticsearch/service/elasticsearch-service.yaml

config-elasticsearch:
	@echo "----------------- Running Elasticsearch config Kubernetes -------------------"
	kubectl delete job elasticsearch-config-job --ignore-not-found=true
	@REGISTRY_HOST=$$(minikube ip); \
	ELASTIC_BUILT_IMAGE=$$(kubectl get configmap elasticsearch-config -o jsonpath='{.data.ELASTIC_BUILT_IMAGE}'); \
	export REGISTRY_HOST ELASTIC_BUILT_IMAGE; \
	envsubst < docker/elasticsearch/elasticsearch-config-job.yaml | kubectl apply -f -
	kubectl wait --for=condition=complete --timeout=300s job/elasticsearch-config-job || true
	@echo "----------------- Logs for Elasticsearch config job -------------------"
	kubectl logs job/elasticsearch-config-job
	#kubectl delete job elasticsearch-config-job

build-k8s-logstash:
	@echo "----------------- Building Logstash for Kubernetes -------------------"
	kubectl delete job logstash-build --ignore-not-found=true
	kubectl apply -f docker/logstash/logstash-build-job.yaml
	kubectl wait --for=condition=complete job/logstash-build --timeout=120s
	@echo "----------------- Logs for Logstash build job -------------------"
	kubectl logs job/logstash-build

build-k8s-kibana:
	@echo "----------------- Building Kibana for Kubernetes -------------------"
	kubectl delete job kibana-build --ignore-not-found=true
	kubectl apply -f docker/kibana/kibana-build-job.yaml
	kubectl wait --for=condition=complete job/kibana-build --timeout=120s
	@echo "----------------- Logs for Kibana build job -------------------"
	kubectl logs job/kibana-build

# Kubernetes Deployment
up-k8s: down-k8s up-k8s-redis up-k8s-redis-commander up-k8s-elasticsearch up-k8s-logstash up-k8s-kibana forward-k8s
	@echo "----------------- Listing running Kubernetes pods -------------------"
	kubectl get pods

up-k8s-redis:
	@echo "----------------- Delete Redis pods... -------------------"
	@kubectl delete pods -l app=redis
	@echo "----------------- Deploying Redis to Kubernetes -------------------"
	@REGISTRY_HOST=$$(minikube ip); \
	REDIS_BUILT_IMAGE=$$(kubectl get configmap redis-config -o jsonpath='{.data.REDIS_BUILT_IMAGE}'); \
	export REGISTRY_HOST REDIS_BUILT_IMAGE; \
	envsubst < docker/redis/redis-deployment.yaml | kubectl apply -f -
	@echo "----------------- Waiting for Redis pod to be ready -------------------"
	kubectl wait --for=condition=ready pod -l app=redis --timeout=60s
	@echo "----------------- Creating Redis Service -------------------"
	kubectl apply -f docker/redis/service/redis-service.yaml
	@echo "----------------- Testing Redis Service -------------------"
	kubectl get service redis

up-k8s-redis-commander:
	@echo "----------------- Deploying Redis Commander to Kubernetes -------------------"
	@REGISTRY_HOST=$$(minikube ip); \
	REDIS_COMMANDER_BUILT_IMAGE=$$(kubectl get configmap redis-commander-config -o jsonpath='{.data.REDIS_COMMANDER_BUILT_IMAGE}'); \
	export REGISTRY_HOST REDIS_COMMANDER_BUILT_IMAGE; \
	envsubst < docker/redis-commander/redis-commander-deployment.yaml | kubectl apply -f -
	@echo "----------------- Waiting for Redis Commander pod to be ready -------------------"
	kubectl wait --for=condition=ready pod -l app=redis-commander --timeout=60s

port-forward-redis-commander:
	@echo "----------------- Forwarding Redis Commander to localhost:8081 -------------------"
	nohup kubectl port-forward $$(kubectl get pods -l app=redis-commander -o jsonpath='{.items[0].metadata.name}') 8081:8081 > /dev/null 2>&1 &
	sleep 2
	@echo "----------------- Redis Commander should be accessible at http://localhost:8081 -------------------"

up-k8s-elasticsearch:
	@echo "----------------- Deploying final Elasticsearch instance -------------------"
	@REGISTRY_HOST=$$(minikube ip); \
	ELASTIC_BUILT_IMAGE=$$(kubectl get configmap elasticsearch-config -o jsonpath='{.data.ELASTIC_BUILT_IMAGE}'); \
	export REGISTRY_HOST ELASTIC_BUILT_IMAGE; \
	envsubst < docker/elasticsearch/elasticsearch-deploy.yaml | kubectl apply -f -
	kubectl wait --for=condition=available deployment/elasticsearch --timeout=300s
	@echo "----------------- Elasticsearch is now fully deployed and running! -------------------"

port-forward-elasticsearch:
	@echo "----------------- Waiting for Elasticsearch pod to be ready -------------------"
	kubectl wait --for=condition=ready pod -l app=elasticsearch --timeout=60s
	@echo "----------------- Forwarding Elasticsearch to localhost:9201 -------------------"
	nohup kubectl port-forward $$(kubectl get pods -l app=elasticsearch -o jsonpath='{.items[0].metadata.name}') 9201:9200 > nohup-elasticsearch.log 2>&1 &
	sleep 2
	@echo "----------------- Elasticsearch should be accessible at https://localhost:9201 -------------------"
	cat nohup-elasticsearch.log

up-k8s-logstash:
	@echo "----------------- Deploying Logstash to Kubernetes -------------------"
	@REGISTRY_HOST=$$(minikube ip); \
	LOGSTASH_BUILT_IMAGE=$$(kubectl get configmap logstash-config -o jsonpath='{.data.LOGSTASH_BUILT_IMAGE}'); \
	export REGISTRY_HOST LOGSTASH_BUILT_IMAGE; \
	envsubst < docker/logstash/logstash-deploy.yaml | kubectl apply -f -
	kubectl wait --for=condition=available deployment/logstash --timeout=300s
	@echo "----------------- Creating Logstash Service -------------------"
	kubectl apply -f docker/logstash/service/logstash-service.yaml
	@echo "----------------- Testing Logstash Service -------------------"
	kubectl get service logstash
	@echo "----------------- Logstash is now fully deployed! -------------------"

up-k8s-kibana:
	@echo "----------------- Deploying Kibana to Kubernetes -------------------"
	@REGISTRY_HOST=$$(minikube ip); \
	KIBANA_BUILT_IMAGE=$$(kubectl get configmap kibana-config -o jsonpath='{.data.KIBANA_BUILT_IMAGE}'); \
	export REGISTRY_HOST KIBANA_BUILT_IMAGE; \
	envsubst < docker/kibana/kibana-deploy.yaml | kubectl apply -f -
	kubectl wait --for=condition=available deployment/kibana --timeout=120s
	@echo "----------------- Kibana is now fully deployed! -------------------"

port-forward-kibana:
	@echo "----------------- Forwarding Kibana to localhost:5603 -------------------"
	kubectl port-forward $$(kubectl get pods -l app=kibana -o jsonpath='{.items[0].metadata.name}') 5603:5601 > /dev/null 2>&1 &
	sleep 2
	@echo "----------------- Kibana should be accessible at http://localhost:5603 -------------------"

forward-k8s: port-forward-redis-commander port-forward-elasticsearch port-forward-kibana


down-k8s:
	@echo "----------------- Deleting Redis and Redis Commander from Kubernetes -------------------"
	kubectl delete -f docker/redis/redis-deployment.yaml --ignore-not-found=true
	kubectl delete -f docker/redis-commander/redis-commander-deployment.yaml --ignore-not-found=true
	kubectl delete -f docker/elasticsearch/elasticsearch-deploy.yaml --ignore-not-found=true
	kubectl delete -f docker//logstash/logstash-deploy.yaml --ignore-not-found=true

ps-k8s:
	@echo "----------------- Listing running Kubernetes pods -------------------"
	kubectl get pods
	@echo "----------------- Listing Kubernetes services -------------------"
	kubectl get services

logs-k8s:
	@echo "----------------- Following logs for Redis deployment -------------------"
	kubectl logs -f deployment/kibana

redis-cli-k8s:
	@echo "----------------- Connecting to Redis CLI inside Kubernetes -------------------"
	kubectl exec -it deployment/redis -- redis-cli

build-logs:
	@echo "----------------- Following logs for Redis build job -------------------"
	kubectl logs job/redis-build --follow

clean-build:
	@echo "----------------- Cleaning up build jobs in Kubernetes -------------------"
	kubectl delete job redis-build redis-commander-build
