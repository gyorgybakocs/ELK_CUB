include .env
.PHONY: base_build pre_build stop_containers remove_containers remove_volumes \
remove_images prune_builders clear build_es build_ls build_kb build_elk \
build_images build provision up down clean ps logs redis_cli

# define some variables
IMG_PREFIX=bgds-dc
CONTAINER_NAMES=elastic-dc logstash-dc kibana-dc redis-dc rediscommander-dc
VOLUME_NAMES=elasticsearch-dc-data redis-dc-data
IMAGE_NAMES=${IMG_PREFIX}-redis:latest ${IMG_PREFIX}-rediscommander:latest ${IMG_PREFIX}-elastic:${ELK_VERSION} ${IMG_PREFIX}-logstash:${ELK_VERSION} ${IMG_PREFIX}-kibana:${ELK_VERSION}

base_build:
	@echo "----------------- Creating base images -------------------"
	docker pull docker.elastic.co/elasticsearch/elasticsearch:${ELK_VERSION}
	echo "FROM docker.elastic.co/elasticsearch/elasticsearch:${ELK_VERSION}" | docker build -t elk/elastic-elk:${ELK_VERSION} -f - .

	docker pull docker.elastic.co/logstash/logstash:${ELK_VERSION}
	echo "FROM docker.elastic.co/logstash/logstash:${ELK_VERSION}" | docker build -t elk/logstash-elk:${ELK_VERSION} -f - .

	docker pull docker.elastic.co/kibana/kibana:${ELK_VERSION}
	echo "FROM docker.elastic.co/kibana/kibana:${ELK_VERSION}" | docker build -t elk/kibana-elk:${ELK_VERSION} -f - .

	docker pull redis:latest
	echo "FROM redis:latest" | docker build -t elk/redis-elk:latest -f - .

	docker pull rediscommander/redis-commander:latest
	echo "FROM rediscommander/redis-commander:latest" | docker build -t elk/redis-commander-elk:latest -f - .

	@echo "All base images created successfully."

# generate and verify all necessary certificates
pre_build:
	KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD} ELASTIC_PASSWORD=${ELASTIC_PASSWORD} ELASTIC_INTERNAL=${ELASTIC_INTERNAL} ELASTICSEARCH_HOST=${ELASTICSEARCH_HOST} bash docker/scripts/gen_certs.sh

# clearing
stop_containers:
	@echo "----------------- Stop all containers -------------------"
	docker stop $(CONTAINER_NAMES) || echo "Some containers are not running or already stopped"
remove_containers:
	@echo "----------------- Remove all containers -------------------"
	docker rm -f $(CONTAINER_NAMES) || echo "Some containers not found or already removed"
remove_volumes:
	@echo "----------------- Remove all volumes -------------------"
	docker volume rm $(VOLUME_NAMES) || echo "Some volumes not found or already removed"
remove_images:
	@echo "----------------- Remove all images -------------------"
	docker rmi -f $(IMAGE_NAMES) || echo "Some images not found or already removed"
prune_builders:
	@echo "----------------- Prune all builders -------------------"
	docker builder prune -a

clear: stop_containers remove_containers remove_volumes remove_images prune_builders

# building
# Build Elasticsearch
build_es:
	@echo "----------------- Building Elasticsearch image -------------------"
	docker compose --env-file .env -f docker-compose-elk.build.yaml build elk-cub-dc-elastic --no-cache --progress plain --no-cache
# Build Logstash
build_ls:
	@echo "----------------- Building Logstash image -------------------"
	docker compose --env-file .env -f docker-compose-elk.build.yaml build elk-cub-dc-logstash --no-cache --progress plain --no-cache
# Build Kibana
build_kb:
	@echo "----------------- Building Kibana image -------------------"
	docker compose --env-file .env -f docker-compose-elk.build.yaml build elk-cub-dc-kibana --no-cache --progress plain --no-cache
# Build ELK in correct order
build_elk: build_es build_ls build_kb

# Docker Compose commands
build_images:
	@echo "----------------- Building all other Docker images -------------------"
	docker compose --env-file .env -f docker-compose.build.yaml build --no-cache --progress plain --no-cache

build: clear build_images build_elk

# Full provision including certificates
provision: pre_build build

up:
	@echo "----------------- Starting Docker containers -------------------"
	docker compose --env-file .env -f docker-compose.yaml up --remove-orphans

upd:
	@echo "----------------- Starting Docker containers -------------------"
	docker compose --env-file .env -f docker-compose.yaml up -d --remove-orphans

down:
	@echo "----------------- Stopping Docker containers -------------------"
	docker compose --env-file .env -f docker-compose.yaml down
clean: down
	@echo "----------------- Cleaning up Docker volumes -------------------"
	docker compose down -v

ps:
	@echo "----------------- Listing running Docker containers -------------------"
	docker compose ps

logs:
	@echo "----------------- Following Docker logs -------------------"
	docker compose logs -f
