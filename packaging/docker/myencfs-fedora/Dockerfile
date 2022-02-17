from fedora:latest

add myencfs.repo /var/lib/dockerbuild/

# Should be removed in favor of remote repo
add myencfs-repo /var/lib/dockerbuild/myencfs-repo

run \
	dnf install -y 'dnf-command(config-manager)' && \
	dnf config-manager --add-repo /var/lib/dockerbuild/myencfs.repo && \
	dnf config-manager --set-enabled myencfs && \
	dnf install -y myencfs
run \
	dnf config-manager --set-disabled myencfs; \
	rm -fr /var/lib/dockerbuild/
run \
	groupadd -r myencfs && useradd -r -g myencfs myencfs
run \
	mkdir -p /var/tmp/myencfs-work

user myencfs:myencfs
volume ["/var/tmp/myencfs-work"]
entrypoint ["/usr/bin/myencfs-tool"]
