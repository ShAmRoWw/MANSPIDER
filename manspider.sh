#!/bin/sh

set -eu

image=${MANSPIDER_IMAGE:-blacklanternsecurity/manspider}
runtime_uid=$(id -u)
runtime_gid=$(id -g)
runtime_volume=${MANSPIDER_VOLUME:-manspider-runtime-$runtime_uid}
kerberos_requested=0
for argument in "$@"; do
    case $argument in
        -k | --kerberos) kerberos_requested=1 ;;
    esac
done

# Keep every writable container path in Docker-managed local storage.  The
# former helper created and bind-mounted ./loot, ./logs, ./state, and a HOME
# tree; invoking it from a mounted customer share could therefore mutate that
# share before Python's path guards started.
volume_created=0
if ! docker volume inspect "$runtime_volume" >/dev/null 2>&1; then
    docker volume create --driver local "$runtime_volume" >/dev/null
    volume_created=1
fi
volume_driver=$(docker volume inspect --format '{{.Driver}}' "$runtime_volume")
volume_options=$(docker volume inspect --format '{{json .Options}}' "$runtime_volume")
if [ "$volume_driver" != local ] || { [ "$volume_options" != null ] && [ "$volume_options" != '{}' ]; }; then
    echo "Refusing non-local or option-backed Docker volume: $runtime_volume" >&2
    exit 2
fi
if [ "$volume_created" -eq 1 ]; then
    docker run --rm \
        --user 0:0 \
        --entrypoint /bin/sh \
        -v "$runtime_volume:/home/manspider" \
        "$image" \
        -c 'mkdir -p /home/manspider/.manspider/loot /home/manspider/.manspider/logs /home/manspider/.local/state/manspider/scans && chown -R -P "$1:$2" /home/manspider && chmod 700 /home/manspider/.local/state/manspider/scans' \
        manspider-volume-init "$runtime_uid" "$runtime_gid"
fi

# Preserve all original MANSPIDER arguments while prepending optional Docker
# arguments for host Kerberos files.
set -- "$image" "$@"
if [ "$kerberos_requested" -eq 1 ] && [ -n "${KRB5_CONFIG:-}" ]; then
    krb5_config_path=$KRB5_CONFIG
    case $krb5_config_path in
        /*) ;;
        *) krb5_config_path=$(pwd)/$krb5_config_path ;;
    esac
    if [ ! -f "$krb5_config_path" ]; then
        echo "KRB5_CONFIG file not found: $krb5_config_path" >&2
        exit 2
    fi
    set -- \
        -e KRB5_CONFIG=/tmp/manspider-krb5.conf \
        -v "$krb5_config_path:/tmp/manspider-krb5.conf:ro" \
        "$@"
fi
if [ "$kerberos_requested" -eq 1 ] && [ -n "${KRB5CCNAME:-}" ]; then
    case $KRB5CCNAME in
        FILE:*) krb5_ccache_path=${KRB5CCNAME#FILE:} ;;
        *:*)
            echo "Unsupported KRB5CCNAME cache type; manspider.sh requires a FILE cache" >&2
            exit 2
            ;;
        *) krb5_ccache_path=$KRB5CCNAME ;;
    esac
    case $krb5_ccache_path in
        /*) ;;
        *) krb5_ccache_path=$(pwd)/$krb5_ccache_path ;;
    esac
    if [ ! -f "$krb5_ccache_path" ]; then
        echo "KRB5CCNAME cache not found: $krb5_ccache_path" >&2
        exit 2
    fi
    set -- \
        -e KRB5CCNAME=FILE:/tmp/manspider-krb5cc \
        -v "$krb5_ccache_path:/tmp/manspider-krb5cc:ro" \
        "$@"
fi

if [ -t 0 ]; then
    set -- -it "$@"
fi

exec docker run --rm \
    --user "$runtime_uid:$runtime_gid" \
    -e HOME=/home/manspider \
    -e XDG_STATE_HOME=/home/manspider/.local/state \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$runtime_volume:/home/manspider" \
    "$@"
