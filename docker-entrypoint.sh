#!/bin/bash
set -e

# Install additional gems by name if specified
if [ -n "$ADDITIONAL_GEM_NAMES" ]; then
    echo "Installing additional gems: $ADDITIONAL_GEM_NAMES"
    IFS=',' read -ra GEM_NAMES <<< "$ADDITIONAL_GEM_NAMES"
    for gem_name in "${GEM_NAMES[@]}"; do
        gem_name=$(echo "$gem_name" | xargs)
        if [ -n "$gem_name" ]; then
            echo "Installing gem: $gem_name"
            fluent-gem install "$gem_name"
        fi
    done
    echo "Additional gems installation completed"
fi

# Execute the base image's entrypoint with all arguments
exec tini -- /bin/entrypoint.sh "$@"
