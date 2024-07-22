#!/bin/bash

CONFIG="$HOME/.config/oem-scripts/config.ini"

valid_oem_scripts_config_jenkins_addr ()
{
    if [ -f "$CONFIG" ] && grep "^jenkins_addr = " "$CONFIG" > /dev/null 2>&1; then
        true
    else
        false
    fi
}

valid_oem_scripts_config ()
{
    if [ -f "$CONFIG" ] && grep "^oauth_consumer_key = " "$CONFIG" >/dev/null 2>&1; then
        true
    elif [ -n "$LAUNCHPAD_TOKEN" ]; then
        true
    else
        false
    fi
}

read_oem_scripts_config ()
{
    grep ^"$1 = " "$CONFIG" | cut -d ' ' -f 3-
}

write_oem_scripts_config ()
{
    if [ ! -f "$CONFIG" ]; then
        mkdir -p "$HOME/.config/oem-scripts"
        echo "[oem-scripts]" > "$CONFIG"
    fi
    if [ -z "$(read_oem_scripts_config "$1")" ]; then
        echo "$1 = $2" >> "$CONFIG"
    else
        sed -i "s/$1 = .*/$1 = $2/" "$CONFIG"
    fi
}
