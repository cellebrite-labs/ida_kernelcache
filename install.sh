#!/usr/bin/env bash

# TODO: support other OS platforms that are not Darwin
# TODO: support other IDA versions (not only 8.4)
IDA_PYTHON_LINK="/Applications/IDA Pro 8.4/idabin/libpython3.link.dylib"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Out variables by detect_python_version
IDA_PYTHON_DIR=""
IDA_PYTHON3=""

detect_python_version() {
    IDA_PYTHON_DIR=$(realpath "$IDA_PYTHON_LINK") || (echo "[❌] Missing file $IDA_PYTHON_LINK" && exit 1)
    IDA_PYTHON3=$(realpath "$IDA_PYTHON_DIR"/../bin/python3) || (echo "[❌] Missing python3" && exit 1)
    echo "[✅] IDA is using python which is installed at $IDA_PYTHON3"
}

install_python_package() {
    if [ "$(pip3 freeze  | grep 'ida[\-_]kernelcache')" != "" ]; then
        echo "[✅] ida_kernelcache python package is already installed"
        return
    fi


    # TODO: add y/n question here to decide if we want to install as user or as system?
    "$IDA_PYTHON3" -m pip install --user -e "$SCRIPT_DIR"
    [ $? = 0 ] && echo "[✅] pip installation as user completed successfully!" && return


    # TODO: do we need system-wide installation? fallback to system-wide ?
#    echo "[✅] enter your password to install the ida_kernelcache python package system-wide.."
#    sudo "$IDA_PYTHON3" -m pip install -e "$SCRIPT_DIR"
    echo "[❌] Failed to install package as root.. "
    exit 1
}

main() {
    detect_python_version
    install_python_package

    # TODO: convert plugins directory to a global constant
    if [ ! -d ~/.idapro/plugins ]; then
        mkdir -p ~/.idapro/plugins
        echo "[✅] Created IDA plugins directory"
    fi

    # TODO: when we call it ida_kernelcache.py it crashes because of a name conflict?
    cp ./ida_plugin_stub.py ~/.idapro/plugins/ida_kernelcache_develop.py
    echo "[✅] Installed plugin successfully [~/.idapro/plugins/ida_kernelcache_develop.py]! 🚀"
}

main
