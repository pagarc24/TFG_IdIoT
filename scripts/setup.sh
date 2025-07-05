#!/bin/bash
[ "$UID" -ne 0 ] && echo "This script must be run as root. Trying again with sudo..." && exit 1

ANALYZER_SOURCE_CODE="analyzer.py"
ANALYZER_EXECUTABLE="system_analyzer.sh"

dependencies() {
    python3 -m pip install --break-system-packages -r dependencies.txt
    if [ $? -eq 0 ]; then
        echo "Dependencies installed"
    else
        echo "Error: An error occurred while installing the dependencies"
        exit 1
    fi
}

command -v python3 &> /dev/null
if [ $? -eq 0 ]; then
    PYTHON_PATH=$(which python3)
else
    echo "Error: Python3 not installed in this system"
    exit 1
fi

python3 -m pip --version
if [ $? -eq 0 ]; then
    dependencies
else
    python3 -c "import urllib.request; urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')"
    python3 get-pip.py --break-system-packages
    if [ $? -eq 0 ]; then
        dependencies
    else
        echo "Error: pip not installed in this system"
    fi
    exit 1
fi

echo "$PYTHON_PATH $(pwd)/$ANALYZER_SOURCE_CODE" > $ANALYZER_EXECUTABLE
chmod +x $ANALYZER_EXECUTABLE
echo "Analyzer installed sucesfully. You can run the script using the command 'sudo ./$ANALYZER_EXECUTABLE'"