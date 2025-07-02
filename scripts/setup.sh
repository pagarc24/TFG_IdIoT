#!/bin/bash

PYTHON_PATH=""
ANALYZER_SOURCE_CODE="analyzer.py"
ANALYZER_EXECUTABLE="system_analyzer.sh"

python_not_installed() {
    VERSION="3.13.5"
    PRODUCT="Python-$VERSION"
    FILE="$PRODUCT.tar.xz"
    URL="https://www.python.org/ftp/python/$VERSION/$FILE"

    echo "Downloading $FILE from $URL..."

    wget -O "$FILE" "$URL"

    if [ $? -eq 0 ]; then
        echo "Download completed successfully. The file was saved as $FILE"
    else
        echo "Error: Download failed"
        exit 1
    fi

    echo "Extracting $FILE into $PRODUCT"

    mkdir $PRODUCT
    tar -xvf $FILE $PRODUCT

    if [ $? -eq 0 ]; then
        echo "Extraction completed successfull"
    else
        echo "Error: Extraction failed"
        exit 1
    fi

    #TODO FINISH
}

#PYTHON
command -v python3 &> /dev/null
if [ $? -eq 0 ]; then
    PYTHON_PATH=$(which python3)
else
    python_not_installed
fi

echo "$PYTHON_PATH $ANALYZER_SOURCE_CODE" > $ANALYZER_EXECUTABLE
chmod +x $ANALYZER_EXECUTABLE
#ALMACENAR EN UNA VARIABLE DE ENTORNO PARA QUE SOLO TENGA QUE LLAMARSE EL COMANDO
echo "Analyzer installed sucesfully. You can run the script using the command './$ANALYZER_EXECUTABLE'"