# SYSTEM ANALYZER  
  
## EN  
### Purpose    
The purpose of this document is to explain the installation of the analyzer dependencies in order to identify possible vulnerabilities in your system.  

### How to install the tool?  
First you need to have Python3 installed on your system. It can be downloaded from the [Python web site](https://www.python.org/downloads/).  
With Python3 installed, you can proceed to set the necessary dependencies to use the analyzer by means of [setup.sh](setup.sh).You must first give yourself permissions to execute:  
```  
chmod +x setup.sh  
```  
Once the permissions are configured, we can run the script, which will check if we have the necessary dependencies, and if we do not have them, it installs them for a correct operation of the analyzer. For a correct installation we must execute the installer as superuser:  
```  
sudo ./setup.sh  
```  
If the resources are installed correctly, a message like this one will appear:  
```  
Analyzer installed sucesfully. You can run the script using the command 'sudo ./system_analyzer.sh'  
```  
In this case you can now use the analyzer as indicated in the message (remember to run it as superuser). ~~Enjoy~~ securize it!  

## ES  
### Objetivo  
El objetivo de este documento es explicar la instalación de las dependencias del analizador para poder identificar posibles vulnerabilidades en tu sistema.  

### ¿Cómo instalar la herramienta?  
Primeramente necesitas tener instalado Python3 en el sistema. Se puede descargar desde [la página web de Python](https://www.python.org/downloads/).  
Con Python3 instalado se puede proceder a poner las dependencias necesarias para usar el analizador por medio de [setup.sh](setup.sh). Primeramente debe darse permisos de ejecución:  
```  
chmod +x setup.sh  
```  
Una vez queden los permisos configurados, ya podemos ejecutar el script, que se encargará de comprobar si tenemeos las dependencias necesarias, y en caso de no tenerlas las instala para un correcto funcionamiento del analizador. Para una correcta instalación debemos ejecutar el instalador como superusuario:  
```  
sudo ./setup.sh  
```  
En caso de que se instalen los recursos correctamente saldrá un mensaje como este:  
```  
Analyzer installed sucesfully. You can run the script using the command 'sudo ./system_analyzer.sh'  
```  
En tal caso ya puedes hacer uso del analizador como se indica en el mensaje (recuerda ejecutarlo como superusuario). ¡A ~~disfrutar~~ securizar se ha dicho!  
