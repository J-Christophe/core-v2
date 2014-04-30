#!/bin/bash
# ---------
# Fonctions
# ---------

checkIfRunning() {
    local pid=`cat ${LOG_DIR}/${prog}.run`
    [ "`ps -ef |grep ${pid} | grep -v 'grep' | awk '{print $2}'`" != "" ] && return 1
    return 0
       
}

# ---------
# principal
# ---------

# Chemins courants du sitools
sitoolsHome="%INSTALL_PATH"
sitoolsSnap="${sitoolsHome}/workspace"
sitoolsCots="${sitoolsHome}/cots"
sitoolsCore="${sitoolsSnap}/fr.cnes.sitools.core"

# Parametres du script
prog=`basename ${0}`
myDir=`dirname ${0}`
myPid=${$}

sitoolsCore="${sitoolsSnap}/fr.cnes.sitools.core"

sitoolsJarName="%{host_port}_fr.cnes.sitools.core.jar"


# Creation du repertoire et du fichier 'LOG'
LOG_DIR="%INSTALL_PATH/LOG"
[ ! -d ${LOG_DIR} ] && mkdir -p ${LOG_DIR}
LOG="${LOG_DIR}/${prog}-${myPid}.log"

SITOOLS_PROPS="${sitoolsCore}/sitools.properties"
if [ ! -f ${SITOOLS_PROPS} ];then
    echo "--- ERREUR ---" | tee -a ${LOG}
    echo "Impossible de trouver ${SITOOLS_PROPS}. Abandon." | tee -a ${LOG}
    echo "--- ERREUR ---" | tee -a ${LOG}
    exit 1
fi

# Lancement de JAVA
if [ -f ${LOG_DIR}/${prog}.run ];then
    checkIfRunning
    if [ ${?} -ne 0 ];then
        echo "sitools est deja lance." | tee -a ${LOG}
        exit 0
    fi
    \rm ${LOG_DIR}/${prog}.run
fi

ARGS="-Xms256m -Xmx512m -Djava.net.preferIPv4Stack=true -Djava.awt.headless=true"



if [ "$i" != "--tests" ];then
 #List of parameters to pass to the java program
 PROGRAM_PARAMS="${1}"
 echo "Refreshing ClassPath for plugins ..."
 nohup java -jar ${sitoolsSnap}/sitools-update-classpath/sitools-update-classpath.jar --tmp_directory=./ext --directory=./ext --jar_target=./${sitoolsJarName} 2>&1 | tee -a ${LOG}
 echo "Lancement de JAVA sitools..." | tee -a ${LOG}
 nohup java -jar ${ARGS} ${sitoolsCore}/${sitoolsJarName} ${PROGRAM_PARAMS} 2>&1 | tee -a ${LOG} &
else
 echo "Lancement de la suite de tests JAVA sitools..." | tee -a ${LOG}
 nohup java -jar ${ARGS} ${sitoolsCore}/fr.cnes.sitools.test.jar 2>&1 | tee -a ${LOG} &
fi

sitoolsPid=`ps -ef |grep $sitoolsJarName | grep -v 'grep' | awk '{print $2}'`
echo "Ecriture du fichier PID [${sitoolsPid}]"
echo "${sitoolsPid}" > ${LOG_DIR}/${prog}.run
# -------------
# fin du script
# -------------
