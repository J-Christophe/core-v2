
@ECHO off
:: Batch file to start Sitools2
:: written by m.marseille (AKKA) 20/01/2011

:: Clear the screen
CLS
SETLOCAL
TITLE startSitools

:: Chemins courants du sitools
SET sitoolsHome="%INSTALL_PATH"
SET sitoolsSnap=%sitoolsHome%\workspace
SET sitoolsCots=%sitoolsHome%\cots
SET sitoolsCore=%sitoolsSnap%\fr.cnes.sitools.core

:: Parametres du script
SET prog=%0
SET prog=%prog:.bat=%
SET myDir=CHDIR
FOR /F "tokens=2 delims= " %%A IN ('TASKLIST /FI ^"WINDOWTITLE eq startSitools^" /NH') DO SET myPid=%%A

:: Creation du repertoire et du fichier 'LOG'
SET LOG_DIR="%USERPROFILE%\LOG"
IF NOT EXIST %LOG_DIR% MKDIR %LOG_DIR%
SET LOG="%LOG_DIR:~1,-1%\%prog%-%myPid%.log"
IF EXIST %LOG% DEL %LOG%
ECHO Fichier de LOG : %LOG:~1,-1%

:: Verifie que le fichier sitools.properties est présent
SET SITOOLS_PROPS=%sitoolsCore%\sitools.properties
IF EXIST %SITOOLS_PROPS% GOTO NOERROR 
ECHO --- ERREUR --- > %LOG%
ECHO Impossible de trouver %SITOOLS_PROPS%. Abandon. >> %LOG%
ECHO --- ERREUR --- >> %LOG%
GOTO :EOF
:NOERROR

:: Lancement de JAVA
SET ARGS=-Xms256m -Xmx512m -Djava.net.preferIPv4Stack=true -Djava.util.logging.config.file=%sitoolsCore%/conf/properties/sitools-logging.properties -Dfile.encoding=utf-8
IF "%1"=="--tests" GOTO tests
	::List of parameters to pass to the java program
	SET PROGRAM_PARAMS=%1
  	TITLE Sitools2
  	ECHO Refreshing CLASSPATH
	java -jar %sitoolsSnap%/sitools-update-classpath/sitools-update-classpath.jar --tmp_directory=ext --directory=ext --jar_target=fr.cnes.sitools.core.jar 2>&1 >> %LOG%
  	ECHO JAVA Sitools2 starting ...
  	ECHO JAVA Sitools2 starting ... >> %LOG%
  	java -jar %ARGS% fr.cnes.sitools.core.jar %PROGRAM_PARAMS% >> %LOG% 2>&1
  	GOTO :EOF
:tests
	TITLE Sitools2-Tests
	ECHO JAVA Sitools2 test suite starting ...
	ECHO JAVA Sitools2 test suite starting ... >> %LOG%
	java -jar %ARGS% fr.cnes.sitools.test.jar


:: -------------
:: fin du script
:: -------------

ENDLOCAL		

