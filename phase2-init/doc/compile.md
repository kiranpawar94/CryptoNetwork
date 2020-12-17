# Compilation Instructions
1 -go to https://www.bouncycastle.org/latest_releases.html

2 - download the latest release (https://www.bouncycastle.org/download/bcprov-ext-jdk15on-165.jar)

3 - copy the JAR file in the same folder as each of the project components (src folder if running on localhost, same folder as each part of the application - RunGroupServer and dependencies, RunFileServer and dependencies, ClientApp and dependencies 

ON THE TERMINAL :
ON WINDOWS:
4 - javac -cp .;bcprov-ext-jdk15on-165.jar *.java


ON UNIX/LINUX
4 - javac -cp .:bcprov-ext-jdk15on-165.jar *.java

*The rest of the instructions in 'usage.md' will be written assuming  UNIX/LINUX users. Adjust ".:" to ".;" as described above for Windows systems.
